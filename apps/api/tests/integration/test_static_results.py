"""Trusted ingest of static.v1 results into tenant tables, the read API and the report."""

import gzip
import json
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from cyberlab_jobs import IngestMessageV1
from cyberlab_jobs.static import ElfInfo, StringRecord
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.main import app
from app.modules.analysis import dispatch
from app.modules.analysis.models import AnalysisJob
from app.modules.audit.models import AuditLog
from app.modules.organizations.models import MemberRole
from app.modules.pcap_analysis import models as pcap_models
from app.modules.static_analysis import ingest as static_ingest
from app.modules.static_analysis import models as static_models
from app.modules.static_analysis import report as reports
from app.modules.static_analysis.schemas import REPORT_SCHEMA, StaticReport
from app.workers import ingest
from tests import pcap_results as pr
from tests import static_results as sr
from tests.analysis_helpers import SentJobs, new_case, pe_bytes, tiny_pcap, upload
from tests.factories import Registered, add_member, login, make_user, register, unique_email

RowCounts = Callable[[], Awaitable[dict[str, int]]]
TABLES = (*pcap_models.RESULT_TABLES, *static_models.RESULT_TABLES)
STATIC_ROUTES = (
    "sample",
    "sections",
    "imports",
    "exports",
    "resources",
    "strings",
    "signatures",
    "capabilities",
)


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


@pytest.fixture
def row_counts(owner_engine: AsyncEngine) -> RowCounts:
    """Rows per result table (pcap and static) across ALL organizations (FORCE RLS lifted
    in a rolled-back transaction, see test_pcap_results.py)."""

    async def count() -> dict[str, int]:
        async with owner_engine.connect() as conn:
            try:
                counts = {}
                for model in TABLES:
                    table = model.__tablename__
                    await conn.execute(text(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY"))
                    counts[table] = int(
                        await conn.scalar(text(f"SELECT count(*) FROM {table}")) or 0
                    )
                return counts
            finally:
                await conn.rollback()

    return count


def _expected_rows(**overrides: int) -> dict[str, int]:
    return {m.__tablename__: 0 for m in TABLES} | sr.TABLE_COUNTS | overrides


SAMPLE_BYTES = pe_bytes()
SAMPLE = sr.sample_for(SAMPLE_BYTES)


async def _job_for(
    sent: SentJobs, content: bytes = SAMPLE_BYTES, filename: str = "sample.exe"
) -> tuple[Registered, dispatch.DispatchInput, dict[str, Any]]:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), content, filename)
    item = sent[-1]
    assert item.analyzer == "static"
    return reg, item, evidence


async def _job(item: dispatch.DispatchInput) -> AnalysisJob:
    async with tenant_session(item.organization_id, None) as session:
        job = await session.get(AnalysisJob, item.job_id)
    assert job is not None
    return job


def _base(reg: Registered, job_id: uuid.UUID | str) -> str:
    return f"/api/v1/orgs/{reg.org_id}/analyses/{job_id}"


async def _get(client: AsyncClient, url: str, **params: Any) -> Any:
    response = await client.get(url, params=params)
    assert response.status_code == 200, response.text
    return response.json()


async def _custody(reg: Registered, evidence_id: str) -> list[dict[str, Any]]:
    url = f"/api/v1/orgs/{reg.org_id}/evidence/{evidence_id}/custody"
    return list((await reg.client.get(url)).json()["items"])


async def _audits(org_id: uuid.UUID, action: str) -> list[AuditLog]:
    async with tenant_session(org_id, None) as session:
        rows = await session.execute(select(AuditLog).where(AuditLog.action == action))
        return list(rows.scalars())


# --- ingest: success ----------------------------------------------------------------------


async def test_result_is_persisted_with_summary_and_custody(
    sent: SentJobs, row_counts: RowCounts
) -> None:
    reg, item, evidence = await _job_for(sent)
    await pr.deliver(item, sr.stream(item.job_id, SAMPLE))

    job = await _job(item)
    assert job.status == "succeeded", job.error_code
    assert await row_counts() == _expected_rows()

    summary = (await _get(reg.client, _base(reg, item.job_id)))["summary"]
    assert summary["schema_version"] == "static.v1" and summary["profile"] == "full"
    assert summary["file_format"] == "pe"
    assert summary["counts"] == sr.SAMPLE_COUNTS
    assert summary["tool_versions"] == sr.TOOLS  # incl. clamav_db, clamav_db_date, capa_rules
    assert summary["engine_errors"] == [] and summary["truncated"] == {}
    # Trusted facts are the evidence record's; analyzer-derived hashes are labelled.
    assert {k: summary["sample"][k] for k in ("md5", "sha1", "sha256")} == evidence["hashes"]
    assert summary["sample"]["size"] == evidence["size_bytes"]
    assert summary["sample"]["analyzer_derived"] == {
        "ssdeep": SAMPLE.ssdeep,
        "imphash": "a" * 32,
        "rich_header_hash": "b" * 32,
    }
    assert summary["pe"]["machine"] == "AMD64" and "imphash" not in summary["pe"]
    assert summary["pe"]["image_base"] == 2**64 - 2**32
    assert summary["elf"] is None

    [analyzed] = [e for e in await _custody(reg, evidence["id"]) if e["action"] == "analyzed"]
    assert analyzed["details"]["tool_versions"] == sr.TOOLS
    assert analyzed["details"]["job_id"] == str(item.job_id)
    [succeeded] = await _audits(reg.org_id, "analysis.succeeded")
    assert succeeded.details["counts"] == sr.SAMPLE_COUNTS


async def test_redelivery_after_success_inserts_nothing(
    sent: SentJobs, row_counts: RowCounts
) -> None:
    _, item, _ = await _job_for(sent)
    stale = await _job(item)  # loaded while still queued: passes the unlocked fast path
    message = await pr.deliver(item, sr.stream(item.job_id, SAMPLE))
    before = await row_counts()
    assert before == _expected_rows()

    await ingest.handle_event(message)  # broker redelivery
    await ingest.ingest_success(stale, IngestMessageV1.model_validate(message))
    assert await row_counts() == before
    assert (await _job(item)).status == "succeeded"


async def test_minimal_result_of_an_other_file(sent: SentJobs, row_counts: RowCounts) -> None:
    """An `av` run over a plain file: a sample line and nothing else."""
    content = b"meeting notes\n"
    _, item, _ = await _job_for(sent, content, "notes.txt")
    assert item.profile == "av"
    raw = sr.lines(
        item.job_id, sr.sample_for(content), [], with_pe=False, profile="av", file_format="other"
    )
    await pr.deliver(item, pr.encode(raw))
    job = await _job(item)
    assert job.status == "succeeded", job.error_code
    assert job.summary["pe"] is None and job.summary["profile"] == "av"
    assert set(job.summary["counts"].values()) == {0}
    assert await row_counts() == {m.__tablename__: 0 for m in TABLES} | {"malware_samples": 1}


async def test_elf_result_keeps_a_capped_needed_list_in_the_summary(sent: SentJobs) -> None:
    reg, item, _ = await _job_for(sent)
    needed = [f"lib{i}.so" for i in range(40)]
    elf = ElfInfo(
        elf_class=64,
        machine="x86-64",
        elf_type="DYN",
        entry_point=0x1000,
        needed=needed,
        stripped=True,
    )
    raw = sr.lines(item.job_id, SAMPLE, [], with_pe=False, file_format="elf")
    await pr.deliver(item, pr.encode([*raw, pr.line(elf)]))
    job = await _job(item)
    assert job.status == "succeeded", job.error_code
    assert job.summary["elf"]["needed_total"] == 40
    assert job.summary["elf"]["needed"] == needed[: static_ingest.SUMMARY_NEEDED_MAX]
    sample = await _get(reg.client, f"{_base(reg, item.job_id)}/sample")
    assert sample["elf"]["needed"] == needed and sample["pe"] is None  # the row keeps all


# --- ingest: hostile streams --------------------------------------------------------------


def _sample_dict(**fields: Any) -> dict[str, Any]:
    return {**SAMPLE.model_dump(mode="json"), **fields}


def _hostile(case: str, job_id: uuid.UUID) -> bytes:
    good = sr.lines(job_id, SAMPLE)
    head, body = good[:3], good[3:]
    header = sr.header(job_id).model_dump(mode="json")

    def with_sample(**fields: Any) -> bytes:
        return pr.encode([head[0], pr.line(_sample_dict(**fields)), *good[2:]])

    if case == "unknown_kind":
        return pr.encode([*good, pr.line({"kind": "shell", "cmd": "id"})])
    if case == "extra_field":
        return pr.encode(
            [
                *good,
                pr.line(
                    {
                        "kind": "string",
                        "value": "x",
                        "encoding": "ascii",
                        "organization_id": str(uuid.uuid4()),
                    }
                ),
            ]
        )
    if case == "pcap_header":  # another schema's header on a static job
        return pr.encode([pr.line(pr.header(job_id)), *good[1:]])
    if case == "foreign_job_header":
        return pr.encode(sr.lines(uuid.uuid4(), SAMPLE))
    if case == "sample_sha256_mismatch":
        return with_sample(sha256="0" * 64)
    if case == "sample_size_mismatch":
        return with_sample(size=SAMPLE.size + 1)
    if case == "sample_md5_mismatch":
        return with_sample(md5="0" * 32)
    if case == "sample_sha1_mismatch":
        return with_sample(sha1="0" * 40)
    if case == "two_samples":
        return pr.encode([*good, good[1]])
    if case == "no_sample":
        return pr.encode([head[0], head[2], *body])
    if case == "pe_line_on_elf_format":
        return pr.encode([pr.line({**header, "file_format": "elf"}), *good[1:]])
    if case == "pe_line_on_other_format":
        return pr.encode([pr.line({**header, "file_format": "other"}), *good[1:]])
    if case == "two_pe":
        return pr.encode([*good, head[2]])
    if case == "nul_string":
        return pr.encode(
            [*good, pr.line({"kind": "string", "value": "a\x00b", "encoding": "ascii"})]
        )
    if case == "oversized_string":
        return pr.encode(
            [*good, pr.line({"kind": "string", "value": "a" * 513, "encoding": "ascii"})]
        )
    if case == "unknown_encoding":
        return pr.encode([*good, pr.line({"kind": "string", "value": "a", "encoding": "utf32"})])
    if case == "nan_entropy":  # json.dumps writes the NaN literal
        return with_sample(entropy=float("nan"))
    if case == "entropy_above_8":
        return with_sample(entropy=8.5)
    if case == "address_over_64_bits":
        section = json.loads(body[0])
        return pr.encode([*good, pr.line({**section, "virtual_address": 2**64})])
    if case == "bad_attack_id":
        cap = {"kind": "capability", "name": "x", "attack": ["T1055; DROP TABLE"]}
        return pr.encode([*good, pr.line(cap)])
    if case == "nul_tool_version":
        tools = {**sr.TOOLS, "yara": "4\x00"}
        return pr.encode([pr.line({**header, "tool_versions": tools}), *good[1:]])
    if case == "duplicate_finding":
        finding = next(x for x in good if b'"kind":"finding"' in x)
        return pr.encode([*good, finding])
    if case == "duplicate_ioc":
        ioc = next(x for x in good if b'"kind":"ioc"' in x)
        return pr.encode([*good, ioc])
    if case == "header_twice":
        return pr.encode([*good, good[0]])
    if case == "bad_trailer_hash":
        return pr.encode(good, trailer={"sha256": "0" * 64})
    if case == "wrong_trailer_count":
        return pr.encode(good, trailer={"line_count": len(good) + 1})
    if case == "missing_trailer":
        return pr.encode(good, add_trailer=False)
    if case == "missing_header":
        return pr.encode(good[1:])
    if case == "not_gzip":
        return b"".join(good)
    if case == "corrupt_gzip":
        data = pr.encode(good)
        return data[: len(data) // 2]
    if case == "unterminated_line":
        return gzip.compress(b"".join(good) + b'{"kind":"trailer"')
    raise AssertionError(case)


HOSTILE = [
    "unknown_kind",
    "extra_field",
    "pcap_header",
    "foreign_job_header",
    "sample_sha256_mismatch",
    "sample_size_mismatch",
    "sample_md5_mismatch",
    "sample_sha1_mismatch",
    "two_samples",
    "no_sample",
    "pe_line_on_elf_format",
    "pe_line_on_other_format",
    "two_pe",
    "nul_string",
    "oversized_string",
    "unknown_encoding",
    "nan_entropy",
    "entropy_above_8",
    "address_over_64_bits",
    "bad_attack_id",
    "nul_tool_version",
    "duplicate_finding",
    "duplicate_ioc",
    "header_twice",
    "bad_trailer_hash",
    "wrong_trailer_count",
    "missing_trailer",
    "missing_header",
    "not_gzip",
    "corrupt_gzip",
    "unterminated_line",
]


async def _assert_refused(item: dispatch.DispatchInput, row_counts: RowCounts) -> None:
    job = await _job(item)
    assert (job.status, job.error_code) == ("failed", "invalid_result")
    assert job.summary == {} and job.result_version_id is None
    assert set((await row_counts()).values()) == {0}


@pytest.mark.parametrize("case", HOSTILE)
async def test_hostile_stream_fails_the_job_and_writes_nothing(
    sent: SentJobs, row_counts: RowCounts, case: str
) -> None:
    reg, item, evidence = await _job_for(sent)
    await pr.deliver(item, _hostile(case, item.job_id))
    await _assert_refused(item, row_counts)
    assert "analyzed" not in [e["action"] for e in await _custody(reg, evidence["id"])]


async def test_sample_of_another_file_is_refused(sent: SentJobs, row_counts: RowCounts) -> None:
    """RT6: a self-consistent result about different bytes than the stored evidence."""
    _, item, _ = await _job_for(sent)
    await pr.deliver(item, sr.stream(item.job_id, sr.sample_for(b"some other file")))
    await _assert_refused(item, row_counts)


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("static_max_strings", 3),  # 4 strings
        ("static_max_imports", 5),  # 6 imports
        ("static_max_iocs", 3),  # 4 IOCs
        ("static_max_findings", 1),  # 2 findings
        ("static_max_signature_matches", 1),
        ("static_max_capabilities", 1),
        ("static_max_sections", 2),
        ("static_max_exports", 1),
        ("static_max_resources", 1),
    ],
)
async def test_more_records_than_the_static_limits_are_refused(
    sent: SentJobs,
    monkeypatch: pytest.MonkeyPatch,
    row_counts: RowCounts,
    setting: str,
    value: int,
) -> None:
    monkeypatch.setattr(get_settings(), setting, value)
    _, item, _ = await _job_for(sent)
    await pr.deliver(item, sr.stream(item.job_id, SAMPLE))
    await _assert_refused(item, row_counts)


async def test_more_lines_than_the_total_cap_are_refused(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch, row_counts: RowCounts
) -> None:
    lines = len(sr.lines(uuid.uuid4(), SAMPLE)) + 1  # + trailer
    monkeypatch.setattr(get_settings(), "analysis_max_result_lines", lines - 1)
    _, item, _ = await _job_for(sent)
    await pr.deliver(item, sr.stream(item.job_id, SAMPLE))
    await _assert_refused(item, row_counts)


async def test_gzip_bomb_is_refused_at_the_decompressed_cap(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch, row_counts: RowCounts
) -> None:
    cap = 256 * 1024
    monkeypatch.setattr(get_settings(), "analysis_max_result_decompressed_bytes", cap)
    _, item, _ = await _job_for(sent)
    filler = [StringRecord(value="A" * 500, encoding="ascii")] * 4000
    data = sr.stream(item.job_id, SAMPLE, records=list(filler))
    assert len(data) < cap // 10 < cap < len(gzip.decompress(data))
    await pr.deliver(item, data)
    await _assert_refused(item, row_counts)


async def test_oversized_compressed_result_is_refused(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch, row_counts: RowCounts
) -> None:
    monkeypatch.setattr(get_settings(), "static_max_result_bytes", 64)
    _, item, _ = await _job_for(sent)
    await pr.deliver(item, sr.stream(item.job_id, SAMPLE))
    await _assert_refused(item, row_counts)


async def test_database_refusal_mid_ingest_rolls_everything_back(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch, row_counts: RowCounts
) -> None:
    """A value the database refuses after the sample row and some batches went in."""
    reg, item, evidence = await _job_for(sent)
    real = static_ingest.to_row

    def poisoned(record: Any) -> Any:
        table, row = real(record)
        if record.kind == "ioc":
            return table, {**row, "source": "x" * 100}  # VARCHAR(16)
        return table, row

    monkeypatch.setattr(static_ingest, "to_row", poisoned)
    monkeypatch.setattr(static_ingest, "BATCH_LINES", 2)
    await pr.deliver(item, sr.stream(item.job_id, SAMPLE))
    await _assert_refused(item, row_counts)
    assert "analyzed" not in [e["action"] for e in await _custody(reg, evidence["id"])]


async def test_unexpected_error_mid_ingest_is_an_ingest_error(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch, row_counts: RowCounts
) -> None:
    _, item, _ = await _job_for(sent)
    real = static_ingest.to_row

    def explode_on_capabilities(record: Any) -> Any:
        if record.kind == "capability":
            raise ValueError("boom")
        return real(record)

    monkeypatch.setattr(static_ingest, "to_row", explode_on_capabilities)
    await pr.deliver(item, sr.stream(item.job_id, SAMPLE))
    job = await _job(item)
    assert (job.status, job.error_code) == ("failed", "ingest_error")
    assert set((await row_counts()).values()) == {0}


# --- read API -----------------------------------------------------------------------------


async def _ingested(sent: SentJobs) -> tuple[Registered, dispatch.DispatchInput, str]:
    reg, item, _ = await _job_for(sent)
    await pr.deliver(item, sr.stream(item.job_id, SAMPLE))
    assert (await _job(item)).status == "succeeded"
    return reg, item, _base(reg, item.job_id)


async def test_sample_shows_trusted_hashes_and_labelled_derived_ones(sent: SentJobs) -> None:
    reg, item, base = await _ingested(sent)
    sample = await _get(reg.client, f"{base}/sample")
    assert sample["sha256"] == SAMPLE.sha256 and sample["size"] == len(SAMPLE_BYTES)
    assert sample["md5"] == SAMPLE.md5 and sample["sha1"] == SAMPLE.sha1
    assert sample["job_id"] == str(item.job_id) and sample["evidence_id"] == str(item.evidence_id)
    assert sample["analyzer_derived"]["ssdeep"] == SAMPLE.ssdeep
    assert sample["analyzer_derived"]["imphash"] == "a" * 32
    assert sample["file_format"] == "pe" and sample["entropy"] == 6.25
    assert sample["pe"]["image_base"] == 2**64 - 2**32  # exact beyond 2**63
    assert sample["pe"]["characteristics"] == ["EXECUTABLE_IMAGE", "LARGE_ADDRESS_AWARE"]


async def test_sections_exports_and_resources(sent: SentJobs) -> None:
    reg, _, base = await _ingested(sent)
    c = reg.client
    sections = await _get(c, f"{base}/sections")
    assert [s["name"] for s in sections["items"]] == [".text", ".rdata", "UPX1"]
    assert sections["items"][2]["virtual_address"] == 2**64 - 4096
    assert sections["items"][2]["flags"] == ["read", "write", "execute"]
    paged = await _get(c, f"{base}/sections", limit=1, offset=1)
    assert paged["total"] == 3 and [s["name"] for s in paged["items"]] == [".rdata"]

    exports = await _get(c, f"{base}/exports")
    assert [e["ordinal"] for e in exports["items"]] == [1, 2**32 - 1]
    assert exports["items"][1]["address"] == 2**64 - 1 and exports["items"][1]["name"] is None
    assert (await _get(c, f"{base}/exports", q="%"))["total"] == 1  # literal, not a wildcard
    assert (await _get(c, f"{base}/exports", q="dllmain"))["total"] == 1

    resources = await _get(c, f"{base}/resources")
    assert [r["type"] for r in resources["items"]] == ["RT_RCDATA", "RT_VERSION"]
    assert resources["items"][0]["sha256"] == "c" * 64


async def test_import_filters(sent: SentJobs) -> None:
    reg, _, base = await _ingested(sent)
    c = reg.client
    imports = await _get(c, f"{base}/imports")
    assert imports["total"] == 6
    assert [i["library"] for i in imports["items"]][:2] == ["ADVAPI32.dll", "KERNEL32.dll"]
    assert (await _get(c, f"{base}/imports", library="kernel32.dll"))["total"] == 4
    assert (await _get(c, f"{base}/imports", library="kernel32"))["total"] == 0  # exact name
    assert (await _get(c, f"{base}/imports", library="%"))["total"] == 0
    assert (await _get(c, f"{base}/imports", library="KERNEL__.dll"))["total"] == 0
    assert (await _get(c, f"{base}/imports", q="process"))["total"] == 1
    assert (await _get(c, f"{base}/imports", q="ws2"))["total"] == 1  # matches the library
    [ordinal] = (await _get(c, f"{base}/imports", library="ws2_32.dll"))["items"]
    assert ordinal["function"] is None and ordinal["ordinal"] == 115
    both = await _get(c, f"{base}/imports", library="KERNEL32.dll", q="thread")
    assert [i["function"] for i in both["items"]] == ["CreateRemoteThread"]
    assert (await c.get(f"{base}/imports", params={"q": "a\x00"})).status_code == 422


async def test_string_filters_and_escaped_search(sent: SentJobs) -> None:
    reg, _, base = await _ingested(sent)
    c = reg.client
    strings = await _get(c, f"{base}/strings")
    assert strings["total"] == 4
    assert [s["offset"] for s in strings["items"]] == [4096, 8192, 12_288, None]
    assert (await _get(c, f"{base}/strings", encoding="ascii"))["total"] == 2
    utf16 = await _get(c, f"{base}/strings", encoding="utf16le")
    assert [s["value"] for s in utf16["items"]] == ["C:\\Users\\Public\\run.bat"]
    assert (await _get(c, f"{base}/strings", encoding="floss_decoded"))["total"] == 1
    assert (await _get(c, f"{base}/strings", encoding="floss_stack"))["total"] == 0
    # LIKE metacharacters are literals.
    assert (await _get(c, f"{base}/strings", q="%"))["total"] == 1
    assert (await _get(c, f"{base}/strings", q="_"))["total"] == 1
    assert (await _get(c, f"{base}/strings", q="0%_o"))["total"] == 1
    assert (await _get(c, f"{base}/strings", q="\\"))["total"] == 1
    assert (await _get(c, f"{base}/strings", q="PAYLOAD"))["total"] == 1
    assert (await _get(c, f"{base}/strings", q="payload", encoding="utf16le"))["total"] == 0
    for bad in ({"q": "a\x00b"}, {"encoding": "utf32"}, {"q": "x" * 201}):
        assert (await c.get(f"{base}/strings", params=bad)).status_code == 422, bad


async def test_signature_and_capability_filters(sent: SentJobs) -> None:
    reg, _, base = await _ingested(sent)
    c = reg.client
    signatures = await _get(c, f"{base}/signatures")
    assert [(s["engine"], s["name"]) for s in signatures["items"]] == [
        ("clamav", "Eicar-Signature"),
        ("yara", "Suspicious_Injection_APIs"),
    ]
    yara = await _get(c, f"{base}/signatures", engine="yara")
    assert yara["total"] == 1 and yara["items"][0]["meta"] == {
        "author": "cyberlab",
        "severity": "low",
    }
    assert yara["items"][0]["tags"] == ["injection"]
    assert (await c.get(f"{base}/signatures", params={"engine": "avast"})).status_code == 422

    capabilities = await _get(c, f"{base}/capabilities")
    assert capabilities["total"] == 2
    inject = next(x for x in capabilities["items"] if x["attack"] == ["T1055.012"])
    assert inject["matches"] == 3 and inject["mbc"] == ["E1055"]
    for namespace, total in [
        ("host-interaction", 1),
        ("host-interaction/process/inject", 1),
        ("host-inter", 0),  # a namespace prefix only matches at a `/` boundary
        ("anti-analysis", 1),
        ("%", 0),
    ]:
        got = await _get(c, f"{base}/capabilities", namespace=namespace)
        assert got["total"] == total, namespace
    for attack, total in [
        ("T1055", 1),
        ("T1055.012", 1),
        ("T1055.001", 0),
        ("T1622", 1),
        ("T1", 0),
    ]:
        if attack == "T1":
            response = await c.get(f"{base}/capabilities", params={"attack": attack})
            assert response.status_code == 422
            continue
        assert (await _get(c, f"{base}/capabilities", attack=attack))["total"] == total, attack
    both = await _get(c, f"{base}/capabilities", namespace="anti-analysis", attack="T1055")
    assert both["total"] == 0


async def test_shared_findings_and_iocs_routes_serve_static_jobs(sent: SentJobs) -> None:
    reg, _, base = await _ingested(sent)
    c = reg.client
    findings = await _get(c, f"{base}/findings")
    assert [f["severity"] for f in findings["items"]] == ["high", "medium"]
    assert findings["items"][1]["evidence_refs"] == ["UPX1"]
    assert (await _get(c, f"{base}/findings", type="packed_section"))["total"] == 1

    iocs = await _get(c, f"{base}/iocs")
    assert iocs["total"] == 4 and iocs["items"][0]["type"] == "registry_key"  # count 2 first
    for ioc_type in ("registry_key", "file_path", "email", "url"):
        assert (await _get(c, f"{base}/iocs", type=ioc_type))["total"] == 1, ioc_type
    assert (await _get(c, f"{base}/iocs", q="CurrentVersion\\Run"))["total"] == 1
    assert (await _get(c, f"{base}/iocs", q="\\"))["total"] == 2  # registry key + file path


async def test_viewer_can_read_static_results(sent: SentJobs) -> None:
    reg, _, base = await _ingested(sent)
    email = unique_email("viewer")
    await add_member(reg.org_id, await make_user(email), MemberRole.VIEWER)
    viewer = await login(email)
    for resource in STATIC_ROUTES[1:]:
        assert (await _get(viewer, f"{base}/{resource}"))["total"] > 0, resource
    assert (await _get(viewer, f"{base}/sample"))["sha256"] == SAMPLE.sha256
    assert (await viewer.get(f"{base}/report")).status_code == 200


async def test_unknown_foreign_or_pcap_job_is_404(sent: SentJobs) -> None:
    reg, item, _ = await _ingested(sent)
    capture = await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())
    pcap_item = sent[-1]
    assert pcap_item.analyzer == "pcap" and pcap_item.evidence_id == uuid.UUID(capture["id"])
    await pr.deliver(pcap_item, pr.stream(pcap_item.job_id))
    other = await register()
    for resource in STATIC_ROUTES:
        unknown = await reg.client.get(f"{_base(reg, uuid.uuid4())}/{resource}")
        assert unknown.status_code == 404, resource
        foreign = await other.client.get(_base(other, item.job_id) + f"/{resource}")
        assert foreign.status_code == 404, resource
        wrong_analyzer = await reg.client.get(f"{_base(reg, pcap_item.job_id)}/{resource}")
        assert wrong_analyzer.status_code == 404, resource
    for resource in ("report",):
        assert (await reg.client.get(f"{_base(reg, uuid.uuid4())}/{resource}")).status_code == 404
        foreign = await other.client.get(_base(other, item.job_id) + f"/{resource}")
        assert foreign.status_code == 404


async def test_queued_static_job_has_no_results_yet(sent: SentJobs) -> None:
    reg, item, _ = await _job_for(sent)
    base = _base(reg, item.job_id)
    assert await _get(reg.client, f"{base}/strings") == {"items": [], "total": 0}
    sample = await reg.client.get(f"{base}/sample")
    assert sample.status_code == 404
    assert sample.json()["error"]["code"] == "results_not_available"


async def test_static_rows_are_tenant_scoped_and_append_only(sent: SentJobs) -> None:
    reg, item, _ = await _ingested(sent)
    other = await register()
    for model in static_models.RESULT_TABLES:
        table = model.__tablename__
        async with tenant_session(reg.org_id, None) as session:
            assert await session.scalar(text(f"SELECT count(*) FROM {table}")) > 0, table
        async with tenant_session(other.org_id, None) as session:
            assert await session.scalar(text(f"SELECT count(*) FROM {table}")) == 0, table
        for statement in (f"UPDATE {table} SET job_id = job_id", f"DELETE FROM {table}"):
            with pytest.raises(Exception, match="permission denied"):
                async with tenant_session(reg.org_id, None) as session:
                    await session.execute(text(statement))
    # WITH CHECK: a row for another organization cannot be written from this tenant.
    with pytest.raises(Exception, match="row-level security"):
        async with tenant_session(reg.org_id, None) as session:
            await session.execute(
                text(
                    "INSERT INTO malware_strings (organization_id, job_id, value, encoding) "
                    "VALUES (:org, :job, 'x', 'ascii')"
                ),
                {"org": other.org_id, "job": item.job_id},
            )


# --- report -------------------------------------------------------------------------------


async def test_report_document_headers_and_audit(sent: SentJobs) -> None:
    reg, item, base = await _ingested(sent)
    evidence_id = str(item.evidence_id)
    custody_before = await _custody(reg, evidence_id)

    response = await reg.client.get(f"{base}/report")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/json"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-security-policy"] == "sandbox"
    assert response.headers["cache-control"] == "no-store"
    disposition = response.headers["content-disposition"]
    short = str(item.job_id)[:8]
    assert disposition.startswith(f'attachment; filename="sample.exe.static-report-{short}.json"')
    assert f"filename*=UTF-8''sample.exe.static-report-{short}.json" in disposition

    body = response.json()
    StaticReport.model_validate(body)  # the published schema
    assert body["schema"] == REPORT_SCHEMA
    assert body["organization"]["id"] == str(reg.org_id)
    assert body["investigation"]["case_ref"].startswith("CASE-")
    assert body["evidence"]["id"] == evidence_id and body["evidence"]["filename"] == "sample.exe"
    assert body["evidence"]["hashes"]["sha256"] == SAMPLE.sha256
    assert body["evidence"]["uploaded_by"] == str(reg.user_id)
    assert body["custody"]["count"] == len(custody_before)
    assert [e["action"] for e in body["custody"]["recent"]] == [e["action"] for e in custody_before]
    analysis = body["analysis"]
    assert analysis["job_id"] == str(item.job_id) and analysis["profile"] == "full"
    assert analysis["status"] == "succeeded" and analysis["worker_version"] == pr.WORKER
    assert analysis["tool_versions"] == sr.TOOLS and analysis["engine_errors"] == []
    assert analysis["counts"] == sr.SAMPLE_COUNTS and analysis["result_schema"] == "static.v1"
    assert body["sample"]["sha256"] == SAMPLE.sha256 and body["sample"]["size"] == SAMPLE.size
    assert body["sample"]["analyzer_derived"]["rich_header_hash"] == "b" * 32
    assert body["pe"]["image_base"] == 2**64 - 2**32 and body["elf"] is None
    assert [f["severity"] for f in body["findings"]["items"]] == ["high", "medium"]
    assert body["findings"]["total"] == 2 and body["findings"]["truncated"] is False
    assert body["signatures"]["total"] == 2 and body["capabilities"]["total"] == 2
    assert {i["type"] for i in body["iocs"]["items"]} == {
        "url",
        "registry_key",
        "file_path",
        "email",
    }
    assert [s["name"] for s in body["sections"]["items"]] == [".text", ".rdata", "UPX1"]
    imports = body["imports_summary"]
    assert imports["total"] == 6 and imports["libraries"] == 3
    assert imports["top_libraries"][0] == {"library": "KERNEL32.dll", "imports": 4}
    assert {(n["function"], n["category"]) for n in imports["notable_functions"]} == {
        ("CreateRemoteThread", "process_injection"),
        ("VirtualAllocEx", "process_injection"),
        ("WriteProcessMemory", "process_injection"),
        ("RegSetValueExW", "persistence"),
    }
    assert "strings" not in body  # summary-level: never a string dump

    [audit] = await _audits(reg.org_id, "analysis.report_downloaded")
    assert audit.actor_id == reg.user_id and audit.target_id == item.job_id
    assert audit.details == {"evidence_id": evidence_id, "schema": REPORT_SCHEMA}
    assert await _custody(reg, evidence_id) == custody_before  # custody unchanged


async def test_report_lists_are_capped_with_totals(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    reg, _, base = await _ingested(sent)
    monkeypatch.setattr(reports, "MAX_SIGNATURES", 1)
    monkeypatch.setattr(reports, "MAX_SECTIONS", 2)
    monkeypatch.setattr(reports, "MAX_NOTABLE", 3)
    body = await _get(reg.client, f"{base}/report")
    assert len(body["signatures"]["items"]) == 1
    assert body["signatures"]["total"] == 2 and body["signatures"]["truncated"] is True
    assert len(body["sections"]["items"]) == 2 and body["sections"]["total"] == 3
    assert len(body["imports_summary"]["notable_functions"]) == 3
    assert body["imports_summary"]["notable_truncated"] is True


async def test_report_of_a_unicode_filename_is_rfc5987_encoded(sent: SentJobs) -> None:
    reg, item, _ = await _job_for(sent, SAMPLE_BYTES, 'mẫu "x"; a.exe')
    await pr.deliver(item, sr.stream(item.job_id, SAMPLE))
    response = await reg.client.get(f"{_base(reg, item.job_id)}/report")
    assert response.status_code == 200, response.text
    disposition = response.headers["content-disposition"]
    assert disposition.startswith('attachment; filename="mu x a.exe.static-report-')
    assert "filename*=UTF-8''m%E1%BA%ABu%20%22x%22%3B%20a.exe.static-report-" in disposition
    assert disposition.isascii()


async def test_report_is_only_for_succeeded_static_jobs(sent: SentJobs) -> None:
    reg, item, _ = await _job_for(sent)
    queued = await reg.client.get(f"{_base(reg, item.job_id)}/report")
    assert queued.status_code == 409
    assert queued.json()["error"]["code"] == "analysis_not_succeeded"

    await pr.deliver(item, _hostile("bad_trailer_hash", item.job_id))  # -> failed
    failed = await reg.client.get(f"{_base(reg, item.job_id)}/report")
    assert failed.status_code == 409
    assert failed.json()["error"]["code"] == "analysis_not_succeeded"

    await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())
    pcap_item = sent[-1]
    await pr.deliver(pcap_item, pr.stream(pcap_item.job_id))
    pcap = await reg.client.get(f"{_base(reg, pcap_item.job_id)}/report")
    assert pcap.status_code == 409 and pcap.json()["error"]["code"] == "report_unavailable"
    assert await _audits(reg.org_id, "analysis.report_downloaded") == []


def test_report_schema_is_published() -> None:
    schemas = app.openapi()["components"]["schemas"]
    report = schemas["StaticReport"]
    assert report["properties"]["schema"]["const"] == REPORT_SCHEMA
    assert "schema" in report["required"]
    for name in ("findings", "signatures", "capabilities", "iocs", "imports_summary", "sections"):
        assert name in report["properties"], name
    assert "strings" not in report["properties"]
    for route in STATIC_ROUTES + ("report",):
        assert f"/api/v1/orgs/{{org_id}}/analyses/{{job_id}}/{route}" in app.openapi()["paths"]
