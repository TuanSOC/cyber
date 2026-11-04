"""Trusted ingest of pcap.v1 results into tenant tables, and the read API over them."""

import gzip
import json
import shutil
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from cyberlab_jobs import IngestMessageV1
from cyberlab_jobs.results import FindingRecord
from httpx import AsyncClient
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch, lifecycle
from app.modules.analysis.models import AnalysisJob
from app.modules.audit.models import AuditLog
from app.modules.organizations.models import MemberRole
from app.modules.pcap_analysis import ingest as pcap_ingest
from app.modules.pcap_analysis import repository as results_repo
from app.modules.pcap_analysis import stream
from app.modules.pcap_analysis.models import RESULT_TABLES, NetworkFlow
from app.workers import ingest, reaper
from tests import pcap_results as pr
from tests.analysis_helpers import SentJobs, new_case, tiny_pcap, upload
from tests.factories import Registered, add_member, login, make_user, register, unique_email

RowCounts = Callable[[], Awaitable[dict[str, int]]]


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


@pytest.fixture
def row_counts(owner_engine: AsyncEngine) -> RowCounts:
    """Rows per result table across ALL organizations.

    The owner is subject to FORCE RLS too, so it lifts FORCE inside a transaction that is
    always rolled back (DDL is transactional): the table owner then sees every row.
    """

    async def count() -> dict[str, int]:
        async with owner_engine.connect() as conn:
            try:
                counts = {}
                for model in RESULT_TABLES:
                    table = model.__tablename__
                    await conn.execute(text(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY"))
                    counts[table] = int(
                        await conn.scalar(text(f"SELECT count(*) FROM {table}")) or 0
                    )
                return counts
            finally:
                await conn.rollback()

    return count


@pytest.fixture
def scratch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A dedicated ingest scratch dir, so tests can check that nothing is left in it."""
    monkeypatch.setattr(get_settings(), "ingest_tmp_dir", str(tmp_path))
    return tmp_path


async def _job_for(sent: SentJobs) -> tuple[Registered, dispatch.DispatchInput, str]:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), tiny_pcap())
    return reg, sent[-1], evidence["id"]


async def _job(item: dispatch.DispatchInput) -> AnalysisJob:
    async with tenant_session(item.organization_id, None) as session:
        job = await session.get(AnalysisJob, item.job_id)
    assert job is not None
    return job


async def _custody_actions(reg: Registered, evidence_id: str) -> list[str]:
    url = f"/api/v1/orgs/{reg.org_id}/evidence/{evidence_id}/custody"
    return [e["action"] for e in (await reg.client.get(url)).json()["items"]]


def _base(reg: Registered, item: dispatch.DispatchInput) -> str:
    return f"/api/v1/orgs/{reg.org_id}/analyses/{item.job_id}"


async def _get(client: AsyncClient, url: str, **params: Any) -> Any:
    response = await client.get(url, params=params)
    assert response.status_code == 200, response.text
    return response.json()


# --- ingest: success ----------------------------------------------------------------------


async def test_result_is_persisted_with_summary_and_custody(
    sent: SentJobs, row_counts: RowCounts
) -> None:
    reg, item, evidence_id = await _job_for(sent)
    await pr.deliver(item, pr.stream(item.job_id))

    job = await _job(item)
    assert job.status == "succeeded" and job.worker_version == pr.WORKER
    assert job.result_version_id is not None
    assert await row_counts() == {
        "network_flows": 3,
        "network_records": 4,
        "network_alerts": 2,
        "analysis_findings": 2,
        "iocs": 2,
        "analysis_timeline": 3,
    }

    out = await _get(reg.client, _base(reg, item))
    summary = out["summary"]
    assert summary["counts"] == pr.SAMPLE_COUNTS
    assert summary["tool_versions"] == pr.TOOLS and summary["capture_format"] == "pcap"
    assert summary["engine_errors"] == [] and summary["truncated"] == {}
    assert summary["capture"]["packets"] == 120
    assert summary["capture"]["protocol_hierarchy"][0]["path"] == "eth:ip:tcp"
    assert summary["engine_counts"] == {"flows": 3}

    custody = (
        await reg.client.get(f"/api/v1/orgs/{reg.org_id}/evidence/{evidence_id}/custody")
    ).json()["items"]
    [analyzed] = [e for e in custody if e["action"] == "analyzed"]
    assert analyzed["details"]["tool_versions"] == pr.TOOLS
    assert analyzed["details"]["job_id"] == str(item.job_id)
    async with tenant_session(reg.org_id, None) as session:
        audit = await session.scalar(
            select(AuditLog).where(AuditLog.action == "analysis.succeeded")
        )
    assert audit is not None and audit.details["counts"] == pr.SAMPLE_COUNTS


async def test_redelivery_after_success_inserts_nothing(
    sent: SentJobs, row_counts: RowCounts
) -> None:
    _, item, _ = await _job_for(sent)
    stale = await _job(item)  # loaded while still queued: passes the unlocked fast path
    message = await pr.deliver(item, pr.stream(item.job_id))
    before = await row_counts()

    await ingest.handle_event(message)  # broker redelivery
    await ingest.ingest_success(stale, IngestMessageV1.model_validate(message))
    assert await row_counts() == before
    assert (await _job(item)).status == "succeeded"


async def test_empty_analysis_is_accepted(sent: SentJobs, row_counts: RowCounts) -> None:
    _, item, _ = await _job_for(sent)
    await pr.deliver(item, pr.stream(item.job_id, records=[]))
    assert (await _job(item)).status == "succeeded"
    assert set((await row_counts()).values()) == {0}


async def test_ingest_timeouts_are_transaction_local(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The write transaction runs with the ingest timeouts; its connection goes back to the
    pool with the role defaults (statement_timeout 30s, idle_in_transaction 60s)."""
    _, item, _ = await _job_for(sent)
    settings = get_settings()
    real = ingest.tenant_session
    inside: list[tuple[str, str]] = []
    drivers: list[Any] = []
    query = (
        "SELECT current_setting('statement_timeout'), "
        "current_setting('idle_in_transaction_session_timeout')"
    )

    @asynccontextmanager
    async def spy(
        org_id: uuid.UUID | None, user_id: uuid.UUID | None
    ) -> AsyncIterator[AsyncSession]:
        async with real(org_id, user_id) as session:
            yield session
            row = (await session.execute(text(query))).one()  # still in the transaction
            inside.append((row[0], row[1]))
            raw = await (await session.connection()).get_raw_connection()
            drivers.append(raw.driver_connection)

    monkeypatch.setattr(ingest, "tenant_session", spy)
    monkeypatch.setattr(settings, "ingest_statement_timeout_s", 123)
    monkeypatch.setattr(settings, "ingest_idle_in_transaction_timeout_s", 7)
    await pr.deliver(item, pr.stream(item.job_id))
    assert (await _job(item)).status == "succeeded"

    assert ("123s", "7s") in inside
    assert drivers
    for driver in drivers:
        assert await driver.fetchval("SHOW statement_timeout") == "30s"
        assert await driver.fetchval("SHOW idle_in_transaction_session_timeout") == "1min"


# --- ingest: hostile streams --------------------------------------------------------------


def _flow_dict(**fields: Any) -> dict[str, Any]:
    return {**pr.flow(1).model_dump(mode="json"), **fields}


def _finding_dict(**fields: Any) -> dict[str, Any]:
    base = next(r for r in pr.sample_records() if isinstance(r, FindingRecord))
    return {**base.model_dump(mode="json"), "finding_id": str(uuid.uuid4()), **fields}


def _hostile(case: str, job_id: uuid.UUID) -> bytes:
    good = pr.lines(job_id)
    header = pr.header(job_id).model_dump(mode="json")
    if case == "unknown_kind":
        return pr.encode([*good, pr.line({"kind": "shell", "cmd": "id"})])
    if case == "extra_field":
        foreign = str(uuid.uuid4())
        return pr.encode([*good, pr.line(_flow_dict(organization_id=foreign))])
    if case == "oversized_string":
        dns = {"kind": "dns", "ts": pr.T0.isoformat(), "query": "a" * 256}
        return pr.encode([*good, pr.line(dns)])
    if case == "nul":
        dns = {"kind": "dns", "ts": pr.T0.isoformat(), "query": "a\x00b"}
        return pr.encode([*good, pr.line(dns)])
    if case == "nan_attribute":  # json.dumps writes NaN / Infinity literals
        return pr.encode([*good, pr.line(_finding_dict(attributes={"x": float("nan")}))])
    if case == "infinity_attribute":
        return pr.encode([*good, pr.line(_finding_dict(attributes={"x": float("inf")}))])
    if case == "huge_int_attribute":
        return pr.encode([*good, pr.line(_finding_dict(attributes={"x": 10**400}))])
    if case == "nul_attribute":
        return pr.encode([*good, pr.line(_finding_dict(attributes={"x": "a\x00"}))])
    if case == "long_detection_method":
        method = "heuristic:" + "a" * 200 + "@1"
        return pr.encode([*good, pr.line(_finding_dict(detection_method=method))])
    if case == "nul_tool_version":
        tools = {**pr.TOOLS, "zeek": "8.0\x00"}
        return pr.encode([pr.line({**header, "tool_versions": tools}), *good[1:]])
    if case == "nul_tool_name":
        tools = {**pr.TOOLS, "ze\x00ek": "8.0"}
        return pr.encode([pr.line({**header, "tool_versions": tools}), *good[1:]])
    if case == "nul_truncated_key":
        return pr.encode([pr.line({**header, "truncated": {"fl\x00ows": True}}), *good[1:]])
    if case == "bad_trailer_hash":
        return pr.encode(good, trailer={"sha256": "0" * 64})
    if case == "wrong_trailer_count":
        return pr.encode(good, trailer={"line_count": len(good) - 1})
    if case == "missing_trailer":
        return pr.encode(good, add_trailer=False)
    if case == "missing_header":
        return pr.encode(good[1:])
    if case == "foreign_job_header":
        return pr.encode(pr.lines(uuid.uuid4()))
    if case == "two_stats":
        return pr.encode([*good, pr.line(pr.stats())])
    if case == "no_stats":
        return pr.encode([good[0], *good[2:]])
    if case == "header_twice":
        return pr.encode([*good, good[0]])
    if case == "duplicate_ioc":
        ioc = next(line for line in good if b'"kind":"ioc"' in line)
        return pr.encode([*good, ioc])
    if case == "timestamp_outside_capture":
        return pr.encode([*good, pr.line(pr.flow(9, ts=pr.at(90 * 86400)))])
    if case == "not_gzip":
        return b"".join(good)
    if case == "corrupt_gzip":
        data = pr.encode(good)
        return data[: len(data) // 2]
    if case == "unterminated_line":
        body = b"".join(good)
        return gzip.compress(body + b'{"kind":"trailer"')
    raise AssertionError(case)


HOSTILE = [
    "unknown_kind",
    "extra_field",
    "oversized_string",
    "nul",
    "nan_attribute",
    "infinity_attribute",
    "huge_int_attribute",
    "nul_attribute",
    "long_detection_method",
    "nul_tool_version",
    "nul_tool_name",
    "nul_truncated_key",
    "bad_trailer_hash",
    "wrong_trailer_count",
    "missing_trailer",
    "missing_header",
    "foreign_job_header",
    "two_stats",
    "no_stats",
    "header_twice",
    "duplicate_ioc",
    "timestamp_outside_capture",
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
    _, item, _ = await _job_for(sent)
    await pr.deliver(item, _hostile(case, item.job_id))
    await _assert_refused(item, row_counts)


async def test_more_flows_than_the_cap_are_refused(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch, row_counts: RowCounts
) -> None:
    monkeypatch.setattr(get_settings(), "analysis_max_flows", 2)
    _, item, _ = await _job_for(sent)
    await pr.deliver(item, pr.stream(item.job_id))  # 3 flows
    await _assert_refused(item, row_counts)


async def test_more_lines_than_the_total_cap_are_refused(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch, row_counts: RowCounts
) -> None:
    # Every kind is within its own cap; the sum of all lines (19) is not.
    monkeypatch.setattr(get_settings(), "analysis_max_result_lines", 18)
    _, item, _ = await _job_for(sent)
    await pr.deliver(item, pr.stream(item.job_id))
    await _assert_refused(item, row_counts)


async def test_gzip_bomb_is_refused_at_the_decompressed_cap(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch, row_counts: RowCounts
) -> None:
    cap = 256 * 1024
    monkeypatch.setattr(get_settings(), "analysis_max_result_decompressed_bytes", cap)
    _, item, _ = await _job_for(sent)
    flows = [pr.flow(1)] * 4000  # identical lines: compresses extremely well
    data = pr.stream(item.job_id, records=list(flows))
    assert len(data) < cap // 10 < cap < len(gzip.decompress(data))
    await pr.deliver(item, data)
    await _assert_refused(item, row_counts)


async def test_oversized_compressed_result_is_refused(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch, row_counts: RowCounts
) -> None:
    monkeypatch.setattr(get_settings(), "analysis_max_result_bytes", 64)
    _, item, _ = await _job_for(sent)
    await pr.deliver(item, pr.stream(item.job_id))
    await _assert_refused(item, row_counts)


# --- ingest: the database as the last line of defence --------------------------------------

# Row values the database refuses, injected after validation (as if the contract had a gap):
# too long for VARCHAR(16), outside int64 (asyncpg refuses it client-side), NUL in text, NaN
# in jsonb. Each must fail the job as invalid_result, never as a retryable error.
DB_REFUSED = {
    "varchar_overflow": {"source": "x" * 100},
    "int64_overflow": {"count": 2**64},
    "nul_in_text": {"value": "a\x00b"},
    "nan_in_jsonb": {"nan": True},
}


@pytest.mark.parametrize("case", DB_REFUSED)
async def test_database_refusal_mid_ingest_rolls_everything_back(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch, row_counts: RowCounts, case: str
) -> None:
    """A real DB error after some batches went in: no rows at all, job invalid_result."""
    reg, item, evidence_id = await _job_for(sent)
    real = pcap_ingest.to_row
    poison = DB_REFUSED[case]

    def poisoned(record: Any) -> Any:
        table, row = real(record)
        if case == "nan_in_jsonb" and record.kind == "finding":
            return table, {**row, "attributes": {"x": float("nan")}}
        if case != "nan_in_jsonb" and record.kind == "ioc":
            return table, {**row, **poison}
        return table, row

    monkeypatch.setattr(pcap_ingest, "to_row", poisoned)
    monkeypatch.setattr(pcap_ingest, "BATCH_LINES", 2)  # flows etc. are inserted before
    await pr.deliver(item, pr.stream(item.job_id))
    job = await _job(item)
    assert (job.status, job.error_code) == ("failed", "invalid_result")
    assert job.summary == {}
    assert set((await row_counts()).values()) == {0}
    assert "analyzed" not in await _custody_actions(reg, evidence_id)


async def test_unique_index_violation_is_an_invalid_result(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch, row_counts: RowCounts
) -> None:
    """Were the validator's IOC key ever to differ from the index, the IntegrityError still
    refuses the result as a whole."""
    _, item, _ = await _job_for(sent)
    monkeypatch.setattr(stream, "ioc_key", lambda kind, value: (kind, uuid.uuid4().bytes))
    await pr.deliver(item, _hostile("duplicate_ioc", item.job_id))
    await _assert_refused(item, row_counts)


async def test_ioc_key_matches_the_database_md5(sent: SentJobs) -> None:
    reg, _, _ = await _job_for(sent)
    async with tenant_session(reg.org_id, None) as session:
        for value in ("example.com", "exämple.com/ü?q=✓", "x" * 2048):
            db = await session.scalar(
                text("SELECT decode(md5(CAST(:v AS text)), 'hex')"), {"v": value}
            )
            assert stream.ioc_key("url", value) == ("url", db)


async def test_unexpected_error_mid_ingest_is_an_ingest_error(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch, row_counts: RowCounts
) -> None:
    """A bug on our side (not a refused value) is recorded as ingest_error, nothing written."""
    _, item, _ = await _job_for(sent)
    real = pcap_ingest.to_row

    def explode_on_iocs(record: Any) -> Any:
        if record.kind == "ioc":
            raise ValueError("boom")
        return real(record)

    monkeypatch.setattr(pcap_ingest, "to_row", explode_on_iocs)
    monkeypatch.setattr(pcap_ingest, "BATCH_LINES", 2)
    await pr.deliver(item, pr.stream(item.job_id))
    job = await _job(item)
    assert (job.status, job.error_code) == ("failed", "ingest_error")
    assert set((await row_counts()).values()) == {0}


async def test_job_reaped_between_validation_and_persist_writes_nothing(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch, row_counts: RowCounts
) -> None:
    reg, item, evidence_id = await _job_for(sent)
    real_persist = ingest._persist
    real_now = lifecycle.now

    async def reaped_first(*args: Any) -> None:
        # The stream is already validated; the reaper wins the row lock first.
        with monkeypatch.context() as m:
            m.setattr(lifecycle, "now", lambda: real_now() + timedelta(days=2))
            assert await reaper.reap() == 1
        await real_persist(*args)

    monkeypatch.setattr(ingest, "_persist", reaped_first)
    await pr.deliver(item, pr.stream(item.job_id))

    job = await _job(item)
    assert (job.status, job.error_code) == ("failed", "never_started")
    assert job.summary == {} and job.result_version_id is None
    assert set((await row_counts()).values()) == {0}
    assert "analyzed" not in await _custody_actions(reg, evidence_id)


# --- ingest: scratch space ----------------------------------------------------------------


@pytest.mark.parametrize("outcome", ["success", "refused", "exception"])
async def test_scratch_dir_is_empty_afterwards(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch, scratch: Path, outcome: str
) -> None:
    _, item, _ = await _job_for(sent)
    data = pr.stream(item.job_id)
    expected = ("succeeded", None)
    if outcome == "refused":
        data = _hostile("bad_trailer_hash", item.job_id)
        expected = ("failed", "invalid_result")
    elif outcome == "exception":

        def explode(*_: Any) -> Any:
            raise ValueError("boom")

        monkeypatch.setattr(pcap_ingest, "to_row", explode)
        expected = ("failed", "ingest_error")
    await pr.deliver(item, data)
    job = await _job(item)
    assert (job.status, job.error_code) == expected
    assert list(scratch.iterdir()) == []


async def test_full_scratch_volume_is_retried_not_failed(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch, scratch: Path, row_counts: RowCounts
) -> None:
    _, item, _ = await _job_for(sent)
    usage = shutil.disk_usage(scratch)
    monkeypatch.setattr(shutil, "disk_usage", lambda _: usage._replace(free=1024))
    assert ingest.ScratchSpaceExhausted in ingest.TRANSIENT_ERRORS
    with pytest.raises(ingest.ScratchSpaceExhausted):
        await pr.deliver(item, pr.stream(item.job_id))
    job = await _job(item)
    assert job.status == "queued" and job.error_code is None  # left for the retry
    assert set((await row_counts()).values()) == {0}
    assert list(scratch.iterdir()) == []


# --- read API -----------------------------------------------------------------------------


async def _ingested(sent: SentJobs) -> tuple[Registered, dispatch.DispatchInput, str]:
    reg, item, _ = await _job_for(sent)
    await pr.deliver(item, pr.stream(item.job_id))
    assert (await _job(item)).status == "succeeded"
    return reg, item, _base(reg, item)


async def test_flow_filters_sorting_and_pagination(sent: SentJobs) -> None:
    reg, _, base = await _ingested(sent)
    c = reg.client

    by_bytes = await _get(c, f"{base}/flows")
    assert by_bytes["total"] == 3
    assert [f["total_bytes"] for f in by_bytes["items"]] == [51_000, 1_200, 1_100]
    assert by_bytes["items"][0]["src_ip"] == "10.0.0.9"
    by_ts = await _get(c, f"{base}/flows", sort="ts")
    assert [f["flow_ref"] for f in by_ts["items"]] == ["C00000001", "C00000002", "C00000003"]

    paged = await _get(c, f"{base}/flows", sort="ts", limit=1, offset=1)
    assert paged["total"] == 3 and [f["flow_ref"] for f in paged["items"]] == ["C00000002"]

    assert (await _get(c, f"{base}/flows", ip="192.0.2.53"))["total"] == 1
    assert (await _get(c, f"{base}/flows", ip="10.0.0.5"))["total"] == 2
    assert (await _get(c, f"{base}/flows", ip="2001:db8::1"))["total"] == 0
    assert (await _get(c, f"{base}/flows", port=53))["total"] == 1
    assert (await _get(c, f"{base}/flows", proto="udp"))["total"] == 1
    assert (await _get(c, f"{base}/flows", proto="icmp"))["total"] == 0

    for bad in (
        {"ip": "not-an-ip"},
        {"ip": "fe80::1%eth0"},  # IPv6 zone id: refused like in the contract, not a 500
        {"ip": "fe80::1%25"},
        {"port": 70000},
        {"sort": "random"},
        {"proto": "x"},
    ):
        response = await c.get(f"{base}/flows", params=bad)
        assert response.status_code == 422, bad


async def test_totals_are_counted_up_to_the_cap(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    reg, _, base = await _ingested(sent)
    monkeypatch.setattr(results_repo, "TOTAL_CAP", 2)
    capped = await _get(reg.client, f"{base}/flows", limit=100)
    assert capped["total"] == 2 and len(capped["items"]) == 3  # items are not capped
    assert (await _get(reg.client, f"{base}/flows", proto="udp"))["total"] == 1


async def test_record_kind_and_escaped_search(sent: SentJobs) -> None:
    reg, _, base = await _ingested(sent)
    c = reg.client

    assert (await _get(c, f"{base}/records"))["total"] == 4
    dns = await _get(c, f"{base}/records", kind="dns")
    assert dns["total"] == 2 and {r["kind"] for r in dns["items"]} == {"dns"}
    assert dns["items"][0]["details"]["answers"] == ["93.184.216.34"]
    assert "example.com" in dns["items"][0]["summary"]

    # LIKE metacharacters are literals: "%" and "_" match only records that contain them.
    assert (await _get(c, f"{base}/records", q="%"))["total"] == 1
    assert (await _get(c, f"{base}/records", q="_"))["total"] == 2
    assert (await _get(c, f"{base}/records", q="0%_o"))["total"] == 1
    assert (await _get(c, f"{base}/records", q="EXAMPLE"))["total"] == 1
    assert (await _get(c, f"{base}/records", q="secure", kind="dns"))["total"] == 0

    response = await c.get(f"{base}/records", params={"q": "a\x00b"})
    assert response.status_code == 422


async def test_findings_alerts_iocs_and_timeline(sent: SentJobs) -> None:
    reg, _, base = await _ingested(sent)
    c = reg.client

    findings = await _get(c, f"{base}/findings")
    assert [f["severity"] for f in findings["items"]] == ["high", "medium"]
    beacon = findings["items"][1]
    assert beacon["evidence_refs"] == ["C00000001"] and beacon["attributes"]["count"] == 15
    assert beacon["detection_method"] == "heuristic:beaconing@1"
    assert (await _get(c, f"{base}/findings", severity="medium"))["total"] == 1
    assert (await _get(c, f"{base}/findings", type="port_scan"))["total"] == 1
    assert (await c.get(f"{base}/findings", params={"type": "Bad-Type"})).status_code == 422

    alerts = await _get(c, f"{base}/alerts")
    assert [a["severity"] for a in alerts["items"]] == [1, 3]
    assert (await _get(c, f"{base}/alerts", severity=3))["items"][0]["signature_id"] == 2_000_001

    iocs = await _get(c, f"{base}/iocs")
    assert [i["value"] for i in iocs["items"]] == ["192.0.2.1", "example.com"]
    assert (await _get(c, f"{base}/iocs", type="domain"))["total"] == 1
    assert (await _get(c, f"{base}/iocs", q="192.0"))["total"] == 1
    assert (await _get(c, f"{base}/iocs", q="_"))["total"] == 0

    timeline = await _get(c, f"{base}/timeline")
    assert [e["event"] for e in timeline["items"]] == ["capture_start", "finding", "capture_end"]


async def test_viewer_can_read_results(sent: SentJobs) -> None:
    reg, _, base = await _ingested(sent)
    email = unique_email("viewer")
    await add_member(reg.org_id, await make_user(email), MemberRole.VIEWER)
    viewer = await login(email)
    for resource in ("findings", "flows", "records", "alerts", "iocs", "timeline"):
        assert (await _get(viewer, f"{base}/{resource}"))["total"] > 0, resource


async def test_unknown_or_foreign_job_is_404(sent: SentJobs) -> None:
    reg, item, _ = await _ingested(sent)
    other = await register()
    for resource in ("findings", "flows", "records", "alerts", "iocs", "timeline"):
        unknown = await reg.client.get(
            f"/api/v1/orgs/{reg.org_id}/analyses/{uuid.uuid4()}/{resource}"
        )
        assert unknown.status_code == 404
        foreign = await other.client.get(
            f"/api/v1/orgs/{other.org_id}/analyses/{item.job_id}/{resource}"
        )
        assert foreign.status_code == 404


async def test_queued_job_has_empty_results(sent: SentJobs) -> None:
    reg, item, _ = await _job_for(sent)
    assert await _get(reg.client, f"{_base(reg, item)}/flows") == {"items": [], "total": 0}


# --- performance --------------------------------------------------------------------------

PERF_FLOWS = 100_000
PERF_BUDGET_S = 60.0


async def test_large_result_ingests_within_budget(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "analysis_max_flows", PERF_FLOWS)
    reg, item, _ = await _job_for(sent)
    template = pr.flow(1).model_dump(mode="json")
    body = [
        json.dumps(
            {
                **template,
                "src_port": i % 65536,
                "dst_ip": f"198.51.{i // 256 % 256}.{i % 256}",
                "orig_bytes": i,
                "flow_ref": f"C{i:09d}",
            }
        ).encode()
        + b"\n"
        for i in range(PERF_FLOWS)
    ]
    data = pr.encode([pr.line(pr.header(item.job_id)), pr.line(pr.stats()), *body])

    started = time.monotonic()
    await pr.deliver(item, data)
    elapsed = time.monotonic() - started

    job = await _job(item)
    assert job.status == "succeeded", job.error_code
    async with tenant_session(reg.org_id, None) as session:
        assert await session.scalar(select(func.count()).select_from(NetworkFlow)) == PERF_FLOWS
    assert elapsed < PERF_BUDGET_S, f"{PERF_FLOWS} flows took {elapsed:.1f}s"
    print(f"\ningested {PERF_FLOWS} flows in {elapsed:.1f}s")
