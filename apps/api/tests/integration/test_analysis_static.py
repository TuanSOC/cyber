"""Static analyzer plumbing (M3 phase 1): selection, auto-run, caps, dispatch and ingest.

Dispatch is captured (no static worker needed); ingest is fed the analyzer's reports.
"""

import gzip
import io
import uuid
from datetime import timedelta
from typing import Any

import pytest
from cyberlab_jobs import STATIC_ANALYZE
from cyberlab_jobs.static import StaticJobV1
from sqlalchemy import func, select, text, update

from app.core.clients import get_minio
from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch, lifecycle
from app.modules.analysis.models import AnalysisJob, AnalysisJobIndex, Analyzer
from app.modules.audit.models import AuditLog
from app.modules.pcap_analysis.models import (
    NetworkAlert,
    NetworkFlow,
    NetworkRecord,
    TimelineEntry,
)
from app.modules.static_analysis.models import MalwareSample
from app.workers import ingest
from tests import static_results as sr
from tests.analysis_helpers import SentJobs, jobs_for, new_case, pe_bytes, tiny_pcap, upload
from tests.factories import Registered, csrf, register


def elf_bytes(e_type: int) -> bytes:
    data = bytearray(128)
    data[0:4] = b"\x7fELF"
    data[4], data[5], data[6] = 2, 1, 1  # 64-bit, little endian, version 1
    data[16:18] = e_type.to_bytes(2, "little")
    return bytes(data)


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


async def _run(reg: Registered, evidence_id: str, **body: Any) -> Any:
    return await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/evidence/{evidence_id}/analyses",
        json=body,
        headers=csrf(reg.client),
    )


async def _audits(org_id: uuid.UUID, action: str) -> list[AuditLog]:
    async with tenant_session(org_id, None) as session:
        rows = await session.execute(select(AuditLog).where(AuditLog.action == action))
        return list(rows.scalars())


# --- selection and auto-run --------------------------------------------------------------


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (tiny_pcap(), ("pcap", None)),
        (pe_bytes(), ("static", "full")),
        (elf_bytes(2), ("static", "full")),  # ET_EXEC
        (elf_bytes(3), ("static", "full")),  # ET_DYN
        (elf_bytes(4), ("static", "av")),  # ET_CORE: never parsed, still AV-scanned
        (pe_bytes(e_lfanew=0x3000, size=0x400), ("static", "av")),  # PE header out of bounds
        (b"just some notes\n", ("static", "av")),
        (gzip.compress(tiny_pcap()), ("static", "av")),  # compressed capture: not a capture
        (b"", None),
    ],
    ids=["pcap", "pe", "elf-exec", "elf-dyn", "elf-core", "pe-bad-lfanew", "text", "gzip", "empty"],
)
async def test_auto_run_matrix(
    sent: SentJobs, content: bytes, expected: tuple[str, str | None] | None
) -> None:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), content, "upload.bin")
    jobs = await jobs_for(reg.client, reg.org_id, evidence["id"])
    if expected is None:
        assert jobs == [] and sent == []
        return
    [job] = jobs
    assert (job["analyzer"], job["profile"]) == expected
    assert job["auto"] is True and job["status"] == "queued"
    [item] = sent
    assert (item.analyzer, item.profile) == expected
    custody = (
        await reg.client.get(f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}/custody")
    ).json()["items"]
    requested = next(e for e in custody if e["action"] == "analysis_requested")
    assert requested["details"]["analyzer"] == expected[0]
    assert requested["details"].get("profile") == expected[1]


async def test_org_list_filters_by_analyzer_and_profile(sent: SentJobs) -> None:
    reg = await register()
    case = await new_case(reg)
    await upload(reg.client, reg.org_id, case, tiny_pcap(), "a.pcap")
    await upload(reg.client, reg.org_id, case, pe_bytes(), "b.exe")
    await upload(reg.client, reg.org_id, case, b"notes\n", "c.txt")
    base = f"/api/v1/orgs/{reg.org_id}/analyses"

    async def names(**params: str) -> list[str]:
        resp = await reg.client.get(base, params=params)
        assert resp.status_code == 200, resp.text
        assert resp.json()["total"] == len(resp.json()["items"])
        return sorted(j["evidence_filename"] for j in resp.json()["items"])

    assert await names() == ["a.pcap", "b.exe", "c.txt"]
    assert await names(analyzer="pcap") == ["a.pcap"]
    assert await names(analyzer="static") == ["b.exe", "c.txt"]
    assert await names(analyzer="static", profile="av") == ["c.txt"]
    assert await names(profile="full", status="queued") == ["b.exe"]
    assert await names(analyzer="static", status="failed") == []
    bad = await reg.client.get(base, params={"analyzer": "dynamic"})
    assert bad.status_code == 422


async def test_oversized_upload_is_not_auto_scanned(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "static_max_bytes", 64)
    reg = await register()
    case = await new_case(reg)
    plain = await upload(reg.client, reg.org_id, case, b"x" * 65, "big.txt")
    assert await jobs_for(reg.client, reg.org_id, plain["id"]) == []
    assert await _audits(reg.org_id, "analysis.skipped") == []  # silently out of scope

    # An oversized executable was meant for analysis: the refusal is audited.
    exe = await upload(reg.client, reg.org_id, case, pe_bytes(), "big.exe")
    assert await jobs_for(reg.client, reg.org_id, exe["id"]) == []
    [skipped] = await _audits(reg.org_id, "analysis.skipped")
    assert skipped.details == {"reason": "sample_too_large", "analyzer": "static"}
    assert sent == []


async def test_auto_rate_limit_counts_both_analyzers(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "auto_analyses_per_user_per_10min", 2)
    reg = await register()
    case = await new_case(reg)
    await upload(reg.client, reg.org_id, case, tiny_pcap())
    await upload(reg.client, reg.org_id, case, pe_bytes(), "a.exe")
    third = await upload(reg.client, reg.org_id, case, b"notes", "c.txt")
    assert await jobs_for(reg.client, reg.org_id, third["id"]) == []
    assert [i.analyzer for i in sent] == ["pcap", "static"]
    [skipped] = await _audits(reg.org_id, "analysis.skipped")
    assert skipped.details == {"reason": "rate_limited", "analyzer": "static"}


# --- manual runs -------------------------------------------------------------------------


async def test_manual_static_run_defaults_to_full_and_accepts_av(sent: SentJobs) -> None:
    reg = await register()
    case = await new_case(reg)
    capture = await upload(reg.client, reg.org_id, case, tiny_pcap())  # auto pcap job
    response = await _run(reg, capture["id"], analyzer="static")
    assert response.status_code == 201, response.text
    body = response.json()
    assert (body["analyzer"], body["profile"], body["auto"]) == ("static", "full", False)

    again = await _run(reg, capture["id"], analyzer="static", profile="av")
    assert again.status_code == 409 and again.json()["error"]["code"] == "analysis_active"

    empty = await upload(reg.client, reg.org_id, case, b"", "empty.bin")  # no auto job
    av = await _run(reg, empty["id"], analyzer="static", profile="av")
    assert av.status_code == 201 and av.json()["profile"] == "av"
    assert [(i.analyzer, i.profile) for i in sent] == [
        ("pcap", None),
        ("static", "full"),
        ("static", "av"),
    ]


async def test_default_analyzer_is_still_pcap(sent: SentJobs) -> None:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), b"", "empty.bin")
    response = await _run(reg, evidence["id"])
    assert response.status_code == 201, response.text
    assert (response.json()["analyzer"], response.json()["profile"]) == ("pcap", None)


@pytest.mark.parametrize(
    "body",
    [
        {"analyzer": "pcap", "profile": "full"},
        {"profile": "av"},  # default analyzer is pcap
        {"analyzer": "static", "profile": "deep"},
        {"analyzer": "macho"},
        {"analyzer": "static", "extra": 1},
    ],
)
async def test_invalid_run_requests_are_rejected(sent: SentJobs, body: dict[str, Any]) -> None:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), b"", "empty.bin")
    response = await _run(reg, evidence["id"], **body)
    assert response.status_code == 422, response.text
    assert await jobs_for(reg.client, reg.org_id, evidence["id"]) == []


async def test_sample_too_large_is_per_analyzer(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "static_max_bytes", 10)
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), b"0123456789AB", "n")
    refused = await _run(reg, evidence["id"], analyzer="static", profile="av")
    assert refused.status_code == 413
    assert refused.json()["error"]["code"] == "sample_too_large"
    # The pcap cap is separate: the same evidence is within it.
    assert (await _run(reg, evidence["id"], analyzer="pcap")).status_code == 201
    assert [i.analyzer for i in sent] == ["pcap"]


# --- caps --------------------------------------------------------------------------------


async def test_org_caps_are_per_analyzer(sent: SentJobs, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "max_active_analyses_per_org", 1)
    reg = await register()
    case = await new_case(reg)
    capture = await upload(reg.client, reg.org_id, case, tiny_pcap())  # pcap slot taken
    sample = await upload(reg.client, reg.org_id, case, pe_bytes(), "a.exe")  # static slot
    assert [j["analyzer"] for j in await jobs_for(reg.client, reg.org_id, sample["id"])] == [
        "static"
    ]
    # Both queues are now full for this org, each on its own.
    full_pcap = await _run(reg, sample["id"], analyzer="pcap")
    assert full_pcap.status_code == 429
    full_static = await _run(reg, capture["id"], analyzer="static")
    assert full_static.status_code == 429
    assert full_static.json()["error"]["code"] == "analysis_queue_full"


async def test_global_caps_are_per_analyzer(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "max_active_analyses_global", 1)
    first, second = await register(), await register()
    await upload(first.client, first.org_id, await new_case(first), tiny_pcap())
    # The pcap queue is full globally; a static run in another org is not blocked by it.
    sample = await upload(second.client, second.org_id, await new_case(second), pe_bytes())
    [job] = await jobs_for(second.client, second.org_id, sample["id"])
    assert job["analyzer"] == "static"
    response = await _run(second, sample["id"], analyzer="pcap")
    assert response.status_code == 429
    # ... and now the static queue is full too.
    other = await upload(first.client, first.org_id, await new_case(first), b"notes", "n.txt")
    assert await jobs_for(first.client, first.org_id, other["id"]) == []


# --- dispatch ----------------------------------------------------------------------------


@pytest.mark.parametrize(("content", "profile"), [(pe_bytes(), "full"), (b"notes", "av")])
async def test_dispatch_builds_a_valid_static_job(
    sent: SentJobs, content: bytes, profile: str
) -> None:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), content, "s.bin")
    [item] = sent
    message = dispatch.build_message(item)
    assert isinstance(message, StaticJobV1)
    dumped = message.model_dump(mode="json")
    assert StaticJobV1.model_validate(dumped) == message  # round-trips the frozen contract

    settings = get_settings()
    assert dumped["schema_version"] == "static.v1" and dumped["profile"] == profile
    assert dumped["expected_sha256"] == evidence["hashes"]["sha256"]
    assert dumped["size_bytes"] == len(content)
    assert "X-Amz-Signature" in dumped["evidence_url"]
    assert item.storage_version_id in dumped["evidence_url"]
    assert settings.minio_secret_key not in str(dumped)
    key = dispatch.result_key(item.organization_id, item.job_id)
    assert dumped["result_post"]["fields"]["key"] == key
    assert dumped["limits"] == dispatch.static_limits(settings).model_dump()
    assert dumped["limits"]["max_bytes"] == settings.static_max_bytes
    assert dumped["limits"]["max_result_bytes"] == settings.static_max_result_bytes

    task, queue = dispatch.task_and_queue(item.analyzer, settings)
    assert (task, queue) == (STATIC_ANALYZE, f"{settings.queue_prefix}static")
    assert dispatch.task_and_queue(Analyzer.PCAP, settings)[1] == f"{settings.queue_prefix}pcap"


def test_static_limits_satisfy_the_contract() -> None:
    limits = dispatch.static_limits(get_settings())
    assert limits.tool_timeout_s < limits.timeout_s


# --- ingest ------------------------------------------------------------------------------


def _message(item: dispatch.DispatchInput, **fields: Any) -> dict[str, Any]:
    return {
        "job_id": str(item.job_id),
        "organization_id": str(item.organization_id),
        "ingest_token": item.ingest_token,
        "event": "started",
        "worker_version": "static-worker/test",
        **fields,
    }


async def _job(item: dispatch.DispatchInput) -> AnalysisJob:
    async with tenant_session(item.organization_id, None) as session:
        job = await session.get(AnalysisJob, item.job_id)
        assert job is not None
        return job


def _store_result(item: dispatch.DispatchInput, data: bytes) -> str:
    stored = get_minio().put_object(
        get_settings().results_bucket,
        dispatch.result_key(item.organization_id, item.job_id),
        io.BytesIO(data),
        len(data),
    )
    assert stored.version_id
    return str(stored.version_id)


async def test_static_success_is_recorded_once(sent: SentJobs) -> None:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), pe_bytes(), "s.exe")
    [item] = sent

    before = lifecycle.now()
    await ingest.handle_event(_message(item))
    async with tenant_session(None, None) as session:
        index = await session.get(AnalysisJobIndex, item.job_id)
        assert index is not None and index.analyzer == "static"
        deadline = index.deadline_at
    settings = get_settings()
    budget = timedelta(seconds=settings.analysis_static_timeout_s + ingest.RUNNING_GRACE_S)
    assert before + budget <= deadline <= lifecycle.now() + budget  # the static timeout

    data = sr.stream(item.job_id, sr.sample_for(pe_bytes()), records=[])
    version = _store_result(item, data)
    await ingest.handle_event(
        _message(item, event="finished", outcome="succeeded", result_version_id=version)
    )
    job = await _job(item)
    assert (job.status, job.result_version_id) == ("succeeded", version)
    assert job.summary["schema_version"] == "static.v1" and job.summary["profile"] == "full"
    assert job.worker_version == "static-worker/test"

    custody = (
        await reg.client.get(f"/api/v1/orgs/{reg.org_id}/evidence/{evidence['id']}/custody")
    ).json()["items"]
    [analyzed] = [e for e in custody if e["action"] == "analyzed"]
    assert analyzed["details"]["job_id"] == str(item.job_id)
    assert analyzed["details"]["system"] is True and analyzed["actor_id"] == str(reg.user_id)
    [succeeded] = await _audits(reg.org_id, "analysis.succeeded")
    assert succeeded.details["evidence_id"] == evidence["id"]

    async with tenant_session(reg.org_id, None) as session:
        # The pcap-only tables stay empty (static rows: see test_static_results.py).
        for model in (NetworkFlow, NetworkRecord, NetworkAlert, TimelineEntry):
            count = await session.scalar(select(func.count()).select_from(model))
            assert count == 0, model
        assert await session.scalar(select(func.count()).select_from(MalwareSample)) == 1

    # A duplicate success report changes nothing.
    await ingest.handle_event(
        _message(item, event="finished", outcome="succeeded", result_version_id=version)
    )
    assert len(await _audits(reg.org_id, "analysis.succeeded")) == 1


async def test_static_success_needs_its_result_object(sent: SentJobs) -> None:
    reg = await register()
    await upload(reg.client, reg.org_id, await new_case(reg), pe_bytes(), "s.exe")
    [item] = sent
    await ingest.handle_event(
        _message(item, event="finished", outcome="succeeded", result_version_id="forged")
    )
    job = await _job(item)
    assert (job.status, job.error_code) == ("failed", "invalid_result")


async def test_static_result_over_its_cap_is_refused(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    reg = await register()
    await upload(reg.client, reg.org_id, await new_case(reg), b"notes", "n.txt")
    [item] = sent
    version = _store_result(item, b"x" * 100)
    monkeypatch.setattr(get_settings(), "static_max_result_bytes", 50)
    await ingest.handle_event(
        _message(item, event="finished", outcome="succeeded", result_version_id=version)
    )
    job = await _job(item)
    assert (job.status, job.error_code) == ("failed", "invalid_result")


# --- database guards ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("analyzer", "profile"), [("pcap", "full"), ("static", None), ("static", "deep")]
)
async def test_profile_is_required_for_static_only(analyzer: str, profile: str | None) -> None:
    reg = await register()
    evidence = await upload(reg.client, reg.org_id, await new_case(reg), b"", "empty.bin")
    with pytest.raises(Exception, match="ck_analysis_jobs_profile"):
        async with tenant_session(reg.org_id, None) as session:
            await session.execute(
                text(
                    "INSERT INTO analysis_jobs (organization_id, evidence_id, analyzer, profile, "
                    "requested_by, ingest_token_sha256) VALUES (:org, :evidence, "
                    "CAST(:analyzer AS analyzer), :profile, :user, :digest)"
                ),
                {
                    "org": reg.org_id,
                    "evidence": uuid.UUID(evidence["id"]),
                    "analyzer": analyzer,
                    "profile": profile,
                    "user": reg.user_id,
                    "digest": "0" * 64,
                },
            )


async def test_profile_and_index_analyzer_are_immutable(sent: SentJobs) -> None:
    reg = await register()
    await upload(reg.client, reg.org_id, await new_case(reg), b"notes", "n.txt")
    [item] = sent
    with pytest.raises(Exception, match="immutable"):
        async with tenant_session(item.organization_id, None) as session:
            await session.execute(
                update(AnalysisJob).where(AnalysisJob.id == item.job_id).values(profile="full")
            )
    with pytest.raises(Exception, match="permission denied"):
        async with tenant_session(None, None) as session:
            await session.execute(
                update(AnalysisJobIndex)
                .where(AnalysisJobIndex.job_id == item.job_id)
                .values(analyzer="pcap")
            )
