"""M8 phase 6: the trusted ingest of a `memory.v1` success, all rows or none.

Each hostile stream must fail the job `invalid_result` and leave every result table empty.
"""

import uuid
from typing import Any

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch
from app.modules.audit.models import AuditLog
from app.workers import ingest
from tests import memory_results as mr
from tests.analysis_helpers import SentJobs
from tests.pcap_results import encode, put_result

EMPTY = dict.fromkeys(mr.TABLES, 0)


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


async def _audits(org_id: uuid.UUID, action: str) -> list[AuditLog]:
    async with tenant_session(org_id, None) as session:
        rows = await session.execute(select(AuditLog).where(AuditLog.action == action))
        return list(rows.scalars())


async def _refused(item: dispatch.DispatchInput, data: bytes) -> None:
    await mr.deliver(item, data)
    job = await mr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "invalid_result")
    assert job.result_version_id is None and job.summary == {}
    assert await mr.row_counts(item.organization_id, item.job_id) == EMPTY


async def test_a_memory_result_is_written_in_one_transaction(sent: SentJobs) -> None:
    reg, evidence_id, item = await mr.queued_job(sent)
    message = await mr.deliver(item, mr.image_stream(item))
    job = await mr.job_of(item)
    assert (job.status, job.error_code) == ("succeeded", None)
    assert job.result_version_id == message["result_version_id"]
    assert job.worker_version == mr.WORKER
    assert await mr.row_counts(reg.org_id, item.job_id) == mr.WINDOWS_TABLES

    summary = job.summary
    assert summary["schema_version"] == "memory.v1"
    assert (summary["profile"], summary["os"], summary["engine"]) == (
        "triage",
        "windows",
        "replay",
    )
    assert summary["counts"] == mr.WINDOWS_COUNTS
    # The trusted identity: the evidence record's, which the image line had to equal.
    assert summary["image"]["sha256"] == mr.IMAGE_SHA256
    assert summary["image"]["size_bytes"] == len(mr.IMAGE)
    assert summary["symbols"]["status"] == "resolved"

    custody = (
        await reg.client.get(f"/api/v1/orgs/{reg.org_id}/evidence/{evidence_id}/custody")
    ).json()["items"]
    [analyzed] = [e for e in custody if e["action"] == "analyzed"]
    assert analyzed["details"]["job_id"] == str(item.job_id)
    assert analyzed["details"]["tool_versions"]["volatility3"] == "2.28.2"
    [succeeded] = await _audits(reg.org_id, "analysis.succeeded")
    assert succeeded.details is not None
    assert succeeded.details["counts"] == mr.WINDOWS_COUNTS

    # A redelivered success report changes nothing.
    await ingest.handle_event(message)
    assert await mr.row_counts(reg.org_id, item.job_id) == mr.WINDOWS_TABLES
    assert len(await _audits(reg.org_id, "analysis.succeeded")) == 1


async def test_a_linux_result_is_ingested(sent: SentJobs) -> None:
    reg, _, item = await mr.queued_job(sent, os_hint="linux")
    await mr.deliver(item, mr.image_stream(item, mr.LINUX))
    job = await mr.job_of(item)
    assert job.status == "succeeded", job.error_code
    counts = await mr.row_counts(reg.org_id, item.job_id)
    assert counts["memory_images"] == 1 and counts["memory_artifacts"] == 2


def _with(objs: list[dict[str, Any]], kind: str, **fields: Any) -> list[dict[str, Any]]:
    index = mr.index_of(objs, kind)
    return [*objs[:index], {**objs[index], **fields}, *objs[index + 1 :]]


HOSTILE: dict[str, Any] = {
    "wrong_job": lambda o, item: _with(o, "header", job_id=str(uuid.uuid4())),
    "wrong_profile": lambda o, item: _with(o, "header", profile="full"),
    "wrong_hash": lambda o, item: _with(o, "image", sha256="a" * 64),
    "wrong_size": lambda o, item: _with(o, "image", size_bytes=len(mr.IMAGE) + 1),
    "no_image": lambda o, item: [x for x in o if x["kind"] != "image"],
    "duplicate_pid": lambda o, item: [*o, o[mr.index_of(o, "process")]],
    "bash_on_windows": lambda o, item: [
        *o,
        {"kind": "artifact", "type": "bash", "pid": 4, "attributes": {"command": "id"}},
    ],
    "extra_field": lambda o, item: _with(o, "process", verdict="malicious"),
    "nul": lambda o, item: _with(o, "process", name="evil\u0000.exe"),
    "symbols_missing_as_success": lambda o, item: _with(
        o,
        "header",
        plugins=[],
        symbols={
            "status": "missing",
            "required": {"name": "ntkrnlmp.pdb", "guid": "0" * 32, "age": 1},
        },
    ),
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
async def test_hostile_results_write_nothing(sent: SentJobs, name: str) -> None:
    _, _, item = await mr.queued_job(sent)
    objs = HOSTILE[name](mr.retargeted(item), item)
    await _refused(item, mr.image_stream(item, objs=objs))


async def test_framing_defects_write_nothing(sent: SentJobs) -> None:
    _, _, item = await mr.queued_job(sent)
    lines = [mr.dumps(o) for o in mr.retargeted(item)]
    await _refused(item, encode(lines, trailer={"line_count": 3}))


@pytest.mark.parametrize("data", [b"not gzip", encode([], add_trailer=False)])
async def test_garbage_writes_nothing(sent: SentJobs, data: bytes) -> None:
    _, _, item = await mr.queued_job(sent)
    await _refused(item, data)


async def test_the_memory_framing_bounds_apply(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The memory ingest uses MEMORY_MAX_RESULT_DECOMPRESSED_BYTES, not the shared bound."""
    _, _, item = await mr.queued_job(sent)
    monkeypatch.setattr(get_settings(), "memory_max_result_decompressed_bytes", 4096)
    await _refused(item, mr.image_stream(item))


async def test_per_kind_caps_apply(sent: SentJobs, monkeypatch: pytest.MonkeyPatch) -> None:
    _, _, item = await mr.queued_job(sent)
    monkeypatch.setattr(get_settings(), "memory_max_processes", 39)
    await _refused(item, mr.image_stream(item))


async def test_a_result_over_the_memory_result_cap_is_refused(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, item = await mr.queued_job(sent)
    data = mr.image_stream(item)
    monkeypatch.setattr(get_settings(), "memory_max_result_bytes", len(data) - 1)
    await _refused(item, data)


async def test_a_value_the_database_refuses_rolls_everything_back(
    sent: SentJobs, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defence in depth: should validation ever let through what a check refuses, the whole
    transaction rolls back and the job fails `invalid_result`."""
    from app.modules.memory_analysis import ingest as memory_ingest

    _, _, item = await mr.queued_job(sent)
    real = memory_ingest.image_row

    def oversized(result: Any) -> dict[str, Any]:
        return {**real(result), "kernel_banner": "x" * 600}  # ck: at most 512 characters

    monkeypatch.setattr(memory_ingest, "image_row", oversized)
    await _refused(item, mr.image_stream(item))


async def test_a_forged_result_version_is_refused(sent: SentJobs) -> None:
    _, _, item = await mr.queued_job(sent)
    await ingest.handle_event(mr.finished(item, "forged-version"))
    job = await mr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "invalid_result")


async def test_a_result_after_the_job_failed_is_ignored(sent: SentJobs) -> None:
    _, _, item = await mr.queued_job(sent)
    await ingest.handle_event(
        {
            **mr.finished(item, "unused"),
            "outcome": "failed",
            "error_code": "plugin_timeout",
            "result_version_id": None,
        }
    )
    version = put_result(item.organization_id, item.job_id, mr.image_stream(item))
    await ingest.handle_event(mr.finished(item, version))
    job = await mr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "plugin_timeout")
    assert await mr.row_counts(item.organization_id, item.job_id) == EMPTY
