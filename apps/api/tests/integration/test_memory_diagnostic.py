"""M8 phase 6: the `symbols_missing` diagnostic result (plan "Symbols").

A failed memory report with `error_code: symbols_missing` and a result version stores the
image facts and the requirement in `memory_images` and fails the job `symbols_missing`, in
one transaction. The same report shape from any other analyzer, or with another code, is
refused unread (`invalid_result`).
"""

from typing import Any

import pytest
from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch
from app.modules.audit.models import AuditLog
from app.modules.memory_analysis.models import MemoryImage
from app.workers import ingest
from tests import memory_results as mr
from tests.analysis_helpers import SentJobs, new_case, upload
from tests.factories import register
from tests.pcap_results import encode, put_result

PDB = {"name": "ntkrnlmp.pdb", "guid": "89ABCDEF0123456789ABCDEF01234567", "age": 2}


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> SentJobs:
    captured = SentJobs()

    async def capture(item: dispatch.DispatchInput) -> None:
        captured.append(item)

    monkeypatch.setattr(dispatch, "send", capture)
    return captured


async def _image(item: dispatch.DispatchInput) -> MemoryImage | None:
    async with tenant_session(item.organization_id, None) as session:
        return await session.get(MemoryImage, item.job_id)


def _diagnostic(item: dispatch.DispatchInput, objs: list[dict[str, Any]] | None = None) -> bytes:
    if objs is None:
        objs = mr.retargeted(item, mr.DIAGNOSTIC)
    return encode([mr.dumps(o) for o in objs])


async def _deliver(item: dispatch.DispatchInput, data: bytes, code: str = "symbols_missing") -> Any:
    return await mr.deliver(item, data, outcome="failed", error_code=code)


async def test_a_diagnostic_stores_the_requirement_and_fails_the_job(sent: SentJobs) -> None:
    reg, _, item = await mr.queued_job(sent)
    message = await _deliver(item, _diagnostic(item))
    job = await mr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "symbols_missing")
    assert job.result_version_id == message["result_version_id"]
    assert job.summary["symbols"] == {"status": "missing", "isf_sha256": None, "required": PDB}
    assert job.summary["image"]["sha256"] == mr.IMAGE_SHA256

    image = await _image(item)
    assert image is not None and image.symbols_status == "missing"
    assert (image.pdb_name, image.pdb_guid, image.pdb_age) == (
        PDB["name"],
        PDB["guid"],
        PDB["age"],
    )
    assert image.plugins == [] and image.os == "windows" and image.arch == "x64"
    counts = await mr.row_counts(reg.org_id, item.job_id)
    assert counts == {**dict.fromkeys(mr.TABLES, 0), "memory_images": 1}
    async with tenant_session(reg.org_id, None) as session:
        failed = (
            (await session.execute(select(AuditLog).where(AuditLog.action == "analysis.failed")))
            .scalars()
            .all()
        )
    assert [a.details and a.details["error_code"] for a in failed] == ["symbols_missing"]

    # A redelivered report changes nothing.
    await ingest.handle_event(message)
    assert (await mr.row_counts(reg.org_id, item.job_id))["memory_images"] == 1


async def test_a_linux_requirement_is_stored_as_inert_text(sent: SentJobs) -> None:
    _, _, item = await mr.queued_job(sent)
    banner = "Linux version 6.1.0-13-amd64 (debian-kernel@lists.debian.org) $(id) `x`; rm -rf /"
    header, _image_line = mr.retargeted(item, mr.DIAGNOSTIC)
    linux = {
        **header,
        "os": "linux",
        "symbols": {"status": "missing", "required": {"banner": banner}},
    }
    await _deliver(item, _diagnostic(item, [linux]))
    job = await mr.job_of(item)
    assert job.error_code == "symbols_missing"
    image = await _image(item)
    assert image is not None and image.os == "linux" and image.kernel_banner == banner
    assert image.pdb_name is None and image.arch is None


async def test_a_diagnostic_without_its_result_keeps_the_code_only(sent: SentJobs) -> None:
    _, _, item = await mr.queued_job(sent)
    await ingest.handle_event(
        {
            **mr.finished(item, "unused", outcome="failed", error_code="symbols_missing"),
            "result_version_id": None,
        }
    )
    job = await mr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "symbols_missing")
    assert await _image(item) is None


HOSTILE: dict[str, Any] = {
    "with_records": lambda o: [
        o[0],
        mr.parsed(mr.WINDOWS)[mr.index_of(mr.parsed(mr.WINDOWS), "process")],
    ],
    "wrong_image": lambda o: [o[0], {**o[1], "sha256": "a" * 64}],
    "resolved_header": lambda o: [
        {**o[0], "symbols": {"status": "resolved", "isf_sha256": "c" * 64}},
        o[1],
    ],
    "bad_guid": lambda o: [
        {**o[0], "symbols": {"status": "missing", "required": {**PDB, "guid": "g" * 32}}},
        o[1],
    ],
    "non_kernel_pdb": lambda o: [
        {**o[0], "symbols": {"status": "missing", "required": {**PDB, "name": "evil.pdb"}}},
        o[1],
    ],
    "banner_control_chars": lambda o: [
        {
            **o[0],
            "os": "linux",
            "symbols": {"status": "missing", "required": {"banner": "Linux\x1b[2J"}},
        }
    ],
    "huge_age": lambda o: [
        {**o[0], "symbols": {"status": "missing", "required": {**PDB, "age": 2**16}}},
        o[1],
    ],
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
async def test_hostile_diagnostics_write_nothing(sent: SentJobs, name: str) -> None:
    _, _, item = await mr.queued_job(sent)
    objs = HOSTILE[name](mr.retargeted(item, mr.DIAGNOSTIC))
    await _deliver(item, _diagnostic(item, objs))
    job = await mr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "invalid_result")
    assert await _image(item) is None and job.result_version_id is None


async def test_the_same_report_from_a_static_job_is_refused_unread(sent: SentJobs) -> None:
    reg = await register()
    await upload(reg.client, reg.org_id, await new_case(reg), b"notes\n", "n.txt")
    [item] = sent  # the automatic static `av` job
    assert item.analyzer == "static"
    version = put_result(item.organization_id, item.job_id, _diagnostic(item))
    message = {
        **mr.finished(item, version, outcome="failed", error_code="symbols_missing"),
        "worker_version": "static-worker/test",
    }
    await ingest.handle_event(message)
    job = await mr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "invalid_result")
    assert job.result_version_id is None
    assert await _image(item) is None


async def test_another_failure_code_with_a_result_is_refused_unread(sent: SentJobs) -> None:
    _, _, item = await mr.queued_job(sent)
    await _deliver(item, _diagnostic(item), code="plugin_failed")
    job = await mr.job_of(item)
    assert (job.status, job.error_code) == ("failed", "invalid_result")
    assert await _image(item) is None
