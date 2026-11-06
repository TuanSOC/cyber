"""M9 phase 10: the file-export request (`POST /analyses/{job}/disk/file-exports`, RT29) and its
dispatch (`build_export_message`).

Only allocated regular files (or named streams) of a succeeded disk job, at most
`DISK_EXPORT_MAX_BYTES`, none of whose names is on the never-collected list (a hard link to
SAM included, RT7) can be exported; each refusal has its reason and creates nothing. A request
is ONE `extract` job (segment set copied, `pending` exports, audit, custody on every segment).
"""

import uuid
from typing import Any

import pytest
from cyberlab_jobs.disk import DiskExportJobV1
from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob, AnalysisStatus, JobProfile
from app.modules.audit.models import AuditLog
from app.modules.disk_forensics import export_service
from app.modules.disk_forensics.dispatch import build_export_message
from app.modules.disk_forensics.models import AnalysisJobSegment, DiskExport, DiskFile
from tests import disk_export_helpers as dx
from tests.disk_export_helpers import Captured
from tests.disk_export_helpers import exports as exports  # noqa: F401 (fixture)
from tests.disk_helpers import seed_disk_job
from tests.disk_results import sent as sent  # noqa: F401 (fixture: the auto static runs)


async def _extract_jobs(org_id: uuid.UUID) -> list[AnalysisJob]:
    async with tenant_session(org_id, None) as s:
        rows = await s.scalars(
            select(AnalysisJob).where(
                AnalysisJob.organization_id == org_id, AnalysisJob.profile == JobProfile.EXTRACT
            )
        )
        return list(rows)


async def test_a_request_creates_one_extract_job_with_its_exports(
    exports: Captured, sent: Any
) -> None:
    src = await dx.source_job(segments=2)
    org = src.reg.org_id
    updater = await dx.file_id(org, src.job_id, dx.UPDATER)
    stream = await dx.file_id(org, src.job_id, dx.NOTES, "payload")
    response = await dx.request(src.reg, src.job_id, [updater, stream, updater])
    assert response.status_code == 202, response.text
    items = response.json()["items"]
    assert [i["file_id"] for i in items] == [str(updater), str(stream)]  # each file once
    assert {i["state"] for i in items} == {"pending"}
    assert items[1]["path"] == f"{dx.NOTES}:payload"
    assert all(i["worker_sha256"] is None and i["evidence_id"] is None for i in items)

    [job] = await _extract_jobs(org)
    assert (job.status, job.os_hint, job.evidence_id) == ("queued", "auto", src.segments[0])
    assert str(job.id) == items[0]["export_job_id"]
    async with tenant_session(org, None) as s:
        copied = list(
            await s.scalars(
                select(AnalysisJobSegment.evidence_id)
                .where(AnalysisJobSegment.job_id == job.id)
                .order_by(AnalysisJobSegment.ordinal)
            )
        )
        audit = await s.scalar(
            select(AuditLog).where(
                AuditLog.organization_id == org, AuditLog.action == "disk.export_requested"
            )
        )
    assert copied == src.segments
    assert audit is not None and audit.target_id == src.job_id
    assert audit.details["files"] == 2 and audit.details["export_job_id"] == str(job.id)

    item, source_job_id, planned = exports.last
    assert (item.job_id, source_job_id, item.profile) == (job.id, src.job_id, "extract")
    assert [p.export_id for p in planned] == [uuid.UUID(i["id"]) for i in items]
    assert planned[1].stream == "payload" and planned[0].expected_size == 204_800

    # The message itself (presigned against the test MinIO): one POST per file, then the
    # result stream's; the file keys are the API's, capped at the listed sizes.
    message = build_export_message(
        item, source_job_id, list(item.segments), planned, get_settings()
    )
    assert isinstance(message, DiskExportJobV1)
    assert [str(s.evidence_id) for s in message.segments] == [str(s) for s in src.segments]
    assert [f.expected_size for f in message.files] == [204_800, 4096]
    keys = [p.fields["key"] for p in message.result_posts]
    assert keys[:2] == [f"exports/{job.id}/{p.export_id}" for p in planned]
    assert keys[2].endswith(f"{job.id}.ndjson.gz")
    assert message.limits.stages["extract"].rlimit_fsize == 64 * 1024**2


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        (dx.SAM, "never_collected"),
        (dx.DELETED, "not_allocated"),
        (dx.ORPHAN, "not_allocated"),
        ("Users/alice/Downloads", "not_regular"),
    ],
)
async def test_refused_files_create_nothing(
    exports: Captured, sent: Any, path: str, reason: str
) -> None:
    src = await dx.source_job()
    org = src.reg.org_id
    good = await dx.file_id(org, src.job_id, dx.UPDATER)
    bad = await dx.file_id(org, src.job_id, path)
    response = await dx.request(src.reg, src.job_id, [good, bad])
    assert response.status_code == 409, response.text
    error = response.json()["error"]
    assert (error["code"], error["reason"], error["file_id"]) == (
        "disk_export_not_allowed",
        reason,
        str(bad),
    )
    assert await _extract_jobs(org) == [] and exports.calls == []


async def test_a_hard_link_to_sam_is_refused(exports: Captured, sent: Any) -> None:
    """RT7: an innocent name of the SAM inode (same partition and meta_addr) is refused too."""
    src = await dx.source_job()
    org = src.reg.org_id
    sam = await dx.file_id(org, src.job_id, dx.SAM)
    async with tenant_session(org, None) as s:
        hive = await s.get(DiskFile, sam)
        assert hive is not None
        link = DiskFile(
            organization_id=org,
            job_id=src.job_id,
            partition_index=hive.partition_index,
            meta_addr=hive.meta_addr,
            meta_seq=hive.meta_seq,
            path="Users/alice/Desktop/innocent.txt",
            parent_addr=hive.parent_addr,
            name="innocent.txt",
            ext="txt",
            type="reg",
            flags=1 | 64,
            size=hive.size,
        )
        s.add(link)
    response = await dx.request(src.reg, src.job_id, [link.id])
    assert response.status_code == 409, response.text
    assert response.json()["error"]["reason"] == "never_collected"


async def test_too_large_files_and_quota(
    exports: Captured, sent: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = await dx.source_job()
    updater = await dx.file_id(src.reg.org_id, src.job_id, dx.UPDATER)
    settings = get_settings()
    monkeypatch.setattr(settings, "disk_export_max_bytes", 1024)
    response = await dx.request(src.reg, src.job_id, [updater])
    assert response.json()["error"]["reason"] == "too_large"
    monkeypatch.setattr(settings, "disk_export_max_bytes", 64 * 1024**2)
    monkeypatch.setattr(settings, "default_storage_quota_bytes", 10_000)
    response = await dx.request(src.reg, src.job_id, [updater])
    assert response.status_code == 507, response.text
    assert response.json()["error"]["code"] == "insufficient_storage"
    assert await _extract_jobs(src.reg.org_id) == []


async def test_files_and_jobs_of_others_are_404(exports: Captured, sent: Any) -> None:
    src = await dx.source_job()
    other = await seed_disk_job(src.t)  # a second disk job of the same org (no hashes needed)
    foreign_file = await dx.file_id(src.reg.org_id, other, dx.UPDATER)
    response = await dx.request(src.reg, src.job_id, [foreign_file])
    assert response.status_code == 404
    assert (await dx.request(src.reg, uuid.uuid4(), [foreign_file])).status_code == 404
    extract = await seed_disk_job(src.t, src.segments, profile="extract", fixture=None)
    assert (await dx.request(src.reg, extract, [foreign_file])).status_code == 404


async def test_the_source_job_must_have_succeeded(exports: Captured, sent: Any) -> None:
    src = await dx.source_job()
    running = await seed_disk_job(src.t, src.segments, status="running", fixture=None)
    response = await dx.request(src.reg, running, [uuid.uuid4()])
    assert (response.status_code, response.json()["error"]["code"]) == (409, "analysis_not_ready")
    failed = await seed_disk_job(src.t, src.segments, status="failed", fixture=None)
    response = await dx.request(src.reg, failed, [uuid.uuid4()])
    assert response.json()["error"]["reason"] == "source_not_succeeded"


async def test_the_org_cap_applies(
    exports: Captured, sent: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "disk_max_active_per_org", 1)
    src = await dx.source_job()
    updater = await dx.file_id(src.reg.org_id, src.job_id, dx.UPDATER)
    assert (await dx.request(src.reg, src.job_id, [updater])).status_code == 202
    again = await dx.request(src.reg, src.job_id, [updater])
    assert (again.status_code, again.json()["error"]["code"]) == (429, "analysis_queue_full")


async def test_a_lost_publish_fails_the_job_and_its_exports(
    sent: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(*_: Any) -> None:
        raise ConnectionError("broker down")

    monkeypatch.setattr(export_service, "send_export", broken)
    src = await dx.source_job()
    updater = await dx.file_id(src.reg.org_id, src.job_id, dx.UPDATER)
    response = await dx.request(src.reg, src.job_id, [updater])
    assert response.status_code == 202, response.text
    [item] = response.json()["items"]
    assert (item["state"], item["error_code"]) == ("failed", "enqueue_failed")
    [job] = await _extract_jobs(src.reg.org_id)
    assert (job.status, job.error_code) == (AnalysisStatus.FAILED, "enqueue_failed")
    async with tenant_session(src.reg.org_id, None) as s:
        pending = await s.scalar(
            select(func.count()).select_from(DiskExport).where(DiskExport.state == "pending")
        )
    assert pending == 0
