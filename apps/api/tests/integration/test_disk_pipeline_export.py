"""File export to derived evidence end to end (M9 phase 13) on the generated `ntfs_windows`
image, through the real `disk-worker-test` (the `extract` job), the real
`disk-ingest-worker-test` and, after promotion, the real `static-worker-test`:

- `tool.exe` (and the `payload` named stream when the image was built on the libntfs route) are
  exported; the worker's sha256 equals the ground truth's; promoting `tool.exe` gives derived,
  restricted evidence with the inherited flags, custody on both sides and its automatic
  static job, whose trusted sha256 equals the worker's;
- `SAM`, the second name of `SAM` (libntfs route only: the FAT32 route has no hard link, a
  recorded phase-4 gap), a deleted entry (when the image lists one) and a file above
  `DISK_EXPORT_MAX_BYTES` are refused with their reasons;
- an unpromoted export expires (time travel: `DISK_EXPORT_TTL_S` set to 0 in-process) and the
  retention worker's purge user deletes its exact object version.

The generated images are at most 64 MiB, so the 65 MiB case runs with the export cap lowered
below the file's size (the same refusal, `too_large`). See `tests/disk_pipeline_helpers.py`.
"""

import uuid
from typing import Any

import pytest
from minio.error import S3Error
from sqlalchemy import select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.disk_forensics import export_service
from app.modules.evidence.models import CustodyAction, EvidenceCustodyEvent
from app.modules.retention import objects
from app.workers import retention as worker_module
from tests import disk_export_helpers as dx
from tests import disk_pipeline_helpers as dp
from tests.analysis_helpers import job_status, jobs_for
from tests.disk_pipeline_helpers import clean_queues as clean_queues  # noqa: F401 (fixture)
from tests.disk_pipeline_helpers import small_budgets as small_budgets  # noqa: F401 (fixture)
from tests.factories import register
from tests.ops_helpers import purge_minio, retention_sessionmaker

pytestmark = [dp.requires_images, pytest.mark.usefixtures("clean_queues", "small_budgets")]

TOOL = "/Users/alice/AppData/Local/Temp/tool.exe"
INVOICE = "/Users/alice/Downloads/invoice.pdf.exe"
REPORT = "/Users/alice/Documents/report.txt"
SAM = "/Windows/System32/config/SAM"


def _truth_sha256(truth: dict[str, Any], path: str, stream: str | None = None) -> str:
    [entry] = [
        f
        for f in truth["files"]
        if dp.norm(f["path"]) == dp.norm(path) and f.get("stream") == stream
    ]
    return str(entry["sha256"])


async def _custody(org_id: uuid.UUID, evidence_id: str) -> list[str]:
    async with tenant_session(org_id, None) as s:
        rows = await s.scalars(
            select(EvidenceCustodyEvent.action)
            .where(EvidenceCustodyEvent.evidence_id == uuid.UUID(evidence_id))
            .order_by(EvidenceCustodyEvent.occurred_at, EvidenceCustodyEvent.id)
        )
        return [str(a) for a in rows]


async def _refused(run: dp.Run, file_id: str, reason: str) -> None:
    response = await dx.request(run.reg, uuid.UUID(run.job_id), [uuid.UUID(file_id)])
    assert response.status_code == 409, response.text
    error = response.json()["error"]
    assert (error["code"], error["reason"]) == ("disk_export_not_allowed", reason), error


async def _export(run: dp.Run, files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Request `files` as one export job and run it to the end: their `ready` exports."""
    response = await dx.request(
        run.reg, uuid.UUID(run.job_id), [uuid.UUID(f["id"]) for f in files]
    )
    assert response.status_code == 202, response.text
    items: list[dict[str, Any]] = response.json()["items"]
    export_job = items[0]["export_job_id"]
    await dp.wait_for(export_job)
    job = await dp.job_row(run.reg.org_id, export_job)
    assert (job.status, job.error_code) == ("succeeded", None), job.summary
    out = [await dp.get_json(run, f"{run.org}/disk-exports/{i['id']}") for i in items]
    assert [e["state"] for e in out] == ["ready"] * len(out), out
    return out


async def test_files_export_promote_refuse_and_expire(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reg = await register(org_name="Disk Pipeline Export Org")
    run = await dp.run_image(reg, "ntfs_windows")
    job = await dp.job_row(reg.org_id, run.job_id)
    assert (job.status, job.error_code) == ("succeeded", None), job.summary
    libntfs = run.truth.get("ntfs_route") == "libntfs"

    tool = await dp.find_file(run, TOOL)
    wanted = [tool]
    if libntfs:
        wanted.append(await dp.find_file(run, REPORT, "payload"))
    ready = await _export(run, wanted)
    assert ready[0]["worker_sha256"] == _truth_sha256(run.truth, TOOL)
    if libntfs:
        assert ready[1]["worker_sha256"] == _truth_sha256(run.truth, REPORT, "payload")
        assert ready[1]["path"].endswith(":payload")

    # Promote tool.exe: derived, restricted evidence with the inherited flags.
    promoted = await dx.promote(reg, ready[0]["id"])
    assert promoted.status_code == 200, promoted.text
    evidence_id = str(promoted.json()["evidence_id"])
    evidence = await dp.get_json(run, f"{run.org}/evidence/{evidence_id}")
    assert evidence["hashes"]["sha256"] == ready[0]["worker_sha256"]  # trusted == worker's
    assert evidence["sensitivity"] == {"state": "restricted", "source": "derived"}
    assert evidence["ai_excluded"] and evidence["ti_excluded"]
    assert evidence["derived_from"] == run.segments[0]
    # Custody on both sides.
    for segment in run.segments:
        actions = await _custody(reg.org_id, segment)
        assert CustodyAction.EXPORT_REQUESTED in actions
        assert CustodyAction.EXPORT_PROMOTED in actions
    derived = await _custody(reg.org_id, evidence_id)
    assert {CustodyAction.UPLOADED, CustodyAction.DERIVED_FROM} <= set(derived), derived
    # Its automatic static job runs on the real static worker.
    [static] = await jobs_for(reg.client, reg.org_id, evidence_id)
    assert static["analyzer"] == "static"
    await dp.wait_for(static["id"], timeout_s=dp.STATIC_TIMEOUT_S)
    assert await job_status(static["id"]) == "succeeded"

    # Refusals: SAM, every second name of a never-collected file, a deleted entry, too large.
    await _refused(run, (await dp.find_file(run, SAM))["id"], "never_collected")
    for meta in run.truth["never_collect_meta"]:
        await _refused(run, (await dp.find_file(run, meta["path"]))["id"], "never_collected")
    if libntfs:
        assert run.truth["never_collect_meta"], "the libntfs route makes a second name of SAM"
    deleted = [
        f
        for f in await dp.all_items(run, f"{run.base}/files", flag="deleted")
        if f["type"] == "reg"
    ]
    if deleted:  # the FAT32 route's 0xE5 entry; NTFS has none (a recorded phase-4 gap)
        await _refused(run, deleted[0]["id"], "not_allocated")
    settings = get_settings()
    with monkeypatch.context() as m:
        m.setattr(settings, "disk_export_max_bytes", max(1, int(tool["size"]) - 1))
        await _refused(run, tool["id"], "too_large")

    # An unpromoted export expires and its object version is deleted by the purge user.
    if libntfs:
        unpromoted = ready[1]
    else:
        [unpromoted] = await _export(run, [await dp.find_file(run, INVOICE)])
    monkeypatch.setattr(settings, "disk_export_ttl_s", 0)  # time travel (test profile only)
    assert await export_service.expire_exports(10_000) >= 1
    assert (await dp.get_json(run, f"{run.org}/disk-exports/{unpromoted['id']}"))[
        "state"
    ] == "expired"
    refused = await dx.promote(reg, unpromoted["id"])
    assert (refused.status_code, refused.json()["error"]["code"]) == (409, "disk_export_expired")
    still = await dp.get_json(run, f"{run.org}/disk-exports/{ready[0]['id']}")
    assert still["state"] == "promoted"  # a promoted copy is evidence: never expired

    row = await dx.export_row(reg.org_id, unpromoted["id"])
    assert row.object_key and row.object_version_id
    monkeypatch.setattr(worker_module, "_sessionmaker", retention_sessionmaker)
    monkeypatch.setattr(objects, "client", purge_minio)
    assert await worker_module.purge_expired_exports(reg.org_id) >= 1
    assert (await dx.export_row(reg.org_id, unpromoted["id"])).object_deleted_at is not None
    with pytest.raises(S3Error) as gone:
        purge_minio().stat_object(
            settings.results_bucket, row.object_key, version_id=row.object_version_id
        )
    assert objects.is_missing(gone.value), gone.value.code
