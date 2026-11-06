"""Deletion of expired export objects (M9 phase 9, RT19).

The api MinIO user has no Delete on the results bucket: the retention worker's purge user
deletes the exact `object_version_id` of every `expired` disk export and stamps
`object_deleted_at` (set once). It runs on every sweep for every indexed org, whatever its
retention mode (an expired export is never evidence); a failed delete leaves the row
unstamped and the next sweep retries it. `ready` and `promoted` exports are never touched
(a promoted copy is evidence).
"""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from minio.error import S3Error

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.disk_forensics.models import DiskExport
from app.modules.retention import objects
from app.workers import retention as worker_module
from tests.case_helpers import seed_evidence
from tests.disk_helpers import seed_disk_job
from tests.integration.seed import Tenant
from tests.integration.test_disk_sensitivity import disk_segments
from tests.integration.test_retention_purge import owner_tenant
from tests.ops_helpers import purge_minio, retention_sessionmaker, seed_retention_policy

Deleted = list[tuple[str, str, str]]


@pytest.fixture
def deletes(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Deleted, set[str]]]:
    """The worker in-process as the retention role; object deletes recorded (keys in
    `failing` raise an S3 error instead)."""
    done: Deleted = []
    failing: set[str] = set()

    async def delete_version(bucket: str, key: str, version_id: str) -> None:
        if key in failing:
            raise S3Error(None, "InternalError", "injected", key, "req", "host")  # type: ignore[arg-type]
        done.append((bucket, key, version_id))

    monkeypatch.setattr(worker_module, "_sessionmaker", retention_sessionmaker)
    monkeypatch.setattr(objects, "client", purge_minio)  # the sweep's hold sync
    monkeypatch.setattr(objects, "delete_version", delete_version)
    monkeypatch.setattr(worker_module, "_enqueue", lambda o, r: None)
    yield done, failing


async def _export(
    t: Tenant, source_job: uuid.UUID, export_job: uuid.UUID, state: str, **values: object
) -> DiskExport:
    key = f"{t.org_id}/disk-exports/{uuid.uuid4()}"
    row = DiskExport(
        organization_id=t.org_id,
        export_job_id=export_job,
        source_job_id=source_job,
        file_id=uuid.uuid4(),
        path="/Users/alice/Downloads/invoice.exe",
        state=state,
        object_key=key,
        object_version_id=f"v-{uuid.uuid4().hex[:12]}",
        size=4096,
        requested_by=t.owner_id,
        **values,
    )
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(row)
    return row


async def _deleted_at(t: Tenant, export_id: uuid.UUID) -> datetime | None:
    async with tenant_session(t.org_id, t.owner_id) as s:
        row = await s.get(DiskExport, export_id)
        assert row is not None
        return row.object_deleted_at


async def test_expired_exports_lose_their_object_version_only(
    deletes: tuple[Deleted, set[str]],
) -> None:
    done, failing = deletes
    _, t = await owner_tenant("Disk Export Purge Org")
    segments = await disk_segments(t, 1)
    source = await seed_disk_job(t, segments)
    export_job = await seed_disk_job(t, segments, profile="extract", fixture=None)
    expired = await _export(t, source, export_job, "expired")
    flaky = await _export(t, source, export_job, "expired")
    ready = await _export(t, source, export_job, "ready")
    promoted_evidence = await seed_evidence(t, filename="invoice.exe")
    promoted = await _export(
        t,
        source,
        export_job,
        "promoted",
        evidence_id=promoted_evidence,
        promoted_by=t.owner_id,
        promoted_at=datetime.now(UTC),
    )
    assert flaky.object_key is not None
    failing.add(flaky.object_key)

    assert await worker_module.purge_expired_exports(t.org_id) == 1
    bucket = get_settings().results_bucket
    assert done == [(bucket, expired.object_key, expired.object_version_id)]
    assert await _deleted_at(t, expired.id) is not None
    assert await _deleted_at(t, flaky.id) is None  # retried next time
    assert await _deleted_at(t, ready.id) is None
    assert await _deleted_at(t, promoted.id) is None

    # The next pass retries the failed delete and never repeats a done one.
    failing.clear()
    assert await worker_module.purge_expired_exports(t.org_id) == 1
    assert done[1:] == [(bucket, flaky.object_key, flaky.object_version_id)]
    assert await _deleted_at(t, flaky.id) is not None
    assert await worker_module.purge_expired_exports(t.org_id) == 0
    assert len(done) == 2


async def test_the_sweep_purges_expired_exports_whatever_the_mode(
    deletes: tuple[Deleted, set[str]],
) -> None:
    """An indexed org whose policy keeps everything (no run is scheduled) still loses its
    expired export objects on the daily sweep."""
    done, _ = deletes
    _, t = await owner_tenant("Disk Export Sweep Org")
    await seed_retention_policy(t)  # every *_days NULL: keep forever, dry run
    segments = await disk_segments(t, 1)
    source = await seed_disk_job(t, segments)
    export_job = await seed_disk_job(t, segments, profile="extract", fixture=None)
    expired = await _export(t, source, export_job, "expired")

    await worker_module.sweep()
    assert (get_settings().results_bucket, expired.object_key, expired.object_version_id) in done
    assert await _deleted_at(t, expired.id) is not None
