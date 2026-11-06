"""M9 phase 10: export expiry (the beat `disk.expire_exports`) and the deletion of expired export
objects for EVERY org (RT19).

- `expire_exports()` marks `ready` exports older than `DISK_EXPORT_TTL_S` `expired` (rows of
  several orgs, found in a system session, updated per org); younger, pending or promoted rows
  are untouched; promote then answers `409 disk_export_expired`.
- The retention sweep deletes the exact object version of every `expired` export (and of a
  `failed` one that kept its object, a refused promotion) for an org WITHOUT a retention policy
  too (phase 9 visited only orgs listed in `retention_policy_index`), with the purge user.
- A system session reads `disk_exports` (0017's `system_read`) but never writes it.
"""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from minio.error import S3Error
from sqlalchemy import text

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.disk_forensics import export_service
from app.modules.disk_forensics.models import DiskExport
from app.modules.retention import objects
from app.workers import retention as worker_module
from tests import disk_export_helpers as dx
from tests.disk_helpers import seed_disk_job
from tests.integration.seed import Tenant
from tests.integration.test_disk_sensitivity import disk_segments
from tests.integration.test_retention_purge import owner_tenant
from tests.ops_helpers import purge_minio, retention_sessionmaker

Deleted = list[tuple[str, str, str]]
OLD = timedelta(days=8)


async def _jobs(t: Tenant) -> tuple[uuid.UUID, uuid.UUID]:
    segments = await disk_segments(t, 1)
    source = await seed_disk_job(t, segments)
    export_job = await seed_disk_job(t, segments, profile="extract", fixture=None)
    return source, export_job


async def _export(
    t: Tenant, jobs: tuple[uuid.UUID, uuid.UUID], state: str, age: timedelta, **values: object
) -> uuid.UUID:
    source, export_job = jobs
    row = DiskExport(
        organization_id=t.org_id,
        export_job_id=export_job,
        source_job_id=source,
        file_id=uuid.uuid4(),
        path=dx.UPDATER,
        state=state,
        object_key=f"exports/{export_job}/{uuid.uuid4()}",
        object_version_id=f"v-{uuid.uuid4().hex[:12]}",
        size=1024,
        worker_sha256="a" * 64,
        requested_by=t.owner_id,
        created_at=datetime.now(UTC) - age,
        **values,
    )
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(row)
    return row.id


async def test_old_ready_exports_expire_in_every_org() -> None:
    _, a = await owner_tenant("Disk Export TTL A")
    reg_b, b = await owner_tenant("Disk Export TTL B")
    jobs_a, jobs_b = await _jobs(a), await _jobs(b)
    old_a = await _export(a, jobs_a, "ready", OLD)
    old_b = await _export(b, jobs_b, "ready", OLD)
    young = await _export(a, jobs_a, "ready", timedelta(hours=1))
    pending = await _export(a, jobs_a, "pending", OLD, object_key=None, object_version_id=None)

    assert await export_service.expire_exports(10_000) >= 2
    assert (await dx.export_row(a.org_id, old_a)).state == "expired"
    assert (await dx.export_row(b.org_id, old_b)).state == "expired"
    assert (await dx.export_row(a.org_id, young)).state == "ready"
    assert (await dx.export_row(a.org_id, pending)).state == "pending"

    response = await dx.promote(reg_b, old_b)
    assert (response.status_code, response.json()["error"]["code"]) == (
        409,
        "disk_export_expired",
    )


async def test_a_system_session_reads_but_never_writes_exports() -> None:
    _, t = await owner_tenant("Disk Export System Org")
    export_id = await _export(t, await _jobs(t), "ready", OLD)
    async with tenant_session(None, None) as s:
        seen = await s.scalar(
            text("SELECT count(*) FROM disk_exports WHERE id = :i"), {"i": export_id}
        )
        changed = await s.execute(
            text("UPDATE disk_exports SET state = 'expired' WHERE id = :i"), {"i": export_id}
        )
    assert seen == 1
    assert changed.rowcount == 0  # type: ignore[attr-defined]
    assert (await dx.export_row(t.org_id, export_id)).state == "ready"


@pytest.fixture
def deletes(monkeypatch: pytest.MonkeyPatch) -> Iterator[Deleted]:
    done: Deleted = []

    async def delete_version(bucket: str, key: str, version_id: str) -> None:
        done.append((bucket, key, version_id))

    monkeypatch.setattr(worker_module, "_sessionmaker", retention_sessionmaker)
    monkeypatch.setattr(objects, "client", purge_minio)
    monkeypatch.setattr(objects, "delete_version", delete_version)
    monkeypatch.setattr(worker_module, "_enqueue", lambda o, r: None)
    yield done


async def test_the_sweep_deletes_export_objects_of_orgs_without_a_policy(
    deletes: Deleted,
) -> None:
    _, t = await owner_tenant("Disk Export No Policy Org")  # no retention policy at all
    jobs = await _jobs(t)
    expired = await _export(t, jobs, "expired", OLD)
    refused = await _export(t, jobs, "failed", OLD, error_code="export_hash_mismatch")
    ready = await _export(t, jobs, "ready", OLD)
    rows = {i: await dx.export_row(t.org_id, i) for i in (expired, refused, ready)}

    assert t.org_id in await worker_module.export_purge_orgs()
    await worker_module.sweep()
    bucket = get_settings().results_bucket
    for export_id in (expired, refused):
        row = rows[export_id]
        assert (bucket, row.object_key, row.object_version_id) in deletes
        assert (await dx.export_row(t.org_id, export_id)).object_deleted_at is not None
    assert all(key != rows[ready].object_key for _, key, _ in deletes)
    assert (await dx.export_row(t.org_id, ready)).object_deleted_at is None
    assert t.org_id not in await worker_module.export_purge_orgs()  # nothing left to delete


async def test_a_failed_delete_is_retried_by_the_next_sweep(
    deletes: Deleted, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, t = await owner_tenant("Disk Export Retry Org")
    expired = await _export(t, await _jobs(t), "expired", OLD)

    async def refuse(bucket: str, key: str, version_id: str) -> None:
        raise S3Error(None, "InternalError", "injected", key, "req", "host")  # type: ignore[arg-type]

    monkeypatch.setattr(objects, "delete_version", refuse)
    await worker_module.sweep()
    assert (await dx.export_row(t.org_id, expired)).object_deleted_at is None
    assert t.org_id in await worker_module.export_purge_orgs()
