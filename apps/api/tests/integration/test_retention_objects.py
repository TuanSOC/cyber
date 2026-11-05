"""S3 legal holds mirrored by the retention worker (M7 phase 3, RT5), on the test buckets with
the purge MinIO user:

- a case hold + sync turns the S3 legal hold ON for the case's evidence versions and report
  snapshots, and stamps `s3_synced_at`;
- it stays ON (and protects) during the delay after a release, and goes OFF after it;
- it stays ON while an org hold or another case hold covers the case;
- the purge user can never delete a legal-held version or a `*/snapshot.json`;
- the api user cannot delete in `reports` and has no legal-hold action.
"""

import io
import uuid

import pytest
from minio.error import S3Error
from sqlalchemy import text

from app.core.clients import get_minio
from app.core.tenancy import tenant_session
from app.workers import retention as worker_module
from tests.analysis_helpers import tiny_pcap
from tests.case_helpers import seed_case
from tests.integration.seed import Tenant
from tests.integration.test_retention_purge import Captured, captured, owner_tenant
from tests.ops_helpers import (
    _stored_evidence,
    purge_minio,
    seed_hold,
    seed_released_hold,
    seed_retention_policy,
)
from tests.report_helpers import new_signing_keys, reports_test_bucket, seed_report, seed_version
from tests.storage_helpers import root_minio

API = "/api/v1/orgs"
__all__ = ["captured"]


async def _case_objects(t: Tenant, case_id: uuid.UUID) -> list[tuple[str, str, str]]:
    """Two evidence versions and one report snapshot of the case."""
    out = []
    for name in ("one.pcap", "two.pcap"):
        _, obj = await _stored_evidence(t, case_id, tiny_pcap(), name)
        out.append(obj)
    report_id = await seed_report(t, case_id)
    version = await seed_version(t, report_id, new_signing_keys())
    out.append((reports_test_bucket(), version.object_key, version.object_version_id))
    return out


def _held(objs: list[tuple[str, str, str]]) -> list[bool]:
    return [bool(root_minio().is_object_legal_hold_enabled(b, k, v)) for b, k, v in objs]


async def _synced_at(t: Tenant, hold_id: uuid.UUID) -> object:
    async with tenant_session(t.org_id, None) as s:
        return (
            await s.execute(
                text("SELECT s3_synced_at FROM legal_holds WHERE id = :h"), {"h": hold_id}
            )
        ).scalar_one()


async def test_a_case_hold_is_mirrored_and_kept_during_the_delay(captured: Captured) -> None:
    reg, t = await owner_tenant()
    objs = await _case_objects(t, t.investigation_id)
    other = await seed_case_objects(t)
    c = reg.client
    placed = await c.post(
        f"{API}/{t.org_id}/legal-holds",
        json={
            "scope": "investigation",
            "investigation_id": str(t.investigation_id),
            "reason": "Hold",
        },
        headers={"X-CSRF-Token": c.cookies.get("cl_csrf") or ""},
    )
    assert placed.status_code == 201, placed.text
    hold_id = uuid.UUID(placed.json()["id"])
    assert _held(objs) == [False, False, False]

    assert await worker_module.sync_holds(t.org_id) == 3
    assert _held(objs) == [True, True, True]
    assert _held(other) == [False, False, False]  # another case: untouched
    assert await _synced_at(t, hold_id) is not None
    listed = (await c.get(f"{API}/{t.org_id}/legal-holds")).json()["items"]
    assert listed[0]["s3_sync"] == "synced"
    # Idempotent: nothing left to change.
    assert await worker_module.sync_holds(t.org_id) == 0

    # The purge user cannot delete a held version (nor any snapshot, held or not).
    bucket, key, version = objs[0]
    with pytest.raises(S3Error):
        purge_minio().remove_object(bucket, key, version_id=version)

    # Released: still protecting during the delay, so still ON (RT1).
    released = await c.post(
        f"{API}/{t.org_id}/legal-holds/{hold_id}/release",
        json={"reason": "Done"},
        headers={"X-CSRF-Token": c.cookies.get("cl_csrf") or ""},
    )
    assert released.status_code == 200
    assert await worker_module.sync_holds(t.org_id) == 0
    assert _held(objs) == [True, True, True]
    assert released.json()["s3_sync"] == "pending"


async def seed_case_objects(t: Tenant) -> list[tuple[str, str, str]]:
    return await _case_objects(t, await seed_case(t, title="Unheld case"))


def _turn_on(objs: list[tuple[str, str, str]]) -> None:
    for b, k, v in objs:
        root_minio().enable_object_legal_hold(b, k, v)


async def test_off_after_the_delay_unless_another_hold_covers(captured: Captured) -> None:
    _, t = await owner_tenant()
    await seed_retention_policy(t)  # puts the org in retention_policy_index (RT3)
    lone, shared, org_case = (
        await seed_case(t, title="Lone"),
        await seed_case(t, title="Shared"),
        await seed_case(t, title="Org"),
    )
    lone_objs = await _case_objects(t, lone)
    shared_objs = await _case_objects(t, shared)
    org_objs = await _case_objects(t, org_case)
    for objs in (lone_objs, shared_objs, org_objs):
        _turn_on(objs)

    # Released 30 days ago (the delay is over); the shared case also has an active hold.
    lone_hold = await seed_released_hold(t, 30, investigation_id=lone)
    shared_released = await seed_released_hold(t, 30, investigation_id=shared)
    await seed_hold(t, investigation_id=shared)
    assert await worker_module.sync_holds(t.org_id) == 3  # only the lone case turns OFF
    assert _held(lone_objs) == [False, False, False]
    assert _held(shared_objs) == [True, True, True]
    assert await _synced_at(t, lone_hold) is not None
    assert await _synced_at(t, shared_released) is not None  # nothing to do: stamped
    assert _held(org_objs) == [True, True, True]  # no hold at all: never touched

    # An org hold keeps a released case's objects ON too (and makes no S3 call itself).
    org_released = await seed_released_hold(t, 30, investigation_id=org_case)
    await seed_hold(t)
    assert await worker_module.sync_holds(t.org_id) == 0
    assert _held(org_objs) == [True, True, True]
    assert await _synced_at(t, org_released) is not None


async def test_sync_drops_orgs_outside_the_index(captured: Captured) -> None:
    _, t = await owner_tenant()
    objs = await _case_objects(t, t.investigation_id)
    await seed_hold(t, investigation_id=t.investigation_id)  # seeded: no index row
    assert await worker_module.sync_holds(t.org_id) == 0
    assert _held(objs) == [False, False, False]


def test_the_purge_user_cannot_delete_a_snapshot_or_set_retention(captured: Captured) -> None:
    bucket = reports_test_bucket()
    key = f"{uuid.uuid4()}/{uuid.uuid4()}/1/snapshot.json"
    stored = root_minio().put_object(bucket, key, io.BytesIO(b"{}"), 2)
    with pytest.raises(S3Error, match="AccessDenied|Access Denied"):
        purge_minio().remove_object(bucket, key, version_id=stored.version_id)
    # Held or not, a snapshot stays; the purge user may set its legal hold (the sync).
    purge_minio().enable_object_legal_hold(bucket, key, version_id=stored.version_id)
    with pytest.raises(S3Error):
        purge_minio().remove_object(bucket, key, version_id=stored.version_id)
    purge_minio().disable_object_legal_hold(bucket, key, version_id=stored.version_id)


def test_the_api_user_has_no_legal_hold_action_and_no_report_delete(captured: Captured) -> None:
    bucket = reports_test_bucket()
    key = f"{uuid.uuid4()}/{uuid.uuid4()}/1/{uuid.uuid4()}.pdf"
    stored = root_minio().put_object(bucket, key, io.BytesIO(b"%PDF"), 4)
    api = get_minio()
    with pytest.raises(S3Error, match="AccessDenied|Access Denied"):
        api.remove_object(bucket, key, version_id=stored.version_id)
    with pytest.raises(S3Error, match="AccessDenied|Access Denied"):
        api.enable_object_legal_hold(bucket, key, version_id=stored.version_id)
    with pytest.raises(S3Error, match="AccessDenied|Access Denied"):
        api.is_object_legal_hold_enabled(bucket, key, version_id=stored.version_id)
