"""S3 legal holds mirrored by the retention worker (M7 phase 3, RT5), on the test buckets with
the purge MinIO user:

- a case hold + sync turns the S3 legal hold ON for the case's evidence versions and report
  snapshots, and stamps `s3_synced_at`;
- it stays ON (and protects) during the delay after a release, and goes OFF after it;
- it stays ON while an org hold or another case hold covers the case;
- an org hold turns it ON for every evidence version of the org (so the api's delete grant on
  an expired lock cannot remove org-held evidence), resumably when the budget runs out, and
  OFF after the delay except where a case hold still covers;
- the purge user can never delete a legal-held version or a `*/snapshot.json`;
- the api user cannot delete in `reports` and has no legal-hold action.
"""

import asyncio
import io
import uuid
from typing import Any

import pytest
from minio.error import S3Error
from sqlalchemy import text

from app.core.clients import get_minio
from app.core.tenancy import tenant_session
from app.modules.evidence.models import Evidence
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
from tests.storage_helpers import evidence_test_bucket, lane_key, root_minio

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

    # An org hold keeps a released case's evidence ON, and turns every evidence version of
    # the org ON itself (the lone case's two; its snapshot is not the org hold's). The
    # released case hold's snapshot is not the org hold's either: it goes OFF (review L1).
    org_released = await seed_released_hold(t, 30, investigation_id=org_case)
    await seed_hold(t)
    assert await worker_module.sync_holds(t.org_id) == 3
    assert _held(org_objs) == [True, True, False]
    assert _held(lone_objs) == [True, True, False]
    assert _held(shared_objs) == [True, True, True]  # its active case hold keeps the snapshot
    assert await _synced_at(t, org_released) is not None


async def test_sync_drops_orgs_outside_the_index(captured: Captured) -> None:
    _, t = await owner_tenant()
    objs = await _case_objects(t, t.investigation_id)
    await seed_hold(t, investigation_id=t.investigation_id)  # seeded: no index row
    assert await worker_module.sync_holds(t.org_id) == 0
    assert _held(objs) == [False, False, False]


def test_the_purge_user_cannot_delete_a_snapshot_or_set_retention(captured: Captured) -> None:
    bucket = reports_test_bucket()
    key = lane_key(f"{uuid.uuid4()}/{uuid.uuid4()}/1/snapshot.json")
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
    key = lane_key(f"{uuid.uuid4()}/{uuid.uuid4()}/1/{uuid.uuid4()}.pdf")
    stored = root_minio().put_object(bucket, key, io.BytesIO(b"%PDF"), 4)
    api = get_minio()
    with pytest.raises(S3Error, match="AccessDenied|Access Denied"):
        api.remove_object(bucket, key, version_id=stored.version_id)
    with pytest.raises(S3Error, match="AccessDenied|Access Denied"):
        api.enable_object_legal_hold(bucket, key, version_id=stored.version_id)
    with pytest.raises(S3Error, match="AccessDenied|Access Denied"):
        api.is_object_legal_hold_enabled(bucket, key, version_id=stored.version_id)


async def _org_evidence(t: Tenant, case_id: uuid.UUID, n: int) -> list[tuple[str, str, str]]:
    return [(await _stored_evidence(t, case_id, tiny_pcap(), f"e{i}.pcap"))[1] for i in range(n)]


async def test_an_org_hold_is_mirrored_on_every_evidence_version(captured: Captured) -> None:
    """Phase 11 (RT5): an org hold reaches S3 too, so the api's delete grant (failed-upload
    cleanup) cannot remove org-held evidence once its GOVERNANCE lock has expired."""
    reg, t = await owner_tenant()
    first = await _case_objects(t, t.investigation_id)
    second = await seed_case_objects(t)
    c = reg.client
    placed = await c.post(
        f"{API}/{t.org_id}/legal-holds",
        json={"scope": "org", "reason": "Regulator"},
        headers={"X-CSRF-Token": c.cookies.get("cl_csrf") or ""},
    )
    assert placed.status_code == 201, placed.text
    assert placed.json()["s3_sync"] == "pending"
    assert captured.published == [("retention.sync_holds", {"org_id": str(t.org_id)})]

    assert await worker_module.sync_holds(t.org_id) == 4  # the four evidence versions
    assert _held(first) == [True, True, False] and _held(second) == [True, True, False]
    listed = (await c.get(f"{API}/{t.org_id}/legal-holds")).json()["items"]
    assert listed[0]["s3_sync"] == "synced"
    # The api MinIO user (DeleteObjectVersion for the cleanup) cannot delete a held version,
    # though this one carries no GOVERNANCE lock at all (as after the lock expired).
    bucket, key, version = first[0]
    with pytest.raises(S3Error):
        get_minio().remove_object(bucket, key, version_id=version)
    # Incremental: a later upload is picked up, the rest is not changed again.
    late = await _org_evidence(t, t.investigation_id, 1)
    assert await worker_module.sync_holds(t.org_id) == 1
    assert _held(late) == [True]
    assert await worker_module.sync_holds(t.org_id) == 0


async def _sync_state(t: Tenant, hold_id: uuid.UUID) -> dict[str, Any]:
    async with tenant_session(t.org_id, None) as s:
        row = (
            await s.execute(
                text(
                    "SELECT s3_synced_at, s3_full_synced_at, s3_sync_cursor_at, "
                    "s3_sync_cursor_id, s3_sync_pass_at, placed_at FROM legal_holds "
                    "WHERE id = :h"
                ),
                {"h": hold_id},
            )
        ).one()
    return dict(row._mapping)


async def test_an_org_hold_resumes_where_the_budget_ran_out(
    captured: Captured, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, t = await owner_tenant()
    await seed_retention_policy(t)  # the org is in retention_policy_index (RT3)
    objs = await _org_evidence(t, t.investigation_id, 5)
    hold_id = await seed_hold(t)
    monkeypatch.setattr(worker_module, "SYNC_INSPECT_MAX", 3)

    assert await worker_module.sync_holds(t.org_id) == 3
    assert _held(objs) == [True, True, True, False, False]
    state = await _sync_state(t, hold_id)
    # A cursor (0015), no completed pass: still `s3_sync: pending`.
    assert state["s3_sync_cursor_at"] is not None and state["s3_sync_cursor_id"] is not None
    assert state["s3_sync_pass_at"] is not None
    assert state["s3_synced_at"] is None and state["s3_full_synced_at"] is None
    # The next pass resumes right after the cursor (nothing re-inspected) and completes.
    assert await worker_module.sync_holds(t.org_id) == 2
    assert _held(objs) == [True] * 5
    done = await _sync_state(t, hold_id)
    assert done["s3_sync_cursor_at"] is None and done["s3_sync_pass_at"] is None
    assert done["s3_full_synced_at"] is not None
    # A completed ON pass stores its START (the next incremental pass's lower bound).
    assert done["s3_synced_at"] == state["s3_sync_pass_at"]


async def test_a_released_org_hold_turns_off_except_case_held(captured: Captured) -> None:
    _, t = await owner_tenant()
    await seed_retention_policy(t)
    held_case = await _case_objects(t, t.investigation_id)
    free_case = await seed_case_objects(t)
    _turn_on(held_case)
    _turn_on(free_case)
    org_hold = await seed_released_hold(t, 30)  # the delay is over
    await seed_hold(t, investigation_id=t.investigation_id)
    # The case hold keeps its case ON; the free case's evidence goes OFF (its snapshot is
    # not the org hold's to clear).
    assert await worker_module.sync_holds(t.org_id) == 2
    assert _held(held_case) == [True, True, True]
    assert _held(free_case) == [False, False, True]
    assert await _synced_at(t, org_hold) is not None
    assert await worker_module.sync_holds(t.org_id) == 0
    # Within the delay a released org hold still protects: everything stays ON.
    _, u = await owner_tenant("Recent release")
    await seed_retention_policy(u)
    recent = await _org_evidence(u, u.investigation_id, 2)
    _turn_on(recent)
    await seed_released_hold(u, 1)
    assert await worker_module.sync_holds(u.org_id) == 0
    assert _held(recent) == [True, True]


# --- M7 review M1/M2/L2: resumable passes, budget shares, the sync's advisory lock ----------
# The real budget is SYNC_INSPECT_MAX = 5000 inspected versions per sync; these tests shrink
# it (monkeypatch) so a handful of rows stands for more than 5000, including many at ONE
# `uploaded_at` (one transaction), where a time-only watermark cannot advance.


async def _same_instant_evidence(
    t: Tenant, case_id: uuid.UUID, n: int
) -> list[tuple[str, str, str]]:
    """`n` evidence versions in `evidence-test` whose rows share one `uploaded_at` (one
    transaction: `now()` is its start)."""
    bucket = evidence_test_bucket()
    stored = []
    for _ in range(n):
        key = f"{t.org_id}/{uuid.uuid4()}"
        version = root_minio().put_object(bucket, key, io.BytesIO(b"x"), 1).version_id
        stored.append((bucket, key, str(version)))
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add_all(
            Evidence(
                organization_id=t.org_id,
                investigation_id=case_id,
                original_filename=f"same-{i}.bin",
                detected_mime="application/octet-stream",
                detected_description="data",
                size_bytes=1,
                storage_bucket=b,
                storage_key=k,
                storage_version_id=v,
                uploaded_by=t.owner_id,
            )
            for i, (b, k, v) in enumerate(stored)
        )
    return stored


async def _passes_in_progress(org_id: uuid.UUID) -> int:
    async with tenant_session(org_id, None) as s:
        found = await s.execute(
            text("SELECT count(*) FROM legal_holds WHERE s3_sync_cursor_at IS NOT NULL")
        )
        return int(found.scalar_one())


async def _sync_until_idle(org_id: uuid.UUID, max_syncs: int = 20) -> list[int]:
    """Changes per sync until a sync changes nothing and no pass is in progress (bounded: a
    stalled pass fails the test)."""
    changed: list[int] = []
    for _ in range(max_syncs):
        changed.append(await worker_module.sync_holds(org_id))
        if changed[-1] == 0 and not await _passes_in_progress(org_id):
            return changed
    raise AssertionError(f"the hold sync never settled: {changed}")


async def test_an_org_hold_first_pass_finishes_past_one_timestamp(
    captured: Captured, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M2: more uploads at one instant (and after the placement) than one sync's budget: the
    keyset cursor (uploaded_at, id) advances inside the instant, the first pass completes."""
    reg, t = await owner_tenant()
    await seed_retention_policy(t)
    hold_id = await seed_hold(t)
    objs = await _same_instant_evidence(t, t.investigation_id, 7)  # all after placed_at
    monkeypatch.setattr(worker_module, "SYNC_INSPECT_MAX", 3)

    assert await worker_module.sync_holds(t.org_id) == 3
    assert (await _sync_state(t, hold_id))["s3_full_synced_at"] is None
    listed = (await reg.client.get(f"{API}/{t.org_id}/legal-holds")).json()["items"]
    assert listed[0]["s3_sync"] == "pending"
    assert await worker_module.sync_holds(t.org_id) == 3
    assert await worker_module.sync_holds(t.org_id) == 1
    assert _held(objs) == [True] * 7
    state = await _sync_state(t, hold_id)
    assert state["s3_full_synced_at"] is not None and state["s3_sync_cursor_at"] is None
    listed = (await reg.client.get(f"{API}/{t.org_id}/legal-holds")).json()["items"]
    assert listed[0]["s3_sync"] == "synced"

    # Incremental passes re-inspect SYNC_SKEW before the last pass's start (all of the rows
    # here), resumably too: a later burst at one instant is mirrored, then nothing changes.
    late = await _same_instant_evidence(t, t.investigation_id, 5)
    changed = await _sync_until_idle(t.org_id)
    assert sum(changed) == 5 and max(changed) <= 3
    assert _held(late) == [True] * 5


async def test_an_org_off_pass_resumes_instead_of_restarting(
    captured: Captured, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M1: a released org hold's OFF pass larger than the budget continues after its cursor
    (an OFF pass used to restart from the beginning, re-inspecting the versions it had
    already cleared, and never got past the budget)."""
    _, t = await owner_tenant()
    await seed_retention_policy(t)
    objs = await _same_instant_evidence(t, t.investigation_id, 7)
    _turn_on(objs)
    hold_id = await seed_released_hold(t, 30)  # the delay is over
    monkeypatch.setattr(worker_module, "SYNC_INSPECT_MAX", 3)

    assert await worker_module.sync_holds(t.org_id) == 3
    state = await _sync_state(t, hold_id)
    assert state["s3_synced_at"] is None and state["s3_sync_cursor_at"] is not None
    assert await worker_module.sync_holds(t.org_id) == 3  # not 0: no restart
    assert await worker_module.sync_holds(t.org_id) == 1
    assert _held(objs) == [False] * 7
    done = await _sync_state(t, hold_id)
    assert done["s3_synced_at"] is not None and done["s3_sync_cursor_at"] is None
    assert await worker_module.sync_holds(t.org_id) == 0  # the OFF pass is done: skipped


async def test_on_passes_run_first_and_every_pass_gets_a_share(
    captured: Captured, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M1: the passes share the budget equally (none starves the ones after it), and ON
    passes run before OFF passes whatever the placement order."""
    _, t = await owner_tenant()
    await seed_retention_policy(t)
    held_case, released_case = await seed_case(t, title="Held"), await seed_case(t, title="Old")
    released_objs = await _case_objects(t, released_case)
    _turn_on(released_objs)
    await seed_released_hold(t, 30, investigation_id=released_case)  # placed first (60 d ago)
    held_objs = await _case_objects(t, held_case)
    await seed_hold(t, investigation_id=held_case)

    # A budget of one: only the first pass runs, and it is the ON pass.
    monkeypatch.setattr(worker_module, "SYNC_INSPECT_MAX", 1)
    assert await worker_module.sync_holds(t.org_id) == 1
    assert sum(_held(held_objs)) == 1 and _held(released_objs) == [True] * 3
    # A budget of two: one version each.
    monkeypatch.setattr(worker_module, "SYNC_INSPECT_MAX", 2)
    assert await worker_module.sync_holds(t.org_id) == 2
    assert sum(_held(held_objs)) == 2 and sum(_held(released_objs)) == 2
    await _sync_until_idle(t.org_id)
    assert _held(held_objs) == [True] * 3  # evidence and the report snapshot
    assert _held(released_objs) == [False] * 3


async def test_the_sync_waits_for_the_orgs_advisory_lock(captured: Captured) -> None:
    """L2: a sync takes the org's retention advisory lock for its whole transaction, so two
    syncs (the sweep, a run, a placed hold's message) never interleave."""
    _, t = await owner_tenant()
    await seed_retention_policy(t)
    objs = await _case_objects(t, t.investigation_id)
    await seed_hold(t, investigation_id=t.investigation_id)
    async with tenant_session(t.org_id, None) as holder:
        await holder.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"),
            {"k": f"retention:{t.org_id}"},
        )
        task = asyncio.create_task(worker_module.sync_holds(t.org_id))
        await asyncio.sleep(1.0)
        assert not task.done()  # waiting for the lock
        assert _held(objs) == [False] * 3
    assert await asyncio.wait_for(task, timeout=30) == 3
    assert _held(objs) == [True] * 3
