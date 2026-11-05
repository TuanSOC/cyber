"""AI run status changes (`ai/lifecycle.py`) and the ingest-side fallback reaper
(`reaper.reap_ai_runs`), M5 phase 2."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, update

from app.core.tenancy import tenant_session
from app.modules.ai import lifecycle
from app.modules.ai.contracts import AiErrorCode, AiRunStatus
from app.modules.ai.models import AiRun, AiRunIndex
from app.modules.audit.models import AuditLog
from app.workers import reaper
from tests.ai_helpers import seed_ai_run
from tests.integration.seed import Tenant, seed_tenant


async def _state(t: Tenant, run_id: uuid.UUID) -> tuple[AiRun, AiRunIndex]:
    async with tenant_session(t.org_id, t.owner_id) as s:
        run = (await s.execute(select(AiRun).where(AiRun.id == run_id))).scalar_one()
        index = (
            await s.execute(select(AiRunIndex).where(AiRunIndex.run_id == run_id))
        ).scalar_one()
        return run, index


async def test_finalize_queued_to_failed_directly() -> None:
    t = await seed_tenant("alpha")
    run_id = await seed_ai_run(t)
    async with tenant_session(t.org_id, None) as s:
        await s.execute(
            update(AiRunIndex)
            .where(AiRunIndex.run_id == run_id)
            .values(lease_until=func.now() + timedelta(seconds=60), lease_owner="x")
        )
    async with tenant_session(t.org_id, None) as s:
        status = await lifecycle.finalize(s, run_id, AiRunStatus.FAILED, AiErrorCode.DEADLINE)
    assert status is AiRunStatus.FAILED
    run, index = await _state(t, run_id)
    assert (run.status, run.error_code) == ("failed", "deadline")
    assert run.finished_at is not None and run.started_at is not None
    assert (index.status, index.lease_until, index.lease_owner, index.resume_at) == (
        "failed",
        None,
        None,
        None,
    )
    # Final runs are left alone (worker after reaper, redelivery).
    async with tenant_session(t.org_id, None) as s:
        assert await lifecycle.finalize(s, run_id, AiRunStatus.COMPLETED) is None


@pytest.mark.parametrize("start", ["queued", "waiting"])
@pytest.mark.parametrize("final", ["completed", "partial", "refused"])
async def test_finalize_passes_through_running(start: str, final: str) -> None:
    t = await seed_tenant("alpha")
    run_id = await seed_ai_run(t)
    if start == "waiting":
        async with tenant_session(t.org_id, None) as s:
            await lifecycle.mark_running(s, run_id)
        async with tenant_session(t.org_id, None) as s:
            await lifecycle.set_waiting(s, run_id, resume_in_s=5)
    code = AiErrorCode.REFUSED if final == "refused" else None
    async with tenant_session(t.org_id, None) as s:
        values = {"usage": {"input_tokens": 3}, "metrics": {"version": "v1"}, "cost_micros": 0}
        assert await lifecycle.finalize(s, run_id, AiRunStatus(final), code, values=values)
    run, index = await _state(t, run_id)
    assert (run.status, index.status) == (final, final)
    assert run.usage == {"input_tokens": 3}
    assert run.cost_micros == 0


async def test_finalize_refuses_non_final_statuses_and_unknown_columns() -> None:
    t = await seed_tenant("alpha")
    run_id = await seed_ai_run(t)
    async with tenant_session(t.org_id, None) as s:
        with pytest.raises(ValueError):
            await lifecycle.finalize(s, run_id, AiRunStatus.WAITING)
    async with tenant_session(t.org_id, None) as s:
        with pytest.raises(ValueError):
            await lifecycle.finalize(
                s, run_id, AiRunStatus.FAILED, values={"deadline_at": datetime.now(UTC)}
            )
    async with tenant_session(t.org_id, None) as s:
        assert await lifecycle.finalize(s, uuid.uuid4(), AiRunStatus.FAILED) is None


async def test_mark_running_and_waiting_within_the_deadline() -> None:
    t = await seed_tenant("alpha")
    run_id = await seed_ai_run(t, deadline_s=600)
    async with tenant_session(t.org_id, None) as s:
        assert await lifecycle.set_waiting(s, run_id, resume_in_s=5) is None  # not running
    async with tenant_session(t.org_id, None) as s:
        assert await lifecycle.mark_running(s, run_id) is not None
    first, _ = await _state(t, run_id)
    async with tenant_session(t.org_id, None) as s:
        resume_at = await lifecycle.set_waiting(
            s, run_id, resume_in_s=10_000, attempts=2, values={"metrics": {"repaired": True}}
        )
    run, index = await _state(t, run_id)
    assert resume_at == run.deadline_at  # never past the deadline
    assert (run.status, index.status, index.resume_at, index.attempts) == (
        "waiting",
        "waiting",
        run.deadline_at,
        2,
    )
    assert run.metrics == {"repaired": True}
    async with tenant_session(t.org_id, None) as s:
        await lifecycle.mark_running(s, run_id)
    again, index = await _state(t, run_id)
    assert again.status == "running" and index.resume_at is None
    assert again.started_at == first.started_at  # set once


# --- the fallback reaper ----------------------------------------------------------------------


async def _lease(t: Tenant, run_id: uuid.UUID) -> None:
    async with tenant_session(t.org_id, None) as s:
        await s.execute(
            update(AiRunIndex)
            .where(AiRunIndex.run_id == run_id)
            .values(lease_until=func.now() + timedelta(seconds=60), lease_owner="worker")
        )


async def test_reaper_fails_runs_long_past_their_deadline_without_a_lease() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    stale = await seed_ai_run(a, deadline_s=-700)  # 11+ minutes past
    other_org = await seed_ai_run(b, deadline_s=-3600)
    leased = await seed_ai_run(a, deadline_s=-700)
    await _lease(a, leased)
    recent = await seed_ai_run(a, deadline_s=-300)  # within the 10-minute grace
    alive = await seed_ai_run(a)
    assert await reaper.reap_ai_runs() == 2
    for t, run_id in ((a, stale), (b, other_org)):
        run, index = await _state(t, run_id)
        assert (run.status, run.error_code, index.status) == ("failed", "deadline", "failed")
    for run_id in (leased, recent, alive):
        run, _ = await _state(a, run_id)
        assert run.status == "queued"
    async with tenant_session(a.org_id, a.owner_id) as s:
        rows = (await s.scalars(select(AuditLog).where(AuditLog.action == "ai.run_deadline"))).all()
    assert [(r.target_id, r.actor_id, r.details["by"]) for r in rows] == [(stale, None, "reaper")]
    assert await reaper.reap_ai_runs() == 0


async def test_only_the_lease_holder_may_park_or_end_the_run() -> None:
    t = await seed_tenant("alpha")
    run_id = await seed_ai_run(t)
    async with tenant_session(t.org_id, None) as s:
        await lifecycle.mark_running(s, run_id)
    await _lease(t, run_id)  # held by "worker"
    async with tenant_session(t.org_id, None) as s:
        assert await lifecycle.set_waiting(s, run_id, resume_in_s=5, lease_owner="lost") is None
        assert await lifecycle.finalize(s, run_id, AiRunStatus.FAILED, lease_owner="lost") is None
    run, index = await _state(t, run_id)
    assert (run.status, index.lease_owner) == ("running", "worker")
    async with tenant_session(t.org_id, None) as s:
        assert await lifecycle.set_waiting(s, run_id, resume_in_s=5, lease_owner="worker")
    run, index = await _state(t, run_id)
    assert (run.status, index.lease_owner, index.lease_until) == ("waiting", None, None)
