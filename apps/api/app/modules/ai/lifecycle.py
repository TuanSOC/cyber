"""AI run status changes, shared by the analyst worker and the ingest-side fallback reaper (M5).

It imports nothing that can reach a provider or open a key, so the ingest worker may use it.
The caller opens the tenant session of the run's org (org taken from `ai_run_index`) and
keeps it short (RT7). Every change locks the run and its index row (`FOR UPDATE`) and keeps
the two statuses in step. The `ai_run_transition` trigger allows queued -> running | failed,
running -> waiting | completed | partial | failed | refused, waiting -> running | failed:
`finalize` passes through `running` when a final status needs it.
"""

import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.ai.contracts import RUN_FINAL, AiErrorCode, AiRunStatus
from app.modules.ai.models import AiRun, AiRunIndex

# `ai_runs` columns the worker may write besides status / error_code / timestamps.
RUN_VALUES = frozenset({"served_model", "usage", "cost_micros", "price_version", "metrics"})


def _apply(run: AiRun, values: Mapping[str, Any] | None) -> None:
    for name, value in (values or {}).items():
        if name not in RUN_VALUES:
            raise ValueError(f"ai_runs.{name} is not writable by the worker")
        setattr(run, name, value)


async def _lock(session: AsyncSession, run_id: uuid.UUID) -> tuple[AiRun, AiRunIndex | None] | None:
    run = await session.scalar(select(AiRun).where(AiRun.id == run_id).with_for_update())
    if run is None:
        return None
    index = await session.get(AiRunIndex, run_id, with_for_update=True)
    return run, index


async def mark_running(session: AsyncSession, run_id: uuid.UUID) -> AiRun | None:
    """queued / waiting -> running (sets `started_at` once). None when missing or final."""
    locked = await _lock(session, run_id)
    if locked is None:
        return None
    run, index = locked
    if run.status in RUN_FINAL:
        return None
    if run.status != AiRunStatus.RUNNING:
        run.status = AiRunStatus.RUNNING
    if run.started_at is None:
        run.started_at = datetime.now(UTC)
    if index is not None:
        index.status = AiRunStatus.RUNNING
        index.resume_at = None
    await session.flush()
    return run


async def set_waiting(
    session: AsyncSession,
    run_id: uuid.UUID,
    *,
    resume_in_s: float,
    values: Mapping[str, Any] | None = None,
    attempts: int | None = None,
    lease_owner: str | None = None,
) -> datetime | None:
    """running -> waiting with `resume_at = least(now() + resume_in_s, deadline)` (DB clock).

    With `lease_owner`, only the holder of that lease may park the run (a worker that lost
    its lease never touches a run another worker is calling for), and the lease is released
    in the same transaction. Returns `resume_at`, or None when the run is missing, final, not
    running or leased by someone else."""
    locked = await _lock(session, run_id)
    if locked is None:
        return None
    run, index = locked
    if run.status != AiRunStatus.RUNNING:
        return None
    if lease_owner is not None and (index is None or index.lease_owner != lease_owner):
        return None
    db_now: datetime = (await session.execute(select(func.now()))).scalar_one()
    resume_at = min(db_now + timedelta(seconds=max(0.0, resume_in_s)), run.deadline_at)
    _apply(run, values)
    run.status = AiRunStatus.WAITING
    if index is not None:
        index.status = AiRunStatus.WAITING
        index.resume_at = min(resume_at, index.deadline_at)
        if attempts is not None:
            index.attempts = attempts
        if lease_owner is not None:
            index.lease_until = None
            index.lease_owner = None
    await session.flush()
    return resume_at


async def finalize(
    session: AsyncSession,
    run_id: uuid.UUID,
    status: AiRunStatus,
    error_code: AiErrorCode | None = None,
    *,
    values: Mapping[str, Any] | None = None,
    lease_owner: str | None = None,
) -> AiRunStatus | None:
    """End the run under `FOR UPDATE` on the run and its index row. Returns the final status,
    or None when the run is missing or already final (worker after reaper, redelivery).

    The worker passes its `lease_owner` token: then only the lease holder may end the run.
    The reaper passes none (it checks itself that no live lease exists)."""
    if status not in RUN_FINAL:
        raise ValueError(f"{status} is not a final status")
    locked = await _lock(session, run_id)
    if locked is None:
        return None
    run, index = locked
    if run.status in RUN_FINAL:
        return None
    if lease_owner is not None and (index is None or index.lease_owner != lease_owner):
        return None
    now = datetime.now(UTC)
    # queued / waiting -> failed is a direct edge; any other final status passes running.
    if status != AiRunStatus.FAILED and run.status != AiRunStatus.RUNNING:
        run.status = AiRunStatus.RUNNING
        await session.flush()
    _apply(run, values)
    run.status = status
    run.error_code = error_code.value if error_code is not None else None
    run.finished_at = now
    if run.started_at is None:
        run.started_at = now
    if index is not None:
        index.status = status
        index.resume_at = None
        index.lease_until = None
        index.lease_owner = None
    await session.flush()
    return status


__all__ = ["RUN_VALUES", "finalize", "mark_running", "set_waiting"]
