"""Job status transitions, shared by the API, the ingest worker and the reaper.

The job row and its non-tenant index row always change in the same transaction. A
transition only applies from the listed states, so late or duplicated messages (broker
redelivery, a message arriving after the reaper gave up) can never reopen a final job.
"""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.analysis.models import (
    TERMINAL,
    AnalysisJob,
    AnalysisJobIndex,
    AnalysisStatus,
)


def now() -> datetime:
    return datetime.now(UTC)


async def transition(
    session: AsyncSession,
    job: AnalysisJob,
    to: AnalysisStatus,
    *,
    allowed_from: tuple[AnalysisStatus, ...],
    error_code: str | None = None,
    deadline_at: datetime | None = None,
) -> bool:
    """Apply `job.status -> to` if allowed; returns False (and changes nothing) otherwise.

    `job` must have been loaded FOR UPDATE in this session.
    """
    if job.status not in allowed_from:
        return False
    if (to == AnalysisStatus.FAILED) != (error_code is not None):
        raise ValueError("error_code is required for (and only for) failed jobs")
    # Load the index row before touching the job: the query autoflushes, and the job must
    # reach its new state in a single UPDATE (the DB refuses any write to a final job, so
    # callers set their extra columns after this returns, flushed together with it).
    index = (
        await session.execute(
            select(AnalysisJobIndex).where(AnalysisJobIndex.job_id == job.id).with_for_update()
        )
    ).scalar_one()
    job.status = to
    job.error_code = error_code
    if to == AnalysisStatus.RUNNING:
        job.started_at = now()
    if to in TERMINAL:
        job.finished_at = now()
    index.status = to
    if deadline_at is not None:
        index.deadline_at = deadline_at
    return True
