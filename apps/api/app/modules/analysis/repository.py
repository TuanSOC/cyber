import uuid
from dataclasses import dataclass

from cyberlab_jobs.static import Profile
from sqlalchemy import Select, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pagination import PageParams
from app.modules.analysis.models import ACTIVE, AnalysisJob, AnalysisStatus, Analyzer
from app.modules.evidence.models import Evidence
from app.modules.users.models import User


@dataclass(frozen=True)
class JobRow:
    job: AnalysisJob
    investigation_id: uuid.UUID
    evidence_filename: str
    requested_by_name: str


def _rows_query() -> Select[AnalysisJob, uuid.UUID, str, str]:
    return (
        select(
            AnalysisJob, Evidence.investigation_id, Evidence.original_filename, User.display_name
        )
        .join(
            Evidence,
            (Evidence.id == AnalysisJob.evidence_id)
            & (Evidence.organization_id == AnalysisJob.organization_id),
        )
        .join(User, User.id == AnalysisJob.requested_by)
    )


async def get_row(session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID) -> JobRow | None:
    stmt = _rows_query().where(AnalysisJob.id == job_id, AnalysisJob.organization_id == org_id)
    row = (await session.execute(stmt)).one_or_none()
    return JobRow(row[0], row[1], row[2], row[3]) if row else None


async def list_rows(
    session: AsyncSession,
    org_id: uuid.UUID,
    page: PageParams,
    *,
    evidence_id: uuid.UUID | None = None,
    status: AnalysisStatus | None = None,
    analyzer: Analyzer | None = None,
    profile: Profile | None = None,
) -> tuple[list[JobRow], int]:
    where = [AnalysisJob.organization_id == org_id]
    if evidence_id is not None:
        where.append(AnalysisJob.evidence_id == evidence_id)
    if status is not None:
        where.append(AnalysisJob.status == status)
    if analyzer is not None:
        where.append(AnalysisJob.analyzer == analyzer)
    if profile is not None:
        where.append(AnalysisJob.profile == profile)
    total = (await session.execute(select(func.count(AnalysisJob.id)).where(*where))).scalar_one()
    stmt = (
        _rows_query()
        .where(*where)
        .order_by(AnalysisJob.created_at.desc(), AnalysisJob.id.desc())
        .limit(page.limit)
        .offset(page.offset)
    )
    rows = (await session.execute(stmt)).all()
    return [JobRow(r[0], r[1], r[2], r[3]) for r in rows], total


async def lock_org_queue(session: AsyncSession, org_id: uuid.UUID) -> None:
    """Serialize job creation per org so the active-job cap cannot be raced past."""
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"analysis-queue:{org_id}"},
    )


async def count_active(session: AsyncSession, org_id: uuid.UUID, analyzer: Analyzer) -> int:
    """Active jobs of one analyzer in one org (each analyzer has its own queue and cap)."""
    stmt = select(func.count(AnalysisJob.id)).where(
        AnalysisJob.organization_id == org_id,
        AnalysisJob.analyzer == analyzer,
        AnalysisJob.status.in_(ACTIVE),
    )
    return (await session.execute(stmt)).scalar_one()


async def get_for_update(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID
) -> AnalysisJob | None:
    stmt = (
        select(AnalysisJob)
        .where(AnalysisJob.id == job_id, AnalysisJob.organization_id == org_id)
        .with_for_update()
    )
    return (await session.execute(stmt)).scalar_one_or_none()
