import uuid
from dataclasses import dataclass

from sqlalchemy import Select, func, select, text
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pagination import PageParams
from app.modules.analysis.models import (
    ACTIVE,
    HEAVY_ANALYZERS,
    AnalysisJob,
    AnalysisJobIndex,
    AnalysisStatus,
    Analyzer,
    JobProfile,
)
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


def matching_jobs(
    org_id: uuid.UUID,
    *,
    evidence_id: uuid.UUID | None = None,
    status: AnalysisStatus | None = None,
    analyzer: Analyzer | None = None,
    profile: JobProfile | None = None,
    investigation_id: uuid.UUID | None = None,
    latest_per_evidence: bool = False,
) -> Select[uuid.UUID]:
    """Ids of the jobs matching the list filters. `investigation_id` keeps the jobs of that
    case's evidence (index `ix_evidence_investigation_id`, then
    `ix_analysis_jobs_evidence_id_created_at`). `latest_per_evidence` keeps the newest job per
    (evidence, analyzer, profile) among the jobs matching the other filters, so
    `status=succeeded` gives the latest succeeded run of each kind."""
    j = AnalysisJob
    where = [j.organization_id == org_id]
    if evidence_id is not None:
        where.append(j.evidence_id == evidence_id)
    if status is not None:
        where.append(j.status == status)
    if analyzer is not None:
        where.append(j.analyzer == analyzer)
    if profile is not None:
        where.append(j.profile == profile)
    if investigation_id is not None:
        where += [Evidence.investigation_id == investigation_id, Evidence.organization_id == org_id]
    stmt = (
        select(j.id)
        .join(
            Evidence,
            (Evidence.id == j.evidence_id) & (Evidence.organization_id == j.organization_id),
        )
        .where(*where)
    )
    if latest_per_evidence:
        stmt = stmt.ext(distinct_on(j.evidence_id, j.analyzer, j.profile)).order_by(
            j.evidence_id, j.analyzer, j.profile, j.created_at.desc(), j.id.desc()
        )
    return stmt


async def list_rows(
    session: AsyncSession,
    org_id: uuid.UUID,
    page: PageParams,
    *,
    evidence_id: uuid.UUID | None = None,
    status: AnalysisStatus | None = None,
    analyzer: Analyzer | None = None,
    profile: JobProfile | None = None,
    investigation_id: uuid.UUID | None = None,
    latest_per_evidence: bool = False,
) -> tuple[list[JobRow], int]:
    """Newest first; filters as in `matching_jobs`."""
    order = (AnalysisJob.created_at.desc(), AnalysisJob.id.desc())
    if investigation_id is None and not latest_per_evidence:
        where = [AnalysisJob.organization_id == org_id]
        if evidence_id is not None:
            where.append(AnalysisJob.evidence_id == evidence_id)
        if status is not None:
            where.append(AnalysisJob.status == status)
        if analyzer is not None:
            where.append(AnalysisJob.analyzer == analyzer)
        if profile is not None:
            where.append(AnalysisJob.profile == profile)
        count = select(func.count(AnalysisJob.id)).where(*where)
        stmt = _rows_query().where(*where)
    else:
        ids = matching_jobs(
            org_id,
            evidence_id=evidence_id,
            status=status,
            analyzer=analyzer,
            profile=profile,
            investigation_id=investigation_id,
            latest_per_evidence=latest_per_evidence,
        ).subquery()
        count = select(func.count()).select_from(ids)
        stmt = _rows_query().where(
            AnalysisJob.organization_id == org_id, AnalysisJob.id.in_(select(ids.c.id))
        )
    total = (await session.execute(count)).scalar_one()
    stmt = stmt.order_by(*order).limit(page.limit).offset(page.offset)
    rows = (await session.execute(stmt)).all()
    return [JobRow(r[0], r[1], r[2], r[3]) for r in rows], total


async def lock_org_queue(session: AsyncSession, org_id: uuid.UUID) -> None:
    """Serialize job creation per org so the active-job cap cannot be raced past."""
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"analysis-queue:{org_id}"},
    )


async def lock_heavy_analyses(session: AsyncSession) -> None:
    """M10 RT2: serialize heavy (memory / disk / reverse) job creation platform-wide, so the
    `ANALYSIS_HEAVY_MAX_ACTIVE` cap cannot be raced past. Taken after the org lock (one order
    everywhere: no deadlock)."""
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": "analysis-heavy"},
    )


async def count_heavy_active(session: AsyncSession) -> int:
    """Active heavy jobs of every org (the non-tenant job index: no other org's row is read,
    only counted)."""
    stmt = select(func.count()).where(
        AnalysisJobIndex.analyzer.in_(HEAVY_ANALYZERS), AnalysisJobIndex.status.in_(ACTIVE)
    )
    return int((await session.execute(stmt)).scalar_one())


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
