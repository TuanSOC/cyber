"""Which AI outputs and report versions cite this row (frozen entry point of M6 phase 1;
implemented by phase 3): `ai_citations` (verified only, the M5 index on (org, kind, ref_id))
and `report_citations` (the 0012 index on the same columns).

AI outputs withheld for a canary leak are never listed. A flow is keyed by (job, flow_ref)
(RT16): the route passes `job_id` through `cited_by_job`."""

import uuid
from typing import cast

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.ai.contracts import CitationStatus, OutputFlag
from app.modules.ai.models import AiCitation, AiOutput, AiRun
from app.modules.reports.models import Report, ReportCitation, ReportVersion
from app.modules.reports.schemas import (
    CitedByOut,
    CitedKind,
    CitingAiOutput,
    CitingReportVersion,
)

MAX_ITEMS = 200


async def cited_by(session: AsyncSession, org_id: uuid.UUID, kind: str, ref_id: str) -> CitedByOut:
    return await cited_by_job(session, org_id, kind, ref_id, None)


async def cited_by_job(
    session: AsyncSession,
    org_id: uuid.UUID,
    kind: str,
    ref_id: str,
    job_id: uuid.UUID | None,
) -> CitedByOut:
    c = AiCitation
    ai_where = [
        c.organization_id == org_id,
        c.kind == kind,
        c.ref_id == ref_id,
        c.status == CitationStatus.VERIFIED.value,
    ]
    if job_id is not None:
        ai_where.append(c.job_id == job_id)
    claims = func.count(func.distinct(func.coalesce(c.claim_id, c.claim_path)))
    ai_rows = await session.execute(
        select(AiRun.id, AiRun.task, AiRun.created_at, claims)
        .join(c, (c.run_id == AiRun.id) & (c.organization_id == AiRun.organization_id))
        .join(AiOutput, (AiOutput.id == c.output_id) & (AiOutput.organization_id == org_id))
        .where(
            *ai_where,
            AiRun.organization_id == org_id,
            AiRun.error_code.is_distinct_from("canary_leak"),
            ~AiOutput.flags.contains([OutputFlag.CANARY_LEAK.value]),
        )
        .group_by(AiRun.id, AiRun.task, AiRun.created_at)
        .order_by(AiRun.created_at.desc(), AiRun.id)
        .limit(MAX_ITEMS)
    )
    ai_outputs = [
        CitingAiOutput(run_id=rid, task=task, claims=int(n), created_at=created)
        for rid, task, created, n in ai_rows.all()
    ]

    rc, rv = ReportCitation, ReportVersion
    report_where = [rc.organization_id == org_id, rc.kind == kind, rc.ref_id == ref_id]
    if job_id is not None:
        report_where.append(rc.job_id == job_id)
    nos = func.array_agg(func.distinct(rc.cite_no))
    report_rows = await session.execute(
        select(rv.report_id, rv.version, Report.title, rv.finalized_at, nos)
        .join(rv, (rv.id == rc.version_id) & (rv.organization_id == rc.organization_id))
        .join(Report, (Report.id == rv.report_id) & (Report.organization_id == rv.organization_id))
        .where(*report_where)
        .group_by(rv.report_id, rv.version, Report.title, rv.finalized_at)
        .order_by(rv.finalized_at.desc(), rv.report_id, rv.version.desc())
        .limit(MAX_ITEMS)
    )
    versions = [
        CitingReportVersion(
            report_id=report_id,
            version=version,
            title=report_title,
            cite_nos=sorted(int(n) for n in (numbers or [])),
            finalized_at=at,
        )
        for report_id, version, report_title, at, numbers in report_rows.all()
    ]
    return CitedByOut(
        kind=cast(CitedKind, kind), ref_id=ref_id, ai_outputs=ai_outputs, report_versions=versions
    )
