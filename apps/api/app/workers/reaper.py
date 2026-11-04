"""Fail jobs whose deadline passed: never started (queue TTL) or ran too long."""

import logging

from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.analysis import lifecycle
from app.modules.analysis import repository as repo
from app.modules.analysis.models import ACTIVE, AnalysisJobIndex, AnalysisStatus
from app.modules.audit import service as audit

log = logging.getLogger(__name__)

BATCH = 100
CODES = {AnalysisStatus.QUEUED: "never_started", AnalysisStatus.RUNNING: "timed_out"}


async def reap() -> int:
    async with tenant_session(None, None) as session:
        stale = (
            await session.execute(
                select(AnalysisJobIndex.job_id, AnalysisJobIndex.organization_id)
                .where(
                    AnalysisJobIndex.status.in_(ACTIVE),
                    AnalysisJobIndex.deadline_at < lifecycle.now(),
                )
                .order_by(AnalysisJobIndex.deadline_at)
                .limit(BATCH)
            )
        ).all()

    reaped = 0
    for job_id, org_id in stale:
        # Org taken from the index row (system data), not from any request or message.
        async with tenant_session(org_id, None) as session:
            job = await repo.get_for_update(session, org_id, job_id)
            index = await session.get(AnalysisJobIndex, job_id, with_for_update=True)
            # Re-check under the lock: a `started` report may have moved the deadline since.
            if (
                job is None
                or index is None
                or job.status not in CODES
                or index.deadline_at >= lifecycle.now()
            ):
                continue
            code = CODES[job.status]
            if await lifecycle.transition(
                session, job, AnalysisStatus.FAILED, allowed_from=ACTIVE, error_code=code
            ):
                audit.record(
                    session,
                    action="analysis.failed",
                    org_id=org_id,
                    actor_id=None,
                    target_type="analysis_job",
                    target_id=job_id,
                    details={"evidence_id": str(job.evidence_id), "error_code": code},
                )
                reaped += 1
    if reaped:
        log.info("reaped %d stale analysis jobs", reaped)
    return reaped
