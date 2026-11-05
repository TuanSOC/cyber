"""Fail jobs whose deadline passed: never started (queue TTL) or ran too long.

Also the threat-intel fallback reaper (`reap_ti_runs`, M4 RT9) and the AI analyst one
(`reap_ai_runs`, M5).
"""

import logging
from datetime import timedelta

from sqlalchemy import func, or_, select

from app.core.tenancy import tenant_session
from app.modules.ai import lifecycle as ai_lifecycle
from app.modules.ai.contracts import RUN_ACTIVE as AI_RUN_ACTIVE
from app.modules.ai.contracts import AiErrorCode, AiRunStatus
from app.modules.ai.models import AiRun, AiRunIndex
from app.modules.analysis import lifecycle
from app.modules.analysis import repository as repo
from app.modules.analysis.models import ACTIVE, AnalysisJobIndex, AnalysisStatus
from app.modules.audit import service as audit
from app.modules.threat_intel.lifecycle import finalize_run
from app.modules.threat_intel.models import RUN_ACTIVE, TiRunIndex

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


# --- Threat intel fallback (M4 RT9) ---------------------------------------------------------
# The enrich worker owns run deadlines; this only finalizes runs it can no longer reach
# (worker down): lease free or expired and the deadline passed more than 10 minutes ago.
TI_GRACE = timedelta(minutes=10)


async def reap_ti_runs() -> int:
    async with tenant_session(None, None) as session:
        stale = (
            await session.execute(
                select(TiRunIndex.run_id, TiRunIndex.organization_id)
                .where(
                    TiRunIndex.status.in_(RUN_ACTIVE),
                    TiRunIndex.deadline_at < func.now() - TI_GRACE,
                    or_(TiRunIndex.lease_until.is_(None), TiRunIndex.lease_until < func.now()),
                )
                .order_by(TiRunIndex.deadline_at)
                .limit(BATCH)
            )
        ).all()

    reaped = 0
    for run_id, org_id in stale:
        # Org taken from the index row (system data). finalize_run locks the run and its index
        # row and is a no-op if the worker finished it meanwhile; it writes no ti_results rows.
        async with tenant_session(org_id, None) as session:
            status = await finalize_run(session, org_id, run_id, abandon_reason="deadline")
            if status is None:
                continue
            audit.record(
                session,
                action="ti.run_deadline",
                org_id=org_id,
                actor_id=None,
                target_type="ti_enrichment_run",
                target_id=run_id,
                details={"status": status, "by": "reaper"},
            )
            reaped += 1
    if reaped:
        log.info("reaped %d stale threat-intel runs", reaped)
    return reaped


# --- AI analyst fallback (M5) ----------------------------------------------------------------
# The analyst worker owns run deadlines; this only finalizes runs it can no longer reach
# (worker down): no live lease and the deadline passed more than 10 minutes ago ->
# `failed / deadline`, audited `ai.run_deadline`. It writes no outputs.
AI_GRACE = timedelta(minutes=10)


async def reap_ai_runs() -> int:
    stale_ai = (
        AiRunIndex.status.in_([s.value for s in AI_RUN_ACTIVE]),
        AiRunIndex.deadline_at < func.now() - AI_GRACE,
        or_(AiRunIndex.lease_until.is_(None), AiRunIndex.lease_until < func.now()),
    )
    async with tenant_session(None, None) as session:
        stale = (
            await session.execute(
                select(AiRunIndex.run_id, AiRunIndex.organization_id)
                .where(*stale_ai)
                .order_by(AiRunIndex.deadline_at)
                .limit(BATCH)
            )
        ).all()

    reaped = 0
    for run_id, org_id in stale:
        # Org taken from the index row (system data). Re-checked under the lock: the worker
        # may have taken a lease or finished the run meanwhile.
        async with tenant_session(org_id, None) as session:
            # Lock order as everywhere else: the run row, then its index row.
            await session.scalar(select(AiRun.id).where(AiRun.id == run_id).with_for_update())
            due = await session.scalar(
                select(AiRunIndex.run_id)
                .where(AiRunIndex.run_id == run_id, *stale_ai)
                .with_for_update()
            )
            if due is None:
                continue
            status = await ai_lifecycle.finalize(
                session, run_id, AiRunStatus.FAILED, AiErrorCode.DEADLINE
            )
            if status is None:
                continue
            audit.record(
                session,
                action="ai.run_deadline",
                org_id=org_id,
                actor_id=None,
                target_type="ai_run",
                target_id=run_id,
                details={"status": status.value, "error_code": "deadline", "by": "reaper"},
            )
            reaped += 1
    if reaped:
        log.info("reaped %d stale ai runs", reaped)
    return reaped


async def reap_report_renders() -> int:
    """M6 (frozen entry point; implemented by phase 4): re-dispatch `queued` renders that
    were never dispatched and fail renders past their deadline with `timeout`. Returns how
    many it handled; 0 until phase 4."""
    return 0
