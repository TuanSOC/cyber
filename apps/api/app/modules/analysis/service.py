"""Analysis job requests (manual and automatic on upload) and reads."""

import hashlib
import logging
import secrets
import uuid
from datetime import timedelta

from cyberlab_jobs.capture import capture_format
from sqlalchemy import func, select
from starlette.requests import HTTPConnection

from app.core import rate_limit
from app.core.config import get_settings
from app.core.deps import CurrentUser
from app.core.errors import AppError, Conflict, NotFound, TooManyRequests
from app.core.pagination import PageParams
from app.core.rbac import OrgContext, Permission, org_session
from app.core.tenancy import tenant_session
from app.modules.analysis import dispatch, lifecycle
from app.modules.analysis import repository as repo
from app.modules.analysis.models import (
    ACTIVE,
    AnalysisJob,
    AnalysisJobIndex,
    AnalysisStatus,
    Analyzer,
)
from app.modules.analysis.schemas import AnalysisJobOut, AnalysisJobPage
from app.modules.audit import service as audit
from app.modules.evidence import service as evidence_service
from app.modules.evidence.models import CustodyAction, EvidenceStatus

log = logging.getLogger(__name__)


class AnalysisActive(Conflict):
    code = "analysis_active"
    message = "An analysis of this evidence is already queued or running"


class AnalysisQueueFull(AppError):
    status_code = 429
    code = "analysis_queue_full"
    message = "Too many analyses are queued or running for this organization"


class CaptureTooLarge(AppError):
    status_code = 413
    code = "capture_too_large"
    message = "Evidence is larger than the analyzer accepts"


def to_out(row: repo.JobRow) -> AnalysisJobOut:
    job = row.job
    return AnalysisJobOut(
        id=job.id,
        evidence_id=job.evidence_id,
        investigation_id=row.investigation_id,
        evidence_filename=row.evidence_filename,
        analyzer=job.analyzer,
        status=job.status,
        error_code=job.error_code,
        auto=job.auto,
        requested_by=job.requested_by,
        requested_by_name=row.requested_by_name,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        summary=job.summary,
    )


async def _global_queue_full() -> bool:
    """All orgs share one analyzer queue; cap it so no org can starve the others for long."""
    async with tenant_session(None, None) as session:
        active = await session.scalar(
            select(func.count()).where(AnalysisJobIndex.status.in_(ACTIVE))
        )
    return int(active or 0) >= get_settings().max_active_analyses_global


async def _create(
    ctx: OrgContext, evidence_id: uuid.UUID, request: HTTPConnection, *, auto: bool, token: str
) -> dispatch.DispatchInput:
    settings = get_settings()
    row = await evidence_service.get_row(ctx, evidence_id, for_update=True)
    evidence = row.evidence
    if evidence.status == EvidenceStatus.ARCHIVED:
        raise Conflict("Archived evidence cannot be analyzed", code="evidence_archived")
    await evidence_service.ensure_open_investigation(ctx, evidence.investigation_id)
    if evidence.size_bytes > settings.pcap_max_bytes:
        raise CaptureTooLarge()

    await repo.lock_org_queue(ctx.session, ctx.org_id)
    active = await ctx.session.execute(
        select(AnalysisJob.id).where(
            AnalysisJob.organization_id == ctx.org_id,
            AnalysisJob.evidence_id == evidence_id,
            AnalysisJob.analyzer == Analyzer.PCAP,
            AnalysisJob.status.in_(ACTIVE),
        )
    )
    if active.first() is not None:
        raise AnalysisActive()
    if await repo.count_active(ctx.session, ctx.org_id) >= settings.max_active_analyses_per_org:
        raise AnalysisQueueFull()

    job = AnalysisJob(
        organization_id=ctx.org_id,
        evidence_id=evidence_id,
        analyzer=Analyzer.PCAP,
        requested_by=ctx.user.id,
        auto=auto,
        ingest_token_sha256=hashlib.sha256(token.encode()).hexdigest(),
    )
    ctx.session.add(job)
    await ctx.session.flush()
    ctx.session.add(
        AnalysisJobIndex(
            job_id=job.id,
            organization_id=ctx.org_id,
            status=AnalysisStatus.QUEUED,
            deadline_at=lifecycle.now() + timedelta(seconds=settings.analysis_queue_ttl_s),
        )
    )
    details = {"job_id": str(job.id), "analyzer": Analyzer.PCAP.value, "auto": auto}
    evidence_service.record_event(
        ctx,
        evidence_id=evidence_id,
        action=CustodyAction.ANALYSIS_REQUESTED,
        audit_action="analysis.requested",
        request=request,
        custody_details=details,
        audit_details=details,
    )
    return dispatch.DispatchInput(
        job_id=job.id,
        organization_id=ctx.org_id,
        evidence_id=evidence_id,
        storage_bucket=evidence.storage_bucket,
        storage_key=evidence.storage_key,
        storage_version_id=evidence.storage_version_id,
        sha256=row.hashes["sha256"],
        size_bytes=evidence.size_bytes,
        ingest_token=token,
    )


async def _mark_enqueue_failed(org_id: uuid.UUID, user: CurrentUser, job_id: uuid.UUID) -> None:
    async with org_session(org_id, user, Permission.EVIDENCE_READ) as ctx:
        job = await repo.get_for_update(ctx.session, org_id, job_id)
        if job and await lifecycle.transition(
            ctx.session,
            job,
            AnalysisStatus.FAILED,
            allowed_from=(AnalysisStatus.QUEUED,),
            error_code="enqueue_failed",
        ):
            audit.record(
                ctx.session,
                action="analysis.failed",
                org_id=org_id,
                actor_id=None,
                target_type="analysis_job",
                target_id=job_id,
                details={"error_code": "enqueue_failed"},
            )


async def request_analysis(
    org_id: uuid.UUID,
    user: CurrentUser,
    evidence_id: uuid.UUID,
    request: HTTPConnection,
    *,
    auto: bool = False,
) -> AnalysisJobOut:
    """Create the job (committed first), then enqueue it. A lost enqueue is a failed job."""
    if await _global_queue_full():
        raise AnalysisQueueFull()
    token = secrets.token_urlsafe(32)
    async with org_session(org_id, user, Permission.EVIDENCE_WRITE) as ctx:
        item = await _create(ctx, evidence_id, request, auto=auto, token=token)
    # The job is committed: nothing below may turn this request into an error.
    try:
        await dispatch.send(item)
    except Exception:
        log.exception("enqueue failed for analysis job %s", item.job_id)
        try:
            await _mark_enqueue_failed(org_id, user, item.job_id)
        except Exception:  # the reaper fails it at its deadline
            log.exception("could not mark analysis job %s as enqueue_failed", item.job_id)
    async with org_session(org_id, user, Permission.EVIDENCE_READ) as ctx:
        return await get_job(ctx, item.job_id)


async def auto_request(
    org_id: uuid.UUID,
    user: CurrentUser,
    evidence_id: uuid.UUID,
    head: bytes,
    request: HTTPConnection,
) -> None:
    """After an upload commits: analyze captures automatically. Never raises."""
    if capture_format(head) is None:
        return
    settings = get_settings()
    try:
        await rate_limit.hit(
            f"analysis:auto:{user.id}", settings.auto_analyses_per_user_per_10min, 600
        )
        await request_analysis(org_id, user, evidence_id, request, auto=True)
    except (AnalysisActive, AnalysisQueueFull, CaptureTooLarge, TooManyRequests) as exc:
        try:
            async with org_session(org_id, user, Permission.EVIDENCE_READ) as ctx:
                audit.record(
                    ctx.session,
                    action="analysis.skipped",
                    org_id=org_id,
                    actor_id=user.id,
                    target_type="evidence",
                    target_id=evidence_id,
                    details={"reason": exc.code},
                    request=request,
                )
        except Exception:
            log.exception("could not audit skipped analysis for evidence %s", evidence_id)
    except Exception:
        log.exception("automatic analysis request failed for evidence %s", evidence_id)


async def get_job(ctx: OrgContext, job_id: uuid.UUID) -> AnalysisJobOut:
    row = await repo.get_row(ctx.session, ctx.org_id, job_id)
    if row is None:
        raise NotFound()
    return to_out(row)


async def list_jobs(
    ctx: OrgContext,
    page: PageParams,
    *,
    evidence_id: uuid.UUID | None = None,
    status: AnalysisStatus | None = None,
) -> AnalysisJobPage:
    if evidence_id is not None:
        await evidence_service.get_row(ctx, evidence_id)  # 404 for foreign/unknown evidence
    rows, total = await repo.list_rows(
        ctx.session, ctx.org_id, page, evidence_id=evidence_id, status=status
    )
    return AnalysisJobPage(items=[to_out(r) for r in rows], total=total)
