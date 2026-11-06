"""Analysis job requests (manual and automatic on upload) and reads."""

import hashlib
import logging
import secrets
import uuid
from datetime import timedelta

from cyberlab_jobs.capture import capture_format, executable_format
from cyberlab_jobs.memory import OsHint
from sqlalchemy import func, select
from starlette.requests import HTTPConnection

from app.core import rate_limit
from app.core.config import Settings, get_settings
from app.core.deps import CurrentUser
from app.core.errors import AppError, Conflict, NotFound, TooManyRequests
from app.core.pagination import PageParams
from app.core.rbac import OrgContext, Permission, org_session
from app.core.stubs import not_implemented
from app.core.tenancy import tenant_session
from app.modules.analysis import analyzers, dispatch, lifecycle
from app.modules.analysis import repository as repo
from app.modules.analysis.models import (
    ACTIVE,
    PROFILES,
    AnalysisJob,
    AnalysisJobIndex,
    AnalysisStatus,
    Analyzer,
    JobProfile,
)
from app.modules.analysis.schemas import AnalysisJobOut, AnalysisJobPage
from app.modules.audit import service as audit
from app.modules.evidence import service as evidence_service
from app.modules.evidence.models import CustodyAction, EvidenceStatus
from app.modules.disk_forensics.errors import DiskImageTooLarge
from app.modules.memory_analysis import sensitivity as memory_sensitivity
from app.modules.memory_analysis.errors import MemoryImageEmpty, MemoryImageTooLarge

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


class SampleTooLarge(AppError):
    status_code = 413
    code = "sample_too_large"
    message = "Evidence is larger than the static analyzer accepts"


TOO_LARGE: dict[Analyzer, type[AppError]] = {
    Analyzer.PCAP: CaptureTooLarge,
    Analyzer.STATIC: SampleTooLarge,
    Analyzer.MEMORY: MemoryImageTooLarge,
    Analyzer.DISK: DiskImageTooLarge,
}
# Automatic runs only (never memory: a memory run is always an explicit request, M8).
SKIPPABLE = (AnalysisActive, AnalysisQueueFull, CaptureTooLarge, SampleTooLarge, TooManyRequests)


def _active_caps(settings: Settings, analyzer: Analyzer) -> tuple[int, int]:
    """(per org, global) active jobs of one analyzer (M8: memory has its own, lower caps)."""
    if analyzer == Analyzer.MEMORY:
        return settings.memory_max_active_per_org, settings.memory_max_active_total
    if analyzer == Analyzer.DISK:
        return settings.disk_max_active_per_org, settings.disk_max_active_total
    return settings.max_active_analyses_per_org, settings.max_active_analyses_global


def to_out(row: repo.JobRow) -> AnalysisJobOut:
    job = row.job
    return AnalysisJobOut(
        id=job.id,
        evidence_id=job.evidence_id,
        investigation_id=row.investigation_id,
        evidence_filename=row.evidence_filename,
        analyzer=job.analyzer,
        profile=job.profile,
        os_hint=job.os_hint,
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


async def _global_queue_full(analyzer: Analyzer) -> bool:
    """All orgs share each analyzer's queue; cap it so no org can starve the others for long."""
    async with tenant_session(None, None) as session:
        active = await session.scalar(
            select(func.count()).where(
                AnalysisJobIndex.analyzer == analyzer, AnalysisJobIndex.status.in_(ACTIVE)
            )
        )
    return int(active or 0) >= _active_caps(get_settings(), analyzer)[1]


async def _create(
    ctx: OrgContext,
    evidence_id: uuid.UUID,
    request: HTTPConnection,
    *,
    analyzer: Analyzer,
    profile: JobProfile | None,
    os_hint: OsHint | None,
    auto: bool,
    token: str,
) -> dispatch.DispatchInput:
    settings = get_settings()
    row = await evidence_service.get_row(ctx, evidence_id, for_update=True)
    evidence = row.evidence
    evidence_service.ensure_not_purged(row)  # M7: 410 evidence_purged
    if evidence.status == EvidenceStatus.ARCHIVED:
        raise Conflict("Archived evidence cannot be analyzed", code="evidence_archived")
    await evidence_service.ensure_open_investigation(ctx, evidence.investigation_id)
    if evidence.size_bytes > analyzers.max_bytes(settings, analyzer):
        raise TOO_LARGE[analyzer]()
    if analyzer == Analyzer.MEMORY and evidence.size_bytes == 0:
        raise MemoryImageEmpty()

    await repo.lock_org_queue(ctx.session, ctx.org_id)
    active = await ctx.session.execute(
        select(AnalysisJob.id).where(
            AnalysisJob.organization_id == ctx.org_id,
            AnalysisJob.evidence_id == evidence_id,
            AnalysisJob.analyzer == analyzer,
            AnalysisJob.status.in_(ACTIVE),
        )
    )
    if active.first() is not None:
        raise AnalysisActive()
    active_count = await repo.count_active(ctx.session, ctx.org_id, analyzer)
    if active_count >= _active_caps(settings, analyzer)[0]:
        raise AnalysisQueueFull()

    job = AnalysisJob(
        organization_id=ctx.org_id,
        evidence_id=evidence_id,
        analyzer=analyzer,
        profile=profile,
        os_hint=os_hint,
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
            analyzer=analyzer,
            status=AnalysisStatus.QUEUED,
            deadline_at=lifecycle.now() + timedelta(seconds=settings.analysis_queue_ttl_s),
        )
    )
    details: dict[str, object] = {"job_id": str(job.id), "analyzer": analyzer.value, "auto": auto}
    if profile is not None:
        details["profile"] = profile.value
    if os_hint is not None:
        details["os_hint"] = os_hint.value
    if analyzer == Analyzer.MEMORY:
        # TLP:RED by default (RT3), in this transaction; idempotent (phase-8 entry point).
        await memory_sensitivity.apply_memory_default(
            ctx.session, ctx.org_id, evidence_id, ctx.user.id
        )
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
        analyzer=analyzer,
        profile=profile,
        os_hint=os_hint,
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
    analyzer: Analyzer = Analyzer.PCAP,
    profile: JobProfile | None = None,
    os_hint: OsHint | None = None,
    auto: bool = False,
    segments: list[uuid.UUID] | None = None,
) -> AnalysisJobOut:
    """Create the job (committed first), then enqueue it. A lost enqueue is a failed job.

    `segments` (disk only, M9): the ordered segment set (phase 7 validates and stores it)."""
    allowed = PROFILES[analyzer]
    if (profile is None) != (not allowed) or (profile is not None and profile not in allowed):
        raise ValueError(f"{analyzer} jobs take a profile of {sorted(allowed)}")
    if (os_hint is not None) != (analyzer in (Analyzer.MEMORY, Analyzer.DISK)):
        raise ValueError("memory and disk jobs need an os_hint; other analyzers take none")
    if analyzer in (Analyzer.MEMORY, Analyzer.DISK) and auto:
        raise ValueError("memory and disk analysis is never automatic")
    if (segments is not None) != (analyzer == Analyzer.DISK):
        raise ValueError("disk jobs name their segments; other analyzers take none")
    if analyzer == Analyzer.DISK:
        # M9 phase 1: the request is accepted by schema; the segment set, the sensitivity
        # default of every segment and the dispatch land with phase 7 (`disk_forensics.
        # segments` / `dispatch`). Until then nothing is created.
        raise not_implemented()
    if await _global_queue_full(analyzer):
        raise AnalysisQueueFull()
    token = secrets.token_urlsafe(32)
    async with org_session(org_id, user, Permission.EVIDENCE_WRITE) as ctx:
        item = await _create(
            ctx,
            evidence_id,
            request,
            analyzer=analyzer,
            profile=profile,
            os_hint=os_hint,
            auto=auto,
            token=token,
        )
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


def auto_choice(
    head: bytes, size: int, settings: Settings
) -> tuple[Analyzer, JobProfile | None] | None:
    """Which analysis an upload gets automatically (from its first bytes), if any.

    - pcap / pcapng magic: the pcap analyzer (an oversized capture is refused and audited);
    - PE (in-bounds PE header) or non-core ELF: static `full` (oversized: refused, audited);
    - any other non-empty file within the static size cap: static `av` (ClamAV + YARA).
    Empty files and other files over the cap get nothing. Never memory (M8: a memory run is
    always an explicit request), and a `kind=memory` upload gets no automatic run at all
    (RT3: the upload route skips `auto_request`).
    """
    if capture_format(head) is not None:
        return Analyzer.PCAP, None
    if executable_format(head) is not None:
        return Analyzer.STATIC, JobProfile.FULL
    if 0 < size <= settings.static_max_bytes:
        return Analyzer.STATIC, JobProfile.AV
    return None


async def auto_request(
    org_id: uuid.UUID,
    user: CurrentUser,
    evidence_id: uuid.UUID,
    head: bytes,
    size: int,
    request: HTTPConnection,
) -> None:
    """After an upload commits: analyze it automatically when it qualifies. Never raises."""
    settings = get_settings()
    choice = auto_choice(head, size, settings)
    if choice is None:
        return
    analyzer, profile = choice
    try:
        await rate_limit.hit(
            f"analysis:auto:{user.id}", settings.auto_analyses_per_user_per_10min, 600
        )
        await request_analysis(
            org_id, user, evidence_id, request, analyzer=analyzer, profile=profile, auto=True
        )
    except SKIPPABLE as exc:
        try:
            async with org_session(org_id, user, Permission.EVIDENCE_READ) as ctx:
                audit.record(
                    ctx.session,
                    action="analysis.skipped",
                    org_id=org_id,
                    actor_id=user.id,
                    target_type="evidence",
                    target_id=evidence_id,
                    details={"reason": exc.code, "analyzer": analyzer.value},
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
    analyzer: Analyzer | None = None,
    profile: JobProfile | None = None,
) -> AnalysisJobPage:
    if evidence_id is not None:
        await evidence_service.get_row(ctx, evidence_id)  # 404 for foreign/unknown evidence
    rows, total = await repo.list_rows(
        ctx.session,
        ctx.org_id,
        page,
        evidence_id=evidence_id,
        status=status,
        analyzer=analyzer,
        profile=profile,
    )
    return AnalysisJobPage(items=[to_out(r) for r in rows], total=total)
