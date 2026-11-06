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
from app.core.tenancy import tenant_session
from app.modules.analysis import analyzers, dispatch, lifecycle
from app.modules.analysis import repository as repo
from app.modules.analysis.models import (
    ACTIVE,
    HEAVY_ANALYZERS,
    PROFILES,
    REQUESTABLE_PROFILES,
    AnalysisJob,
    AnalysisJobIndex,
    AnalysisStatus,
    Analyzer,
    JobProfile,
)
from app.modules.analysis.schemas import AnalysisJobOut, AnalysisJobPage
from app.modules.audit import service as audit
from app.modules.disk_forensics import segments as disk_segments
from app.modules.disk_forensics.errors import DiskImageTooLarge
from app.modules.disk_forensics.models import AnalysisJobSegment
from app.modules.evidence import sensitivity as evidence_sensitivity
from app.modules.evidence import service as evidence_service
from app.modules.evidence.models import CustodyAction, EvidenceCustodyEvent, EvidenceStatus
from app.modules.memory_analysis import sensitivity as memory_sensitivity
from app.modules.memory_analysis.errors import MemoryImageEmpty, MemoryImageTooLarge
from app.modules.reverse_engineering import dispatch as re_dispatch
from app.modules.reverse_engineering.errors import (
    HeavyAnalysisBusy,
    ProfileUnavailable,
    ReSampleTooLarge,
)

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
    Analyzer.REVERSE: ReSampleTooLarge,
}
# Automatic runs only (never memory: a memory run is always an explicit request, M8).
SKIPPABLE = (AnalysisActive, AnalysisQueueFull, CaptureTooLarge, SampleTooLarge, TooManyRequests)


def _active_caps(settings: Settings, analyzer: Analyzer) -> tuple[int, int]:
    """(per org, global) active jobs of one analyzer (M8: memory has its own, lower caps)."""
    if analyzer == Analyzer.MEMORY:
        return settings.memory_max_active_per_org, settings.memory_max_active_total
    if analyzer == Analyzer.DISK:
        return settings.disk_max_active_per_org, settings.disk_max_active_total
    if analyzer == Analyzer.REVERSE:
        return settings.re_max_active_per_org, settings.analysis_heavy_max_active
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
        source_job_id=job.source_job_id,
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
    segments: list[uuid.UUID] | None = None,
    source_job_id: uuid.UUID | None = None,
    decompile_addresses: tuple[int, ...] = (),
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
    disk_set: list[disk_segments.Segment] = []
    if analyzer == Analyzer.DISK:
        # M9 phase 7: every segment is active evidence of this case and the set fits.
        disk_set = await disk_segments.load(
            ctx.session, ctx.org_id, evidence.investigation_id, segments or [], settings
        )

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
    if analyzer in HEAVY_ANALYZERS:
        # M10 RT2: one heavy analysis (memory, disk or reverse) at a time platform-wide by
        # default; the refusal never names the other job (it may be another org's).
        await repo.lock_heavy_analyses(ctx.session)
        if await repo.count_heavy_active(ctx.session) >= settings.analysis_heavy_max_active:
            raise HeavyAnalysisBusy()
    re_source: re_dispatch.ReSource | None = None
    if analyzer == Analyzer.REVERSE:
        # M10 phase 7: the succeeded static `full` source job (409 static_analysis_required),
        # the architecture check, the capa file VAs. Phase 1: 501 before anything is created.
        assert profile is not None  # noqa: S101 - request_analysis checked it
        re_source = await re_dispatch.load_source(
            ctx.session,
            ctx.org_id,
            evidence_id,
            source_job_id=source_job_id,
            profile=profile,
            decompile_addresses=decompile_addresses,
            settings=settings,
        )

    job = AnalysisJob(
        organization_id=ctx.org_id,
        evidence_id=evidence_id,
        analyzer=analyzer,
        profile=profile,
        os_hint=os_hint,
        source_job_id=re_source.job_id if re_source is not None else None,
        re_params=(
            {"decompile_addresses": [str(a) for a in decompile_addresses]}
            if re_source is not None
            else None
        ),
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
    if re_source is not None:
        details["source_job_id"] = str(re_source.job_id)
        if decompile_addresses:
            details["decompile_addresses"] = len(decompile_addresses)
    if analyzer == Analyzer.DISK:
        details["segments"] = [str(s.evidence_id) for s in disk_set]
        await _record_disk_segments(ctx, job, disk_set)
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
        segments=tuple(disk_set),
        re_source=re_source,
        decompile_addresses=decompile_addresses,
    )


async def _record_disk_segments(
    ctx: OrgContext,
    job: AnalysisJob,
    disk_set: list[disk_segments.Segment],
) -> None:
    """M9 phase 7, in the job's transaction: the ordered `analysis_job_segments` (the trigger
    re-checks the investigation), the restricted default of EVERY segment (source `disk`;
    idempotent, RT2) and a custody entry on each segment after the first (the first gets the
    request's own custody and audit entry)."""
    ctx.session.add_all(
        AnalysisJobSegment(
            job_id=job.id,
            ordinal=s.ordinal,
            organization_id=ctx.org_id,
            evidence_id=s.evidence_id,
        )
        for s in disk_set
    )
    await ctx.session.flush()
    for s in disk_set:
        await evidence_sensitivity.apply_restricted_default(
            ctx.session, ctx.org_id, s.evidence_id, ctx.user.id, "disk"
        )
    for s in disk_set[1:]:
        ctx.session.add(
            EvidenceCustodyEvent(
                organization_id=ctx.org_id,
                evidence_id=s.evidence_id,
                action=CustodyAction.ANALYSIS_REQUESTED,
                actor_id=ctx.user.id,
                details={
                    "job_id": str(job.id),
                    "analyzer": Analyzer.DISK.value,
                    "ordinal": s.ordinal,
                    "segments": len(disk_set),
                },
            )
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
    source_job_id: uuid.UUID | None = None,
    decompile_addresses: list[int] | None = None,
) -> AnalysisJobOut:
    """Create the job (committed first), then enqueue it. A lost enqueue is a failed job.

    `segments` (disk only, M9): the ordered segment set, validated and stored with the job
    (`disk_forensics.segments`); every segment gets the restricted default."""
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
        if profile not in REQUESTABLE_PROFILES[Analyzer.DISK]:
            raise ValueError("an extract job is created by a file export, never requested")
        # The rules that need no database (order, count, duplicates; M9 phase 7).
        disk_segments.check_shape(evidence_id, segments or [], get_settings())
    if analyzer == Analyzer.REVERSE:
        if auto:
            raise ValueError("reverse engineering is never automatic")
        if profile == JobProfile.QUICK and not get_settings().re_quick_enabled:
            raise ProfileUnavailable()
        if decompile_addresses and profile != JobProfile.FULL:
            raise ValueError("decompile_addresses apply to the full profile only")
    elif source_job_id is not None or decompile_addresses:
        raise ValueError("source_job_id and decompile_addresses apply to reverse only")
    # Reverse has no queue cap of its own: the heavy-analysis cap (RT2) bounds it.
    if analyzer != Analyzer.REVERSE and await _global_queue_full(analyzer):
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
            segments=segments,
            source_job_id=source_job_id,
            decompile_addresses=tuple(decompile_addresses or ()),
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
