"""File exports to derived evidence (M9 phase 10).

The bridge from disk triage to the M3 Malware Lab. The API never parses the exported bytes: it
only hashes and stores them, exactly as an upload (the existing evidence pipeline).

**Request** (`request_exports`, `POST /analyses/{job}/disk/file-exports`, evidence.write; RT29):
1..`DISK_EXPORT_MAX_FILES` distinct listed files of a succeeded disk `triage` / `full` job of
the org. Each file must be allocated (neither deleted nor orphan), a regular file (or a named
stream of one), of a known size in 1..`DISK_EXPORT_MAX_BYTES`, with NO name of its inode (every
`disk_files` row of the same partition and `meta_addr`: hard links, and the file a named stream
belongs to) on the never-collected list (`cyberlab_jobs.disk.never_collect`, the constant phase
3's catalog uses; RT7). A refusal is `409 disk_export_not_allowed` with `reason`
(`not_allocated`, `not_regular`, `size_unknown`, `empty`, `too_large`, `never_collected`,
`too_many_names`, `source_not_succeeded`, `too_many_files`) and the offending `file_id`. A file
of another job is 404 (as an unknown one). No segment of the source may be purged (410) or
archived (409), nor its case archived (409). The sum of the sizes is checked against the
storage quota (`507 insufficient_storage`: the promoted copies will count). Then, in ONE
transaction under the org's analysis-queue lock (`DISK_MAX_ACTIVE_*`): the `extract` job
(`os_hint auto`, evidence = segment 0) and its index row, the segment set copied from the
source job, one `pending` `disk_exports` row per file (the path snapshot; a named stream as
`path:stream`), the audit `disk.export_requested` and the custody `export_requested` on every
segment. After commit the `disk-export.v1` message is published (`send_export`); a lost publish
fails the job `enqueue_failed`, and with it its exports.

**List** (`list_exports`, `GET /analyses/{job}/disk/file-exports`, evidence.read): the
exports requested from one analysis, newest first. **Read** (`get_export`).

**Promote** (`promote`, `POST /disk-exports/{id}/promote`, evidence.write): a `ready` export
(else `409 disk_export_not_ready` / `disk_export_already_promoted` / `disk_export_expired`) is
streamed from its exact object version in the results bucket (the api user has Get there)
through `hashing.spool()` (sha256 / sha1 / md5 by the trusted side), then the shared
`evidence.uploads.store_spooled` (sniff, quota, the evidence bucket with object lock, custody
`uploaded`, the automatic static job after commit). The trusted sha256 and size must equal the
worker's report, else the export becomes `failed` / `export_hash_mismatch` (integrity), nothing
is promoted and the answer is `409 export_hash_mismatch`. In the evidence transaction
(`store_spooled(on_insert=...)`): the export row (re-checked `ready` under its row lock: a
concurrent promote rolls back and its stored version is discarded) becomes `promoted` with the
evidence id; `apply_restricted_default(source="derived")` when any source segment is
restricted, plus the source segments' share-policy flags (OR-ed, never loosening); custody
`derived_from` on the new evidence and `export_promoted` on every source segment; the audit
`disk.export_promoted`.

**Expiry** (`expire_exports`, the hourly beat `disk.expire_exports`, DB only): `ready` exports
created more than `DISK_EXPORT_TTL_S` ago become `expired` (promote then refuses them). The
rows are found in a system session (0017's read-only `system_read` policy) and updated per org
in tenant sessions. The object versions are deleted by the retention worker's purge user for
every org (`workers/retention.purge_expired_exports`, RT19).

`fail_pending_exports(session, job)`: an `extract` job that fails (the reaper, a worker
failure, a refused result, a lost publish) marks its `pending` exports `failed` with the job's
error code, in the failing transaction.
"""

import hashlib
import logging
import secrets
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import anyio
from cyberlab_jobs import DISK_EXPORT, Queues
from cyberlab_jobs.disk import FILE_FLAG_BITS, OsHint
from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.core import storage
from app.core.config import Settings, get_settings
from app.core.deps import CurrentUser
from app.core.errors import AppError, Conflict, NotFound
from app.core.hashing import Spooled, TooLarge, spool
from app.core.rbac import OrgContext, Permission, org_session
from app.core.tenancy import tenant_session
from app.core.threads import broker_limiter
from app.core.upload_slots import slot
from app.modules.analysis import dispatch as analysis_dispatch
from app.modules.analysis import lifecycle
from app.modules.analysis import repository as analysis_repo
from app.modules.analysis import service as analysis_service
from app.modules.analysis.models import (
    ACTIVE,
    AnalysisJob,
    AnalysisJobIndex,
    AnalysisStatus,
    Analyzer,
    JobProfile,
)
from app.modules.audit import service as audit
from app.modules.disk_forensics import dispatch as disk_dispatch
from app.modules.disk_forensics import repository as disk_repo
from app.modules.disk_forensics import segments as disk_segments
from app.modules.disk_forensics.errors import (
    DiskExportAlreadyPromoted,
    DiskExportExpired,
    DiskExportNotAllowed,
    DiskExportNotReady,
)
from app.modules.disk_forensics.models import (
    AnalysisJobSegment,
    DiskExport,
    DiskExportState,
    DiskFile,
    DiskPartition,
)
from app.modules.disk_forensics.schemas import DiskExportList, DiskExportOut
from app.modules.disk_forensics.service import export_refusal
from app.modules.evidence import repository as evidence_repo
from app.modules.evidence import sensitivity as evidence_sensitivity
from app.modules.evidence import service as evidence_service
from app.modules.evidence import uploads
from app.modules.evidence.models import CustodyAction, EvidenceCustodyEvent, EvidenceStatus
from app.modules.evidence.schemas import EvidenceOut
from app.modules.investigations.models import EvidenceSharePolicy
from app.modules.memory_analysis.errors import InsufficientStorage
from app.modules.memory_analysis.models import SensitivityState
from app.modules.memory_analysis.service import AnalysisNotReady
from app.modules.organizations import storage as quota

log = logging.getLogger(__name__)

# Names of one inode read for the never-collected check: more is refused (fail closed).
MAX_INODE_NAMES = 1_000
SEND_TIMEOUT_S = 15
# The derived evidence's description (the upload route's own cap).
DESCRIPTION_MAX = 2_000
EXPIRE_ORGS_MAX = 100
# Exports listed per analysis (20 files per request: 25 requests).
LIST_MAX = 500
SOURCE_PROFILES = (JobProfile.TRIAGE, JobProfile.FULL)
HASH_MISMATCH = "export_hash_mismatch"


class DiskExportHashMismatch(AppError):
    """The trusted re-hash of the exported object differs from the worker's report."""

    status_code = 409
    code = HASH_MISMATCH
    message = (
        "The exported file does not match what the analyzer reported; it was not added to "
        "the case. Export it again."
    )


@dataclass(frozen=True)
class Planned:
    """One file of an `extract` job: what `build_export_message` sends for it."""

    export_id: uuid.UUID
    partition_index: int
    meta_addr: int
    meta_seq: int | None
    stream: str | None
    expected_size: int


def not_allowed(reason: str, file_id: uuid.UUID | None = None) -> DiskExportNotAllowed:
    extra: dict[str, object] = {"reason": reason}
    if file_id is not None:
        extra["file_id"] = str(file_id)
    return DiskExportNotAllowed(extra=extra)


def to_out(row: DiskExport) -> DiskExportOut:
    return DiskExportOut.model_validate(
        {
            "id": row.id,
            "export_job_id": row.export_job_id,
            "source_job_id": row.source_job_id,
            "file_id": row.file_id,
            "path": row.path,
            "state": row.state,
            "size": row.size,
            "worker_sha256": row.worker_sha256,
            "evidence_id": row.evidence_id,
            "error_code": row.error_code,
            "created_at": row.created_at,
            "promoted_at": row.promoted_at,
        }
    )


def snapshot_path(row: DiskFile) -> str:
    """The stored path of an export (a named stream as `path:stream`), within the column."""
    path = f"{row.path}:{row.stream}" if row.stream else row.path
    return path.encode("utf-8")[:4096].decode("utf-8", "ignore")


# --- request ---------------------------------------------------------------------------------


def file_refusal(
    row: DiskFile, names: Sequence[str], fs_type: str | None, max_bytes: int
) -> str | None:
    """Why this listed entry cannot be exported (None: it can): phase 8's `export_refusal`
    (the reason the file page shows), plus orphans and empty files."""
    if row.flags & FILE_FLAG_BITS["orphan"]:
        return "not_allocated"
    reason = export_refusal(row, names, fs_type, max_bytes)
    if reason is None and not row.size:
        return "empty"  # the contract's `expected_size` is > 0
    return reason


async def inode_names(session: AsyncSession, org_id: uuid.UUID, row: DiskFile) -> list[str] | None:
    """Every listed name of the row's inode (hard links, and the file of a named stream: the
    same (partition, meta_addr)), or None past `MAX_INODE_NAMES` (refused)."""
    m = DiskFile
    paths = list(
        (
            await session.scalars(
                select(m.path)
                .where(
                    m.organization_id == org_id,
                    m.job_id == row.job_id,
                    m.partition_index == row.partition_index,
                    m.meta_addr == row.meta_addr,
                )
                .distinct()
                .limit(MAX_INODE_NAMES + 1)
            )
        ).all()
    )
    if len(paths) > MAX_INODE_NAMES:
        return None
    return sorted({row.path, *paths})


async def _fs_types(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID
) -> dict[int, str | None]:
    rows = await session.execute(
        select(DiskPartition.index, DiskPartition.fs_type).where(
            DiskPartition.organization_id == org_id, DiskPartition.job_id == job_id
        )
    )
    return {index: fs_type for index, fs_type in rows.tuples()}


async def _source_segments(ctx: OrgContext, job: AnalysisJob) -> list[disk_segments.Segment]:
    """The source job's segment set, every segment still stored (410 when purged) and active
    (409 when archived), its case open (409 when archived)."""
    segments = await disk_segments.of_job(ctx.session, ctx.org_id, job.id)
    if not segments or segments[0].evidence_id != job.evidence_id:
        raise not_allowed("source_not_succeeded")
    for i, segment in enumerate(segments):
        row = await evidence_service.get_row(ctx, segment.evidence_id, for_update=i == 0)
        evidence_service.ensure_not_purged(row)
        if row.evidence.status == EvidenceStatus.ARCHIVED:
            raise Conflict("Archived evidence cannot be exported from", code="evidence_archived")
        if i == 0:
            await evidence_service.ensure_open_investigation(ctx, row.evidence.investigation_id)
    return segments


async def _checked_files(
    ctx: OrgContext, source: AnalysisJob, file_ids: list[uuid.UUID], settings: Settings
) -> list[DiskFile]:
    found = {
        f.id: f
        for f in (
            await ctx.session.scalars(
                select(DiskFile).where(
                    DiskFile.organization_id == ctx.org_id,
                    DiskFile.job_id == source.id,
                    DiskFile.id.in_(file_ids),
                )
            )
        ).all()
    }
    if len(found) != len(file_ids):
        raise NotFound()  # a file of another job (or org) is indistinguishable from none
    fs_types = await _fs_types(ctx.session, ctx.org_id, source.id)
    files = [found[i] for i in file_ids]
    for f in files:
        names = await inode_names(ctx.session, ctx.org_id, f)
        if names is None:
            raise not_allowed("too_many_names", f.id)
        reason = file_refusal(
            f, names, fs_types.get(f.partition_index), settings.disk_export_max_bytes
        )
        if reason is not None:
            raise not_allowed(reason, f.id)
    return files


def _custody_requested(
    org_id: uuid.UUID,
    actor_id: uuid.UUID,
    job: AnalysisJob,
    source: AnalysisJob,
    segments: list[disk_segments.Segment],
    files: int,
) -> list[EvidenceCustodyEvent]:
    return [
        EvidenceCustodyEvent(
            organization_id=org_id,
            evidence_id=s.evidence_id,
            action=CustodyAction.EXPORT_REQUESTED,
            actor_id=actor_id,
            details={
                "export_job_id": str(job.id),
                "source_job_id": str(source.id),
                "ordinal": s.ordinal,
                "files": files,
            },
        )
        for s in segments
    ]


async def _create(
    ctx: OrgContext, job_id: uuid.UUID, file_ids: list[uuid.UUID], request: Request, token: str
) -> tuple[analysis_dispatch.DispatchInput, list[Planned], list[uuid.UUID]]:
    settings = get_settings()
    source = await disk_repo.ensure_disk_job(ctx.session, ctx.org_id, job_id)  # 404
    if source.status in ACTIVE:
        raise AnalysisNotReady()
    if source.status != AnalysisStatus.SUCCEEDED or source.profile not in SOURCE_PROFILES:
        raise not_allowed("source_not_succeeded")
    segments = await _source_segments(ctx, source)
    files = await _checked_files(ctx, source, file_ids, settings)
    total = sum(int(f.size or 0) for f in files)
    try:
        await quota.check_fits(ctx, total)
    except quota.StorageQuotaExceeded as exc:
        raise InsufficientStorage() from exc

    await analysis_repo.lock_org_queue(ctx.session, ctx.org_id)
    active = await analysis_repo.count_active(ctx.session, ctx.org_id, Analyzer.DISK)
    if active >= analysis_service._active_caps(settings, Analyzer.DISK)[0]:
        raise analysis_service.AnalysisQueueFull()

    job = AnalysisJob(
        organization_id=ctx.org_id,
        evidence_id=source.evidence_id,
        analyzer=Analyzer.DISK,
        profile=JobProfile.EXTRACT,
        os_hint=OsHint.AUTO,
        requested_by=ctx.user.id,
        auto=False,
        ingest_token_sha256=hashlib.sha256(token.encode()).hexdigest(),
    )
    ctx.session.add(job)
    await ctx.session.flush()
    ctx.session.add(
        AnalysisJobIndex(
            job_id=job.id,
            organization_id=ctx.org_id,
            analyzer=Analyzer.DISK,
            status=AnalysisStatus.QUEUED,
            deadline_at=lifecycle.now() + timedelta(seconds=settings.analysis_queue_ttl_s),
        )
    )
    ctx.session.add_all(
        AnalysisJobSegment(
            job_id=job.id, ordinal=s.ordinal, organization_id=ctx.org_id, evidence_id=s.evidence_id
        )
        for s in segments
    )
    await ctx.session.flush()  # the segment trigger, before the exports reference the job
    exports = [
        DiskExport(
            id=uuid.uuid4(),
            organization_id=ctx.org_id,
            export_job_id=job.id,
            source_job_id=source.id,
            file_id=f.id,
            path=snapshot_path(f),
            state=DiskExportState.PENDING.value,
            requested_by=ctx.user.id,
        )
        for f in files
    ]
    ctx.session.add_all(exports)
    audit.record(
        ctx.session,
        action="disk.export_requested",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="analysis_job",
        target_id=source.id,
        details={
            "export_job_id": str(job.id),
            "files": len(files),
            "file_ids": [str(f.id) for f in files],
            "export_ids": [str(e.id) for e in exports],
            "bytes": total,
        },
        request=request,
    )
    ctx.session.add_all(
        _custody_requested(ctx.org_id, ctx.user.id, job, source, segments, len(files))
    )
    await ctx.session.flush()
    planned = [
        Planned(
            export_id=e.id,
            partition_index=f.partition_index,
            meta_addr=int(f.meta_addr),
            meta_seq=f.meta_seq,
            stream=f.stream,
            expected_size=int(f.size or 0),
        )
        for e, f in zip(exports, files, strict=True)
    ]
    first = segments[0]
    item = analysis_dispatch.DispatchInput(
        job_id=job.id,
        organization_id=ctx.org_id,
        evidence_id=first.evidence_id,
        storage_bucket=first.storage_bucket,
        storage_key=first.storage_key,
        storage_version_id=first.storage_version_id,
        sha256=first.sha256,
        size_bytes=first.size_bytes,
        ingest_token=token,
        analyzer=Analyzer.DISK,
        profile=JobProfile.EXTRACT,
        os_hint=OsHint.AUTO,
        segments=tuple(segments),
    )
    return item, planned, [e.id for e in exports]


def _send_sync(
    item: analysis_dispatch.DispatchInput, source_job_id: uuid.UUID, planned: list[Planned]
) -> None:
    from app.workers.celery_app import celery_app  # broker client only, no worker

    settings = get_settings()
    message = disk_dispatch.build_export_message(
        item, source_job_id, list(item.segments), planned, settings
    )
    timeout = settings.analysis_disk_timeout_s
    celery_app.send_task(
        DISK_EXPORT,
        kwargs={"message": message.model_dump(mode="json")},
        queue=Queues(settings.queue_prefix).disk,
        # Never run a job whose URLs have expired; soft limit leaves room for cleanup.
        expires=settings.analysis_queue_ttl_s,
        soft_time_limit=timeout + 60,
        time_limit=timeout + 90,
        retry=True,
        retry_policy={"max_retries": 1, "interval_start": 0, "interval_step": 0.5},
    )


async def send_export(
    item: analysis_dispatch.DispatchInput, source_job_id: uuid.UUID, planned: list[Planned]
) -> None:
    """Publish the `disk-export.v1` message (task `disk.export`, queue `disk`) within a
    bounded time, after the job row committed (`analysis.dispatch.send`'s rules)."""
    with anyio.fail_after(SEND_TIMEOUT_S):
        await anyio.to_thread.run_sync(
            _send_sync,
            item,
            source_job_id,
            planned,
            limiter=broker_limiter(),
            abandon_on_cancel=True,
        )


async def _mark_enqueue_failed(org_id: uuid.UUID, user: CurrentUser, job_id: uuid.UUID) -> None:
    async with org_session(org_id, user, Permission.EVIDENCE_READ) as ctx:
        job = await analysis_repo.get_for_update(ctx.session, org_id, job_id)
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
            await fail_pending_exports(ctx.session, job)


async def request_exports(
    org_id: uuid.UUID,
    user: CurrentUser,
    job_id: uuid.UUID,
    file_ids: list[uuid.UUID],
    request: Request,
) -> DiskExportList:
    """Create the `extract` job and its `pending` exports (committed first), then publish
    it. A lost publish fails the job and its exports, never this request."""
    settings = get_settings()
    ids = list(dict.fromkeys(file_ids))  # the request's order, each file once
    if not 1 <= len(ids) <= settings.disk_export_max_files:
        raise not_allowed("too_many_files")
    if await analysis_service._global_queue_full(Analyzer.DISK):
        raise analysis_service.AnalysisQueueFull()
    token = secrets.token_urlsafe(32)
    async with org_session(org_id, user, Permission.EVIDENCE_WRITE) as ctx:
        item, planned, export_ids = await _create(ctx, job_id, ids, request, token)
    # The job is committed: nothing below may turn this request into an error.
    try:
        await send_export(item, job_id, planned)
    except Exception:
        log.exception("enqueue failed for disk export job %s", item.job_id)
        try:
            await _mark_enqueue_failed(org_id, user, item.job_id)
        except Exception:  # the reaper fails it (and its exports) at its deadline
            log.exception("could not mark disk export job %s as enqueue_failed", item.job_id)
    async with org_session(org_id, user, Permission.EVIDENCE_READ) as ctx:
        rows = await _rows(ctx.session, org_id, export_ids)
    return DiskExportList(items=[to_out(r) for r in rows])


async def _rows(
    session: AsyncSession, org_id: uuid.UUID, export_ids: list[uuid.UUID]
) -> list[DiskExport]:
    found = {
        r.id: r
        for r in (
            await session.scalars(
                select(DiskExport).where(
                    DiskExport.organization_id == org_id, DiskExport.id.in_(export_ids)
                )
            )
        ).all()
    }
    return [found[i] for i in export_ids if i in found]


# --- read ------------------------------------------------------------------------------------


async def _export(
    session: AsyncSession, org_id: uuid.UUID, export_id: uuid.UUID, *, for_update: bool = False
) -> DiskExport:
    stmt = select(DiskExport).where(
        DiskExport.organization_id == org_id, DiskExport.id == export_id
    )
    if for_update:
        stmt = stmt.with_for_update()
    row: DiskExport | None = await session.scalar(stmt)
    if row is None:
        raise NotFound()
    return row


async def list_exports(ctx: OrgContext, job_id: uuid.UUID) -> DiskExportList:
    """The exports requested from one disk analysis (`triage` / `full`; 404 otherwise),
    newest first, at most `LIST_MAX`."""
    await disk_repo.ensure_disk_job(ctx.session, ctx.org_id, job_id)
    rows = await ctx.session.scalars(
        select(DiskExport)
        .where(DiskExport.organization_id == ctx.org_id, DiskExport.source_job_id == job_id)
        .order_by(DiskExport.created_at.desc(), DiskExport.id)
        .limit(LIST_MAX)
    )
    return DiskExportList(items=[to_out(r) for r in rows])


async def get_export(ctx: OrgContext, export_id: uuid.UUID) -> DiskExportOut:
    """State, size, the worker's (untrusted, display only) sha256 and, once promoted, the
    evidence (whose hashes are the API's own)."""
    return to_out(await _export(ctx.session, ctx.org_id, export_id))


# --- promote ---------------------------------------------------------------------------------


def check_promotable(row: DiskExport) -> None:
    if row.state == DiskExportState.PROMOTED:
        raise DiskExportAlreadyPromoted()
    if row.state == DiskExportState.EXPIRED or row.object_deleted_at is not None:
        raise DiskExportExpired()
    if (
        row.state != DiskExportState.READY
        or row.object_key is None
        or row.object_version_id is None
        or row.worker_sha256 is None
        or row.size is None
    ):
        raise DiskExportNotReady()


@dataclass(frozen=True)
class Promotable:
    """What a promote reads before it streams the object (no transaction held meanwhile)."""

    export_id: uuid.UUID
    source_job_id: uuid.UUID
    export_job_id: uuid.UUID
    investigation_id: uuid.UUID
    object_key: str
    object_version_id: str
    worker_sha256: str
    size: int
    path: str
    partition_index: int | None = None
    meta_addr: str | None = None
    stream: str | None = None


async def _promotable(ctx: OrgContext, export_id: uuid.UUID) -> Promotable:
    row = await _export(ctx.session, ctx.org_id, export_id)
    check_promotable(row)
    source = await ctx.session.scalar(
        select(AnalysisJob).where(
            AnalysisJob.organization_id == ctx.org_id, AnalysisJob.id == row.source_job_id
        )
    )
    if source is None:  # the composite FK makes this unreachable
        raise NotFound()
    evidence = await evidence_service.get_row(ctx, source.evidence_id)
    evidence_service.ensure_not_purged(evidence)
    investigation_id = evidence.evidence.investigation_id
    await evidence_service.ensure_open_investigation(ctx, investigation_id)
    if (
        row.size is None
        or row.object_key is None
        or row.object_version_id is None
        or row.worker_sha256 is None
    ):
        raise DiskExportNotReady()  # check_promotable already refused it
    await quota.check_fits(ctx, row.size)
    # A soft reference: retention may have deleted the listing since.
    listed = await ctx.session.scalar(
        select(DiskFile).where(
            DiskFile.organization_id == ctx.org_id,
            DiskFile.job_id == row.source_job_id,
            DiskFile.id == row.file_id,
        )
    )
    return Promotable(
        export_id=row.id,
        source_job_id=row.source_job_id,
        export_job_id=row.export_job_id,
        investigation_id=investigation_id,
        object_key=row.object_key,
        object_version_id=row.object_version_id,
        worker_sha256=row.worker_sha256,
        size=row.size,
        path=row.path,
        partition_index=listed.partition_index if listed is not None else None,
        meta_addr=str(int(listed.meta_addr)) if listed is not None else None,
        stream=listed.stream if listed is not None else None,
    )


def derived_filename(p: Promotable) -> str:
    """The original file name (a named stream as `name_stream`); `store_spooled` sanitizes
    it."""
    path = p.path
    if p.stream and path.endswith(f":{p.stream}"):
        path = f"{path[: -len(p.stream) - 1]}_{p.stream}"
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    return name or "exported-file"


def derived_description(p: Promotable) -> str:
    partition = "?" if p.partition_index is None else str(p.partition_index)
    text = f"Exported from disk job {p.source_job_id}, partition {partition}, path {p.path}"
    return text.replace("\x00", "")[:DESCRIPTION_MAX]


async def _spool_object(p: Promotable, settings: Settings) -> Spooled | None:
    """The exact object version, spooled and hashed by the trusted side (None: larger than
    the export cap, i.e. a mismatch). `409 disk_export_expired` when the version is gone."""
    chunks = storage.iter_version(settings.results_bucket, p.object_key, p.object_version_id)
    try:
        return await spool(chunks, settings.upload_tmp_dir, settings.disk_export_max_bytes)
    except TooLarge:
        return None
    except storage.ObjectMissing as exc:
        raise DiskExportExpired() from exc
    finally:
        await chunks.aclose()


async def _record_mismatch(
    org_id: uuid.UUID, user: CurrentUser, p: Promotable, spooled: Spooled | None, request: Request
) -> None:
    """The export becomes `failed` / `export_hash_mismatch` (committed before the answer)."""
    async with org_session(org_id, user, Permission.EVIDENCE_WRITE) as ctx:
        row = await _export(ctx.session, org_id, p.export_id, for_update=True)
        if row.state != DiskExportState.READY:
            return  # a concurrent promote or the expiry won
        row.state = DiskExportState.FAILED.value
        row.error_code = HASH_MISMATCH
        audit.record(
            ctx.session,
            action="disk.export_rejected",
            org_id=org_id,
            actor_id=user.id,
            target_type="analysis_job",
            target_id=p.source_job_id,
            details={
                "export_id": str(p.export_id),
                "error_code": HASH_MISMATCH,
                "worker_sha256": p.worker_sha256,
                "worker_size": p.size,
                "sha256": spooled.hashes["sha256"] if spooled else None,
                "size": spooled.size if spooled else None,
            },
            request=request,
        )


async def inherit_restriction(
    session: AsyncSession,
    org_id: uuid.UUID,
    evidence_id: uuid.UUID,
    actor_id: uuid.UUID,
    segment_ids: list[uuid.UUID],
) -> dict[str, bool]:
    """Derived evidence inherits the restriction (source `derived`) when any source segment
    is restricted, and the source segments' share-policy flags (OR-ed; never loosening)."""
    states = await evidence_repo.sensitivity_states(session, org_id, segment_ids)
    restricted = any(state == SensitivityState.RESTRICTED.value for state, _ in states.values())
    if restricted:
        await evidence_sensitivity.apply_restricted_default(
            session, org_id, evidence_id, actor_id, "derived"
        )
    p = EvidenceSharePolicy
    ai_any, ti_any = (
        await session.execute(
            select(
                func.coalesce(func.bool_or(p.ai_excluded), False),
                func.coalesce(func.bool_or(p.ti_excluded), False),
            ).where(p.organization_id == org_id, p.evidence_id.in_(segment_ids))
        )
    ).one()
    ai, ti = bool(ai_any), bool(ti_any)
    if ai or ti:
        await evidence_repo.lock_evidence_for_policy(session, org_id, evidence_id)
        await session.execute(
            insert(p)
            .values(
                evidence_id=evidence_id,
                organization_id=org_id,
                ai_excluded=ai,
                ti_excluded=ti,
                updated_by=actor_id,
            )
            .on_conflict_do_update(
                index_elements=[p.evidence_id],
                set_={
                    "ai_excluded": p.ai_excluded | ai,
                    "ti_excluded": p.ti_excluded | ti,
                    "updated_by": actor_id,
                    "updated_at": func.now(),
                },
            )
        )
    return {
        "restricted": restricted,
        "ai_excluded": ai or restricted,
        "ti_excluded": ti or restricted,
    }


def _custody_promoted(
    org_id: uuid.UUID,
    actor_id: uuid.UUID,
    p: Promotable,
    evidence_id: uuid.UUID,
    segment_ids: list[uuid.UUID],
    sha256: str,
) -> list[EvidenceCustodyEvent]:
    derived = EvidenceCustodyEvent(
        organization_id=org_id,
        evidence_id=evidence_id,
        action=CustodyAction.DERIVED_FROM,
        actor_id=actor_id,
        details={
            "source_job_id": str(p.source_job_id),
            "export_job_id": str(p.export_job_id),
            "export_id": str(p.export_id),
            "segments": [str(s) for s in segment_ids],
            "partition_index": p.partition_index,
            "path": p.path,
            "meta_addr": p.meta_addr,
            "stream": p.stream,
            "sha256": sha256,
        },
    )
    promoted = [
        EvidenceCustodyEvent(
            organization_id=org_id,
            evidence_id=segment_id,
            action=CustodyAction.EXPORT_PROMOTED,
            actor_id=actor_id,
            details={
                "export_id": str(p.export_id),
                "source_job_id": str(p.source_job_id),
                "derived_evidence_id": str(evidence_id),
            },
        )
        for segment_id in segment_ids
    ]
    return [derived, *promoted]


def _on_insert(p: Promotable, user: CurrentUser, request: Request, sha256: str) -> uploads.OnInsert:
    async def hook(ctx: OrgContext, out: EvidenceOut) -> None:
        row = await _export(ctx.session, ctx.org_id, p.export_id, for_update=True)
        check_promotable(row)  # re-checked under the row lock (a concurrent promote)
        row.state = DiskExportState.PROMOTED.value
        row.evidence_id = out.id
        row.promoted_by = user.id
        row.promoted_at = datetime.now(UTC)
        segments = await disk_segments.of_job(ctx.session, ctx.org_id, p.source_job_id)
        segment_ids = [s.evidence_id for s in segments]
        inherited = await inherit_restriction(ctx.session, ctx.org_id, out.id, user.id, segment_ids)
        ctx.session.add_all(_custody_promoted(ctx.org_id, user.id, p, out.id, segment_ids, sha256))
        audit.record(
            ctx.session,
            action="disk.export_promoted",
            org_id=ctx.org_id,
            actor_id=user.id,
            target_type="evidence",
            target_id=out.id,
            details={
                "export_id": str(p.export_id),
                "source_job_id": str(p.source_job_id),
                "sha256": sha256,
                **inherited,
            },
            request=request,
        )

    return hook


async def promote(
    org_id: uuid.UUID, user: CurrentUser, export_id: uuid.UUID, request: Request
) -> DiskExportOut:
    settings = get_settings()
    async with org_session(org_id, user, Permission.EVIDENCE_WRITE) as ctx:
        p = await _promotable(ctx, export_id)
    async with slot("upload", user.id, settings.max_concurrent_uploads_per_user):
        spooled = await _spool_object(p, settings)
        if spooled is None or spooled.size != p.size or spooled.hashes["sha256"] != p.worker_sha256:
            if spooled is not None:
                spooled.path.unlink(missing_ok=True)
            log.warning("disk export %s: the trusted re-hash differs from the worker's", export_id)
            await _record_mismatch(org_id, user, p, spooled, request)
            raise DiskExportHashMismatch()
        await uploads.store_spooled(
            request,
            org_id=org_id,
            investigation_id=p.investigation_id,
            user=user,
            spooled=spooled,
            filename=derived_filename(p),
            description=derived_description(p),
            on_insert=_on_insert(p, user, request, spooled.hashes["sha256"]),
        )
    async with org_session(org_id, user, Permission.EVIDENCE_READ) as ctx:
        return to_out(await _export(ctx.session, org_id, export_id))


# --- expiry and failure ----------------------------------------------------------------------


async def expire_exports(limit: int) -> int:
    """`ready` exports created more than `DISK_EXPORT_TTL_S` ago become `expired` (at most
    `limit` per call). Returns the rows marked."""
    cutoff = datetime.now(UTC) - timedelta(seconds=get_settings().disk_export_ttl_s)
    async with tenant_session(None, None) as session:  # 0017 `system_read`: SELECT only
        rows = (
            (
                await session.execute(
                    select(DiskExport.organization_id, DiskExport.id)
                    .where(
                        DiskExport.state == DiskExportState.READY.value,
                        DiskExport.created_at < cutoff,
                    )
                    .order_by(DiskExport.created_at, DiskExport.id)
                    .limit(limit)
                )
            )
            .tuples()
            .all()
        )
    by_org: dict[uuid.UUID, list[uuid.UUID]] = {}
    for org_id, export_id in rows:
        by_org.setdefault(org_id, []).append(export_id)
    expired = 0
    for org_id, ids in list(by_org.items())[:EXPIRE_ORGS_MAX]:
        try:
            async with tenant_session(org_id, None) as session:
                result = await session.execute(
                    update(DiskExport)
                    .where(
                        DiskExport.organization_id == org_id,
                        DiskExport.id.in_(ids),
                        DiskExport.state == DiskExportState.READY.value,
                        DiskExport.created_at < cutoff,
                    )
                    .values(state=DiskExportState.EXPIRED.value)
                    .execution_options(synchronize_session=False)
                )
                expired += int(getattr(result, "rowcount", 0) or 0)
        except Exception:  # one org's failure never stops the others
            log.exception("disk export expiry failed for org %s", org_id)
    return expired


async def fail_pending_exports(session: AsyncSession, job: AnalysisJob) -> int:
    """An `extract` job that failed: its `pending` exports become `failed` with the job's
    error code (in the caller's transaction). Returns the rows marked."""
    if job.profile != JobProfile.EXTRACT:
        return 0
    result = await session.execute(
        update(DiskExport)
        .where(
            DiskExport.organization_id == job.organization_id,
            DiskExport.export_job_id == job.id,
            DiskExport.state == DiskExportState.PENDING.value,
        )
        .values(state=DiskExportState.FAILED.value, error_code=job.error_code or "analyzer_failed")
        .execution_options(synchronize_session=False)
    )
    return int(getattr(result, "rowcount", 0) or 0)


__all__ = [
    "DiskExportHashMismatch",
    "Planned",
    "Promotable",
    "check_promotable",
    "derived_description",
    "derived_filename",
    "expire_exports",
    "fail_pending_exports",
    "file_refusal",
    "get_export",
    "inherit_restriction",
    "inode_names",
    "list_exports",
    "promote",
    "request_exports",
    "send_export",
    "snapshot_path",
    "to_out",
]
