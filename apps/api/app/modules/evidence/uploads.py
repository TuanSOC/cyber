"""Evidence upload: spool + hash -> store exact version -> record -> retention lock.

Once the evidence rows are committed nothing may turn the request into an error: the
retention lock, its failure audit and the slot release are all best effort (logged).

M8: `kind=memory` declares a memory image. It has its own size limit (`MEMORY_MAX_BYTES`,
early on the declared length and again while spooling), a free-space check of the spool dir,
the declared type `memory`, the TLP:RED default in the upload transaction and no automatic
analysis of any kind (RT3).

M9 phase 7: `kind=disk` declares a disk image segment, the same way: `DISK_MAX_UPLOAD_BYTES`
(`413 disk_image_too_large`, declared length and while spooling), an empty body refused
(`422 disk_image_empty`), the spool free-space check, the declared type `disk`, the
`detected_description` label (EWF segment or raw image), the restricted default (source
`disk`, AI and TI excluded) in the upload transaction and no automatic analysis (no static
`av`: the M8 RT3 rule). A disk analysis is always an explicit request over a segment set.
"""

import contextlib
import logging
import shutil
import uuid
from collections.abc import Iterator

import magic
from starlette.requests import ClientDisconnect, Request

from app.core import filetypes, storage
from app.core.config import get_settings
from app.core.deps import CurrentUser
from app.core.errors import AppError
from app.core.filenames import sanitize_filename
from app.core.hashing import ALGORITHMS, Spooled, TooLarge, spool
from app.core.rbac import OrgContext, Permission, org_session
from app.core.upload_slots import slot
from app.modules.analysis import service as analysis_service
from app.modules.audit import service as audit
from app.modules.disk_forensics.errors import DiskImageEmpty, DiskImageTooLarge
from app.modules.evidence import repository as repo
from app.modules.evidence import sensitivity as evidence_sensitivity
from app.modules.evidence.locking import discard_version, lock_version
from app.modules.evidence.models import CustodyAction, Evidence, EvidenceHash, HashAlgorithm
from app.modules.evidence.schemas import EvidenceOut, UploadKind
from app.modules.evidence.service import ensure_open_investigation, record_event, to_out
from app.modules.memory_analysis import sensitivity as memory_sensitivity
from app.modules.memory_analysis.errors import InsufficientStorage, MemoryImageTooLarge
from app.modules.organizations import storage as quota

log = logging.getLogger(__name__)

MEMORY: UploadKind = "memory"
DISK: UploadKind = "disk"
# Image kinds: spooled whole after a free-space check, restricted at upload, never automatic.
IMAGE_KINDS: frozenset[UploadKind] = frozenset({MEMORY, DISK})
# Free space the spool dir must keep beyond a memory image (M8; checked before spooling).
MEMORY_SPOOL_RESERVE_BYTES = 1024**3


class PayloadTooLarge(AppError):
    status_code = 413
    code = "payload_too_large"
    message = "Evidence exceeds the maximum allowed size"


class ClientGone(AppError):
    status_code = 400
    code = "client_disconnected"
    message = "Upload was interrupted"


class UnsupportedMediaType(AppError):
    status_code = 415
    code = "unsupported_media_type"
    message = "Upload the raw file bytes with Content-Type: application/octet-stream"


def _sniff(head: bytes) -> tuple[str, str]:
    """libmagic on the first bytes only. Recorded as metadata, never used to reject."""
    try:
        return magic.from_buffer(head, mime=True)[:255], magic.from_buffer(head)[:512]
    except Exception:  # libmagic failure must not lose the evidence
        log.exception("file type detection failed")
        return "application/octet-stream", "unknown"


def _type_check(
    filename: str, mime: str, head: bytes, kind: UploadKind | None = None
) -> tuple[str | None, str | None, bool]:
    """(declared family, detected family, mismatch). Metadata only: never raises, never
    rejects, and the analyzers' routing is unchanged."""
    try:
        declared = filetypes.declared_family(filename, kind=kind)
        detected = filetypes.detected_family(mime, filetypes.magic_route(head))
    except Exception:  # a classification bug must not lose the evidence
        log.exception("file type classification failed")
        return None, None, False
    return declared, detected, filetypes.type_mismatch(declared, detected)


def max_upload_bytes(kind: UploadKind | None) -> int:
    """The size limit of one upload: memory images (M8, RT14) and disk image segments (M9)
    have their own."""
    settings = get_settings()
    if kind == MEMORY:
        return settings.memory_max_bytes
    if kind == DISK:
        return settings.disk_max_upload_bytes
    return settings.max_evidence_bytes


def _too_large(kind: UploadKind | None) -> AppError:
    if kind == MEMORY:
        return MemoryImageTooLarge()
    if kind == DISK:
        return DiskImageTooLarge()
    return PayloadTooLarge()


def _check_request(request: Request, kind: UploadKind | None = None) -> int:
    """Validates the headers; returns the declared length (0 when not declared)."""
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/octet-stream":
        raise UnsupportedMediaType()
    declared = request.headers.get("content-length", "")
    size = int(declared) if declared.isdigit() else 0
    if size > max_upload_bytes(kind):
        raise _too_large(kind)
    return size


# Bytes promised to the memory uploads now spooling in this process (review fix). The check
# and the increment run without an await between them, so concurrent uploads on one event
# loop never both take the same free space. Conservative: bytes already spooled count twice
# (in `free` and here) until the upload ends. Several API processes sharing the spool volume
# each keep their own count; the 1 GiB reserve is the margin between them.
_spool_reserved = 0


def spool_reservation(kind: UploadKind | None, declared: int) -> int:
    """Bytes a memory upload reserves: its declared length, or the memory limit when the
    body is chunked (no Content-Length), since its real size is known only at the end."""
    return declared if declared > 0 else max_upload_bytes(kind)


@contextlib.contextmanager
def _reserve_spool(directory: str, size: int) -> Iterator[None]:
    """A memory image is spooled whole before it is stored: refuse it now when the spool dir
    cannot hold it, every other running memory upload's reservation and the reserve (507,
    retry later) instead of failing gigabytes in. Released when the upload ends."""
    global _spool_reserved
    if shutil.disk_usage(directory).free - _spool_reserved < size + MEMORY_SPOOL_RESERVE_BYTES:
        raise InsufficientStorage()
    _spool_reserved += size
    try:
        yield
    finally:
        _spool_reserved -= size


async def _insert_records(
    ctx: OrgContext,
    request: Request,
    *,
    investigation_id: uuid.UUID,
    spooled: Spooled,
    key: str,
    version_id: str,
    filename: str,
    description: str,
    kind: UploadKind | None = None,
) -> EvidenceOut:
    await ensure_open_investigation(ctx, investigation_id)
    # Case (FOR SHARE) before org lock: a case update holding the case row then inserting
    # its audit row (KEY SHARE on the org) can then never wait in a cycle with this upload.
    await quota.reserve(ctx, spooled.size)
    mime, magic_text = _sniff(spooled.head)
    if kind == DISK:
        magic_text = filetypes.disk_description(spooled.head, magic_text)
    stored_name = sanitize_filename(filename)
    declared, detected, mismatch = _type_check(stored_name, mime, spooled.head, kind)
    evidence = Evidence(
        organization_id=ctx.org_id,
        investigation_id=investigation_id,
        original_filename=stored_name,
        detected_mime=mime,
        detected_description=magic_text,
        size_bytes=spooled.size,
        storage_bucket=storage.bucket(),
        storage_key=key,
        storage_version_id=version_id,
        description=description,
        uploaded_by=ctx.user.id,
        # M7: set at INSERT, write-once (evidence_immutable).
        declared_type=declared,
        type_mismatch=mismatch,
    )
    ctx.session.add(evidence)
    await ctx.session.flush()
    ctx.session.add_all(
        EvidenceHash(
            organization_id=ctx.org_id,
            evidence_id=evidence.id,
            algorithm=HashAlgorithm(name),
            value=spooled.hashes[name],
        )
        for name in ALGORITHMS
    )
    if kind == MEMORY:
        # RT3: TLP:RED (restricted, AI and TI excluded) in the upload's own transaction, so
        # nothing ever reads the image unrestricted (phase-8 entry point; idempotent).
        await memory_sensitivity.apply_memory_default(
            ctx.session, ctx.org_id, evidence.id, ctx.user.id
        )
    elif kind == DISK:
        # M9 phase 7: restricted (source `disk`, AI and TI excluded) in the upload's own
        # transaction, before anything can read the segment (idempotent).
        await evidence_sensitivity.apply_restricted_default(
            ctx.session, ctx.org_id, evidence.id, ctx.user.id, "disk"
        )
    sha256 = spooled.hashes["sha256"]
    record_event(
        ctx,
        evidence_id=evidence.id,
        action=CustodyAction.UPLOADED,
        audit_action="evidence.uploaded",
        request=request,
        custody_details={"size_bytes": spooled.size, "sha256": sha256},
        audit_details={
            "investigation_id": str(investigation_id),
            "filename": evidence.original_filename,
            "size_bytes": spooled.size,
            "sha256": sha256,
        },
    )
    if mismatch:
        # Flagged and audited in the upload's transaction; never rejected (decision).
        audit.record(
            ctx.session,
            action="evidence.type_mismatch",
            org_id=ctx.org_id,
            actor_id=ctx.user.id,
            target_type="evidence",
            target_id=evidence.id,
            details={"declared_type": declared, "detected_type": detected},
            request=request,
        )
    out = to_out(repo.EvidenceRow(evidence, ctx.user.display_name, dict(spooled.hashes)))
    return out.model_copy(update={"declared_type": declared, "type_mismatch": mismatch})


async def upload(
    request: Request,
    *,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    user: CurrentUser,
    filename: str,
    description: str,
    kind: UploadKind | None = None,
) -> EvidenceOut:
    settings = get_settings()
    declared = _check_request(request, kind)
    async with org_session(org_id, user, Permission.EVIDENCE_WRITE) as ctx:
        await ensure_open_investigation(ctx, investigation_id)
        # Early, unlocked: refuse a declared size that cannot fit before reading the body.
        # Authoritative (actual size, org locked) again before the records commit.
        await quota.check_fits(ctx, declared)

    async with contextlib.AsyncExitStack() as stack:
        await stack.enter_async_context(
            slot("upload", user.id, settings.max_concurrent_uploads_per_user)
        )
        cap = max_upload_bytes(kind)
        if kind in IMAGE_KINDS:
            # The reservation is also the spool cap (a body never outgrows what it reserved).
            cap = spool_reservation(kind, declared)
            stack.enter_context(_reserve_spool(settings.upload_tmp_dir, cap))
        try:
            spooled = await spool(request.stream(), settings.upload_tmp_dir, cap)
        except TooLarge as exc:
            raise _too_large(kind) from exc
        except ClientDisconnect as exc:
            raise ClientGone() from exc
        if kind == DISK and spooled.size == 0:
            spooled.path.unlink(missing_ok=True)
            raise DiskImageEmpty()
        try:
            key = f"{org_id}/{uuid.uuid4()}"
            version_id = await storage.put_file(key, spooled.path)
            committed = False
            committing = False
            try:
                # Re-authorized: membership may have changed during a long upload.
                async with org_session(org_id, user, Permission.EVIDENCE_WRITE) as ctx:
                    out = await _insert_records(
                        ctx,
                        request,
                        investigation_id=investigation_id,
                        spooled=spooled,
                        key=key,
                        version_id=version_id,
                        filename=filename,
                        description=description,
                        kind=kind,
                    )
                    committing = True  # leaving the block commits
                committed = True
                await lock_version(org_id, user, out.id, key, version_id, request)
            except BaseException:
                if committing and not committed:
                    # The COMMIT itself failed (or was cancelled): its outcome is unknown,
                    # the row may be committed or still committing, so a check now could
                    # race it. Keep the version (`reconcile_orphans.py` reports an orphan).
                    log.error("kept upload %s %s: commit outcome unknown", key, version_id)
                elif not committed:
                    await discard_version(org_id, user, investigation_id, key, version_id)
                raise
        finally:
            spooled.path.unlink(missing_ok=True)
    # Best effort, after commit: uploads are analyzed automatically (never fails the upload).
    # M8 RT3: never a memory image (an automatic static `av` run would read its contents
    # before the TLP:RED default applies); a memory run is always an explicit request. M9:
    # never a disk image segment either.
    if kind not in IMAGE_KINDS:
        await analysis_service.auto_request(
            org_id, user, out.id, spooled.head, spooled.size, request
        )
    return out
