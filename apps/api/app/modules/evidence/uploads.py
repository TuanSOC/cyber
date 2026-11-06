"""Evidence upload: spool + hash -> store exact version -> record -> retention lock.

Once the evidence rows are committed nothing may turn the request into an error: the
retention lock, its failure audit and the slot release are all best effort (logged).
"""

import logging
import uuid

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
from app.modules.evidence import repository as repo
from app.modules.evidence.locking import discard_version, lock_version
from app.modules.evidence.models import CustodyAction, Evidence, EvidenceHash, HashAlgorithm
from app.modules.evidence.schemas import EvidenceOut
from app.modules.evidence.service import ensure_open_investigation, record_event, to_out
from app.modules.organizations import storage as quota

log = logging.getLogger(__name__)


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


def _type_check(filename: str, mime: str, head: bytes) -> tuple[str | None, str | None, bool]:
    """(declared family, detected family, mismatch). Metadata only: never raises, never
    rejects, and the analyzers' routing is unchanged."""
    try:
        declared = filetypes.declared_family(filename)
        detected = filetypes.detected_family(mime, filetypes.magic_route(head))
    except Exception:  # a classification bug must not lose the evidence
        log.exception("file type classification failed")
        return None, None, False
    return declared, detected, filetypes.type_mismatch(declared, detected)


def _check_request(request: Request) -> int:
    """Validates the headers; returns the declared length (0 when not declared)."""
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/octet-stream":
        raise UnsupportedMediaType()
    declared = request.headers.get("content-length", "")
    size = int(declared) if declared.isdigit() else 0
    if size > get_settings().max_evidence_bytes:
        raise PayloadTooLarge()
    return size


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
) -> EvidenceOut:
    await ensure_open_investigation(ctx, investigation_id)
    # Case (FOR SHARE) before org lock: a case update holding the case row then inserting
    # its audit row (KEY SHARE on the org) can then never wait in a cycle with this upload.
    await quota.reserve(ctx, spooled.size)
    mime, kind = _sniff(spooled.head)
    stored_name = sanitize_filename(filename)
    declared, detected, mismatch = _type_check(stored_name, mime, spooled.head)
    evidence = Evidence(
        organization_id=ctx.org_id,
        investigation_id=investigation_id,
        original_filename=stored_name,
        detected_mime=mime,
        detected_description=kind,
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
) -> EvidenceOut:
    settings = get_settings()
    declared = _check_request(request)
    async with org_session(org_id, user, Permission.EVIDENCE_WRITE) as ctx:
        await ensure_open_investigation(ctx, investigation_id)
        # Early, unlocked: refuse a declared size that cannot fit before reading the body.
        # Authoritative (actual size, org locked) again before the records commit.
        await quota.check_fits(ctx, declared)

    async with slot("upload", user.id, settings.max_concurrent_uploads_per_user):
        try:
            spooled = await spool(
                request.stream(), settings.upload_tmp_dir, settings.max_evidence_bytes
            )
        except TooLarge as exc:
            raise PayloadTooLarge() from exc
        except ClientDisconnect as exc:
            raise ClientGone() from exc
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
    await analysis_service.auto_request(org_id, user, out.id, spooled.head, spooled.size, request)
    return out
