"""Evidence upload: spool + hash -> store exact version -> record -> retention lock.

Once the evidence rows are committed nothing may turn the request into an error: the
retention lock, its failure audit and the slot release are all best effort (logged).
"""

import logging
import uuid

import magic
from starlette.requests import ClientDisconnect, Request

from app.core import storage
from app.core.config import get_settings
from app.core.deps import CurrentUser
from app.core.errors import AppError
from app.core.filenames import sanitize_filename
from app.core.hashing import ALGORITHMS, Spooled, TooLarge, spool
from app.core.rbac import OrgContext, Permission, org_session
from app.core.upload_slots import slot
from app.modules.analysis import service as analysis_service
from app.modules.evidence import repository as repo
from app.modules.evidence.locking import discard_version, lock_version
from app.modules.evidence.models import CustodyAction, Evidence, EvidenceHash, HashAlgorithm
from app.modules.evidence.schemas import EvidenceOut
from app.modules.evidence.service import ensure_open_investigation, record_event, to_out

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


def _check_request(request: Request) -> None:
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/octet-stream":
        raise UnsupportedMediaType()
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > get_settings().max_evidence_bytes:
        raise PayloadTooLarge()


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
    mime, kind = _sniff(spooled.head)
    evidence = Evidence(
        organization_id=ctx.org_id,
        investigation_id=investigation_id,
        original_filename=sanitize_filename(filename),
        detected_mime=mime,
        detected_description=kind,
        size_bytes=spooled.size,
        storage_bucket=storage.bucket(),
        storage_key=key,
        storage_version_id=version_id,
        description=description,
        uploaded_by=ctx.user.id,
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
    return to_out(repo.EvidenceRow(evidence, ctx.user.display_name, dict(spooled.hashes)))


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
    _check_request(request)
    async with org_session(org_id, user, Permission.EVIDENCE_WRITE) as ctx:
        await ensure_open_investigation(ctx, investigation_id)

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
                committed = True
                await lock_version(org_id, user, out.id, key, version_id, request)
            except BaseException:
                if not committed:
                    await discard_version(key, version_id)
                raise
        finally:
            spooled.path.unlink(missing_ok=True)
    # Best effort, after commit: uploads are analyzed automatically (never fails the upload).
    await analysis_service.auto_request(org_id, user, out.id, spooled.head, spooled.size, request)
    return out
