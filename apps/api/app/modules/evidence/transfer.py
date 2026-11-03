"""Evidence download and re-verification, always by exact stored bucket + version."""

import logging
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Literal

from starlette.requests import Request

from app.core import storage
from app.core.config import get_settings
from app.core.deps import CurrentUser
from app.core.errors import AppError
from app.core.rbac import Permission, org_session
from app.core.upload_slots import slot
from app.modules.evidence.models import CustodyAction
from app.modules.evidence.schemas import VerifyOut
from app.modules.evidence.service import get_row, record_event

log = logging.getLogger(__name__)


class ContentMissing(AppError):
    status_code = 409
    code = "evidence_content_missing"
    message = "Stored evidence content is missing; run verify"


@dataclass(frozen=True)
class Download:
    filename: str
    size_bytes: int
    chunks: AsyncIterator[bytes]


async def _prefetched(first: bytes, rest: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    if first:
        yield first
    async for chunk in rest:
        yield chunk


async def download(
    request: Request, *, org_id: uuid.UUID, evidence_id: uuid.UUID, user: CurrentUser
) -> Download:
    async with org_session(org_id, user, Permission.EVIDENCE_READ) as ctx:
        row = await get_row(ctx, evidence_id)
    e = row.evidence
    chunks = storage.iter_version(e.storage_bucket, e.storage_key, e.storage_version_id)
    try:
        first = await anext(chunks, b"")  # fail before headers are sent if content is gone
        # The download *request* is recorded (and committed) before streaming starts.
        async with org_session(org_id, user, Permission.EVIDENCE_READ) as ctx:
            record_event(
                ctx,
                evidence_id=evidence_id,
                action=CustodyAction.DOWNLOADED,
                audit_action="evidence.downloaded",
                request=request,
            )
    except storage.ObjectMissing as exc:
        raise ContentMissing() from exc
    except BaseException:
        await chunks.aclose()  # release the storage connection
        raise
    return Download(e.original_filename, e.size_bytes, _prefetched(first, chunks))


async def verify(
    request: Request, *, org_id: uuid.UUID, evidence_id: uuid.UUID, user: CurrentUser
) -> VerifyOut:
    async with org_session(org_id, user, Permission.EVIDENCE_WRITE) as ctx:
        row = await get_row(ctx, evidence_id)
    e, expected = row.evidence, row.hashes
    result: Literal["ok", "mismatch", "missing"]
    reason: Literal["hash", "size", "missing"] | None = None
    size: int | None
    actual: dict[str, str] | None
    async with slot("verify", user.id, get_settings().max_concurrent_uploads_per_user):
        try:
            size, actual = await storage.hash_version(
                e.storage_bucket, e.storage_key, e.storage_version_id
            )
            if actual != expected:
                result, reason = "mismatch", "hash"
            elif size != e.size_bytes:
                result, reason = "mismatch", "size"
            else:
                result = "ok"
        except storage.ObjectMissing:
            size, actual, result, reason = None, None, "missing", "missing"

    async with org_session(org_id, user, Permission.EVIDENCE_WRITE) as ctx:
        record_event(
            ctx,
            evidence_id=evidence_id,
            action=CustodyAction.VERIFIED_OK if result == "ok" else CustodyAction.VERIFIED_MISMATCH,
            audit_action="evidence.verified",
            request=request,
            custody_details={} if reason is None else {"result": result, "reason": reason},
            audit_details={"result": result},
        )
    if result != "ok":
        log.warning("evidence %s failed verification: %s", evidence_id, reason)
    return VerifyOut(result=result, expected=expected, actual=actual, size_bytes=size)
