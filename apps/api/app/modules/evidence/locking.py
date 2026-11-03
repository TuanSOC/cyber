"""Retention locking of committed evidence versions, and cleanup of failed uploads."""

import logging
import uuid
from datetime import UTC, datetime, timedelta

import anyio
from starlette.requests import Request

from app.core import storage
from app.core.config import get_settings
from app.core.deps import CurrentUser
from app.core.rbac import Permission, org_session
from app.modules.evidence.service import record_event

log = logging.getLogger(__name__)


async def discard_version(key: str, version_id: str) -> None:
    """Remove exactly the version stored for a failed upload (not yet retention-locked)."""
    with anyio.CancelScope(shield=True):
        try:
            await storage.delete_version(storage.bucket(), key, version_id)
        except Exception:
            log.exception("orphaned evidence version %s %s", key, version_id)


async def lock_version(
    org_id: uuid.UUID,
    user: CurrentUser,
    evidence_id: uuid.UUID,
    key: str,
    version_id: str,
    request: Request,
) -> None:
    """Retention-lock the committed version. Never raises: the upload already succeeded."""
    days = get_settings().evidence_lock_days
    if days <= 0:
        return
    with anyio.CancelScope(shield=True):
        try:
            until = datetime.now(UTC) + timedelta(days=days)
            await storage.set_retention(storage.bucket(), key, version_id, until)
            return
        except Exception:
            log.exception("could not set retention on evidence %s", evidence_id)
        try:
            async with org_session(org_id, user, Permission.EVIDENCE_READ) as ctx:
                record_event(
                    ctx,
                    evidence_id=evidence_id,
                    action=None,
                    audit_action="evidence.lock_failed",
                    request=request,
                )
        except Exception:
            log.exception("could not audit lock failure of evidence %s", evidence_id)
