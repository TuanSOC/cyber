"""Retention locking of committed evidence versions, and cleanup of failed uploads."""

import logging
import uuid
from datetime import UTC, datetime, timedelta

import anyio
from sqlalchemy import select
from starlette.requests import Request

from app.core import storage
from app.core.config import get_settings
from app.core.deps import CurrentUser
from app.core.rbac import Permission, org_session
from app.modules.evidence.models import Evidence
from app.modules.evidence.service import record_event
from app.modules.retention.holds import active_holds

log = logging.getLogger(__name__)


async def _may_discard(
    org_id: uuid.UUID, user: CurrentUser, investigation_id: uuid.UUID, key: str
) -> bool:
    """No evidence row records the key and no legal hold (case or org, active or released
    within the delay, RT1) covers the case. The uploader's membership is re-checked (the
    vetted org session); losing it raises, which keeps the version."""
    async with org_session(org_id, user, Permission.EVIDENCE_WRITE) as ctx:
        recorded = (
            await ctx.session.execute(select(Evidence.id).where(Evidence.storage_key == key))
        ).first()
        if recorded is not None:
            return False
        holds = await active_holds(ctx.session, org_id, now=datetime.now(UTC))
        return not holds.covers(investigation_id)


async def discard_version(
    org_id: uuid.UUID,
    user: CurrentUser,
    investigation_id: uuid.UUID,
    key: str,
    version_id: str,
) -> None:
    """Remove exactly the version stored for a failed upload (never committed, not yet
    retention-locked). This is the api's only evidence delete (its MinIO delete grant, RT5),
    and it refuses (keeps the version; `reconcile_orphans.py` reports it) when an evidence
    row records the key, when a legal hold covers the case or the org, or when that cannot be
    checked: the api never deletes committed or held evidence, whatever the lock says."""
    with anyio.CancelScope(shield=True):
        try:
            allowed = await _may_discard(org_id, user, investigation_id, key)
        except Exception:
            log.exception("kept failed upload %s %s: hold check failed", key, version_id)
            return
        if not allowed:
            log.warning("kept failed upload %s %s: recorded or under legal hold", key, version_id)
            return
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
