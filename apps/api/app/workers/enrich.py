"""Enrich worker logic (trusted, internet-facing; M4).

Phase 1 skeleton: the worker checks its keys at startup and consumes `ti.enrich`, but has no
providers yet, so a run it receives ends `failed` with `not_implemented`. Phase 2 replaces
`handle_enrich` with the time-sliced run loop.

The org comes from `ti_run_index` (system data, read in a system session); the message's org
must match it before a tenant session is opened for that org.
"""

import base64
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError
from sqlalchemy import select

from app.core.config import Settings
from app.core.tenancy import tenant_session
from app.modules.threat_intel.messages import TiRunMessage
from app.modules.threat_intel.models import RUN_FINAL, TiEnrichmentRun, TiRunIndex
from app.modules.threat_intel.seal import raw_public
from app.modules.threat_intel.unseal import UnsealError, load_private_keys

log = logging.getLogger(__name__)


def check_startup(settings: Settings) -> None:
    """Refuse to start without a usable private key for the active kid (clear message)."""
    if settings.process_role != "enrich":
        raise RuntimeError("the enrich worker needs PROCESS_ROLE=enrich")
    path = settings.ti_seal_private_keys_file
    if path is None:
        raise RuntimeError("TI_SEAL_PRIVATE_KEYS_FILE is not set")
    try:
        keys = load_private_keys(path)
    except UnsealError as exc:
        raise RuntimeError(f"seal private key file {path} is unusable ({exc.code})") from None
    kid = settings.ti_seal_active_kid
    if not kid or kid not in keys:
        raise RuntimeError(f"seal private key file {path} lacks the active kid {kid!r}")
    published = settings.ti_seal_public_keys.get(kid)
    derived = base64.b64encode(raw_public(keys[kid].public_key())).decode()
    if published != derived:
        raise RuntimeError(f"TI_SEAL_PUBLIC_KEYS[{kid!r}] does not match the private key file")


async def _drop(reason: str, message: dict[str, Any]) -> None:
    # Ids only: a message never carries values or keys, but log nothing else either.
    log.warning("ti.enrich dropped (%s): run %s", reason, str(message.get("run_id"))[:36])


async def handle_enrich(message: dict[str, Any]) -> None:
    try:
        msg = TiRunMessage.model_validate(message)
    except ValidationError:
        await _drop("invalid message", message)
        return
    async with tenant_session(None, None) as session:
        index = await session.get(TiRunIndex, msg.run_id)
        org_id: uuid.UUID | None = index.organization_id if index else None
        status = index.status if index else None
    if org_id is None or org_id != msg.org_id:
        await _drop("unknown run or org mismatch", message)
        return
    if status in RUN_FINAL:
        return

    # Phase 1: no provider is wired up yet; end the run instead of leaving it queued.
    async with tenant_session(org_id, None) as session:
        run = await session.scalar(
            select(TiEnrichmentRun).where(TiEnrichmentRun.id == msg.run_id).with_for_update()
        )
        index = await session.get(TiRunIndex, msg.run_id, with_for_update=True)
        if run is None or index is None or run.status in RUN_FINAL:
            return
        now = datetime.now(UTC)
        run.status = "failed"
        run.summary = {"error_code": "not_implemented"}
        run.finished_at = now
        index.status = "failed"
        index.lease_until = None
        index.lease_owner = None
    log.info("ti run %s failed: not_implemented", msg.run_id)
