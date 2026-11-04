"""The trusted AI analyst worker (M5). Phase 1: a no-op that fails every run with
`not_implemented`; phase 2 owns this module afterwards (lifecycle, lease, limiter, budget,
provider call, verification, persistence).

Isolation (clone of the M4 enrich worker): `PROCESS_ROLE=analyst`, networks `enrich` +
`egress`, no JWT secret / MinIO / app Redis / TI private key (Settings refuses them), its own
broker user confined to `analyst*`. Only `app/workers/analyst*.py` may import `ai.unseal`.

The org always comes from the non-tenant `ai_run_index` (system data); a message whose org
differs is dropped.
"""

import base64
import logging
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError
from sqlalchemy import func, select, update

from app.core.config import Settings
from app.core.sealbox import raw_public
from app.core.tenancy import tenant_session
from app.modules.ai.contracts import RUN_FINAL, AiErrorCode, AiRunStatus
from app.modules.ai.messages import AiResumeMessage, AiRunMessage, AiVerifyMessage
from app.modules.ai.models import AiRun, AiRunIndex
from app.modules.ai.unseal import UnsealError, load_private_keys

log = logging.getLogger(__name__)


def check_startup(settings: Settings) -> None:
    """Refuse to start without a usable AI private key for the active kid (clear message)."""
    if settings.process_role != "analyst":
        raise RuntimeError("the analyst worker needs PROCESS_ROLE=analyst")
    path = settings.ai_seal_private_keys_file
    if path is None:
        raise RuntimeError("AI_SEAL_PRIVATE_KEYS_FILE is not set")
    try:
        keys = load_private_keys(path)
    except UnsealError as exc:
        raise RuntimeError(f"AI seal private key file {path} is unusable ({exc.code})") from None
    kid = settings.ai_seal_active_kid
    if not kid or kid not in keys:
        raise RuntimeError(f"AI seal private key file {path} lacks the active kid {kid!r}")
    published = settings.ai_seal_public_keys.get(kid)
    derived = base64.b64encode(raw_public(keys[kid].public_key())).decode()
    if published != derived:
        raise RuntimeError(f"AI_SEAL_PUBLIC_KEYS[{kid!r}] does not match the private key file")


def _drop(reason: str, message: Mapping[str, Any]) -> None:
    # Ids only (messages carry nothing else); never message bodies of other shapes.
    log.warning("dropped ai message: %s (keys=%s)", reason, sorted(message)[:8])


async def handle_run(message: Mapping[str, Any]) -> AiRunStatus | None:
    """Phase 1: mark a non-final run `failed / not_implemented`. Returns the new status, or
    None when nothing changed (invalid message, unknown run, org mismatch, already final)."""
    try:
        msg = AiRunMessage.model_validate(message)
    except ValidationError:
        _drop("invalid message", message)
        return None
    async with tenant_session(None, None) as session:
        org_id = (
            await session.execute(
                select(AiRunIndex.organization_id).where(AiRunIndex.run_id == msg.run_id)
            )
        ).scalar_one_or_none()
    if org_id is None or org_id != msg.org_id:
        _drop("unknown run or org mismatch", message)
        return None
    async with tenant_session(org_id, None) as session:
        run = (
            await session.execute(select(AiRun).where(AiRun.id == msg.run_id).with_for_update())
        ).scalar_one_or_none()
        if run is None or run.status in RUN_FINAL:
            return None
        await session.execute(
            update(AiRun)
            .where(AiRun.id == msg.run_id)
            .values(
                status=AiRunStatus.FAILED,
                error_code=AiErrorCode.NOT_IMPLEMENTED,
                finished_at=func.now(),
            )
        )
        await session.execute(
            update(AiRunIndex)
            .where(AiRunIndex.run_id == msg.run_id)
            .values(status=AiRunStatus.FAILED, lease_until=None, lease_owner=None)
        )
    log.info("ai run %s failed: %s", msg.run_id, AiErrorCode.NOT_IMPLEMENTED.value)
    return AiRunStatus.FAILED


async def handle_resume(message: Mapping[str, Any] | None = None) -> int:
    """Phase 1: validates and does nothing (phase 2 re-sends due runs)."""
    try:
        AiResumeMessage.model_validate(message or {})
    except ValidationError:
        _drop("invalid message", message or {})
    return 0


async def handle_verify(message: Mapping[str, Any]) -> None:
    """Phase 1: validates and does nothing (phase 2 verifies the key with the provider)."""
    try:
        AiVerifyMessage.model_validate(message)
    except ValidationError:
        _drop("invalid message", message)
