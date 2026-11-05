"""Render creation and dispatch (frozen entry points of M6 phase 1; implemented by phase 4).

- `create_render` (in the caller's tenant transaction, after its permission check):
  - dedupe: a non-failed render of the same (version, format) is returned. The API holds no
    renderer version; the `report_renders` unique index covers (version, format,
    renderer version) for renders that completed under different renderer versions;
  - caps: `REPORT_ACTIVE_RENDERS_PER_ORG` under the per-org advisory lock, then
    `REPORT_ACTIVE_RENDERS_GLOBAL` under the global one (always in that order, held until
    the commit; the M4 / M5 pattern) -> `409 render_busy` (RT5);
  - a `report_renders` row (`queued`, the token's sha256) and its `report_render_index`
    row (deadline `REPORT_RENDER_DEADLINE_S`).
- `dispatch_render` (after the commit): `ReportRenderMessageV1` with a presigned GET of the
  exact snapshot version, the signed manifest bytes, signature, kid and `finalized_at`, a
  presigned POST for `{org}/{report}/{version}/{render_id}.{ext}` (content type fixed per
  format, 1 … REPORT_MAX_ARTIFACT_BYTES), the token and the deadline; then `report.render`
  on the `report` queue. A publish failure leaves the render `queued` with no
  `dispatched_at`, and the reaper re-dispatches it.

The per-render token is derived, not stored: HMAC-SHA256 under a key derived from the
JWT secret (domain `cyberlab/report-render-token/v1`) over the render id. Only its sha256
is stored (`token_sha256`), and the reaper can rebuild the message for a render whose
first publish was lost (the trigger keeps `token_sha256` immutable, so a fresh random token
could never be re-issued). Whoever holds the JWT secret can already forge any session.

The inputs of a message are taken in the creating transaction (`create_render`, verified
tenant session) and kept in this process until `dispatch_render`; a render whose inputs
are not here (another process, a restart) is left to the reaper, which rebuilds them in
its own vetted session (`input_for`).
"""

import base64
import hashlib
import hmac
import logging
import uuid
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import anyio
from cyberlab_jobs import REPORT_RENDER, PresignedPost, Queues
from cyberlab_jobs.report import (
    RENDER_CONTENT_TYPES,
    RenderFormat,
    ReportRenderMessageV1,
    canonical_json,
)
from minio.datatypes import PostPolicy
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.clients import get_minio
from app.core.config import get_settings
from app.core.errors import Conflict
from app.core.tenancy import tenant_session
from app.core.threads import broker_limiter
from app.modules.reports.models import ReportRender, ReportRenderIndex, ReportVersion

log = logging.getLogger(__name__)

ACTIVE = ("queued", "running")
GLOBAL_LOCK = "report-renders:global"
SEND_TIMEOUT_S = 15
TOKEN_DOMAIN = b"cyberlab/report-render-token/v1"
# Inputs kept between create_render and dispatch_render (bounded: a rolled-back creation
# leaves an entry behind that is never popped).
_PENDING_MAX = 256
_PENDING: OrderedDict[uuid.UUID, "RenderInput"] = OrderedDict()


class RenderBusy(Conflict):
    code = "render_busy"
    message = "Too many renders are active, try again when one has finished"


def org_lock_key(org_id: uuid.UUID) -> str:
    return f"report-renders:{org_id}"


def render_key(
    org_id: uuid.UUID, report_id: uuid.UUID, version: int, render_id: uuid.UUID, fmt: str
) -> str:
    """The only key a renderer may write for a render; ingest re-derives it."""
    return f"{org_id}/{report_id}/{version}/{render_id}.{fmt}"


def render_token(render_id: uuid.UUID) -> str:
    secret = get_settings().need("jwt_secret").encode()
    key = hmac.new(secret, TOKEN_DOMAIN, hashlib.sha256).digest()
    digest = hmac.new(key, render_id.bytes, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def token_sha256(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def token_ok(render: ReportRender, token: str) -> bool:
    return hmac.compare_digest(token_sha256(token), render.token_sha256)


@dataclass(frozen=True)
class RenderInput:
    render_id: uuid.UUID
    org_id: uuid.UUID
    report_id: uuid.UUID
    version: int
    format: str
    object_key: str
    object_version_id: str
    snapshot_sha256: str
    snapshot_bytes: int
    manifest: dict[str, Any]
    signature: str
    kid: str
    deadline: datetime


def input_for(render: ReportRender, version: ReportVersion, deadline: datetime) -> RenderInput:
    return RenderInput(
        render_id=render.id,
        org_id=render.organization_id,
        report_id=version.report_id,
        version=version.version,
        format=render.format,
        object_key=version.object_key,
        object_version_id=version.object_version_id,
        snapshot_sha256=version.snapshot_sha256,
        snapshot_bytes=version.snapshot_bytes,
        manifest=dict(version.manifest),
        signature=version.signature,
        kid=version.kid,
        deadline=deadline,
    )


async def _advisory_lock(session: AsyncSession, key: str) -> None:
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": key}
    )


async def _global_active() -> int:
    """Non-final renders of every org (system lookup; no tenant data)."""
    async with tenant_session(None, None) as session:
        active = await session.scalar(
            select(func.count())
            .select_from(ReportRenderIndex)
            .where(ReportRenderIndex.status.in_(ACTIVE))
        )
    return int(active or 0)


def _remember(item: RenderInput) -> None:
    _PENDING[item.render_id] = item
    while len(_PENDING) > _PENDING_MAX:
        _PENDING.popitem(last=False)


async def create_render_deduplicated(
    session: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    version: ReportVersion,
    fmt: RenderFormat,
) -> tuple[ReportRender, bool]:
    """`create_render` that also says whether an existing render was returned."""
    settings = get_settings()
    await _advisory_lock(session, org_lock_key(org_id))
    existing = await session.scalar(
        select(ReportRender)
        .where(
            ReportRender.organization_id == org_id,
            ReportRender.version_id == version.id,
            ReportRender.format == fmt,
            # M7 (RT11): a purged rendition frees the slot like a failed one (index 0014).
            ReportRender.status.not_in(("failed", "purged")),
        )
        .order_by(ReportRender.created_at.desc())
        .limit(1)
    )
    if existing is not None:
        return existing, True
    active = await session.scalar(
        select(func.count())
        .select_from(ReportRender)
        .where(ReportRender.organization_id == org_id, ReportRender.status.in_(ACTIVE))
    )
    if int(active or 0) >= settings.report_active_renders_per_org:
        raise RenderBusy()
    await _advisory_lock(session, GLOBAL_LOCK)
    if await _global_active() >= settings.report_active_renders_global:
        raise RenderBusy()

    render_id = uuid.uuid4()
    render = ReportRender(
        id=render_id,
        organization_id=org_id,
        version_id=version.id,
        format=fmt,
        status="queued",
        token_sha256=token_sha256(render_token(render_id)),
        requested_by=user_id,
    )
    session.add(render)
    await session.flush()
    deadline = datetime.now(UTC) + timedelta(seconds=settings.report_render_deadline_s)
    session.add(
        ReportRenderIndex(
            render_id=render_id,
            organization_id=org_id,
            status="queued",
            dispatched_at=None,
            deadline_at=deadline,
            attempts=0,
        )
    )
    await session.flush()
    await session.refresh(render)
    _remember(input_for(render, version, deadline))
    return render, False


async def create_render(
    session: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    version: ReportVersion,
    fmt: RenderFormat,
) -> ReportRender:
    render, _ = await create_render_deduplicated(session, org_id, user_id, version, fmt)
    return render


def build_message(item: RenderInput) -> ReportRenderMessageV1:
    """Blocking (MinIO region lookup on first use): call from a worker thread."""
    settings = get_settings()
    minio = get_minio()
    bucket = settings.reports_bucket
    ttl = max(timedelta(seconds=1), item.deadline - datetime.now(UTC))
    snapshot_url = minio.presigned_get_object(
        bucket, item.object_key, expires=ttl, version_id=item.object_version_id
    )
    key = render_key(item.org_id, item.report_id, item.version, item.render_id, item.format)
    content_type = RENDER_CONTENT_TYPES[item.format]
    policy = PostPolicy(bucket, item.deadline)
    policy.add_equals_condition("key", key)
    policy.add_equals_condition("Content-Type", content_type)
    policy.add_content_length_range_condition(1, settings.report_max_artifact_bytes)
    fields = {**minio.presigned_post_policy(policy), "key": key, "Content-Type": content_type}
    scheme = "https" if settings.minio_secure else "http"
    manifest_raw = canonical_json(item.manifest)
    return ReportRenderMessageV1.model_validate(
        {
            "render_id": item.render_id,
            "org_id": item.org_id,
            "format": item.format,
            "snapshot_url": snapshot_url,
            "snapshot_sha256": item.snapshot_sha256,
            "snapshot_bytes": item.snapshot_bytes,
            "manifest_b64": base64.b64encode(manifest_raw).decode(),
            "signature": item.signature,
            "kid": item.kid,
            # The signed instant: the renderer's fixed document and attachment dates.
            "finalized_at": item.manifest["finalized_at"],
            "upload": PresignedPost(
                url=f"{scheme}://{settings.need('minio_endpoint')}/{bucket}", fields=fields
            ),
            "token": render_token(item.render_id),
            "deadline": item.deadline,
        }
    )


def _send_sync(item: RenderInput) -> None:
    from app.workers.celery_app import celery_app  # broker client only, no worker

    message = build_message(item)
    expires = max(1, int((item.deadline - datetime.now(UTC)).total_seconds()))
    celery_app.send_task(
        REPORT_RENDER,
        kwargs={"message": message.model_dump(mode="json")},
        queue=Queues(get_settings().queue_prefix).report,
        # Never run a render whose URLs have expired.
        expires=expires,
        retry=True,
        retry_policy={"max_retries": 1, "interval_start": 0, "interval_step": 0.5},
    )


async def publish(item: RenderInput) -> bool:
    """Send one render message; on success record the dispatch on the index row."""
    try:
        with anyio.fail_after(SEND_TIMEOUT_S):
            await anyio.to_thread.run_sync(
                _send_sync, item, limiter=broker_limiter(), abandon_on_cancel=True
            )
    except Exception as exc:  # noqa: BLE001 - any broker failure is left to the reaper
        log.warning("report.render publish failed for %s (%s)", item.render_id, type(exc).__name__)
        return False
    async with tenant_session(None, None) as session:
        await session.execute(
            update(ReportRenderIndex)
            .where(ReportRenderIndex.render_id == item.render_id)
            .values(dispatched_at=func.now(), attempts=ReportRenderIndex.attempts + 1)
        )
    return True


async def dispatch_render(render_ids: Sequence[uuid.UUID]) -> None:
    """Publish the renders created (and committed) by this process; others are left to the
    reaper. Never raises: the renders are committed."""
    for render_id in render_ids:
        item = _PENDING.pop(render_id, None)
        if item is None:
            log.info("report render %s: not dispatched here, left to the reaper", render_id)
            continue
        await publish(item)
