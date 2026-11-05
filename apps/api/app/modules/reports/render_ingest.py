"""`report.rendered` in the trusted ingest worker (frozen entry point of M6 phase 1;
implemented by phase 4).

Nothing in the renderer's answer is trusted beyond what it proves:

1. The render's org comes from `report_render_index` (system session), never from the
   message. The per-render token must hash to the stored `token_sha256`, and the render must
   still be `queued` or `running`; anything else is logged (ids only) and dropped. A final
   render never changes again (the transition trigger enforces it too).
2. `succeeded`: the uploaded object is read back from MinIO at the key re-derived here and
   at the version id the renderer reported, outside any transaction. Its size must be
   1 … REPORT_MAX_ARTIFACT_BYTES and equal the message's `bytes`; its sha256 is computed here
   and must equal the message's `sha256`; the magic must match the format (`%PDF-`, strict
   UTF-8 for HTML / Markdown). Ingest never parses the artifact (RT27). On any mismatch the
   render fails with `invalid_output`. Otherwise the per-object GOVERNANCE retention
   (EVIDENCE_LOCK_DAYS; 0 disables it) is set on that exact version (RT6) and the render
   becomes `succeeded` (through `running`, the trigger's only path) with the sha256, size,
   pages, renderer version and object version.
3. `failed`: the typed `error_code` is stored.
4. Audit `report.rendered` / `report.render_failed` (format, version, code).

Allowlisted in `tests/unit/test_tenant_session_guard.py` (org from the index + token).
"""

import codecs
import hashlib
import logging
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import anyio
from cyberlab_jobs.report import ReportRenderedV1
from minio.error import S3Error
from pydantic import ValidationError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import storage
from app.core.clients import get_minio
from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.core.threads import evidence_io_limiter
from app.modules.audit import service as audit
from app.modules.reports import dispatch
from app.modules.reports.models import ReportRender, ReportRenderIndex, ReportVersion

log = logging.getLogger(__name__)

OPEN = ("queued", "running")
CHUNK = 256 * 1024
PDF_MAGIC = b"%PDF-"
_MISSING = {"NoSuchKey", "NoSuchVersion", "InvalidArgument", "BadRequest"}


@dataclass(frozen=True)
class _Target:
    org_id: uuid.UUID
    format: str
    key: str
    report_id: uuid.UUID
    version: int


class _Invalid(Exception):
    """The uploaded artifact does not match the answer (-> `invalid_output`)."""


async def _org_of(render_id: uuid.UUID) -> uuid.UUID | None:
    async with tenant_session(None, None) as session:
        return await session.scalar(
            select(ReportRenderIndex.organization_id).where(
                ReportRenderIndex.render_id == render_id
            )
        )


async def _locked(
    session: AsyncSession, org_id: uuid.UUID, msg: ReportRenderedV1
) -> tuple[ReportRender, ReportVersion] | None:
    """The render (locked) and its version, if the token proves the message and the render
    is still open."""
    render = await session.scalar(
        select(ReportRender)
        .where(ReportRender.id == msg.render_id, ReportRender.organization_id == org_id)
        .with_for_update()
    )
    if render is None:
        log.warning("report.rendered %s: no such render", msg.render_id)
        return None
    if not dispatch.token_ok(render, msg.token):
        log.warning("report.rendered %s: token mismatch", msg.render_id)
        return None
    if render.status not in OPEN:
        log.warning("report.rendered %s: render already %s", msg.render_id, render.status)
        return None
    version = await session.get(ReportVersion, render.version_id)
    if version is None:  # pragma: no cover - composite FK
        return None
    return render, version


def _check_sync(
    bucket: str, key: str, version_id: str, fmt: str, max_bytes: int
) -> tuple[int, str]:
    """(size, sha256) of the exact object version, with the format's magic checked."""
    client = get_minio()
    try:
        stat = client.stat_object(bucket, key, version_id=version_id)
    except S3Error as exc:
        if exc.code in _MISSING:
            raise _Invalid("missing") from exc
        raise
    if stat.size is None or not 1 <= stat.size <= max_bytes:
        raise _Invalid("size")
    response = client.get_object(bucket, key, version_id=version_id)
    digest = hashlib.sha256()
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    size, head = 0, b""
    try:
        while chunk := response.read(CHUNK):
            size += len(chunk)
            if size > max_bytes:
                raise _Invalid("size")
            if len(head) < len(PDF_MAGIC):
                head = (head + chunk)[: len(PDF_MAGIC)]
            if fmt != "pdf":
                decoder.decode(chunk)
            digest.update(chunk)
        if fmt != "pdf":
            decoder.decode(b"", final=True)
    except UnicodeDecodeError as exc:
        raise _Invalid("utf8") from exc
    finally:
        response.close()
        response.release_conn()
    if fmt == "pdf" and head != PDF_MAGIC:
        raise _Invalid("magic")
    return size, digest.hexdigest()


async def _verify_artifact(target: _Target, msg: ReportRenderedV1) -> None:
    settings = get_settings()
    if msg.object_version_id is None:  # pragma: no cover - the contract requires it
        raise _Invalid("version")
    size, sha = await anyio.to_thread.run_sync(
        _check_sync,
        settings.reports_bucket,
        target.key,
        msg.object_version_id,
        target.format,
        settings.report_max_artifact_bytes,
        limiter=evidence_io_limiter(),
    )
    if size != msg.bytes or sha != msg.sha256:
        raise _Invalid("hash")
    if settings.evidence_lock_days > 0:  # 0 disables locking (the test stack)
        until = datetime.now(UTC) + timedelta(days=settings.evidence_lock_days)
        await storage.set_retention(
            settings.reports_bucket, target.key, msg.object_version_id, until
        )


def _audit(
    session: AsyncSession,
    render: ReportRender,
    version: ReportVersion,
    action: str,
    **details: Any,
) -> None:
    audit.record(
        session,
        action=action,
        org_id=render.organization_id,
        actor_id=None,
        target_type="report_render",
        target_id=render.id,
        details={
            "report_id": str(version.report_id),
            "version": version.version,
            "format": render.format,
            **details,
        },
    )


async def _finish(
    session: AsyncSession,
    render: ReportRender,
    version: ReportVersion,
    msg: ReportRenderedV1,
    error_code: str | None,
) -> None:
    now = datetime.now(UTC)
    if error_code is None:
        if render.status == "queued":  # the trigger's only path to succeeded
            render.status = "running"
            render.started_at = now
            await session.flush()
        render.status = "succeeded"
        render.sha256 = msg.sha256
        render.bytes = msg.bytes
        render.pages = msg.pages
        render.object_version_id = msg.object_version_id
    else:
        render.status = "failed"
        render.error_code = error_code
    render.renderer_version = msg.renderer_version
    render.finished_at = now
    await session.flush()
    await session.execute(
        update(ReportRenderIndex)
        .where(ReportRenderIndex.render_id == render.id)
        .values(status=render.status)
    )
    if error_code is None:
        _audit(
            session,
            render,
            version,
            "report.rendered",
            bytes=msg.bytes,
            pages=msg.pages,
            renderer_version=msg.renderer_version,
        )
    else:
        _audit(session, render, version, "report.render_failed", error_code=error_code)


async def handle_rendered(msg: ReportRenderedV1) -> None:
    org_id = await _org_of(msg.render_id)
    if org_id is None:
        log.warning("report.rendered %s: unknown render", msg.render_id)
        return
    error_code: str | None = msg.error_code if msg.status == "failed" else None
    if msg.status == "succeeded":
        # Prove the message first, then read the object outside any transaction.
        async with tenant_session(org_id, None) as session:
            found = await _locked(session, org_id, msg)
            if found is None:
                return
            render, version = found
            target = _Target(
                org_id,
                render.format,
                dispatch.render_key(
                    org_id, version.report_id, version.version, render.id, render.format
                ),
                version.report_id,
                version.version,
            )
        try:
            await _verify_artifact(target, msg)
        except _Invalid as exc:
            log.warning("report.rendered %s: artifact refused (%s)", msg.render_id, exc)
            error_code = "invalid_output"
    async with tenant_session(org_id, None) as session:
        found = await _locked(session, org_id, msg)
        if found is None:
            return
        render, version = found
        await _finish(session, render, version, msg, error_code)
    log.info("report render %s: %s %s", msg.render_id, render.status, error_code)


async def handle_rendered_message(message: Mapping[str, Any]) -> None:
    """The Celery entry point: validate, then `handle_rendered` (ids only in the logs)."""
    try:
        msg = ReportRenderedV1.model_validate(message)
    except ValidationError:
        log.warning("report.rendered: invalid message dropped")
        return
    await handle_rendered(msg)
