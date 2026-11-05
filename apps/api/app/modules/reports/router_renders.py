"""Report rendition routes (M6). Frozen in phase 1 with their final paths, permissions and
models; bodies by phase 4.

- `POST …/versions/{v}/renders` (`investigation.write`, 20 per user per 10 minutes):
  `{format}` -> 202 with a new queued render, or 200 with the existing non-failed render of
  that format (dedupe); `409 render_busy` over the active caps. Audited
  `report.render_requested`.
- `GET …/versions/{v}/renders`, `GET /report-renders/{id}` (`investigation.read`).
- `GET /report-renders/{id}/download` (`evidence.read`): the exact object version is
  re-hashed before the first byte is sent (`409 integrity_failed`, audited
  `report.integrity_failed`) and again while it streams (a mismatch aborts the stream). An
  attachment named `CASE-00012_v2_TLP-AMBER.pdf` (RFC 5987), `nosniff`, `no-store`, and
  `Content-Security-Policy: sandbox` (`sandbox; default-src 'none'; style-src
  'unsafe-inline'` for HTML). Audited `report.downloaded` (format, version, TLP).
"""

import hashlib
import logging
import uuid
from collections.abc import AsyncIterator
from typing import Annotated

from cyberlab_jobs.report import RENDER_CONTENT_TYPES, TLP, TLP_LABELS
from fastapi import APIRouter, Depends, Path, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from app.core import rate_limit, storage
from app.core.config import get_settings
from app.core.errors import Conflict, NotFound
from app.core.filenames import content_disposition
from app.core.rbac import OrgContext, Permission, require
from app.modules.audit import service as audit
from app.modules.investigations.models import Investigation
from app.modules.investigations.schemas import case_ref
from app.modules.reports import dispatch
from app.modules.reports.models import Report, ReportRender, ReportVersion
from app.modules.reports.schemas import RenderCreate, RenderList, RenderOut

log = logging.getLogger(__name__)

router = APIRouter(prefix="/orgs/{org_id}", tags=["reports"])

InvRead = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_READ), scope="function")]
InvWrite = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_WRITE), scope="function")]
EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]
Version = Annotated[int, Path(ge=1, le=100_000)]

DOWNLOAD_HEADERS = {"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}
CSP = {
    "pdf": "sandbox",
    "md": "sandbox",
    "html": "sandbox; default-src 'none'; style-src 'unsafe-inline'",
}


class RenderNotReady(Conflict):
    code = "render_not_ready"
    message = "This rendition has not succeeded"


class IntegrityFailed(Conflict):
    code = "integrity_failed"
    message = "The stored rendition does not match its recorded hash"


def _out(render: ReportRender) -> RenderOut:
    return RenderOut(
        id=render.id,
        version_id=render.version_id,
        format=render.format,
        status=render.status,
        error_code=render.error_code,
        sha256=render.sha256,
        bytes=render.bytes,
        pages=render.pages,
        renderer_version=render.renderer_version,
        requested_by=render.requested_by,
        created_at=render.created_at,
        started_at=render.started_at,
        finished_at=render.finished_at,
    )


async def _version(ctx: OrgContext, report_id: uuid.UUID, version: int) -> ReportVersion:
    row = await ctx.session.scalar(
        select(ReportVersion).where(
            ReportVersion.organization_id == ctx.org_id,
            ReportVersion.report_id == report_id,
            ReportVersion.version == version,
        )
    )
    if row is None:
        raise NotFound()
    return row


async def _render(ctx: OrgContext, render_id: uuid.UUID) -> ReportRender:
    row = await ctx.session.scalar(
        select(ReportRender).where(
            ReportRender.organization_id == ctx.org_id, ReportRender.id == render_id
        )
    )
    if row is None:
        raise NotFound()
    return row


@router.post(
    "/reports/{report_id}/versions/{version}/renders",
    response_model=RenderOut,
    status_code=status.HTTP_202_ACCEPTED,
    responses={200: {"model": RenderOut, "description": "An existing render (deduplicated)"}},
)
async def request_render(
    report_id: uuid.UUID,
    version: Version,
    body: RenderCreate,
    ctx: InvWrite,
    request: Request,
    response: Response,
) -> RenderOut:
    """202 (queued) or 200 (deduplicated); `409 render_busy`."""
    settings = get_settings()
    await rate_limit.hit(
        f"reports:render:{ctx.user.id}", settings.report_renders_per_user_10min, 600
    )
    row = await _version(ctx, report_id, version)
    render, deduplicated = await dispatch.create_render_deduplicated(
        ctx.session, ctx.org_id, ctx.user.id, row, body.format
    )
    if not deduplicated:
        audit.record(
            ctx.session,
            action="report.render_requested",
            org_id=ctx.org_id,
            actor_id=ctx.user.id,
            target_type="report_render",
            target_id=render.id,
            details={"report_id": str(report_id), "version": version, "format": body.format},
            request=request,
        )
    out = _out(render)
    await ctx.session.commit()
    if deduplicated:
        response.status_code = status.HTTP_200_OK
    else:
        await dispatch.dispatch_render([render.id])
    return out


@router.get("/reports/{report_id}/versions/{version}/renders", response_model=RenderList)
async def list_renders(report_id: uuid.UUID, version: Version, ctx: InvRead) -> RenderList:
    row = await _version(ctx, report_id, version)
    renders = (
        await ctx.session.scalars(
            select(ReportRender)
            .where(ReportRender.organization_id == ctx.org_id, ReportRender.version_id == row.id)
            .order_by(ReportRender.created_at, ReportRender.id)
        )
    ).all()
    return RenderList(items=[_out(r) for r in renders])


@router.get("/report-renders/{render_id}", response_model=RenderOut)
async def get_render(render_id: uuid.UUID, ctx: InvRead) -> RenderOut:
    return _out(await _render(ctx, render_id))


def download_name(case_number: int, version: int, tlp: str, fmt: str) -> str:
    """`CASE-00012_v2_TLP-AMBER.pdf` (`TLP:AMBER+STRICT` -> `TLP-AMBER+STRICT`)."""
    label = TLP_LABELS[TLP(tlp)].replace(":", "-")
    return f"{case_ref(case_number)}_v{version}_{label}.{fmt}"


async def _verified_stream(
    bucket: str, key: str, version_id: str, sha256: str, size: int, render_id: uuid.UUID
) -> AsyncIterator[bytes]:
    """The exact object version, hashed again while it streams: a mismatch (the object
    changed after the pre-check) aborts the response before its last byte."""
    digest, seen = hashlib.sha256(), 0
    async for chunk in storage.iter_version(bucket, key, version_id):
        seen += len(chunk)
        digest.update(chunk)
        if seen > size:
            break
        if seen == size and digest.hexdigest() != sha256:
            break
        yield chunk
    if seen != size or digest.hexdigest() != sha256:
        log.error("report render %s: integrity failed while streaming", render_id)
        raise IntegrityFailed()


@router.get(
    "/report-renders/{render_id}/download",
    response_class=StreamingResponse,
    responses={
        200: {
            "content": {
                "application/pdf": {},
                "text/html": {},
                "text/markdown": {},
            }
        }
    },
)
async def download_render(
    render_id: uuid.UUID, ctx: EvidenceRead, request: Request
) -> StreamingResponse:
    """Streamed from the exact object version, re-hashed while streaming (`409
    integrity_failed`); attachment with the TLP in the filename, nosniff, no-store, CSP
    sandbox; audited `report.downloaded`."""
    render = await _render(ctx, render_id)
    if render.status != "succeeded" or render.object_version_id is None:
        raise RenderNotReady()
    version = await ctx.session.get(ReportVersion, render.version_id)
    report = await ctx.session.get(Report, version.report_id) if version else None
    case = await ctx.session.get(Investigation, report.investigation_id) if report else None
    if version is None or report is None or case is None:  # pragma: no cover - FKs
        raise NotFound()
    bucket = get_settings().reports_bucket
    key = dispatch.render_key(ctx.org_id, report.id, version.version, render.id, render.format)
    details = {
        "report_id": str(report.id),
        "version": version.version,
        "format": render.format,
        "tlp": version.tlp,
    }
    try:
        size, hashes = await storage.hash_version(bucket, key, render.object_version_id)
        intact = size == render.bytes and hashes["sha256"] == render.sha256
    except storage.ObjectMissing:
        intact = False
    if not intact:
        audit.record(
            ctx.session,
            action="report.integrity_failed",
            org_id=ctx.org_id,
            actor_id=ctx.user.id,
            target_type="report_render",
            target_id=render.id,
            details=details,
            request=request,
        )
        await ctx.session.commit()
        log.error("report render %s: stored artifact does not match its hash", render.id)
        raise IntegrityFailed()
    audit.record(
        ctx.session,
        action="report.downloaded",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="report_render",
        target_id=render.id,
        details=details,
        request=request,
    )
    filename = download_name(case.case_number, version.version, version.tlp, render.format)
    expected_sha, expected_size = str(render.sha256), int(render.bytes or 0)
    version_id, fmt = render.object_version_id, render.format
    await ctx.session.commit()
    return StreamingResponse(
        _verified_stream(bucket, key, version_id, expected_sha, expected_size, render_id),
        media_type=RENDER_CONTENT_TYPES[fmt],
        headers={
            **DOWNLOAD_HEADERS,
            "Content-Security-Policy": CSP[fmt],
            "Content-Disposition": content_disposition(filename),
            "Content-Length": str(expected_size),
        },
    )
