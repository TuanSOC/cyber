"""Report rendition routes (M6). Frozen in phase 1 as `501 not_implemented` stubs with their
final paths, permissions and models; phase 4 fills the bodies. Rate limit (phase 4): 20
render requests per user per 10 minutes."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Request, status
from fastapi.responses import StreamingResponse

from app.core.rbac import OrgContext, Permission, require
from app.core.stubs import not_implemented
from app.modules.reports.schemas import RenderCreate, RenderList, RenderOut

router = APIRouter(prefix="/orgs/{org_id}", tags=["reports"])

InvRead = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_READ), scope="function")]
InvWrite = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_WRITE), scope="function")]
EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]
Version = Annotated[int, Path(ge=1, le=100_000)]


@router.post(
    "/reports/{report_id}/versions/{version}/renders",
    response_model=RenderOut,
    status_code=status.HTTP_202_ACCEPTED,
    responses={200: {"model": RenderOut, "description": "An existing render (deduplicated)"}},
)
async def request_render(
    report_id: uuid.UUID, version: Version, body: RenderCreate, ctx: InvWrite, request: Request
) -> RenderOut:
    """202 (queued) or 200 (deduplicated); `409 render_busy`."""
    raise not_implemented()


@router.get("/reports/{report_id}/versions/{version}/renders", response_model=RenderList)
async def list_renders(report_id: uuid.UUID, version: Version, ctx: InvRead) -> RenderList:
    raise not_implemented()


@router.get("/report-renders/{render_id}", response_model=RenderOut)
async def get_render(render_id: uuid.UUID, ctx: InvRead) -> RenderOut:
    raise not_implemented()


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
    raise not_implemented()
