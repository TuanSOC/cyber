import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import StreamingResponse
from pydantic import StringConstraints

from app.core.deps import CurrentUserDep
from app.core.filenames import content_disposition
from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.modules.evidence import service, transfer, uploads
from app.modules.evidence.schemas import CustodyPage, EvidenceOut, EvidencePage, VerifyOut

router = APIRouter(prefix="/orgs/{org_id}", tags=["evidence"])

EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]
EvidenceWrite = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_WRITE), scope="function")]
Filename = Annotated[str, StringConstraints(min_length=1, max_length=1024, pattern=r"^[^\x00]+$")]
Description = Annotated[str, StringConstraints(max_length=2000, pattern=r"^[^\x00]*$")]

# Download responses: never rendered or sniffed by the browser, never cached.
DOWNLOAD_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "sandbox",
}


@router.post(
    "/investigations/{investigation_id}/evidence",
    response_model=EvidenceOut,
    status_code=status.HTTP_201_CREATED,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}
            },
        }
    },
)
async def upload_evidence(
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    user: CurrentUserDep,
    request: Request,
    filename: Annotated[Filename, Query()],
    description: Annotated[Description, Query()] = "",
) -> EvidenceOut:
    """Raw request body = the evidence bytes (streamed, hashed, stored; never parsed)."""
    return await uploads.upload(
        request,
        org_id=org_id,
        investigation_id=investigation_id,
        user=user,
        filename=filename,
        description=description,
    )


@router.get("/investigations/{investigation_id}/evidence", response_model=EvidencePage)
async def list_evidence(
    investigation_id: uuid.UUID, ctx: EvidenceRead, page: PageParamsDep
) -> EvidencePage:
    return await service.list_for_investigation(ctx, investigation_id, page)


@router.get("/evidence/{evidence_id}", response_model=EvidenceOut)
async def get_evidence(evidence_id: uuid.UUID, ctx: EvidenceRead) -> EvidenceOut:
    return await service.get_evidence(ctx, evidence_id)


@router.get(
    "/evidence/{evidence_id}/download",
    response_class=StreamingResponse,
    responses={200: {"content": {"application/octet-stream": {}}}},
)
async def download_evidence(
    org_id: uuid.UUID, evidence_id: uuid.UUID, user: CurrentUserDep, request: Request
) -> StreamingResponse:
    download = await transfer.download(request, org_id=org_id, evidence_id=evidence_id, user=user)
    return StreamingResponse(
        download.chunks,
        media_type="application/octet-stream",
        headers={
            **DOWNLOAD_HEADERS,
            "Content-Disposition": content_disposition(download.filename),
            "Content-Length": str(download.size_bytes),
        },
    )


@router.post("/evidence/{evidence_id}/verify", response_model=VerifyOut)
async def verify_evidence(
    org_id: uuid.UUID, evidence_id: uuid.UUID, user: CurrentUserDep, request: Request
) -> VerifyOut:
    return await transfer.verify(request, org_id=org_id, evidence_id=evidence_id, user=user)


@router.post("/evidence/{evidence_id}/archive", response_model=EvidenceOut)
async def archive_evidence(
    evidence_id: uuid.UUID, ctx: EvidenceWrite, request: Request
) -> EvidenceOut:
    return await service.archive(ctx, evidence_id, request)


@router.get("/evidence/{evidence_id}/custody", response_model=CustodyPage)
async def evidence_custody(
    evidence_id: uuid.UUID, ctx: EvidenceRead, page: PageParamsDep
) -> CustodyPage:
    return await service.custody(ctx, evidence_id, page)
