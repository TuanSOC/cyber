import contextlib
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import StreamingResponse
from pydantic import StringConstraints

from app.core import audit_dedupe
from app.core.clients import get_redis
from app.core.config import get_settings
from app.core.deps import CurrentUserDep
from app.core.filenames import content_disposition
from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.modules.audit import service as audit
from app.modules.evidence import service, share_policy, transfer, uploads
from app.modules.evidence.schemas import CustodyPage, EvidenceOut, EvidencePage, VerifyOut
from app.modules.investigations.schemas import EvidenceSharePolicyIn, EvidenceSharePolicyOut

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

VIEWED = "evidence.viewed"
CUSTODY_VIEWED = "evidence.custody_viewed"


async def _audit_view(ctx: OrgContext, evidence_id: uuid.UUID, action: str) -> None:
    """M7 (§10 auditable access): one `audit_logs` row per (user, evidence, action) per
    `EVIDENCE_VIEW_AUDIT_DEDUPE_S` (15 min), after the read found the evidence (a 404 for
    another org writes nothing). In the request's tenant session, committed here (these read
    routes otherwise never commit). No details beyond the ids and no IP: the row carries the
    actor. The list routes are not audited (the detail and custody views are the access).
    A Redis failure raises (503): the audit fails closed. If the commit fails, the dedupe key
    is given back so the next view records the row."""
    key = f"{ctx.user.id}:{evidence_id}:{action}"
    if not await audit_dedupe.once_per(key, get_settings().evidence_view_audit_dedupe_s):
        return
    try:
        audit.record(
            ctx.session,
            action=action,
            org_id=ctx.org_id,
            actor_id=ctx.user.id,
            target_type="evidence",
            target_id=evidence_id,
        )
        await ctx.session.commit()
    except Exception:
        with contextlib.suppress(Exception):
            await get_redis().delete(audit_dedupe.PREFIX + key)
        raise


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
    out = await service.get_evidence(ctx, evidence_id)
    await _audit_view(ctx, evidence_id, VIEWED)
    return out


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
    out = await service.custody(ctx, evidence_id, page)
    await _audit_view(ctx, evidence_id, CUSTODY_VIEWED)
    return out


# --- share policy (M6) ----------------------------------------------------------------------


@router.get("/evidence/{evidence_id}/share-policy", response_model=EvidenceSharePolicyOut)
async def get_share_policy(evidence_id: uuid.UUID, ctx: EvidenceRead) -> EvidenceSharePolicyOut:
    """The evidence's "do not send to AI / TI" flags and its effective policy."""
    return await share_policy.get_policy(ctx, evidence_id)


@router.put("/evidence/{evidence_id}/share-policy", response_model=EvidenceSharePolicyOut)
async def put_share_policy(
    evidence_id: uuid.UUID, body: EvidenceSharePolicyIn, ctx: EvidenceWrite, request: Request
) -> EvidenceSharePolicyOut:
    """Set the flags (turning one off needs `integrations.manage`); audited
    `evidence.share_policy_updated`. The evidence row itself is never touched."""
    return await share_policy.put_policy(ctx, evidence_id, body, request)
