"""IOC collection and case-wide IOC routes (M6): paths, permissions and models frozen in
phase 1; bodies in `service.py`, `export.py` and `case_iocs.py`."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import StreamingResponse

from app.core.filenames import content_disposition
from app.core.rbac import OrgContext, Permission, require
from app.core.validation import SearchTerm
from app.modules.investigations import timeline
from app.modules.ioc_collections import case_iocs, export, service
from app.modules.ioc_collections.case_iocs import MAX_PAGE
from app.modules.ioc_collections.schemas import (
    CaseIocPage,
    ExportFormat,
    IocCollectionCreate,
    IocCollectionDetail,
    IocCollectionItemPage,
    IocCollectionOut,
    IocCollectionPage,
    IocCollectionUpdate,
    IocItemsAdd,
    IocItemsAddResult,
    IocTypeName,
)

router = APIRouter(prefix="/orgs/{org_id}", tags=["ioc-collections"])

InvRead = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_READ), scope="function")]
InvWrite = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_WRITE), scope="function")]
EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]
Cursor = Annotated[str | None, Query(max_length=512)]

# Download responses: an attachment, never rendered or sniffed, never cached.
EXPORT_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "sandbox",
    # Exports are never redacted (internal values stay in clear; RT8).
    "X-Export-Redacted": "false",
}


@router.get("/investigations/{investigation_id}/ioc-collections", response_model=IocCollectionPage)
async def list_collections(
    investigation_id: uuid.UUID, ctx: InvRead, cursor: Cursor = None
) -> IocCollectionPage:
    return await service.list_collections(ctx, investigation_id, cursor=cursor)


@router.post(
    "/investigations/{investigation_id}/ioc-collections",
    response_model=IocCollectionOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_collection(
    investigation_id: uuid.UUID, body: IocCollectionCreate, ctx: InvWrite, request: Request
) -> IocCollectionOut:
    """`409 collection_exists` for a duplicate name in the case."""
    return await service.create_collection(ctx, investigation_id, body, request)


@router.get("/ioc-collections/{collection_id}", response_model=IocCollectionDetail)
async def get_collection(collection_id: uuid.UUID, ctx: InvRead) -> IocCollectionDetail:
    return await service.get_collection(ctx, collection_id)


@router.patch("/ioc-collections/{collection_id}", response_model=IocCollectionOut)
async def update_collection(
    collection_id: uuid.UUID, body: IocCollectionUpdate, ctx: InvWrite, request: Request
) -> IocCollectionOut:
    return await service.update_collection(ctx, collection_id, body, request)


@router.get("/ioc-collections/{collection_id}/items", response_model=IocCollectionItemPage)
async def list_items(
    collection_id: uuid.UUID,
    ctx: InvRead,
    type_: Annotated[IocTypeName | None, Query(alias="type")] = None,
    q: Annotated[SearchTerm | None, Query()] = None,
    include_removed: bool = False,
    cursor: Cursor = None,
) -> IocCollectionItemPage:
    """Each item with its attributed TI summary (latest per provider) and source job."""
    return await service.list_items(
        ctx,
        collection_id,
        ioc_type=type_,
        q=q or None,
        include_removed=include_removed,
        cursor=cursor,
    )


@router.post("/ioc-collections/{collection_id}/items", response_model=IocItemsAddResult)
async def add_items(
    collection_id: uuid.UUID, body: IocItemsAdd, ctx: InvWrite, request: Request
) -> IocItemsAddResult:
    """Up to 500 per call; per item `added | duplicate | invalid(reason)`."""
    return await service.add_items(ctx, collection_id, body, request)


@router.delete(
    "/ioc-collections/{collection_id}/items/{item_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def remove_item(
    collection_id: uuid.UUID, item_id: uuid.UUID, ctx: InvWrite, request: Request
) -> None:
    """Soft remove (audited)."""
    await service.remove_item(ctx, collection_id, item_id, request)


@router.get(
    "/ioc-collections/{collection_id}/export",
    response_class=StreamingResponse,
    responses={
        200: {
            "content": {
                "text/csv": {},
                "application/json": {},
                "application/stix+json": {},
            }
        }
    },
)
async def export_collection(
    collection_id: uuid.UUID,
    ctx: EvidenceRead,
    request: Request,
    format: ExportFormat = "csv",
    defang: bool = True,
) -> StreamingResponse:
    """A streamed attachment (RFC 5987 filename, nosniff, no-store, CSP sandbox); never
    redacted; `defang=false` needs `evidence.write`; audited `ioc_collection.exported`."""
    out = await export.export_collection(
        ctx, collection_id, fmt=format, defang=defang, request=request
    )
    return StreamingResponse(
        out.chunks,
        media_type=out.content_type,
        headers={
            **EXPORT_HEADERS,
            "Content-Disposition": content_disposition(out.filename),
            "X-Export-Count": str(out.count),
            "X-Export-Skipped": str(out.skipped),
            "X-Export-Defanged": "true" if defang else "false",
        },
    )


@router.get("/investigations/{investigation_id}/iocs", response_model=CaseIocPage)
async def list_case_iocs(
    investigation_id: uuid.UUID,
    ctx: EvidenceRead,
    type_: Annotated[list[IocTypeName] | None, Query(alias="type", max_length=16)] = None,
    q: Annotated[SearchTerm | None, Query()] = None,
    cursor: Cursor = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 100,
) -> CaseIocPage:
    """IOCs of the latest succeeded job per evidence, deduplicated (`case_iocs.case_iocs`)."""
    await timeline.ensure_investigation(ctx.session, ctx.org_id, investigation_id)
    return await case_iocs.case_iocs(
        ctx.session,
        ctx.org_id,
        investigation_id,
        types=type_ or None,
        q=q or None,
        limit=limit,
        cursor=cursor,
    )
