"""IOC collection and case-wide IOC routes (M6). Frozen in phase 1 as `501 not_implemented`
stubs with their final paths, permissions and models; phase 2 fills the bodies."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import StreamingResponse

from app.core.rbac import OrgContext, Permission, require
from app.core.stubs import not_implemented
from app.core.validation import SearchTerm
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


@router.get("/investigations/{investigation_id}/ioc-collections", response_model=IocCollectionPage)
async def list_collections(
    investigation_id: uuid.UUID, ctx: InvRead, cursor: Cursor = None
) -> IocCollectionPage:
    raise not_implemented()


@router.post(
    "/investigations/{investigation_id}/ioc-collections",
    response_model=IocCollectionOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_collection(
    investigation_id: uuid.UUID, body: IocCollectionCreate, ctx: InvWrite, request: Request
) -> IocCollectionOut:
    """`409 collection_exists` for a duplicate name in the case."""
    raise not_implemented()


@router.get("/ioc-collections/{collection_id}", response_model=IocCollectionDetail)
async def get_collection(collection_id: uuid.UUID, ctx: InvRead) -> IocCollectionDetail:
    raise not_implemented()


@router.patch("/ioc-collections/{collection_id}", response_model=IocCollectionOut)
async def update_collection(
    collection_id: uuid.UUID, body: IocCollectionUpdate, ctx: InvWrite, request: Request
) -> IocCollectionOut:
    raise not_implemented()


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
    raise not_implemented()


@router.post("/ioc-collections/{collection_id}/items", response_model=IocItemsAddResult)
async def add_items(
    collection_id: uuid.UUID, body: IocItemsAdd, ctx: InvWrite, request: Request
) -> IocItemsAddResult:
    """Up to 500 per call; per item `added | duplicate | invalid(reason)`."""
    raise not_implemented()


@router.delete(
    "/ioc-collections/{collection_id}/items/{item_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def remove_item(
    collection_id: uuid.UUID, item_id: uuid.UUID, ctx: InvWrite, request: Request
) -> None:
    """Soft remove (audited)."""
    raise not_implemented()


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
    raise not_implemented()


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
    raise not_implemented()
