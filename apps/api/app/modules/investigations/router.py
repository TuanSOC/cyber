import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status

from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.core.validation import SearchTerm
from app.modules.investigations import service
from app.modules.investigations.models import InvestigationStatus, Severity
from app.modules.investigations.repository import Filters, SortKey
from app.modules.investigations.schemas import (
    InvestigationCreate,
    InvestigationOut,
    InvestigationPage,
    InvestigationUpdate,
)

router = APIRouter(prefix="/orgs/{org_id}/investigations", tags=["investigations"])

InvRead = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_READ), scope="function")]
InvWrite = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_WRITE), scope="function")]


@router.get("", response_model=InvestigationPage)
async def list_investigations(
    ctx: InvRead,
    page: PageParamsDep,
    q: Annotated[SearchTerm | None, Query()] = None,
    status_: Annotated[InvestigationStatus | None, Query(alias="status")] = None,
    severity: Severity | None = None,
    sort: SortKey = SortKey.CREATED_DESC,
) -> InvestigationPage:
    filters = Filters(q=q or None, status=status_, severity=severity, sort=sort)
    return await service.list_investigations(ctx, filters, page)


@router.post("", response_model=InvestigationOut, status_code=status.HTTP_201_CREATED)
async def create_investigation(
    body: InvestigationCreate, ctx: InvWrite, request: Request
) -> InvestigationOut:
    return await service.create_investigation(ctx, body, request)


@router.get("/{investigation_id}", response_model=InvestigationOut)
async def get_investigation(investigation_id: uuid.UUID, ctx: InvRead) -> InvestigationOut:
    return await service.get_investigation(ctx, investigation_id)


@router.patch("/{investigation_id}", response_model=InvestigationOut)
async def update_investigation(
    investigation_id: uuid.UUID, body: InvestigationUpdate, ctx: InvWrite, request: Request
) -> InvestigationOut:
    return await service.update_investigation(ctx, investigation_id, body, request)
