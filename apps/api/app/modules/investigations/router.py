import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status

from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.core.validation import SearchTerm
from app.modules.investigations import service
from app.modules.investigations import timeline as case_timeline
from app.modules.investigations.models import InvestigationStatus, Severity
from app.modules.investigations.repository import Filters, SortKey
from app.modules.investigations.schemas import (
    InvestigationCreate,
    InvestigationOut,
    InvestigationPage,
    InvestigationTimelinePage,
    InvestigationUpdate,
    StatusEventPage,
    TimelineEntryOut,
)

router = APIRouter(prefix="/orgs/{org_id}/investigations", tags=["investigations"])

InvRead = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_READ), scope="function")]
InvWrite = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_WRITE), scope="function")]
EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]


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


@router.get("/{investigation_id}/timeline", response_model=InvestigationTimelinePage)
async def get_investigation_timeline(
    investigation_id: uuid.UUID,
    ctx: EvidenceRead,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=case_timeline.MAX_PAGE)] = case_timeline.DEFAULT_PAGE,
    kinds: Annotated[list[case_timeline.TimelineKind] | None, Query(max_length=16)] = None,
) -> InvestigationTimelinePage:
    """Merged case timeline: custody, job lifecycle, the latest pcap job's timeline and alerts
    per evidence, and static findings at analysis time; sorted (ts, kind, ref_id). M6: case
    events (notes, status changes) have no `evidence_id`; `kinds` filters by ref kind."""
    await case_timeline.ensure_investigation(ctx.session, ctx.org_id, investigation_id)
    after = case_timeline.Cursor.decode(cursor) if cursor else None
    entries = await case_timeline.page(
        ctx.session, ctx.org_id, investigation_id, limit=limit + 1, after=after, kinds=kinds
    )
    return InvestigationTimelinePage(
        items=[TimelineEntryOut.model_validate(e, from_attributes=True) for e in entries[:limit]],
        next_cursor=case_timeline.next_cursor(entries, limit),
    )


@router.get("/{investigation_id}/status-events", response_model=StatusEventPage)
async def list_status_events(
    investigation_id: uuid.UUID,
    ctx: InvRead,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> StatusEventPage:
    """Status history of the case, newest first, with the actor's display name (M6)."""
    return await service.list_status_events(ctx, investigation_id, cursor=cursor, limit=limit)
