"""Case timeline export (M6). Path, permission and parameters frozen in phase 1; the body
is phase 5's (`service.py`)."""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from app.core.rbac import OrgContext, Permission, require
from app.modules.case_timeline import service
from app.modules.case_timeline.schemas import TimelineExportFormat
from app.modules.investigations.timeline import TimelineKind

router = APIRouter(prefix="/orgs/{org_id}", tags=["investigations"])

EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]


@router.get(
    "/investigations/{investigation_id}/timeline/export",
    response_class=StreamingResponse,
    responses={200: {"content": {"text/csv": {}, "application/json": {}}}},
)
async def export_timeline(
    investigation_id: uuid.UUID,
    ctx: EvidenceRead,
    request: Request,
    format: TimelineExportFormat = "csv",
    kinds: Annotated[list[TimelineKind] | None, Query(max_length=16)] = None,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
) -> StreamingResponse:
    """A streamed, TLP-headed, formula-safe attachment of at most TIMELINE_EXPORT_MAX_ROWS
    entries (nosniff, no-store, CSP sandbox); audited `investigation.timeline_exported`."""
    return await service.export(
        ctx, investigation_id, request, fmt=format, kinds=kinds, since=from_, until=to
    )
