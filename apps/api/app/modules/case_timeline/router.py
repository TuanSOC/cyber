"""Case timeline export (M6). Frozen in phase 1 as a `501 not_implemented` stub with its
final path, permission and parameters; phase 5 fills the body."""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from app.core.rbac import OrgContext, Permission, require
from app.core.stubs import not_implemented
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
    raise not_implemented()
