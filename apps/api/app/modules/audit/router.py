import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import AwareDatetime

from app.core.errors import AppError
from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.core.validation import SearchTerm
from app.modules.audit import repository
from app.modules.audit.repository import AuditFilters
from app.modules.audit.schemas import AuditLogOut, AuditLogPage

router = APIRouter(prefix="/orgs/{org_id}/audit-logs", tags=["audit"])

AuditRead = Annotated[OrgContext, Depends(require(Permission.AUDIT_READ), scope="function")]


class InvalidRange(AppError):
    status_code = 422
    code = "validation_error"
    message = "`from` must be earlier than `to`"


@router.get("", response_model=AuditLogPage)
async def list_audit_logs(
    ctx: AuditRead,
    page: PageParamsDep,
    action: Annotated[SearchTerm | None, Query(max_length=100)] = None,
    actor_id: uuid.UUID | None = None,
    occurred_from: Annotated[AwareDatetime | None, Query(alias="from")] = None,
    occurred_to: Annotated[AwareDatetime | None, Query(alias="to")] = None,
) -> AuditLogPage:
    if occurred_from and occurred_to and occurred_from >= occurred_to:
        raise InvalidRange()
    filters = AuditFilters(
        action=action, actor_id=actor_id, occurred_from=occurred_from, occurred_to=occurred_to
    )
    rows, total = await repository.list_logs(ctx.session, ctx.org_id, filters, page)
    items = [
        AuditLogOut.model_validate(log).model_copy(update={"actor_email": email})
        for log, email in rows
    ]
    return AuditLogPage(items=items, total=total)
