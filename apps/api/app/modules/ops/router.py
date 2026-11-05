"""Org operations metrics (M7). Path, permission and models are frozen in phase 1; the body
answers `501 not_implemented` until phase 5 lands."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.core.rbac import OrgContext, Permission, require
from app.core.stubs import not_implemented
from app.modules.ops.schemas import OrgOpsMetricsOut, Window

router = APIRouter(prefix="/orgs/{org_id}", tags=["ops"])

AuditRead = Annotated[OrgContext, Depends(require(Permission.AUDIT_READ), scope="function")]


@router.get("/ops/metrics", response_model=OrgOpsMetricsOut)
async def org_metrics(
    ctx: AuditRead, window: Annotated[Window, Query()] = "24h"
) -> OrgOpsMetricsOut:
    """The org's failure rate, latency and parse success per analyzer, TI / AI provider and
    report format over the window."""
    raise not_implemented()
