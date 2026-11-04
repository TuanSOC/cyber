"""Threat intel results routes (M4 phase 5; registered through `router.py`): the history of
one indicator and single results (`evidence.read`). The latest answer per provider on an
analysis job's IOC list is `GET /analyses/{job_id}/iocs?include=enrichment`."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.modules.threat_intel import service_results as service
from app.modules.threat_intel.models import MAX_VALUE_CHARS
from app.modules.threat_intel.providers.base import ProviderName
from app.modules.threat_intel.schemas import HistoryOut, LookupType, ResultOut

router = APIRouter(prefix="/orgs/{org_id}/ti/results", tags=["threat-intel"])

EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]


@router.get("", response_model=HistoryOut)
async def get_history(
    ctx: EvidenceRead,
    page: PageParamsDep,
    value: Annotated[str, Query(min_length=1, max_length=MAX_VALUE_CHARS)],
    type: LookupType | None = None,  # noqa: A002 - public query parameter name
    provider: ProviderName | None = None,
) -> HistoryOut:
    """Every stored answer for the normalized indicator, newest first (400 `invalid_ioc`
    when the value cannot be normalized; `skipped` says why no provider would receive it)."""
    return await service.history(ctx, page, value=value, type_=type, provider=provider)


@router.get("/{result_id}", response_model=ResultOut)
async def get_result(result_id: uuid.UUID, ctx: EvidenceRead) -> ResultOut:
    return await service.get_result(ctx, result_id)
