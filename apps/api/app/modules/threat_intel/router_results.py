"""Threat intel results routes (M4 phase 5; registered through `router.py`): the history of
one indicator and single results (`evidence.read`). The latest answer per provider on an
analysis job's IOC list is `GET /analyses/{job_id}/iocs?include=enrichment`.

M7 phase 11: the history is `POST /ti/results/lookup` with the indicator in the JSON body
(the M4 `GET /ti/results?value=` put IOC values into URLs and access logs, RT13); the
pagination stays in the query string (it carries no indicator).
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends

from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.modules.threat_intel import service_results as service
from app.modules.threat_intel.schemas import HistoryLookupIn, HistoryOut, ResultOut

router = APIRouter(prefix="/orgs/{org_id}/ti/results", tags=["threat-intel"])

EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]


@router.post("/lookup", response_model=HistoryOut)
async def lookup_history(
    body: HistoryLookupIn, ctx: EvidenceRead, page: PageParamsDep
) -> HistoryOut:
    """Every stored answer for the normalized indicator, newest first (400 `invalid_ioc`
    when the value cannot be normalized; `skipped` says why no provider would receive it).
    A POST so the indicator stays out of every URL and access log; a read: it writes
    nothing and is not audited."""
    return await service.history(
        ctx, page, value=body.value, type_=body.type, provider=body.provider
    )


@router.get("/{result_id}", response_model=ResultOut)
async def get_result(result_id: uuid.UUID, ctx: EvidenceRead) -> ResultOut:
    return await service.get_result(ctx, result_id)
