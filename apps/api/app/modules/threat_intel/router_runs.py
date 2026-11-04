"""Threat intel enrichment run routes (M4 phase 5; registered through `router.py`).

Requests need `evidence.write`, reads `evidence.read`. A new run answers 202; an active run
of the same job (deduplicated) or a request with nothing eligible answers 200.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response, status

from app.core.deps import CurrentUserDep
from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.modules.threat_intel import service_runs as service
from app.modules.threat_intel.providers.base import ProviderName
from app.modules.threat_intel.schemas import (
    EnrichmentCreate,
    ItemState,
    LookupCreate,
    RunDetailOut,
    RunPage,
    RunRequestOut,
    RunStatus,
)

router = APIRouter(prefix="/orgs/{org_id}", tags=["threat-intel"])

EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]


def _status(response: Response, created: bool) -> None:
    response.status_code = status.HTTP_202_ACCEPTED if created else status.HTTP_200_OK


@router.post(
    "/analyses/{job_id}/enrichments",
    response_model=RunRequestOut,
    status_code=status.HTTP_202_ACCEPTED,
    responses={200: {"model": RunRequestOut, "description": "Deduplicated or nothing eligible"}},
)
async def request_job_enrichment(
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    body: EnrichmentCreate,
    user: CurrentUserDep,
    request: Request,
    response: Response,
) -> RunRequestOut:
    """Enrich a succeeded analysis job's IOC set (sample hashes first, then by count)."""
    out, created = await service.request_job_enrichment(
        org_id, user, job_id, body.providers, request
    )
    _status(response, created)
    return out


@router.post(
    "/ti/lookups",
    response_model=RunRequestOut,
    status_code=status.HTTP_202_ACCEPTED,
    responses={200: {"model": RunRequestOut, "description": "Nothing eligible (report only)"}},
)
async def request_lookup(
    org_id: uuid.UUID,
    body: LookupCreate,
    user: CurrentUserDep,
    request: Request,
    response: Response,
) -> RunRequestOut:
    """Manual IOC lookup: a per-value normalization report plus the run (if any value is
    eligible for a requested provider)."""
    out, created = await service.request_lookup(org_id, user, body, request)
    _status(response, created)
    return out


@router.get("/ti/runs", response_model=RunPage)
async def list_runs(
    ctx: EvidenceRead,
    page: PageParamsDep,
    job_id: uuid.UUID | None = None,
    status_: Annotated[RunStatus | None, Query(alias="status")] = None,
) -> RunPage:
    return await service.list_runs(ctx, page, job_id=job_id, status=status_)


@router.get("/ti/runs/{run_id}", response_model=RunDetailOut)
async def get_run(
    run_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    provider: ProviderName | None = None,
    state: ItemState | None = None,
) -> RunDetailOut:
    """The run with one page of its items, each with its result (`from_cache` when the
    answer came from an earlier run)."""
    return await service.get_run(ctx, run_id, page, provider=provider, state=state)
