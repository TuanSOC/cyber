"""Correlation routes (M7). Paths, permissions and models are frozen in phase 1; bodies in
`service.py` (phase 4). All reads are `investigation.read` and RLS-bound: correlation never
crosses an org. The key lookup is a POST with the value in the body (an IOC value never goes
in a URL, RT13); the GET routes carry ids and filters only."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.core.rbac import OrgContext, Permission, require
from app.modules.correlation import service
from app.modules.correlation.schemas import (
    CorrelationKind,
    CorrelationLookupIn,
    CorrelationLookupOut,
    JobCorrelationsOut,
    RelatedCasesOut,
)

router = APIRouter(prefix="/orgs/{org_id}", tags=["correlation"])

InvRead = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_READ), scope="function")]


@router.get("/analyses/{job_id}/correlations", response_model=JobCorrelationsOut)
async def job_correlations(
    job_id: uuid.UUID,
    ctx: InvRead,
    kind: Annotated[CorrelationKind | None, Query()] = None,
    cursor: Annotated[
        str | None, Query(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    ] = None,
    include_unique: Annotated[bool, Query()] = False,
) -> JobCorrelationsOut:
    """The job's keys that other jobs of the org share ("also seen in"); `kind` narrows to
    one kind, `include_unique` adds the keys seen nowhere else, `cursor` continues
    (`400 invalid_cursor`)."""
    return await service.job_correlations(
        ctx, job_id, kind=kind, cursor=cursor, include_unique=include_unique
    )


@router.post("/correlations/lookup", response_model=CorrelationLookupOut)
async def lookup(body: CorrelationLookupIn, ctx: InvRead) -> CorrelationLookupOut:
    """Where one observable was seen in the org (the server normalizes `value`; `422
    search_query_invalid` when it does not normalize as `kind`), with the stored threat
    intel answer count and the IOC collections holding it. A POST so the value stays out of
    every URL and access log (RT13); a read, so it writes nothing and is not audited."""
    return await service.lookup(ctx, body.kind, body.value)


@router.get("/investigations/{investigation_id}/related", response_model=RelatedCasesOut)
async def related_cases(investigation_id: uuid.UUID, ctx: InvRead) -> RelatedCasesOut:
    """Cases sharing at least one non-common key, ranked by shared keys."""
    return await service.related_cases(ctx, investigation_id)
