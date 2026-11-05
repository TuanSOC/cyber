"""Correlation routes (M7). Paths, permissions and models are frozen in phase 1; every body
answers `501 not_implemented` until phase 4 lands. All reads are `investigation.read` and
RLS-bound: correlation never crosses an org."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.core.rbac import OrgContext, Permission, require
from app.core.stubs import not_implemented
from app.modules.correlation.schemas import (
    CorrelationKind,
    CorrelationLookupOut,
    JobCorrelationsOut,
    RelatedCasesOut,
)

router = APIRouter(prefix="/orgs/{org_id}", tags=["correlation"])

InvRead = Annotated[OrgContext, Depends(require(Permission.INVESTIGATION_READ), scope="function")]


@router.get("/analyses/{job_id}/correlations", response_model=JobCorrelationsOut)
async def job_correlations(job_id: uuid.UUID, ctx: InvRead) -> JobCorrelationsOut:
    """The job's keys that other jobs of the org share ("also seen in")."""
    raise not_implemented()


@router.get("/correlations", response_model=CorrelationLookupOut)
async def lookup(
    ctx: InvRead,
    kind: Annotated[CorrelationKind, Query()],
    value: Annotated[str, Query(min_length=1, max_length=2048)],
) -> CorrelationLookupOut:
    """Where one observable was seen in the org (the server normalizes `value`)."""
    raise not_implemented()


@router.get("/investigations/{investigation_id}/related", response_model=RelatedCasesOut)
async def related_cases(investigation_id: uuid.UUID, ctx: InvRead) -> RelatedCasesOut:
    """Cases sharing at least one non-common key, ranked by shared keys."""
    raise not_implemented()
