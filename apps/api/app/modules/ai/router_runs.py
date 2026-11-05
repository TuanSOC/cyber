"""AI analyst run routes (M5 phase 7; registered via `router.py`).

Requests, previews, revealing a context's pseudonym map and reversing an output's
pseudonyms need `evidence.write`, reads `evidence.read`. A new run answers 202;
an identical active or completed run (deduplicated) answers 200.
"""

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request, Response, status

from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.modules.ai import runs
from app.modules.ai import service_runs as service
from app.modules.ai.contracts import AiRunStatus, AiTask
from app.modules.ai.schemas import (
    AiContextPreviewOut,
    AiRunContextOut,
    AiRunCreate,
    AiRunCreated,
    AiRunDetail,
    AiRunPage,
)

router = APIRouter(prefix="/orgs/{org_id}", tags=["ai"])

EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]
EvidenceWrite = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_WRITE), scope="function")]


@router.post("/ai/context-preview", response_model=AiContextPreviewOut)
async def preview_ai_context(body: AiRunCreate, ctx: EvidenceWrite) -> AiContextPreviewOut:
    """What a run with this body would send (pseudonyms shown). Nothing is persisted."""
    return await service.preview(ctx, body)


@router.post(
    "/ai/runs",
    response_model=AiRunCreated,
    status_code=status.HTTP_202_ACCEPTED,
    responses={200: {"model": AiRunCreated, "description": "Deduplicated"}},
)
async def request_ai_run(
    body: AiRunCreate, ctx: EvidenceWrite, request: Request, response: Response
) -> AiRunCreated:
    """Freeze the context and queue an analysis (an incident also queues one digest per
    job). An identical active or completed run is returned instead (200), unless
    `regenerate`."""
    out, run_ids = await service.request_run(ctx, body, request)
    await ctx.session.commit()
    if out.deduplicated:
        response.status_code = status.HTTP_200_OK
        return out
    # Committed: a lost publish is left to ai.resume and never turns this into an error.
    await runs.dispatch(run_ids)
    return out


@router.get("/ai/runs", response_model=AiRunPage)
async def list_ai_runs(
    ctx: EvidenceRead,
    page: PageParamsDep,
    job_id: uuid.UUID | None = None,
    investigation_id: uuid.UUID | None = None,
    task: AiTask | None = None,
    status_: Annotated[AiRunStatus | None, Query(alias="status")] = None,
    target_id: uuid.UUID | None = None,
) -> AiRunPage:
    """Top-level runs, newest first (incident digests are listed in their parent)."""
    return await service.list_runs(
        ctx,
        page,
        job_id=job_id,
        investigation_id=investigation_id,
        task=task,
        status=status_,
        target_id=target_id,
    )


@router.get("/ai/runs/{run_id}", response_model=AiRunDetail)
async def get_ai_run(
    run_id: uuid.UUID,
    ctx: EvidenceRead,
    pseudonyms: Literal["reverse", "keep"] | None = None,
) -> AiRunDetail:
    """The run with its output read model when completed: claim statuses, resolved
    citations (deep links for verified ones only) and pseudonyms. Reversing them to the
    original internal values needs `evidence.write` (the default for analysts and up unless
    `keep`); viewers always get them kept as sent (403 on an explicit `reverse`)."""
    keep = None if pseudonyms is None else pseudonyms == "keep"
    return await service.get_run(ctx, run_id, keep_pseudonyms=keep)


@router.get("/ai/runs/{run_id}/context", response_model=AiRunContextOut)
async def get_ai_run_context(
    run_id: uuid.UUID, ctx: EvidenceRead, request: Request, reveal: bool = False
) -> AiRunContextOut:
    """The exact frozen context(s) sent; `reveal=true` adds the pseudonym map (audited;
    `evidence.write` only, 403 for viewers)."""
    out = await service.get_context(ctx, run_id, reveal=reveal, request=request)
    if reveal:
        await ctx.session.commit()  # the ai.context_revealed audit row
    return out
