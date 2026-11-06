import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status

from app.core import rate_limit
from app.core.deps import CurrentUserDep
from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.modules.analysis import repository as repo
from app.modules.analysis import service
from app.modules.analysis.models import AnalysisStatus, Analyzer, JobProfile
from app.modules.analysis.schemas import AnalysisCreate, AnalysisJobOut, AnalysisJobPage
from app.modules.investigations.timeline import ensure_investigation

router = APIRouter(prefix="/orgs/{org_id}", tags=["analysis"])

EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]
MANUAL_RUNS_PER_10MIN = 20


@router.post(
    "/evidence/{evidence_id}/analyses",
    response_model=AnalysisJobOut,
    status_code=status.HTTP_201_CREATED,
)
async def run_analysis(
    org_id: uuid.UUID,
    evidence_id: uuid.UUID,
    body: AnalysisCreate,
    user: CurrentUserDep,
    request: Request,
) -> AnalysisJobOut:
    """Queue an analyzer run over the evidence (re-runs keep earlier jobs as history)."""
    await rate_limit.hit(f"analysis:run:{user.id}", MANUAL_RUNS_PER_10MIN, 600)
    return await service.request_analysis(
        org_id,
        user,
        evidence_id,
        request,
        analyzer=body.analyzer,
        profile=body.profile,
        os_hint=body.os_hint,
        segments=body.segments,
        source_job_id=body.source_job_id,
        decompile_addresses=body.decompile_address_values(),
    )


@router.get("/evidence/{evidence_id}/analyses", response_model=AnalysisJobPage)
async def list_evidence_analyses(
    evidence_id: uuid.UUID, ctx: EvidenceRead, page: PageParamsDep
) -> AnalysisJobPage:
    return await service.list_jobs(ctx, page, evidence_id=evidence_id)


@router.get("/analyses", response_model=AnalysisJobPage)
async def list_analyses(
    ctx: EvidenceRead,
    page: PageParamsDep,
    status: Annotated[AnalysisStatus | None, Query()] = None,
    analyzer: Annotated[Analyzer | None, Query()] = None,
    profile: Annotated[JobProfile | None, Query()] = None,
    investigation_id: Annotated[uuid.UUID | None, Query()] = None,
    latest_per_evidence: Annotated[bool, Query()] = False,
) -> AnalysisJobPage:
    """`investigation_id`: only that case's evidence (404 for an unknown or foreign case);
    `latest_per_evidence`: the newest job per evidence and kind of run (analyzer, profile)
    among the jobs matching the other filters."""
    if investigation_id is not None:
        await ensure_investigation(ctx.session, ctx.org_id, investigation_id)
    rows, total = await repo.list_rows(
        ctx.session,
        ctx.org_id,
        page,
        status=status,
        analyzer=analyzer,
        profile=profile,
        investigation_id=investigation_id,
        latest_per_evidence=latest_per_evidence,
    )
    return AnalysisJobPage(items=[service.to_out(r) for r in rows], total=total)


@router.get("/analyses/{job_id}", response_model=AnalysisJobOut)
async def get_analysis(job_id: uuid.UUID, ctx: EvidenceRead) -> AnalysisJobOut:
    return await service.get_job(ctx, job_id)
