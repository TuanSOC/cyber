"""Read API over one memory analysis job's persisted results (evidence.read; M8 phase 7 on the
phase-1 frozen paths and models).

Every route answers 404 for unknown or foreign jobs and for jobs of another analyzer, and
`409 analysis_not_ready` while the job is queued or running. Findings, IOCs and the timeline
of memory jobs are served by the shared per-job routes (pcap_analysis.router: /findings,
/iocs, /timeline). Reads are not audited (the M7 evidence view audit covers the job page).
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query

from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.core.validation import SearchTerm
from app.modules.memory_analysis import repository as repo
from app.modules.memory_analysis import service
from app.modules.memory_analysis.schemas import (
    ArtifactPage,
    ConnectionPage,
    InjectionPage,
    MemoryArtifactType,
    MemorySummaryOut,
    ProcessDetailOut,
    ProcessPage,
)

router = APIRouter(prefix="/orgs/{org_id}/analyses/{job_id}/memory", tags=["memory-analysis"])

EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]
Search = Annotated[SearchTerm | None, Query()]
# `ref=<row id>`: a page with just that row of the job (citation deep links; 404 otherwise).
RowRef = Annotated[uuid.UUID | None, Query()]
PidFilter = Annotated[int | None, Query(ge=0, le=2**32 - 1)]


@router.get("", response_model=MemorySummaryOut)
async def get_memory_summary(job_id: uuid.UUID, ctx: EvidenceRead) -> MemorySummaryOut:
    """The image facts, symbols outcome and per-plugin status of a memory job (a
    `symbols_missing` job has a summary with the requirement; `404 results_not_available`
    for a terminal job without a stored result)."""
    job = await service.ready_job(ctx.session, ctx.org_id, job_id)
    return await service.summary(ctx.session, ctx.org_id, job)


@router.get("/processes", response_model=ProcessPage)
async def list_processes(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    q: Search = None,
    ppid: PidFilter = None,
    hidden: Annotated[bool | None, Query()] = None,
    ref: RowRef = None,
    view: Annotated[service.ProcessView, Query()] = "list",
) -> ProcessPage:
    """`q`: substring of name, image path or command line; `hidden`: seen by psscan only.

    `view=tree`: the whole job in depth-first pre-order (siblings oldest first; orphans and
    cycle breakers are roots; `children` counts tree children), no filters (422). A job with
    more than `MEMORY_TREE_MAX_NODES` processes answers the list order instead, with a
    `total` above that cap."""
    await service.ready_job(ctx.session, ctx.org_id, job_id)
    items, total = await service.process_page(
        ctx.session, ctx.org_id, job_id, page, view=view, q=q, ppid=ppid, hidden=hidden, ref=ref
    )
    return ProcessPage(items=items, total=total)


@router.get("/processes/{pid}", response_model=ProcessDetailOut)
async def get_process(
    job_id: uuid.UUID, pid: Annotated[int, Path(ge=0, le=2**32 - 1)], ctx: EvidenceRead
) -> ProcessDetailOut:
    """One process with its parent, children, connections, private executable regions and
    artifacts (each at most 200); 404 for a pid the job does not have."""
    await service.ready_job(ctx.session, ctx.org_id, job_id)
    return await service.process_detail(ctx.session, ctx.org_id, job_id, pid)


@router.get("/connections", response_model=ConnectionPage)
async def list_connections(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    pid: PidFilter = None,
    q: Search = None,
    ref: RowRef = None,
) -> ConnectionPage:
    """`q`: substring of either address, the owner or the state."""
    await service.ready_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.connections(
        ctx.session, ctx.org_id, job_id, page, pid=pid, q=q, ref=ref
    )
    return ConnectionPage(items=[service.connection_out(r) for r in rows], total=total)


@router.get("/injections", response_model=InjectionPage)
async def list_injections(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    pid: PidFilter = None,
    ref: RowRef = None,
) -> InjectionPage:
    """Private executable regions: the hex head and disassembly are plain text."""
    await service.ready_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.injections(ctx.session, ctx.org_id, job_id, page, pid=pid, ref=ref)
    return InjectionPage(items=[service.injection_out(r) for r in rows], total=total)


@router.get("/artifacts", response_model=ArtifactPage)
async def list_artifacts(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    type: Annotated[MemoryArtifactType | None, Query()] = None,  # noqa: A002 - API name
    pid: PidFilter = None,
    q: Search = None,
    ref: RowRef = None,
) -> ArtifactPage:
    """`q`: substring of an attribute value (never a key)."""
    await service.ready_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.artifacts(
        ctx.session, ctx.org_id, job_id, page, type_=type, pid=pid, q=q, ref=ref
    )
    return ArtifactPage(items=[service.artifact_out(r) for r in rows], total=total)
