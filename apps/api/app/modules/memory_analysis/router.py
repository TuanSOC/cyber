"""Read API over one memory analysis job's persisted results (evidence.read; M8 phase 1 stubs,
phase 7 implements them with their final paths, permissions and models).

Every route will answer 404 for unknown or foreign jobs and for jobs of another analyzer.
Findings, IOCs and the timeline of memory jobs are served by the shared per-job routes
(pcap_analysis.router: /findings, /iocs, /timeline).
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query

from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.core.stubs import not_implemented
from app.core.validation import SearchTerm
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
    """The image facts, symbols outcome and per-plugin status of a memory job."""
    raise not_implemented()


@router.get("/processes", response_model=ProcessPage)
async def list_processes(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    q: Search = None,
    ppid: PidFilter = None,
    hidden: Annotated[bool | None, Query()] = None,
    ref: RowRef = None,
) -> ProcessPage:
    """`q`: substring of name, image path or command line; `hidden`: seen by psscan only."""
    raise not_implemented()


@router.get("/processes/{pid}", response_model=ProcessDetailOut)
async def get_process(
    job_id: uuid.UUID, pid: Annotated[int, Path(ge=0, le=2**32 - 1)], ctx: EvidenceRead
) -> ProcessDetailOut:
    raise not_implemented()


@router.get("/connections", response_model=ConnectionPage)
async def list_connections(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    pid: PidFilter = None,
    q: Search = None,
    ref: RowRef = None,
) -> ConnectionPage:
    raise not_implemented()


@router.get("/injections", response_model=InjectionPage)
async def list_injections(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    pid: PidFilter = None,
    ref: RowRef = None,
) -> InjectionPage:
    raise not_implemented()


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
    raise not_implemented()
