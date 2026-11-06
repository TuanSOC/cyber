"""Read API over one reverse-engineering job's persisted results (evidence.read; M10 phase 1
stubs on the frozen paths and schemas, phase 8 implements them).

Every route will answer 404 for unknown or foreign jobs and for jobs of another analyzer,
`404 function_not_found` for an entry that is not a function of the job, and `409
analysis_not_ready` while the job is queued or running. Findings and IOCs of RE jobs are
served by the shared per-job routes (pcap_analysis.router: /findings, /iocs). Until phase 8
every route answers `501 not_implemented`. No call-graph route (RT24).
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query

from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.core.stubs import not_implemented
from app.core.validation import SearchTerm
from app.modules.reverse_engineering.schemas import (
    HEX_ADDRESS_PATTERN,
    FunctionCodeOut,
    FunctionDetailOut,
    FunctionPage,
    ImportPage,
    ReSummaryOut,
    StringPage,
)

router = APIRouter(prefix="/orgs/{org_id}/analyses/{job_id}/reverse", tags=["reverse-engineering"])

EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]
Search = Annotated[SearchTerm | None, Query(min_length=1, max_length=128)]
# `ref=<row id>`: a page with just that row of the job (citation deep links; 404 otherwise).
RowRef = Annotated[uuid.UUID | None, Query()]
Entry = Annotated[str, Path(pattern=HEX_ADDRESS_PATTERN, examples=["0x401000"])]


@router.get("", response_model=ReSummaryOut)
async def get_re_summary(job_id: uuid.UUID, ctx: EvidenceRead) -> ReSummaryOut:
    """Program facts, the per-stage status (with `truncated` flags), counts and the newer RE
    job of the same sample, if any."""
    raise not_implemented()


@router.get("/functions", response_model=FunctionPage)
async def list_functions(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    q: Search = None,
    decompiled: Annotated[bool | None, Query()] = None,
    has_capability: Annotated[bool | None, Query()] = None,
    calls_suspicious_import: Annotated[bool | None, Query()] = None,
    references_ioc_string: Annotated[bool | None, Query()] = None,
    include_library: Annotated[bool, Query()] = False,
    ref: RowRef = None,
) -> FunctionPage:
    """Functions by priority rank, then entry. `q`: a name substring."""
    raise not_implemented()


@router.get("/functions/{entry}", response_model=FunctionDetailOut)
async def get_function(job_id: uuid.UUID, entry: Entry, ctx: EvidenceRead) -> FunctionDetailOut:
    raise not_implemented()


@router.get("/functions/{entry}/code", response_model=FunctionCodeOut)
async def get_function_code(
    job_id: uuid.UUID, entry: Entry, ctx: EvidenceRead
) -> FunctionCodeOut:
    """The decompiled (or disassembled) text of one function: untrusted text."""
    raise not_implemented()


@router.get("/imports", response_model=ImportPage)
async def list_imports(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    q: Search = None,
    library: Search = None,
    ref: RowRef = None,
) -> ImportPage:
    raise not_implemented()


@router.get("/strings", response_model=StringPage)
async def list_strings(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    q: Search = None,
    referenced: Annotated[bool | None, Query()] = None,
    ref: RowRef = None,
) -> StringPage:
    raise not_implemented()
