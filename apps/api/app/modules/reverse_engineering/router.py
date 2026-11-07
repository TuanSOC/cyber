"""Read API over one reverse-engineering job's persisted results (evidence.read; M10 phase 8
on the phase-1 frozen paths and schemas).

Every route answers 404 for unknown or foreign jobs and for jobs of another analyzer,
`404 function_not_found` for an entry that is not a function of the job (`{entry}`: `0x…`,
< 2**64), and `409 analysis_not_ready` while the job is queued or running. Findings and IOCs
of RE jobs are served by the shared per-job routes (pcap_analysis.router: /findings, /iocs).
Reads are not audited (the M7 evidence view audit covers the job page). No call-graph route
(RT24): the callers / callees of the function detail give the navigation. Nothing here
renders code or names into HTML: the code route is JSON with `Cache-Control: no-store`.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Response

from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.core.validation import SearchTerm
from app.modules.reverse_engineering import repository as repo
from app.modules.reverse_engineering import service
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
    job = await service.ready_job(ctx.session, ctx.org_id, job_id)
    return await service.summary(ctx.session, ctx.org_id, job)


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
    """Functions by priority rank (unranked last), then entry. `q`: a name substring;
    library (FID) functions only with `include_library` (or a `ref`)."""
    job = await service.ready_job(ctx.session, ctx.org_id, job_id)
    items, total = await service.function_page(
        ctx.session,
        ctx.org_id,
        job,
        page,
        q=q,
        decompiled=decompiled,
        has_capability=has_capability,
        calls_suspicious_import=calls_suspicious_import,
        references_ioc_string=references_ioc_string,
        include_library=include_library,
        ref=ref,
    )
    return FunctionPage(items=items, total=total)


@router.get("/functions/{entry}", response_model=FunctionDetailOut)
async def get_function(job_id: uuid.UUID, entry: Entry, ctx: EvidenceRead) -> FunctionDetailOut:
    """The function with its callers / callees, imports called, strings referenced, linked
    capabilities and the findings citing it (each list <= 200)."""
    job = await service.ready_job(ctx.session, ctx.org_id, job_id)
    return await service.function_detail(ctx.session, ctx.org_id, job, service.parse_entry(entry))


@router.get("/functions/{entry}/code", response_model=FunctionCodeOut)
async def get_function_code(
    job_id: uuid.UUID, entry: Entry, ctx: EvidenceRead, response: Response
) -> FunctionCodeOut:
    """The decompiled (or disassembled) text of one function: untrusted text, as stored.
    `404 code_not_available` for a function without a decompiled line."""
    job = await service.ready_job(ctx.session, ctx.org_id, job_id)
    out = await service.function_code(ctx.session, ctx.org_id, job, service.parse_entry(entry))
    response.headers["Cache-Control"] = "no-store"
    return out


@router.get("/imports", response_model=ImportPage)
async def list_imports(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    q: Search = None,
    library: Search = None,
    ref: RowRef = None,
) -> ImportPage:
    """`library`: case-insensitive exact name; `q`: substring of the name or the library.
    Each import carries its calling functions (count, the first 20)."""
    await service.ready_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.imports(
        ctx.session, ctx.org_id, job_id, page, q=q, library=library, ref=ref
    )
    items = await service.import_items(ctx.session, ctx.org_id, job_id, rows)
    return ImportPage(items=items, total=total)


@router.get("/strings", response_model=StringPage)
async def list_strings(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    q: Search = None,
    referenced: Annotated[bool | None, Query()] = None,
    ref: RowRef = None,
) -> StringPage:
    """`q`: a value substring; `referenced`: referenced by code (or not). Each string
    carries its referencing functions (count, the first 20)."""
    await service.ready_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.strings(
        ctx.session, ctx.org_id, job_id, page, q=q, referenced=referenced, ref=ref
    )
    items = await service.string_items(ctx.session, ctx.org_id, job_id, rows)
    return StringPage(items=items, total=total)
