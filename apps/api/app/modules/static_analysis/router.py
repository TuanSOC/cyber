"""Read API over one static analysis job's persisted results, and its report (evidence.read).

Every route answers 404 for unknown or foreign jobs and for jobs of another analyzer.
Findings and IOCs of static jobs are served by the shared per-job routes
(pcap_analysis.router: /findings, /iocs).
"""

import uuid
from typing import Annotated

from cyberlab_jobs.static import AttackId
from fastapi import APIRouter, Depends, Query, Request, Response

from app.core.errors import NotFound
from app.core.filenames import content_disposition
from app.core.pagination import PageParamsDep
from app.core.rbac import OrgContext, Permission, require
from app.core.validation import SearchTerm
from app.modules.audit import service as audit
from app.modules.evidence.router import DOWNLOAD_HEADERS
from app.modules.static_analysis import report as reports
from app.modules.static_analysis import repository as repo
from app.modules.static_analysis.schemas import (
    REPORT_SCHEMA,
    AnalyzerDerivedHashes,
    CapabilityOut,
    CapabilityPage,
    ElfOut,
    ExportOut,
    ExportPage,
    ImportOut,
    ImportPage,
    PeOut,
    ResourceOut,
    ResourcePage,
    SampleOut,
    SectionOut,
    SectionPage,
    SignatureEngine,
    SignatureOut,
    SignaturePage,
    StaticReport,
    StringEncoding,
    StringOut,
    StringPage,
)

router = APIRouter(prefix="/orgs/{org_id}/analyses/{job_id}", tags=["static-analysis"])

EvidenceRead = Annotated[OrgContext, Depends(require(Permission.EVIDENCE_READ), scope="function")]
Search = Annotated[SearchTerm | None, Query()]
# `ref=<row id>`: a page with just that row of the job (citation deep links; 404
# otherwise).
RowRef = Annotated[uuid.UUID | None, Query()]


class ResultsNotAvailable(NotFound):
    code = "results_not_available"
    message = "This analysis has no stored results"


@router.get("/sample", response_model=SampleOut)
async def get_sample(job_id: uuid.UUID, ctx: EvidenceRead) -> SampleOut:
    job = await repo.ensure_static_job(ctx.session, ctx.org_id, job_id)
    found = await repo.sample(ctx.session, ctx.org_id, job)
    if found is None:
        raise ResultsNotAvailable()
    row, hashes = found
    pe = PeOut.model_validate(row.pe) if row.pe is not None else None
    return SampleOut(
        job_id=job.id,
        evidence_id=job.evidence_id,
        size=row.size,
        md5=hashes.get("md5"),
        sha1=hashes.get("sha1"),
        sha256=hashes.get("sha256", row.sha256),
        file_type=row.file_type,
        mime=row.mime,
        entropy=row.entropy,
        file_format=row.file_format,  # DB check constraint
        analyzer_derived=AnalyzerDerivedHashes(
            ssdeep=row.ssdeep,
            imphash=pe.imphash if pe else None,
            rich_header_hash=pe.rich_header_hash if pe else None,
        ),
        pe=pe,
        elf=ElfOut.model_validate(row.elf) if row.elf is not None else None,
    )


@router.get("/sections", response_model=SectionPage)
async def list_sections(job_id: uuid.UUID, ctx: EvidenceRead, page: PageParamsDep) -> SectionPage:
    await repo.ensure_static_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.sections(ctx.session, ctx.org_id, job_id, page)
    return SectionPage(items=[SectionOut.model_validate(r) for r in rows], total=total)


@router.get("/imports", response_model=ImportPage)
async def list_imports(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    library: Search = None,
    q: Search = None,
    ref: RowRef = None,
) -> ImportPage:
    """`library`: case-insensitive exact DLL name; `q`: substring of function or library."""
    await repo.ensure_static_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.imports(
        ctx.session, ctx.org_id, job_id, page, library=library, q=q, ref=ref
    )
    return ImportPage(items=[ImportOut.model_validate(r) for r in rows], total=total)


@router.get("/exports", response_model=ExportPage)
async def list_exports(
    job_id: uuid.UUID, ctx: EvidenceRead, page: PageParamsDep, q: Search = None
) -> ExportPage:
    await repo.ensure_static_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.exports(ctx.session, ctx.org_id, job_id, page, q=q)
    return ExportPage(items=[ExportOut.model_validate(r) for r in rows], total=total)


@router.get("/resources", response_model=ResourcePage)
async def list_resources(job_id: uuid.UUID, ctx: EvidenceRead, page: PageParamsDep) -> ResourcePage:
    await repo.ensure_static_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.resources(ctx.session, ctx.org_id, job_id, page)
    return ResourcePage(items=[ResourceOut.model_validate(r) for r in rows], total=total)


@router.get("/strings", response_model=StringPage)
async def list_strings(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    encoding: StringEncoding | None = None,
    q: Search = None,
    ref: RowRef = None,
) -> StringPage:
    await repo.ensure_static_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.strings(
        ctx.session, ctx.org_id, job_id, page, encoding=encoding, q=q, ref=ref
    )
    return StringPage(items=[StringOut.model_validate(r) for r in rows], total=total)


@router.get("/signatures", response_model=SignaturePage)
async def list_signatures(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    engine: SignatureEngine | None = None,
    ref: RowRef = None,
) -> SignaturePage:
    await repo.ensure_static_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.signatures(
        ctx.session, ctx.org_id, job_id, page, engine=engine, ref=ref
    )
    return SignaturePage(items=[SignatureOut.model_validate(r) for r in rows], total=total)


@router.get("/capabilities", response_model=CapabilityPage)
async def list_capabilities(
    job_id: uuid.UUID,
    ctx: EvidenceRead,
    page: PageParamsDep,
    namespace: Search = None,
    attack: Annotated[AttackId | None, Query()] = None,
    ref: RowRef = None,
) -> CapabilityPage:
    """`namespace`: that capa namespace or below; `attack`: an ATT&CK technique id (its
    sub-techniques included) or sub-technique id."""
    await repo.ensure_static_job(ctx.session, ctx.org_id, job_id)
    rows, total = await repo.capabilities(
        ctx.session, ctx.org_id, job_id, page, namespace=namespace, attack=attack, ref=ref
    )
    return CapabilityPage(items=[CapabilityOut.model_validate(r) for r in rows], total=total)


@router.get(
    "/report",
    response_model=StaticReport,
    responses={
        200: {"description": f"The `{REPORT_SCHEMA}` document, as an attachment."},
        409: {"description": "Not a static analysis, or it has not succeeded."},
    },
)
async def download_report(
    job_id: uuid.UUID, ctx: EvidenceRead, request: Request, response: Response
) -> StaticReport:
    """Versioned JSON report of a succeeded static analysis (an audited download; the
    evidence custody chain is unchanged: the evidence bytes are not read)."""
    report, evidence_filename = await reports.build(ctx, job_id)
    audit.record(
        ctx.session,
        action="analysis.report_downloaded",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="analysis_job",
        target_id=job_id,
        details={"evidence_id": str(report.evidence.id), "schema": REPORT_SCHEMA},
        request=request,
    )
    await ctx.session.commit()
    response.headers.update(
        {
            **DOWNLOAD_HEADERS,
            "Content-Disposition": content_disposition(reports.filename(evidence_filename, job_id)),
        }
    )
    return report
