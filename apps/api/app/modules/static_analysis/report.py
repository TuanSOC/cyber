"""The `cyberlab.report.static.v1` document of one succeeded static analysis.

Summary-level and capped (M3 RT14): findings, signatures, capabilities, IOCs and sections
are listed up to fixed caps with their full totals; imports are summarised (top libraries,
notable API names); strings are never dumped. Sample size and hashes are the evidence
record's (trusted), never the analyzer's.
"""

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import Conflict, NotFound
from app.core.rbac import OrgContext
from app.modules.analysis import repository as jobs_repo
from app.modules.analysis.models import AnalysisStatus, Analyzer
from app.modules.evidence import repository as evidence_repo
from app.modules.evidence.models import EvidenceCustodyEvent
from app.modules.investigations.schemas import case_ref
from app.modules.organizations.models import Organization
from app.modules.pcap_analysis.models import AnalysisFinding, Ioc
from app.modules.pcap_analysis.repository import _SEVERITY_RANK
from app.modules.pcap_analysis.schemas import FindingOut, IocOut
from app.modules.static_analysis.models import (
    MalwareCapability,
    MalwareImport,
    MalwareSample,
    MalwareSection,
    MalwareSignatureMatch,
)
from app.modules.static_analysis.schemas import (
    AnalyzerDerivedHashes,
    CapabilityOut,
    ElfOut,
    ImportsSummary,
    LibraryCount,
    NotableFunction,
    PeOut,
    ReportAnalysis,
    ReportCapabilities,
    ReportCustody,
    ReportCustodyEvent,
    ReportEvidence,
    ReportFindings,
    ReportInvestigation,
    ReportIocs,
    ReportOrganization,
    ReportSample,
    ReportSections,
    ReportSignatures,
    SectionOut,
    SignatureOut,
    StaticReport,
)
from app.modules.users.models import User

MAX_FINDINGS = 500
MAX_SIGNATURES = 500
MAX_CAPABILITIES = 500
MAX_IOCS = 500
MAX_SECTIONS = 256
TOP_LIBRARIES = 25
MAX_NOTABLE = 200
RECENT_CUSTODY = 20

# Imported Windows API names worth a closer look, by what they are commonly used for. Many
# benign programs import some of them: the report lists them, it never scores them.
NOTABLE_APIS: dict[str, tuple[str, ...]] = {
    "process_injection": (
        "VirtualAllocEx",
        "VirtualProtectEx",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "QueueUserAPC",
        "NtQueueApcThread",
        "SetThreadContext",
        "NtUnmapViewOfSection",
        "ZwUnmapViewOfSection",
        "NtWriteVirtualMemory",
        "NtMapViewOfSection",
    ),
    "anti_analysis": (
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "NtSetInformationThread",
        "OutputDebugString",
    ),
    "dynamic_resolution": ("LdrLoadDll", "LdrGetProcedureAddress"),
    "input_capture": ("SetWindowsHookEx", "GetAsyncKeyState", "RegisterRawInputDevices"),
    "execution": (
        "WinExec",
        "ShellExecute",
        "ShellExecuteEx",
        "CreateProcessAsUser",
        "CreateProcessWithLogon",
    ),
    "persistence": ("CreateService", "ChangeServiceConfig", "RegSetValueEx", "RegCreateKeyEx"),
    "networking": (
        "InternetOpen",
        "InternetOpenUrl",
        "InternetConnect",
        "HttpSendRequest",
        "URLDownloadToFile",
        "WinHttpOpen",
        "WinHttpSendRequest",
        "WSAStartup",
    ),
    "cryptography": (
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptGenKey",
        "CryptAcquireContext",
        "BCryptEncrypt",
        "BCryptDecrypt",
    ),
    "privileges": (
        "AdjustTokenPrivileges",
        "OpenProcessToken",
        "LookupPrivilegeValue",
        "ImpersonateLoggedOnUser",
    ),
    "credential_access": ("MiniDumpWriteDump", "LsaRetrievePrivateData", "CredEnumerate"),
    "discovery": ("CreateToolhelp32Snapshot", "Process32First", "Process32Next", "EnumProcesses"),
}
# Exact import names, with the ANSI / wide variants of each API.
NOTABLE_FUNCTIONS: dict[str, str] = {
    f"{name}{suffix}": category
    for category, names in NOTABLE_APIS.items()
    for name in names
    for suffix in ("", "A", "W")
}


class ReportUnavailable(Conflict):
    code = "report_unavailable"
    message = "Reports are only available for static analyses"


class AnalysisNotSucceeded(Conflict):
    code = "analysis_not_succeeded"
    message = "The analysis has not succeeded; there is nothing to report"


async def _count(session: AsyncSession, model: Any, org_id: uuid.UUID, job_id: uuid.UUID) -> int:
    stmt = select(func.count()).where(model.organization_id == org_id, model.job_id == job_id)
    return int(await session.scalar(stmt) or 0)


async def _capped(
    session: AsyncSession,
    model: Any,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    order_by: Sequence[Any],
    cap: int,
) -> tuple[Sequence[Any], int]:
    where = (model.organization_id == org_id, model.job_id == job_id)
    rows = (await session.scalars(select(model).where(*where).order_by(*order_by).limit(cap))).all()
    total = len(rows) if len(rows) < cap else await _count(session, model, org_id, job_id)
    return rows, total


async def _imports_summary(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID
) -> ImportsSummary:
    m = MalwareImport
    where = (m.organization_id == org_id, m.job_id == job_id)
    total = await _count(session, m, org_id, job_id)
    libraries = int(
        await session.scalar(select(func.count(m.library.distinct())).where(*where)) or 0
    )
    count = func.count().label("imports")
    top = await session.execute(
        select(m.library, count)
        .where(*where)
        .group_by(m.library)
        .order_by(count.desc(), m.library)
        .limit(TOP_LIBRARIES)
    )
    notable = await session.execute(
        select(m.library, m.function)
        .where(*where, m.function.in_(NOTABLE_FUNCTIONS))
        .order_by(m.function, m.library)
        .limit(MAX_NOTABLE + 1)
    )
    hits = [(library, function) for library, function in notable if function]
    return ImportsSummary(
        total=total,
        libraries=libraries,
        top_libraries=[LibraryCount(library=lib, imports=n) for lib, n in top],
        notable_functions=[
            NotableFunction(library=lib, function=fn, category=NOTABLE_FUNCTIONS[fn])
            for lib, fn in hits[:MAX_NOTABLE]
        ],
        notable_truncated=len(hits) > MAX_NOTABLE,
    )


async def _custody(
    session: AsyncSession, org_id: uuid.UUID, evidence_id: uuid.UUID
) -> ReportCustody:
    e = EvidenceCustodyEvent
    where = (e.organization_id == org_id, e.evidence_id == evidence_id)
    count = int(await session.scalar(select(func.count()).where(*where)) or 0)
    rows = await session.execute(
        select(e, User.display_name)
        .join(User, User.id == e.actor_id)
        .where(*where)
        .order_by(e.occurred_at.desc(), e.id.desc())
        .limit(RECENT_CUSTODY)
    )
    recent = [
        ReportCustodyEvent(
            action=event.action,
            occurred_at=event.occurred_at,
            actor_id=event.actor_id,
            actor_name=name,
        )
        for event, name in rows
    ]
    return ReportCustody(count=count, recent=recent[::-1])


async def build(ctx: OrgContext, job_id: uuid.UUID) -> tuple[StaticReport, str]:
    """The report and the evidence's original filename. 404 for unknown/foreign jobs, 409
    for non-static or not (yet) succeeded ones."""
    session, org_id = ctx.session, ctx.org_id
    job_row = await jobs_repo.get_row(session, org_id, job_id)
    if job_row is None:
        raise NotFound()
    job = job_row.job
    if job.analyzer != Analyzer.STATIC:
        raise ReportUnavailable()
    if job.status != AnalysisStatus.SUCCEEDED:
        raise AnalysisNotSucceeded()
    evidence_row = await evidence_repo.get_row(session, org_id, job.evidence_id)
    investigation = await evidence_repo.get_investigation(session, org_id, job_row.investigation_id)
    organization = await session.get(Organization, org_id)
    sample = await session.scalar(
        select(MalwareSample).where(
            MalwareSample.organization_id == org_id, MalwareSample.job_id == job.id
        )
    )
    if sample is None:  # succeeded before results were stored (M3 phase 1 placeholder)
        raise ReportUnavailable("This analysis has no stored results")
    if evidence_row is None or investigation is None or organization is None:
        raise RuntimeError(f"succeeded static job {job.id} has incomplete records")
    evidence, hashes = evidence_row.evidence, evidence_row.hashes
    summary = job.summary

    findings, findings_total = await _capped(
        session,
        AnalysisFinding,
        org_id,
        job.id,
        (_SEVERITY_RANK.desc(), AnalysisFinding.ts, AnalysisFinding.id),
        MAX_FINDINGS,
    )
    s = MalwareSignatureMatch
    signatures, signatures_total = await _capped(
        session, s, org_id, job.id, (s.engine, s.name, s.id), MAX_SIGNATURES
    )
    c = MalwareCapability
    capabilities, capabilities_total = await _capped(
        session, c, org_id, job.id, (c.namespace, c.name, c.id), MAX_CAPABILITIES
    )
    iocs, iocs_total = await _capped(
        session, Ioc, org_id, job.id, (Ioc.count.desc(), Ioc.first_seen, Ioc.id), MAX_IOCS
    )
    sections, sections_total = await _capped(
        session,
        MalwareSection,
        org_id,
        job.id,
        (MalwareSection.index, MalwareSection.id),
        MAX_SECTIONS,
    )
    pe = PeOut.model_validate(sample.pe) if sample.pe is not None else None
    report = StaticReport(
        generated_at=datetime.now(UTC),
        organization=ReportOrganization(id=organization.id, name=organization.name),
        investigation=ReportInvestigation(
            id=investigation.id,
            case_ref=case_ref(investigation.case_number),
            title=investigation.title,
        ),
        evidence=ReportEvidence(
            id=evidence.id,
            filename=evidence.original_filename,
            size_bytes=evidence.size_bytes,
            hashes=hashes,
            detected_mime=evidence.detected_mime,
            uploaded_at=evidence.uploaded_at,
            uploaded_by=evidence.uploaded_by,
            uploaded_by_name=evidence_row.uploaded_by_name,
        ),
        custody=await _custody(session, org_id, evidence.id),
        analysis=ReportAnalysis(
            job_id=job.id,
            analyzer=job.analyzer,
            profile=None if job.profile is None else job.profile.value,
            status=job.status,
            auto=job.auto,
            requested_by=job.requested_by,
            requested_by_name=job_row.requested_by_name,
            created_at=job.created_at,
            started_at=job.started_at,
            finished_at=job.finished_at,
            worker_version=job.worker_version,
            result_schema=summary.get("schema_version", "static.v1"),
            tool_versions=summary.get("tool_versions", {}),
            engine_errors=summary.get("engine_errors", []),
            truncated=summary.get("truncated", {}),
            counts=summary.get("counts", {}),
        ),
        sample=ReportSample(
            size=evidence.size_bytes,
            md5=hashes.get("md5"),
            sha1=hashes.get("sha1"),
            sha256=hashes["sha256"],
            file_type=sample.file_type,
            mime=sample.mime,
            entropy=sample.entropy,
            file_format=sample.file_format,  # DB check constraint
            analyzer_derived=AnalyzerDerivedHashes(
                ssdeep=sample.ssdeep,
                imphash=pe.imphash if pe else None,
                rich_header_hash=pe.rich_header_hash if pe else None,
            ),
        ),
        pe=pe,
        elf=ElfOut.model_validate(sample.elf) if sample.elf is not None else None,
        findings=ReportFindings(
            items=[FindingOut.model_validate(r) for r in findings],
            total=findings_total,
            truncated=findings_total > len(findings),
        ),
        signatures=ReportSignatures(
            items=[SignatureOut.model_validate(r) for r in signatures],
            total=signatures_total,
            truncated=signatures_total > len(signatures),
        ),
        capabilities=ReportCapabilities(
            items=[CapabilityOut.model_validate(r) for r in capabilities],
            total=capabilities_total,
            truncated=capabilities_total > len(capabilities),
        ),
        iocs=ReportIocs(
            items=[IocOut.model_validate(r) for r in iocs],
            total=iocs_total,
            truncated=iocs_total > len(iocs),
        ),
        imports_summary=await _imports_summary(session, org_id, job.id),
        sections=ReportSections(
            items=[SectionOut.model_validate(r) for r in sections],
            total=sections_total,
            truncated=sections_total > len(sections),
        ),
    )
    return report, evidence.original_filename


def filename(evidence_filename: str, job_id: uuid.UUID) -> str:
    """Download name: always ends in `.json` (sanitized again for the header)."""
    return f"{evidence_filename}.static-report-{str(job_id)[:8]}.json"
