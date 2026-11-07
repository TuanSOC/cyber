"""The `re.v1` job message and its source (M10 phase 1 entry points; phase 7 owns the bodies,
never the signatures).

- `load_source(session, org_id, evidence_id, *, source_job_id, profile, decompile_addresses,
  settings) -> ReSource`: in the request transaction, the succeeded static `full` job of the
  evidence (the requested one, else the latest) that identified a PE / ELF file
  (`409 static_analysis_required` otherwise), the x86 / x64 check from its facts
  (`422 unsupported_architecture` / `unsupported_managed_code`), its capa locations as file
  virtual addresses (RT8: `file_va = location - (capa_base - preferred_base)`; <= 512, sorted,
  unique) and the preferred base (PE `ImageBase`; ELF: the lowest allocated section VA,
  page-aligned down: `ElfInfo` carries no `PT_LOAD` field). Nothing is created when it
  refuses. The worker re-checks the architecture and the CLR directory (authoritative).
- `build_re_message(item, source_job, settings) -> ReJobV1`: the shared presigned fields, the
  profile, the requested addresses (`full` only), the capa file VAs and `ReLimits` from
  settings. Blocking (MinIO): called from the dispatch worker thread.
"""

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, cast

from cyberlab_jobs.reverse import FileFormat, ReJobV1, ReLimits, ReProfile
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.modules.analysis.dispatch import DispatchInput, presigned_common
from app.modules.analysis.models import AnalysisJob, AnalysisStatus, Analyzer, JobProfile
from app.modules.reverse_engineering import join
from app.modules.reverse_engineering.errors import (
    StaticAnalysisRequired,
    UnsupportedArchitecture,
    UnsupportedManagedCode,
)
from app.modules.static_analysis.models import (
    MalwareCapability,
    MalwareImport,
    MalwareSample,
    MalwareSection,
)

# The stage wall timeout above the analysis monitor: export and project save after it.
STAGE_MARGIN_S = 300
# x86 / x86-64 as the M3 probes name them (pefile machine map, pyelftools `e_machine`),
# compared case-insensitively.
X86_MACHINES: Mapping[str, frozenset[str]] = {
    "pe": frozenset({"i386", "amd64"}),
    "elf": frozenset({"em_386", "em_x86_64"}),
}
# A .NET program's import of the CLR entry point (the worker's CLR-directory check decides).
CLR_LIBRARY = "mscoree.dll"
CLR_ENTRY_POINTS = ("_CorExeMain", "_CorDllMain")
PAGE = 0x1000


@dataclass(frozen=True)
class ReSource:
    """What an RE job starts from (resolved in the request transaction)."""

    job_id: uuid.UUID  # the static `full` job (analysis_jobs.source_job_id)
    file_format: FileFormat
    preferred_base: int  # RT8: PE ImageBase / ELF lowest PT_LOAD vaddr
    capa_file_vas: tuple[int, ...] = ()  # sorted, unique, <= 512


def re_limits(settings: Settings) -> ReLimits:
    tool_timeout = min(
        settings.re_analysis_timeout_s + STAGE_MARGIN_S, settings.analysis_re_timeout_s - 1
    )
    return ReLimits(
        max_bytes=settings.re_max_bytes,
        timeout_s=settings.analysis_re_timeout_s,
        tool_timeout_s=tool_timeout,
        analysis_timeout_s=settings.re_analysis_timeout_s,
        decompile_timeout_s=settings.re_decompile_timeout_s,
        quick_timeout_s=min(settings.re_quick_timeout_s, tool_timeout),
        max_functions=settings.re_max_functions,
        max_call_edges=settings.re_max_call_edges,
        max_imports=settings.re_max_imports,
        max_import_refs=settings.re_max_import_refs,
        max_strings=settings.re_max_strings,
        max_string_refs=settings.re_max_string_refs,
        max_decompiled=settings.re_max_decompiled,
        max_code_bytes=64 * 1024,
        max_code_total_bytes=32 * 1024**2,
        max_findings=settings.re_max_findings,
        max_iocs=settings.re_max_iocs,
        max_result_bytes=settings.re_max_result_bytes,
        max_work_bytes=settings.re_max_work_bytes,
    )


async def load_source(
    session: AsyncSession,
    org_id: uuid.UUID,
    evidence_id: uuid.UUID,
    *,
    source_job_id: uuid.UUID | None,
    profile: JobProfile,
    decompile_addresses: Sequence[int],
    settings: Settings,
) -> ReSource:
    found = await _source_job(session, org_id, evidence_id, source_job_id)
    if found is None:
        raise StaticAnalysisRequired()
    job, sample = found
    fmt = cast(FileFormat, sample.file_format)
    facts = sample.pe if fmt == "pe" else sample.elf
    machine = facts.get("machine") if isinstance(facts, Mapping) else None
    if not isinstance(machine, str) or machine.lower() not in X86_MACHINES[fmt]:
        raise UnsupportedArchitecture()
    if fmt == "pe" and await _imports_clr(session, org_id, job.id):
        raise UnsupportedManagedCode()
    preferred = await preferred_base(session, org_id, job.id, sample)
    capa_base = None if sample.capa_base_address is None else int(sample.capa_base_address)
    rows = await session.scalars(
        select(MalwareCapability.locations).where(
            MalwareCapability.organization_id == org_id, MalwareCapability.job_id == job.id
        )
    )
    locations = [loc for value in rows for loc in join.parse_locations(value)]
    return ReSource(
        job_id=job.id,
        file_format=fmt,
        preferred_base=preferred,
        capa_file_vas=tuple(join.capa_file_vas(locations, capa_base, preferred)),
    )


async def _source_job(
    session: AsyncSession,
    org_id: uuid.UUID,
    evidence_id: uuid.UUID,
    source_job_id: uuid.UUID | None,
) -> tuple[AnalysisJob, MalwareSample] | None:
    """The requested (else the latest) succeeded static `full` job of this evidence whose
    sample row says PE / ELF (a purged result has no row: it does not qualify)."""
    j, s = AnalysisJob, MalwareSample
    stmt = (
        select(j, s)
        .join(s, (s.job_id == j.id) & (s.organization_id == j.organization_id))
        .where(
            j.organization_id == org_id,
            j.evidence_id == evidence_id,
            j.analyzer == Analyzer.STATIC,
            j.profile == JobProfile.FULL,
            j.status == AnalysisStatus.SUCCEEDED,
            s.file_format.in_(("pe", "elf")),
        )
        .order_by(j.created_at.desc(), j.id.desc())
        .limit(1)
    )
    if source_job_id is not None:
        stmt = stmt.where(j.id == source_job_id)
    row = (await session.execute(stmt)).one_or_none()
    return (row[0], row[1]) if row is not None else None


async def _imports_clr(session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID) -> bool:
    m = MalwareImport
    found = await session.scalar(
        select(m.id)
        .where(
            m.organization_id == org_id,
            m.job_id == job_id,
            func.lower(m.library) == CLR_LIBRARY,
            m.function.in_(CLR_ENTRY_POINTS),
        )
        .limit(1)
    )
    return found is not None


def _address(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value < join.ADDRESS_LIMIT else None


async def preferred_base(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, sample: MalwareSample
) -> int:
    """The file's own base from the static facts: PE `ImageBase`; ELF the lowest allocated
    section address, page-aligned down (the first `PT_LOAD` starts at or below it: 0 for a
    PIE, 0x400000 for a classic x86-64 executable); 0 when unknown."""
    if sample.file_format == "pe":
        pe: Any = sample.pe or {}
        return _address(pe.get("image_base")) or 0
    lowest = await session.scalar(
        select(func.min(MalwareSection.virtual_address)).where(
            MalwareSection.organization_id == org_id,
            MalwareSection.job_id == job_id,
            MalwareSection.virtual_address > 0,
            MalwareSection.flags.contains(["alloc"]),
        )
    )
    return (int(lowest) // PAGE) * PAGE if lowest is not None else 0


def build_re_message(item: DispatchInput, source_job: ReSource, settings: Settings) -> ReJobV1:
    """Implemented with the phase-1 contract so the message shape is fixed; phase 7 owns it."""
    expires = timedelta(seconds=settings.analysis_queue_ttl_s + settings.analysis_re_timeout_s)
    common = presigned_common(item, settings, get_expires=expires)
    profile = ReProfile(item.profile or JobProfile.FULL)
    addresses = list(item.decompile_addresses) if profile == ReProfile.FULL else []
    limits = re_limits(settings)
    # The worker's stream checker caps decompiled rows at max_decompiled and priority.rank never
    # cuts requested addresses, so the cap must cover every requested one.
    if len(addresses) > limits.max_decompiled:
        limits = limits.model_copy(update={"max_decompiled": len(addresses)})
    return ReJobV1.model_validate(
        {
            **common,
            "source_job_id": source_job.job_id,
            "profile": profile,
            "file_format": source_job.file_format,
            "decompile_addresses": addresses,
            "capa_file_vas": list(source_job.capa_file_vas),
            "limits": limits,
        }
    )
