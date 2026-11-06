"""The `re.v1` job message and its source (M10 phase 1 entry points; phase 7 owns the bodies,
never the signatures).

- `load_source(session, org_id, evidence_id, *, source_job_id, profile, decompile_addresses,
  settings) -> ReSource`: in the request transaction, the succeeded static `full` job of the
  evidence (the requested one, else the latest) that identified a PE / ELF file
  (`409 static_analysis_required` otherwise), the x86 / x64 check from its facts
  (`422 unsupported_architecture` / `unsupported_managed_code`), its capa locations as file
  virtual addresses (RT8: `file_va = location - (capa_base - preferred_base)`; <= 512, sorted,
  unique) and the preferred base. Phase 1: raises `501 not_implemented` before anything is
  created.
- `build_re_message(item, source_job, settings) -> ReJobV1`: the shared presigned fields, the
  profile, the requested addresses (`full` only), the capa file VAs and `ReLimits` from
  settings. Blocking (MinIO): called from the dispatch worker thread.
"""

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta

from cyberlab_jobs.reverse import FileFormat, ReJobV1, ReLimits, ReProfile
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.stubs import not_implemented
from app.modules.analysis.dispatch import DispatchInput, presigned_common
from app.modules.analysis.models import JobProfile

# The stage wall timeout above the analysis monitor: export and project save after it.
STAGE_MARGIN_S = 300


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
    raise not_implemented()


def build_re_message(item: DispatchInput, source_job: ReSource, settings: Settings) -> ReJobV1:
    """Implemented with the phase-1 contract so the message shape is fixed; phase 7 owns it."""
    expires = timedelta(seconds=settings.analysis_queue_ttl_s + settings.analysis_re_timeout_s)
    common = presigned_common(item, settings, get_expires=expires)
    profile = ReProfile(item.profile or JobProfile.FULL)
    return ReJobV1.model_validate(
        {
            **common,
            "source_job_id": source_job.job_id,
            "profile": profile,
            "file_format": source_job.file_format,
            "decompile_addresses": list(item.decompile_addresses)
            if profile == ReProfile.FULL
            else [],
            "capa_file_vas": list(source_job.capa_file_vas),
            "limits": re_limits(settings),
        }
    )
