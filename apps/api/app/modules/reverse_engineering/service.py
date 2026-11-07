"""RE read API logic (M10 phase 8): job readiness, the summary, row mapping, the function
detail and the capability -> functions link of the static side.

- Every read runs under `SET LOCAL statement_timeout = '5s'` (the request's tenant
  transaction) and answers `409 analysis_not_ready` while the job is queued or running.
- Text (names, signatures, string values, code) is returned exactly as stored (bounded and
  NUL-free at ingest); the web renders it as text only. Addresses are `0x…` hex strings
  (`schemas.HexAddress`): a JSON number above 2**53 would lose its low bits.
- No audit per read (the M7 evidence-view audit covers the job page; same decision as the
  static and memory result pages).
"""

import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFound
from app.core.pagination import PageParams
from app.modules.analysis.models import ACTIVE, AnalysisJob
from app.modules.memory_analysis.service import AnalysisNotReady, ResultsNotAvailable
from app.modules.reverse_engineering import join
from app.modules.reverse_engineering import repository as repo
from app.modules.reverse_engineering.errors import FunctionNotFound
from app.modules.reverse_engineering.models import ReFunction, ReImport, ReProgram, ReString
from app.modules.reverse_engineering.schemas import (
    BodyRangeOut,
    CapabilityFunctionRef,
    CapabilityFunctionsOut,
    DecompilationMetaOut,
    FunctionCodeOut,
    FunctionDetailOut,
    FunctionOut,
    FunctionRef,
    ImportOut,
    LinkedCapabilityOut,
    PriorityReason,
    ReStageOut,
    ReSummaryOut,
    StringOut,
)
from app.modules.static_analysis import repository as static_repo
from app.modules.static_analysis.models import MalwareCapability, MalwareSample
from app.modules.static_analysis.schemas import CapabilityOut

STATEMENT_TIMEOUT = "SET LOCAL statement_timeout = '5s'"


class CodeNotAvailable(NotFound):
    """The function exists but has no decompiled text (not selected, timed out, failed)."""

    code = "code_not_available"
    message = "This function has no decompiled code in this analysis"


async def ready_job(session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID) -> AnalysisJob:
    """The org's RE job (404 otherwise) once it is terminal (409 before), with the read
    statement timeout set for the rest of the request's transaction."""
    await session.execute(text(STATEMENT_TIMEOUT))
    job = await repo.ensure_re_job(session, org_id, job_id)
    if job.status in ACTIVE:
        raise AnalysisNotReady()
    return job


def parse_entry(value: str) -> int:
    """A `0x…` path entry (the route's pattern allows at most 16 hex digits: < 2**64)."""
    return int(value, 16)


# --- helpers -----------------------------------------------------------------------------------


def _str_map(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(k): v for k, v in value.items() if isinstance(v, str)}


def _bool_map(value: object) -> dict[str, bool]:
    if not isinstance(value, Mapping):
        return {}
    return {str(k): v for k, v in value.items() if isinstance(v, bool)}


def _int_map(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    return {str(k): v for k, v in value.items() if isinstance(v, int) and not isinstance(v, bool)}


def requested_addresses(job: AnalysisJob) -> list[int]:
    """`re_params.decompile_addresses` (decimal strings, checked by 0018) as integers."""
    params = job.re_params if isinstance(job.re_params, Mapping) else {}
    return join.parse_locations(params.get("decompile_addresses"))


def _stages(value: object) -> list[ReStageOut]:
    out = []
    for stage in value if isinstance(value, list) else []:
        try:
            out.append(ReStageOut.model_validate(stage))
        except ValueError:
            continue  # validated at ingest; never fail a read on an old shape
    return out


# --- summary -----------------------------------------------------------------------------------


async def summary(session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob) -> ReSummaryOut:
    """The program header, the stage strip, the counts (a partial run is never shown as
    complete: per-stage status and truncation flags) and the newer RE job of the same
    evidence. A diagnostic job (`unsupported_*`) has its program row too."""
    program = await repo.program(session, org_id, job.id)
    if program is None or job.source_job_id is None or job.profile is None:
        raise ResultsNotAvailable()
    stored: Mapping[str, Any] = job.summary if isinstance(job.summary, Mapping) else {}
    counts = {**_int_map(program.counts), **_int_map(stored.get("counts"))}
    return ReSummaryOut.model_validate(
        {
            "job_id": job.id,
            "evidence_id": job.evidence_id,
            "source_job_id": job.source_job_id,
            "profile": job.profile.value,
            "engine": program.engine,
            "engine_version": program.engine_version,
            "code_kind": program.code_kind,
            "format": program.format,
            "arch": program.arch,
            "machine": program.machine,
            "bits": program.bits,
            "endianness": program.endianness,
            "language_id": program.language_id,
            "compiler_spec": program.compiler_spec,
            "image_base": program.image_base,
            "preferred_base": program.preferred_base,
            "entry": program.entry,
            "analysis_status": program.analysis_status,
            "peak_memory_bytes": program.peak_memory_bytes,
            "stages": _stages(program.stages),
            "counts": counts,
            "truncated": _bool_map(program.truncated),
            "tool_versions": _str_map(program.tool_versions),
            "decompile_addresses": requested_addresses(job),
            "newer_job_id": await repo.newer_job(session, org_id, job),
        }
    )


# --- functions ---------------------------------------------------------------------------------


def function_out(
    row: ReFunction, *, capabilities: int = 0, reason: PriorityReason | None = None
) -> FunctionOut:
    out = FunctionOut.model_validate(row)
    out.capabilities = capabilities
    out.priority_reason = reason
    return out


async def _reasons(
    session: AsyncSession,
    org_id: uuid.UUID,
    job: AnalysisJob,
    rows: Sequence[ReFunction],
    capabilities: Mapping[int, int],
) -> dict[int, PriorityReason]:
    """Why each ranked function is on the decompile list: the first priority class (phase 5's
    order) its stored facts satisfy. Unranked functions (thunks, externals, library code, the
    quick profile) have none."""
    ranked = [r for r in rows if r.priority_rank is not None]
    if not ranked:
        return {}
    program = await repo.program(session, org_id, job.id)
    program_entry = None
    if program is not None and program.entry is not None:
        program_entry = int(program.entry)
    requested = set(requested_addresses(job))
    entries = [r.entry for r in ranked]
    suspicious = await repo.entries_with(
        session, org_id, job.id, entries, repo._calls_suspicious_import(org_id)
    )
    ioc = await repo.entries_with(
        session, org_id, job.id, entries, repo._references_ioc_string(org_id)
    )
    reasons: dict[int, PriorityReason] = {}
    for row in ranked:
        entry = int(row.entry)
        if entry in requested:
            reasons[entry] = "requested"
        elif entry == program_entry or row.name_source == "export":
            reasons[entry] = "entry_or_export"
        elif capabilities.get(entry):
            reasons[entry] = "capability"
        elif entry in suspicious:
            reasons[entry] = "suspicious_import"
        elif entry in ioc:
            reasons[entry] = "ioc_string"
        else:
            reasons[entry] = "size"
    return reasons


async def function_items(
    session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob, rows: Sequence[ReFunction]
) -> list[FunctionOut]:
    capabilities = await repo.capability_counts(session, org_id, job.id, [r.entry for r in rows])
    reasons = await _reasons(session, org_id, job, rows, capabilities)
    return [
        function_out(
            r, capabilities=capabilities.get(int(r.entry), 0), reason=reasons.get(int(r.entry))
        )
        for r in rows
    ]


async def function_page(
    session: AsyncSession,
    org_id: uuid.UUID,
    job: AnalysisJob,
    page: PageParams,
    **filters: Any,
) -> tuple[list[FunctionOut], int]:
    rows, total = await repo.functions(session, org_id, job.id, page, **filters)
    return await function_items(session, org_id, job, rows), total


async def _function(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, entry: int
) -> ReFunction:
    row = await repo.function(session, org_id, job_id, entry)
    if row is None:
        raise FunctionNotFound()
    return row


def _refs(rows: Sequence[Any]) -> list[FunctionRef]:
    return [FunctionRef(entry=entry, name=name) for entry, name in rows]


async def function_detail(
    session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob, entry: int
) -> FunctionDetailOut:
    """One function with what links to it (each list <= 200; the function's `callers` /
    `callees` counts are the totals)."""
    row = await _function(session, org_id, job.id, entry)
    [item] = await function_items(session, org_id, job, [row])
    body = [
        BodyRangeOut(start=r["start"], end=r["end"])
        for r in (row.body if isinstance(row.body, list) else [])
        if isinstance(r, Mapping) and "start" in r and "end" in r
    ]
    imports = await repo.imports_called(session, org_id, job.id, entry)
    strings = await repo.strings_referenced(session, org_id, job.id, entry)
    capabilities = [
        LinkedCapabilityOut(
            capability_id=cap.id,
            static_job_id=cap.job_id,
            name=cap.name,
            namespace=cap.namespace,
            attack=[a for a in cap.attack if isinstance(a, str)] if cap.attack else [],
            file_va=link.file_va,
        )
        for link, cap in await repo.linked_capabilities(session, org_id, job.id, entry)
    ]
    meta = await repo.decompilation(session, org_id, job.id, entry)
    return FunctionDetailOut(
        function=item,
        body=body,
        body_truncated=row.body_truncated,
        callers=_refs(await repo.callers(session, org_id, job.id, entry)),
        callees=_refs(await repo.callees(session, org_id, job.id, entry)),
        imports=[ImportOut.model_validate(i) for i in imports],
        strings=[StringOut.model_validate(s) for s in strings],
        capabilities=capabilities,
        finding_ids=await repo.finding_ids(session, org_id, job.id, entry),
        decompilation=DecompilationMetaOut.model_validate(meta) if meta is not None else None,
    )


async def function_code(
    session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob, entry: int
) -> FunctionCodeOut:
    row = await _function(session, org_id, job.id, entry)
    meta = await repo.decompilation(session, org_id, job.id, entry)
    if meta is None:
        raise CodeNotAvailable()
    return FunctionCodeOut.model_validate(
        {
            "entry": row.entry,
            "name": row.name,
            "status": meta.status,
            "code_kind": meta.code_kind,
            "code": meta.code,
            "lines": meta.lines,
            "code_sha256": meta.code_sha256,
            "truncated_bytes": meta.truncated_bytes,
        }
    )


# --- imports and strings -----------------------------------------------------------------------


def _with_functions(
    out: Any,
    row_id: uuid.UUID,
    totals: Mapping[uuid.UUID, int],
    listed: Mapping[uuid.UUID, list[Any]],
) -> Any:
    out.function_count = totals.get(row_id, 0)
    out.functions = [FunctionRef(entry=e, name=n) for e, n in listed.get(row_id, [])]
    return out


async def import_items(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, rows: Sequence[ReImport]
) -> list[ImportOut]:
    totals, listed = await repo.import_functions(session, org_id, job_id, [r.id for r in rows])
    return [_with_functions(ImportOut.model_validate(r), r.id, totals, listed) for r in rows]


async def string_items(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, rows: Sequence[ReString]
) -> list[StringOut]:
    totals, listed = await repo.string_functions(session, org_id, job_id, [r.id for r in rows])
    return [_with_functions(StringOut.model_validate(r), r.id, totals, listed) for r in rows]


# --- the static side ---------------------------------------------------------------------------


async def capability_function_counts(
    session: AsyncSession,
    org_id: uuid.UUID,
    static_job_id: uuid.UUID,
    capability_ids: list[uuid.UUID],
) -> dict[uuid.UUID, int] | None:
    """How many functions of the newest succeeded RE job sourced from this static job contain
    each capability (`CapabilityLinkedOut.functions`); None when there is no such job."""
    re_job = await repo.newest_linked_job(session, org_id, static_job_id)
    if re_job is None:
        return None
    return await repo.capability_function_counts(session, org_id, re_job, capability_ids)


def _locations(cap: MalwareCapability) -> list[int]:
    return join.parse_locations(cap.locations)


async def _unlocated(
    session: AsyncSession,
    org_id: uuid.UUID,
    static_job_id: uuid.UUID,
    program: ReProgram | None,
    locations: list[int],
    functions: Sequence[ReFunction],
) -> int:
    """Locations no listed function body contains (all of them without a capa base)."""
    if not locations:
        return 0
    capa_base = await session.scalar(
        select(MalwareSample.capa_base_address).where(
            MalwareSample.organization_id == org_id, MalwareSample.job_id == static_job_id
        )
    )
    if capa_base is None or program is None:
        return len(locations)
    index = join.BodyIndex(
        (int(r["start"]), int(r["end"]), int(f.entry))
        for f in functions
        for r in (f.body if isinstance(f.body, list) else [])
        if isinstance(r, Mapping) and "start" in r and "end" in r
    )
    capabilities = [join.SourceCapability(uuid.UUID(int=0), tuple(locations))]
    result = join.join(
        capabilities,
        capa_base=int(capa_base),
        preferred_base=int(program.preferred_base),
        index=index,
    )
    return result.unlocated


async def capability_functions(
    session: AsyncSession, org_id: uuid.UUID, static_job_id: uuid.UUID, capability_id: uuid.UUID
) -> CapabilityFunctionsOut:
    """`GET /analyses/{static_job}/capabilities/{id}/functions`: the functions of the newest
    succeeded RE job sourced from that static job that contain the capability (<= 50).
    404 for an unknown / foreign / non-static job or a capability of another job."""
    await session.execute(text(STATEMENT_TIMEOUT))
    await static_repo.ensure_static_job(session, org_id, static_job_id)
    cap = await session.scalar(
        select(MalwareCapability).where(
            MalwareCapability.organization_id == org_id,
            MalwareCapability.job_id == static_job_id,
            MalwareCapability.id == capability_id,
        )
    )
    if cap is None:
        raise NotFound()
    locations = _locations(cap)
    out = CapabilityFunctionsOut(capability=CapabilityOut.model_validate(cap), locations=locations)
    re_job = await repo.newest_linked_job(session, org_id, static_job_id)
    if re_job is None:
        out.unlocated = len(locations)
        return out
    rows = await repo.capability_functions(session, org_id, re_job, capability_id)
    out.re_job_id = re_job
    out.functions = [
        CapabilityFunctionRef(
            re_job_id=re_job,
            function=FunctionRef(entry=function.entry, name=function.name),
            file_va=link.file_va,
        )
        for link, function in rows
    ]
    program = await repo.program(session, org_id, re_job)
    out.unlocated = await _unlocated(
        session, org_id, static_job_id, program, locations, [f for _, f in rows]
    )
    return out
