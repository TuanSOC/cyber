"""Trusted ingest of an `re.v1` result (M10 phase 7). Called from `app.workers.ingest` by the
job's analyzer (`SUCCESS_INGESTERS[REVERSE]`, `DIAGNOSTIC_INGESTERS[REVERSE]`):

- `ingest_re(job, msg, path)`: a `succeeded` report with its downloaded result. Validates the
  whole stream first in a worker thread (`stream.validate`: framing with the RE bounds, the
  contract, the shared cross-record rules, the program's sha256 / size against the evidence,
  the source job's format, `engine: replay` refused outside the test profile), joins the
  source static job's capa locations to the functions on file virtual addresses (`join`,
  RT8), then writes in ONE transaction: `re_programs` (with `preferred_base`, the peak
  memory and `counts.capa_linked` / `capa_unlocated`), the eight bulk tables in batches
  (imports and strings get their row ids here; their references are mapped from the
  stream-local index), the capa links (`re_function_capabilities`), `analysis_findings`,
  `iocs`, the job summary (<= 32 KiB), the final state, custody `analyzed` and the audit
  entry (the shared `_persist`).
- `ingest_re_diagnostic(job, msg, path)`: a `failed` report (`unsupported_architecture` /
  `unsupported_managed_code`) with its diagnostic stream (header, program, trailer):
  `re_programs` only, and the job fails with the worker's code.

Any defect fails the job `invalid_result` with no row written. A source static job whose
results were purged (M7 retention) leaves the stream ingestible: no format check and no
links. The transaction plumbing is the shared one of `app.workers.ingest`, imported at call
time because that module imports this one.
"""

import json
import uuid
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import anyio
from cyberlab_jobs import IngestMessageV1
from cyberlab_jobs.results import FindingRecord, IocRecord
from cyberlab_jobs.reverse import (
    ReCallEdgeRecord,
    ReDecompiledRecord,
    ReFunctionRecord,
    ReImportRecord,
    ReImportRefRecord,
    ReStringRecord,
    ReStringRefRecord,
)
from sqlalchemy import Table, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis import repository as repo
from app.modules.analysis import result_rows
from app.modules.analysis.models import ACTIVE, AnalysisJob
from app.modules.analysis.result_stream import InvalidResult
from app.modules.pcap_analysis import ingest as pcap_ingest
from app.modules.reverse_engineering import join, stream
from app.modules.reverse_engineering.models import (
    FunctionDecompileStatus,
    ReCallEdge,
    ReDecompilation,
    ReFunction,
    ReFunctionCapability,
    ReImport,
    ReImportRef,
    ReProgram,
    ReString,
    ReStringRef,
)
from app.modules.static_analysis.models import MalwareCapability, MalwareSample

BATCH_LINES = 1000
BATCH_BYTES = 8 * 1024**2
LINK_BATCH = 1000
# `analysis_jobs.summary` of an RE job and `re_programs.counts` (0018 check).
SUMMARY_MAX_BYTES = 32 * 1024
PROGRAM_COUNTS_MAX_BYTES = 4096

# Summary counter name per record kind.
COUNT_NAMES = {
    "function": "functions",
    "call_edge": "call_edges",
    "import": "imports",
    "import_ref": "import_refs",
    "string": "strings",
    "string_ref": "string_refs",
    "decompiled": "decompiled",
    "finding": "findings",
    "ioc": "iocs",
}
PROGRAMS = cast(Table, ReProgram.__table__)
FUNCTIONS = cast(Table, ReFunction.__table__)
CALL_EDGES = cast(Table, ReCallEdge.__table__)
IMPORTS = cast(Table, ReImport.__table__)
IMPORT_REFS = cast(Table, ReImportRef.__table__)
STRINGS = cast(Table, ReString.__table__)
STRING_REFS = cast(Table, ReStringRef.__table__)
DECOMPILATIONS = cast(Table, ReDecompilation.__table__)
LINKS = cast(Table, ReFunctionCapability.__table__)


# --- the source static job ---------------------------------------------------------------


@dataclass(frozen=True)
class Source:
    """What the join needs from the RE job's source static job (empty once purged)."""

    file_format: str | None
    capa_base: int | None
    capabilities: tuple[join.SourceCapability, ...] = ()


async def load_source(job: AnalysisJob) -> Source:
    if job.source_job_id is None:  # the 0018 checks make this unreachable
        raise RuntimeError(f"reverse job {job.id} has no source job")
    async with tenant_session(job.organization_id, None) as session:
        sample = (
            await session.execute(
                select(MalwareSample.file_format, MalwareSample.capa_base_address).where(
                    MalwareSample.organization_id == job.organization_id,
                    MalwareSample.job_id == job.source_job_id,
                )
            )
        ).one_or_none()
        rows = await session.execute(
            select(MalwareCapability.id, MalwareCapability.locations)
            .where(
                MalwareCapability.organization_id == job.organization_id,
                MalwareCapability.job_id == job.source_job_id,
            )
            .order_by(MalwareCapability.id)
        )
        capabilities = tuple(
            join.SourceCapability(cap_id, tuple(join.parse_locations(locations)))
            for cap_id, locations in rows
        )
    if sample is None:
        return Source(file_format=None, capa_base=None, capabilities=capabilities)
    base = None if sample.capa_base_address is None else int(sample.capa_base_address)
    return Source(file_format=sample.file_format, capa_base=base, capabilities=capabilities)


def replay_allowed() -> bool:
    """`engine: replay` streams are hand-written test data: accepted only under the test
    profile (the api-test service runs with ENV=test)."""
    return get_settings().env == "test"


def job_facts(job: AnalysisJob, source: Source) -> stream.JobFacts:
    if job.profile is None:  # the 0018 checks make this unreachable
        raise RuntimeError(f"reverse job {job.id} has no profile")
    return stream.JobFacts(
        job_id=job.id,
        profile=job.profile.value,
        file_format=source.file_format,
        allow_replay=replay_allowed(),
    )


async def _expected(job: AnalysisJob) -> stream.Expected:
    from app.workers import ingest as plumbing

    facts = await plumbing._evidence_facts(job)
    return stream.Expected(sha256=facts.sha256, size=facts.size)


# --- rows ----------------------------------------------------------------------------------


class RowBuilder:
    """`to_row` of one stream: imports and strings get their row ids when their line is
    read (before any reference to them: `LINE_ORDER`), their references map the stream-local
    index to that id; a function's decompile status comes from the validated stream."""

    def __init__(self, decompile_status: dict[int, str]) -> None:
        self.decompile_status = decompile_status
        self.imports: dict[int, uuid.UUID] = {}
        self.strings: dict[int, uuid.UUID] = {}

    def __call__(self, record: Any) -> tuple[Table, dict[str, Any]]:
        if isinstance(record, ReFunctionRecord):
            return FUNCTIONS, {
                "entry": record.entry,
                "rva": record.rva,
                "name": record.name,
                "name_source": record.name_source.value,
                "size": record.size,
                "body": [{"start": r.start, "end": r.end} for r in record.body],
                "body_truncated": record.body_truncated,
                "is_thunk": record.is_thunk,
                "is_external": record.is_external,
                "is_library": record.is_library,
                "signature": record.signature,
                "calling_convention": record.calling_convention,
                "instructions": record.instructions,
                "callers": record.callers,
                "callees": record.callees,
                "decompile_status": self.decompile_status.get(
                    record.entry, FunctionDecompileStatus.NOT_SELECTED.value
                ),
                "priority_rank": record.priority_rank,
            }
        if isinstance(record, ReCallEdgeRecord):
            return CALL_EDGES, {
                "caller_entry": record.caller,
                "callee_entry": record.callee,
                "sites": record.sites,
            }
        if isinstance(record, ReImportRecord):
            row_id = self.imports[record.index] = uuid.uuid4()
            return IMPORTS, {
                "id": row_id,
                "library": record.library,
                "name": record.name,
                "ordinal": record.ordinal,
                "address": record.address,
            }
        if isinstance(record, ReImportRefRecord):
            return IMPORT_REFS, {
                "import_id": self.imports[record.import_index],
                "function_entry": record.function_entry,
                "count": record.count,
            }
        if isinstance(record, ReStringRecord):
            row_id = self.strings[record.index] = uuid.uuid4()
            return STRINGS, {
                "id": row_id,
                "address": record.address,
                "encoding": record.encoding,
                "value": record.value,
                "length": record.length,
            }
        if isinstance(record, ReStringRefRecord):
            return STRING_REFS, {
                "string_id": self.strings[record.string_index],
                "function_entry": record.function_entry,
                "count": record.count,
            }
        if isinstance(record, ReDecompiledRecord):
            return DECOMPILATIONS, {
                "function_entry": record.function_entry,
                "status": record.status.value,
                "code_kind": record.code_kind.value,
                "code": record.code,
                "lines": record.lines,
                "code_sha256": record.code_sha256,
                "truncated_bytes": record.truncated_bytes,
                "duration_ms": record.duration_ms,
            }
        if isinstance(record, FindingRecord | IocRecord):
            return pcap_ingest.to_row(record)  # the shared tables, one row shape
        raise TypeError(f"no table for record kind {record.kind!r}")


def counts(result: stream.Validated, linked: join.JoinResult) -> dict[str, int]:
    return {
        **{name: result.counts[kind] for kind, name in COUNT_NAMES.items()},
        "capa_linked": linked.linked,
        "capa_unlocated": linked.unlocated,
        "capabilities_linked": linked.capabilities,
    }


def peak_memory(result: stream.Validated) -> int | None:
    peaks = [s.peak_memory_bytes for s in result.header.stages if s.peak_memory_bytes is not None]
    return max(peaks) if peaks else None


def program_row(result: stream.Validated, linked: join.JoinResult | None) -> dict[str, Any]:
    """The `re_programs` row (header blocks bounded by `stream.check_header_blocks`)."""
    header, program = result.header, result.program
    program_counts: dict[str, int] = dict(program.counts)
    if linked is not None:
        program_counts |= {"capa_linked": linked.linked, "capa_unlocated": linked.unlocated}
    if stream.json_size(program_counts) > PROGRAM_COUNTS_MAX_BYTES:
        raise InvalidResult("program_counts_too_large")
    return {
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
        "peak_memory_bytes": peak_memory(result),
        "engine": header.engine.value,
        "engine_version": stream.engine_version(header),
        "code_kind": header.code_kind.value,
        "stages": [s.model_dump(mode="json") for s in header.stages],
        "counts": program_counts,
        "truncated": dict(header.truncated),
        "tool_versions": dict(header.tool_versions),
        "audit": dict(header.audit),
        "jvm_args": list(header.jvm_args),
    }


def build_summary(
    job: AnalysisJob,
    result: stream.Validated,
    evidence: stream.Expected,
    linked: join.JoinResult | None,
    max_decompiled: int | None,
) -> dict[str, Any]:
    """The job summary (<= 32 KiB): the run facts of the header, the trusted sample identity
    (the evidence record's size and sha256, which the program line had to equal), the
    program facts, per-stage status, counts and the decompile budget. Raises InvalidResult
    if it would not fit."""
    header = result.header.model_dump(mode="json")
    program = result.program
    summary: dict[str, Any] = {
        "schema_version": header["schema_version"],
        "profile": header["profile"],
        "engine": header["engine"],
        "code_kind": header["code_kind"],
        "tool_versions": header["tool_versions"],
        "stages": header["stages"],
        "audit": header["audit"],
        "engine_errors": header["engine_errors"],
        "truncated": header["truncated"],
        "source_job_id": str(job.source_job_id),
        "sample": {"size_bytes": evidence.size, "sha256": evidence.sha256},
        "program": {
            "format": program.format,
            "arch": program.arch,
            "bits": program.bits,
            "analysis_status": program.analysis_status,
        },
        "peak_memory_bytes": peak_memory(result),
    }
    if linked is not None:
        summary["counts"] = counts(result, linked)
        summary["decompile_budget"] = {"used": result.counts["decompiled"], "max": max_decompiled}
    if len(json.dumps(summary).encode()) > SUMMARY_MAX_BYTES:
        raise InvalidResult("summary_too_large")
    return summary


@dataclass(frozen=True)
class Prepared:
    """A validated stream with everything its write needs (computed off the event loop)."""

    result: stream.Validated
    linked: join.JoinResult
    program: dict[str, Any]


def prepare(
    path: Path,
    facts: stream.JobFacts,
    expected: stream.Expected,
    caps: stream.Caps,
    source: Source,
) -> Prepared:
    """Blocking (worker thread): validate, then join the capa locations (RT8)."""
    has_locations = any(c.locations for c in source.capabilities)
    result = stream.validate(path, facts, expected, caps, ranges=has_locations)
    linked = join.join(
        source.capabilities,
        capa_base=source.capa_base,
        preferred_base=result.program.preferred_base,
        index=join.BodyIndex(result.ranges),
    )
    return Prepared(result, linked, program_row(result, linked))


async def insert_program(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, row: dict[str, Any]
) -> None:
    await session.execute(insert(PROGRAMS), [{**row, "organization_id": org_id, "job_id": job_id}])


async def insert_rows(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    path: Path,
    prepared: Prepared,
    caps: stream.Caps,
) -> Counter[str]:
    """The program row, every record and the capa links; returns the record rows written per
    kind (the program line and the links are not counted)."""
    await insert_program(session, org_id, job_id, prepared.program)
    to_row = RowBuilder(prepared.result.decompile_status)

    def make_batch(
        records: Iterator[tuple[Any, int]], scope: dict[str, Any], written: Counter[str]
    ) -> result_rows.Batch:
        return result_rows.next_batch(
            records, scope, written, to_row, max_lines=BATCH_LINES, max_bytes=BATCH_BYTES
        )

    written = await result_rows.insert_batches(
        session, org_id, job_id, stream.records(path, caps), make_batch
    )
    links = [
        {
            "organization_id": org_id,
            "job_id": job_id,
            "capability_id": link.capability_id,
            "function_entry": link.function_entry,
            "file_va": link.file_va,
        }
        for link in prepared.linked.links
    ]
    for start in range(0, len(links), LINK_BATCH):
        await session.execute(insert(LINKS), links[start : start + LINK_BATCH])
    return written


async def ingest_re(job: AnalysisJob, msg: IngestMessageV1, path: Path) -> None:
    """`re.v1` success: validate the whole stream and join (worker thread), then write it in
    one transaction."""
    from app.workers import ingest as plumbing

    caps = stream.Caps.from_settings(get_settings())
    expected = await _expected(job)
    source = await load_source(job)
    max_decompiled = caps.limits.max_decompiled if caps.limits is not None else None
    try:
        prepared = await anyio.to_thread.run_sync(
            prepare, path, job_facts(job, source), expected, caps, source
        )
        summary = build_summary(job, prepared.result, expected, prepared.linked, max_decompiled)
    except InvalidResult as exc:
        await plumbing._refuse(job, exc)
        return

    async def write(session: AsyncSession) -> dict[str, Any]:
        written = await insert_rows(session, job.organization_id, job.id, path, prepared, caps)
        plumbing._check_written(written, prepared.result.counts)
        return summary

    await plumbing._persist(job, msg, write)


async def ingest_re_diagnostic(job: AnalysisJob, msg: IngestMessageV1, path: Path) -> None:
    """`unsupported_architecture` / `unsupported_managed_code` with its diagnostic stream:
    store the program facts, fail the job with the worker's code."""
    from app.workers import ingest as plumbing

    expected = await _expected(job)
    source = await load_source(job)
    try:
        result = await anyio.to_thread.run_sync(
            stream.validate_diagnostic, path, job_facts(job, source), expected
        )
        row = program_row(result, None)
        summary = build_summary(job, result, expected, None, None)
    except InvalidResult as exc:
        await plumbing._refuse(job, exc)
        return

    code = msg.error_code
    if code is None:  # is_diagnostic() admits the two diagnostic codes only
        raise RuntimeError(f"diagnostic report of job {job.id} without an error code")
    settings = get_settings()
    async with tenant_session(job.organization_id, None) as session:
        await plumbing._limit_transaction(session, settings)
        # Under the row lock in this transaction: a redelivered report cannot insert twice.
        locked = await repo.get_for_update(session, job.organization_id, job.id)
        if locked is None or locked.status not in ACTIVE:
            return
        # The row first: the job guard refuses any write after the final state, and this
        # INSERT would otherwise flush the transition before the columns set below.
        await insert_program(session, job.organization_id, job.id, row)
        await plumbing._fail(session, locked, code)
        # Flushed in the same UPDATE as the transition.
        locked.result_version_id = msg.result_version_id
        locked.worker_version = msg.worker_version
        locked.summary = summary
