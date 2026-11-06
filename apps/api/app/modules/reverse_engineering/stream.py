"""Validation of a downloaded `re.v1` result stream (a local gzip NDJSON file; M10 phase 7).

Everything in the stream comes from the untrusted RE analyzer, which parsed an
attacker-chosen binary. `validate()` reads it once and refuses it as a whole on the first
problem, before anything is written. On top of the shared framing (result_stream: inflated
size, line count, line length, header first, hashed trailer last) with the RE bounds
(`RE_MAX_RESULT_DECOMPRESSED_BYTES`, lines = the sum of the caps + 3, the M8 RT9 lesson), a
stream must have:

- an `re.v1` header naming this job and its requested profile; `engine: replay` only when
  the API runs the test profile (`ENV=test`); header blocks that fit their `re_programs`
  columns (`tool_versions`, `truncated`, `audit` <= 2 KiB, `stages` <= 8 KiB, `jvm_args`
  <= 16 KiB, the engine version <= 32 characters);
- every body line exactly one known record (the frozen contract refuses unknown kinds and
  fields, oversized text, NUL, non-finite floats, a code / sha256 mismatch, ...);
- the shared cross-record rules of `cyberlab_jobs.reverse.StreamChecker` (line order, one
  program line second, every reference to a known function / import / string, no duplicate
  key, the per-kind caps of the job's `ReLimits`, the code byte budget, no decompiled line
  in a `quick` stream, the header's code kind);
- a program line whose sha256 and size equal the evidence record and whose format equals the
  source static job's (when that job still has its sample row; M7 retention may have
  purged it);
- no duplicate finding id or IOC (the shared tables' unique indexes).

Memory stays bounded: the checker keeps key sets only (≈ 300 000 ints at the caps), plus the
functions' decompile status (<= `max_decompiled` entries) and, only when the source job has
capa locations to link, the body ranges (<= 16 per function) for the join. The write pass
(`records()`) re-reads the validated file.

A **diagnostic stream** (`unsupported_architecture`, `unsupported_managed_code`) is header,
program, trailer (`validate_diagnostic`).
"""

import json
import uuid
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cyberlab_jobs.results import FindingRecord, IocRecord, ResultTrailer
from cyberlab_jobs.reverse import (
    RE_RECORD_ADAPTER,
    ReDecompiledRecord,
    ReEngine,
    ReFunctionRecord,
    ReLimits,
    ReProgramRecord,
    ReRecordLine,
    ReResultHeader,
    StreamChecker,
    StreamRefused,
)
from pydantic import BaseModel, ValidationError

from app.core.config import Settings
from app.modules.analysis.result_stream import (
    MAX_LINE_BYTES,
    InvalidResult,
    body_lines,
    check_framing,
    ioc_key,
)
from app.modules.reverse_engineering.dispatch import re_limits

__all__ = [
    "DIAGNOSTIC_CAPS",
    "PROGRAM_KIND",
    "Caps",
    "Expected",
    "InvalidResult",
    "JobFacts",
    "Validated",
    "json_size",
    "records",
    "validate",
    "validate_diagnostic",
]

# Folded into the one `re_programs` row, not inserted on its own.
PROGRAM_KIND = "program"
# `re_programs` column bounds (0018 checks), refused here as `invalid_result`.
MAX_ENGINE_VERSION = 32
HEADER_BLOCKS: dict[str, int] = {
    "tool_versions": 2048,
    "truncated": 2048,
    "audit": 2048,
    "stages": 8192,
    "jvm_args": 16384,
}


def json_size(value: object) -> int:
    """`octet_length(value::text)` of a jsonb value, conservatively (Postgres prints jsonb
    with `, ` and `: ` separators, as `json.dumps` does by default)."""
    return len(json.dumps(value, ensure_ascii=False).encode())


@dataclass(frozen=True)
class Caps:
    max_decompressed_bytes: int
    max_lines: int  # every line of the stream, header and trailer included
    limits: ReLimits | None  # None: a diagnostic stream (no records)

    @classmethod
    def from_settings(cls, settings: Settings) -> "Caps":
        # The very limits the worker was sent (dispatch builds them the same way).
        return cls(
            max_decompressed_bytes=settings.re_max_result_decompressed_bytes,
            max_lines=settings.re_max_result_lines(),
            limits=re_limits(settings),
        )


# A diagnostic stream is header, program, trailer: three lines, none above MAX_LINE_BYTES.
DIAGNOSTIC_CAPS = Caps(max_decompressed_bytes=3 * MAX_LINE_BYTES, max_lines=3, limits=None)


@dataclass(frozen=True)
class Expected:
    """The trusted evidence record the program line must match."""

    sha256: str
    size: int


@dataclass(frozen=True)
class JobFacts:
    """What the job asked for (our own job row and its source static job, never the
    stream)."""

    job_id: uuid.UUID
    profile: str  # `quick` or `full`
    file_format: str | None  # the source job's `pe` / `elf`; None once its result was purged
    allow_replay: bool = False  # the test profile only


@dataclass
class Validated:
    header: ReResultHeader
    program: ReProgramRecord
    counts: Counter[str] = field(default_factory=Counter)  # record kind -> lines (no program)
    # function entry -> its decompiled line's status (`not_selected` when absent)
    decompile_status: dict[int, str] = field(default_factory=dict)
    # (start RVA, end RVA, entry) of every body range; collected only for the capa join
    ranges: list[tuple[int, int, int]] = field(default_factory=list)


def _record(line: bytes) -> ReRecordLine:
    try:
        return RE_RECORD_ADAPTER.validate_json(line)
    except ValidationError as exc:
        raise InvalidResult("invalid_record") from exc


def check_header_blocks(header: ReResultHeader) -> None:
    """The header blocks fit their `re_programs` columns (else the database would refuse the
    row: refuse the stream first, cleanly)."""
    dumped = header.model_dump(mode="json")
    for name, limit in HEADER_BLOCKS.items():
        if json_size(dumped[name]) > limit:
            raise InvalidResult("header_too_large")
    version = engine_version(header)
    if version is not None and len(version) > MAX_ENGINE_VERSION:
        raise InvalidResult("invalid_header")


def engine_version(header: ReResultHeader) -> str | None:
    """The analysis engine's version: Ghidra's or radare2's (a replay run names the engine it
    replays)."""
    versions = header.tool_versions
    if header.engine == ReEngine.REPLAY:
        return versions.get("ghidra") or versions.get("radare2")
    return versions.get(header.engine.value)


class _Checker:
    def __init__(
        self, job: JobFacts, expected: Expected, caps: Caps, *, diagnostic: bool, ranges: bool
    ) -> None:
        self.job = job
        self.expected = expected
        self.diagnostic = diagnostic
        self.keep_ranges = ranges
        self.stream = StreamChecker(job_id=job.job_id, limits=caps.limits, diagnostic=diagnostic)
        self.header: ReResultHeader | None = None
        self.program: ReProgramRecord | None = None
        self.counts: Counter[str] = Counter()
        self.decompile_status: dict[int, str] = {}
        self.ranges: list[tuple[int, int, int]] = []
        self.findings: set[uuid.UUID] = set()
        self.iocs: set[tuple[str, bytes]] = set()  # ioc_key(): bounded memory

    def _feed(self, line: BaseModel) -> None:
        try:
            self.stream.feed(line)
        except StreamRefused as exc:
            raise InvalidResult("stream_rule") from exc

    def first(self, line: bytes) -> None:
        try:
            header = ReResultHeader.model_validate_json(line)
        except ValidationError as exc:  # incl. another schema's header (e.g. static.v1)
            raise InvalidResult("invalid_header") from exc
        if header.job_id != self.job.job_id:
            raise InvalidResult("header_job_mismatch")
        if header.profile.value != self.job.profile:
            raise InvalidResult("header_profile_mismatch")
        if header.engine == ReEngine.REPLAY and not self.job.allow_replay:
            raise InvalidResult("replay_engine_refused")
        check_header_blocks(header)
        self._feed(header)
        self.header = header

    def middle(self, line: bytes) -> None:
        if self.header is None:  # unreachable: check_framing feeds the header first
            raise InvalidResult("missing_header")
        record = _record(line)
        self._feed(record)  # order, references, duplicates, caps, code budget
        if isinstance(record, ReProgramRecord):
            self._program(record)
            return
        self.counts[record.kind] += 1
        if isinstance(record, ReFunctionRecord):
            if self.keep_ranges:
                self.ranges.extend((r.start, r.end, record.entry) for r in record.body)
        elif isinstance(record, ReDecompiledRecord):
            self.decompile_status[record.function_entry] = record.status.value
        elif isinstance(record, FindingRecord):
            if record.finding_id in self.findings:
                raise InvalidResult("duplicate_finding")
            self.findings.add(record.finding_id)
        elif isinstance(record, IocRecord):
            key = ioc_key(record.type, record.value)
            if key in self.iocs:
                raise InvalidResult("duplicate_ioc")
            self.iocs.add(key)

    def _program(self, program: ReProgramRecord) -> None:
        if program.sha256 != self.expected.sha256 or program.size_bytes != self.expected.size:
            raise InvalidResult("program_mismatch")
        if self.job.file_format is not None and program.format != self.job.file_format:
            raise InvalidResult("format_mismatch")
        self.program = program

    def result(self) -> Validated:
        # check_framing verified the trailer's count and digest; the checker only needs to
        # see that one came last.
        self._feed(ResultTrailer.model_construct())
        try:
            self.stream.finish()
        except StreamRefused as exc:
            raise InvalidResult("stream_rule") from exc
        if self.header is None:
            raise InvalidResult("missing_header")
        if self.program is None:
            raise InvalidResult("missing_program")
        return Validated(self.header, self.program, self.counts, self.decompile_status, self.ranges)


def _validate(
    path: Path, job: JobFacts, expected: Expected, caps: Caps, *, diagnostic: bool, ranges: bool
) -> Validated:
    check = _Checker(job, expected, caps, diagnostic=diagnostic, ranges=ranges)
    check_framing(
        path,
        max_decompressed=caps.max_decompressed_bytes,
        max_lines=caps.max_lines,
        first=check.first,
        middle=check.middle,
    )
    return check.result()


def validate(
    path: Path, job: JobFacts, expected: Expected, caps: Caps, *, ranges: bool = False
) -> Validated:
    """A full (`succeeded`) result. Blocking (run in a worker thread). Raises InvalidResult;
    never touches the database. `ranges`: keep the body ranges for the capa join."""
    return _validate(path, job, expected, caps, diagnostic=False, ranges=ranges)


def validate_diagnostic(path: Path, job: JobFacts, expected: Expected) -> Validated:
    """An `unsupported_architecture` / `unsupported_managed_code` stream: header, program,
    trailer (the program identity checked as for a full result)."""
    return _validate(path, job, expected, DIAGNOSTIC_CAPS, diagnostic=True, ranges=False)


def records(path: Path, caps: Caps) -> Iterator[tuple[Any, int]]:
    """Every row-per-line record of an already validated stream (not the program line), with
    the size of its raw line in bytes."""
    for line in body_lines(path, caps.max_decompressed_bytes):
        record = _record(line)
        if record.kind != PROGRAM_KIND:
            yield record, len(line)
