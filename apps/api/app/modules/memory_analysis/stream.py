"""Validation of a downloaded `memory.v1` result stream (a local gzip NDJSON file).

Everything in the stream comes from the untrusted memory analyzer, which parsed an
attacker-chosen image. `validate()` reads it once, in bounded memory, and refuses it as a
whole on the first problem. On top of the shared framing rules (result_stream: inflated size,
line count, line length, header first, hashed trailer last), with the memory bounds of the
settings (`MEMORY_MAX_RESULT_DECOMPRESSED_BYTES`, lines = the sum of the caps + 3, RT9), a
stream must have:

- a `memory.v1` header naming this job and its profile, an OS allowed by the job's OS hint
  and the symbols outcome of its kind of report (`resolved` for a success, `missing` for a
  diagnostic);
- every body line exactly one known record (unknown kind or field, oversized text, NUL,
  non-finite floats are all refused by the contract);
- exactly one `image` line (a diagnostic: at most one, and nothing else) whose size and sha256
  equal the evidence record: the analyzer must have looked at the stored bytes only;
- records of the header's OS only (no `bash` artifact on Windows, no `service` on Linux, no
  PDB on a Linux image, no kernel banner on a Windows one);
- the process-list plugin `ok` (the job-success rule, plan "Job success");
- no more records of a kind than the job's MemoryLimits, no duplicate process (pid, offset),
  finding id or IOC.

A pid referenced by a connection, injection, artifact or timeline line that no process line
carries is not refused (a smeared image has such rows) but counted as `orphan_refs`, so a
hostile stream cannot invent links silently. Only after that does `records()` read the same
file again to feed the database writes.
"""

import uuid
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from cyberlab_jobs.memory import (
    LINUX_ARTIFACTS,
    MEMORY_RECORD_ADAPTER,
    PROCESS_LIST_PLUGIN,
    WINDOWS_ARTIFACTS,
    MemoryArtifactRecord,
    MemoryConnectionRecord,
    MemoryImageRecord,
    MemoryInjectionRecord,
    MemoryProcessRecord,
    MemoryRecordLine,
    MemoryResultHeader,
    MemoryTimelineEvent,
    OsHint,
)
from cyberlab_jobs.results import FindingRecord, IocRecord
from pydantic import ValidationError

from app.core.config import Settings
from app.modules.analysis.result_stream import (
    MAX_LINE_BYTES,
    InvalidResult,
    body_lines,
    check_framing,
    ioc_key,
)
from app.modules.memory_analysis.dispatch import memory_limits

__all__ = [
    "DIAGNOSTIC_CAPS",
    "Caps",
    "Expected",
    "InvalidResult",
    "JobFacts",
    "Validated",
    "records",
    "validate",
    "validate_diagnostic",
]

# Folded into the one `memory_images` row, not inserted on its own.
IMAGE_KIND = "image"
# `memory_images.volatility_version` is a 64-character column.
MAX_ENGINE_VERSION = 64


@dataclass(frozen=True)
class Caps:
    max_decompressed_bytes: int
    per_kind: dict[str, int]
    max_lines: int  # every line of the stream, header and trailer included

    @classmethod
    def from_settings(cls, settings: Settings) -> "Caps":
        # The very limits the worker was sent (dispatch builds them the same way).
        limits = memory_limits(settings)
        return cls(
            max_decompressed_bytes=settings.memory_max_result_decompressed_bytes,
            per_kind={
                IMAGE_KIND: 1,
                "process": limits.max_processes,
                "connection": limits.max_connections,
                "injection": limits.max_injections,
                "artifact": limits.max_artifacts,
                "finding": limits.max_findings,
                "ioc": limits.max_iocs,
                "timeline": limits.max_timeline,
            },
            max_lines=settings.memory_max_result_lines(),
        )


# A diagnostic stream is header, at most the image line, trailer: one header line can never
# legitimately exceed MAX_LINE_BYTES, so three of them bound the whole stream.
DIAGNOSTIC_CAPS = Caps(
    max_decompressed_bytes=3 * MAX_LINE_BYTES, per_kind={IMAGE_KIND: 1}, max_lines=3
)


@dataclass(frozen=True)
class Expected:
    """The trusted evidence record the image line must match."""

    sha256: str
    size: int


@dataclass(frozen=True)
class JobFacts:
    """What the job asked for (from our own job row, never from the stream)."""

    job_id: uuid.UUID
    profile: str  # `triage` or `full`
    os_hint: str  # `auto`, `windows` or `linux`


@dataclass
class Validated:
    header: MemoryResultHeader
    image: MemoryImageRecord | None  # always set for a full result
    counts: Counter[str] = field(default_factory=Counter)  # record kind -> lines
    orphan_refs: int = 0  # referencing lines whose pid no process line carries


def _record(line: bytes) -> MemoryRecordLine:
    try:
        return MEMORY_RECORD_ADAPTER.validate_json(line)
    except ValidationError as exc:
        raise InvalidResult("invalid_record") from exc


def _referenced_pid(record: MemoryRecordLine) -> int | None:
    if isinstance(
        record,
        MemoryConnectionRecord | MemoryInjectionRecord | MemoryArtifactRecord | MemoryTimelineEvent,
    ):
        return record.pid
    return None


class _Checker:
    def __init__(self, job: JobFacts, caps: Caps, *, diagnostic: bool) -> None:
        self.job = job
        self.caps = caps
        self.diagnostic = diagnostic
        self.header: MemoryResultHeader | None = None
        self.image: MemoryImageRecord | None = None
        self.counts: Counter[str] = Counter()
        self.processes: set[tuple[int, int | None]] = set()
        self.pids: set[int] = set()
        # pid -> referencing lines (bounded by the per-kind caps).
        self.references: Counter[int] = Counter()
        self.findings: set[uuid.UUID] = set()
        self.iocs: set[tuple[str, bytes]] = set()  # ioc_key(): bounded memory

    def first(self, line: bytes) -> None:
        try:
            header = MemoryResultHeader.model_validate_json(line)
        except ValidationError as exc:  # incl. another schema's header (e.g. static.v1)
            raise InvalidResult("invalid_header") from exc
        if header.job_id != self.job.job_id:
            raise InvalidResult("header_job_mismatch")
        if header.profile.value != self.job.profile:
            raise InvalidResult("header_profile_mismatch")
        if self.job.os_hint != OsHint.AUTO.value and header.os != self.job.os_hint:
            raise InvalidResult("header_os_mismatch")
        version = header.tool_versions.get("volatility3")
        if version is not None and len(version) > MAX_ENGINE_VERSION:
            raise InvalidResult("invalid_header")
        if self.diagnostic:
            if header.symbols.status != "missing":
                raise InvalidResult("not_diagnostic")
        else:
            if header.symbols.status != "resolved":
                raise InvalidResult("symbols_status_mismatch")
            ok = {p.plugin for p in header.plugins if p.status == "ok"}
            if PROCESS_LIST_PLUGIN[header.os] not in ok:
                raise InvalidResult("process_list_not_ok")
        self.header = header

    def middle(self, line: bytes) -> None:
        header = self.header
        if header is None:  # unreachable: check_framing feeds the header first
            raise InvalidResult("missing_header")
        record = _record(line)
        kind = record.kind
        if self.diagnostic and kind != IMAGE_KIND:
            raise InvalidResult("diagnostic_with_records")
        self.counts[kind] += 1
        if self.counts[kind] > self.caps.per_kind[kind]:
            raise InvalidResult(f"too_many_{kind}")
        if isinstance(record, MemoryImageRecord):
            if header.os == "windows" and record.kernel_banner is not None:
                raise InvalidResult("os_mismatch")
            if header.os == "linux" and (record.pdb is not None or record.nt_build is not None):
                raise InvalidResult("os_mismatch")
            self.image = record
        elif isinstance(record, MemoryProcessRecord):
            key = (record.pid, record.offset)
            if key in self.processes:
                raise InvalidResult("duplicate_process")
            self.processes.add(key)
            self.pids.add(record.pid)
        elif isinstance(record, MemoryArtifactRecord):
            allowed = WINDOWS_ARTIFACTS if header.os == "windows" else LINUX_ARTIFACTS
            if record.type not in allowed:
                raise InvalidResult("os_mismatch")
        elif isinstance(record, FindingRecord):
            if record.finding_id in self.findings:
                raise InvalidResult("duplicate_finding")
            self.findings.add(record.finding_id)
        elif isinstance(record, IocRecord):
            ioc = ioc_key(record.type, record.value)
            if ioc in self.iocs:
                raise InvalidResult("duplicate_ioc")
            self.iocs.add(ioc)
        pid = _referenced_pid(record)
        if pid is not None:
            self.references[pid] += 1

    def orphan_refs(self) -> int:
        return sum(n for pid, n in self.references.items() if pid not in self.pids)


def _check_image(image: MemoryImageRecord, expected: Expected) -> None:
    if image.sha256 != expected.sha256 or image.size_bytes != expected.size:
        raise InvalidResult("image_mismatch")


def validate(path: Path, job: JobFacts, expected: Expected, caps: Caps) -> Validated:
    """A full (`succeeded`) result. Blocking (run in a worker thread). Raises InvalidResult;
    never touches the database."""
    check = _Checker(job, caps, diagnostic=False)
    check_framing(
        path,
        max_decompressed=caps.max_decompressed_bytes,
        max_lines=caps.max_lines,
        first=check.first,
        middle=check.middle,
    )
    if check.header is None:
        raise InvalidResult("missing_header")
    if check.image is None:
        raise InvalidResult("missing_image")
    _check_image(check.image, expected)
    return Validated(check.header, check.image, check.counts, check.orphan_refs())


def validate_diagnostic(path: Path, job: JobFacts, expected: Expected) -> Validated:
    """A `symbols_missing` diagnostic stream: header (symbols missing, the requirement
    validated strictly by the contract: kernel PDB allow-list, 32-hex GUID, age, or a
    printable banner of at most 512 characters), at most the image line, trailer."""
    check = _Checker(job, DIAGNOSTIC_CAPS, diagnostic=True)
    check_framing(
        path,
        max_decompressed=DIAGNOSTIC_CAPS.max_decompressed_bytes,
        max_lines=DIAGNOSTIC_CAPS.max_lines,
        first=check.first,
        middle=check.middle,
    )
    if check.header is None:
        raise InvalidResult("missing_header")
    if check.image is not None:
        _check_image(check.image, expected)
    return Validated(check.header, check.image, check.counts, 0)


def records(path: Path, caps: Caps) -> Iterator[tuple[MemoryRecordLine, int]]:
    """Every row-per-line record of an already validated stream (not the image line), with
    the size of its raw line in bytes."""
    for line in body_lines(path, caps.max_decompressed_bytes):
        record = _record(line)
        if record.kind != IMAGE_KIND:
            yield record, len(line)
