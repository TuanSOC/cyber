"""Validation of a downloaded `static.v1` result stream (a local gzip NDJSON file).

Everything in the stream comes from the untrusted analyzer, which parsed an attacker-chosen
file. `validate()` reads it once, in bounded memory, and refuses it as a whole on the first
problem. On top of the shared framing rules (result_stream: inflated size, line count, line
length, header first, hashed trailer last) a stream must have:

- a `static.v1` header naming this job;
- every body line exactly one known record (unknown kind or field, oversized text, NUL,
  non-finite floats are all refused);
- exactly one `sample` line, whose sha256 and size (and md5 / sha1) equal the evidence
  record (M3 RT6): the analyzer must have looked at the stored bytes and nothing else;
- at most one `pe` or `elf` line, and only when the header's `file_format` says so;
- no more records of a kind than the job's StaticLimits, no duplicate finding ids or IOCs.

Only after that does `records()` read the same file again to feed the database writes.
"""

import uuid
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from cyberlab_jobs.results import FindingRecord, IocRecord
from cyberlab_jobs.static import (
    STATIC_RECORD_ADAPTER,
    ElfInfo,
    PeInfo,
    SampleInfo,
    StaticRecordLine,
    StaticResultHeader,
)
from pydantic import ValidationError

from app.core.config import Settings
from app.modules.analysis import dispatch
from app.modules.analysis.result_stream import (
    InvalidResult,
    body_lines,
    check_framing,
    ioc_key,
)

__all__ = ["Caps", "Expected", "InvalidResult", "Validated", "records", "validate"]

# Folded into the one `malware_samples` row, not inserted on their own.
SAMPLE_KINDS = frozenset({"sample", "pe", "elf"})


@dataclass(frozen=True)
class Caps:
    max_decompressed_bytes: int
    per_kind: dict[str, int]
    max_lines: int  # every line of the stream, header and trailer included

    @classmethod
    def from_settings(cls, settings: Settings) -> "Caps":
        # The very limits the worker was sent (dispatch builds them the same way).
        limits = dispatch.static_limits(settings)
        return cls(
            max_decompressed_bytes=settings.analysis_max_result_decompressed_bytes,
            per_kind={
                "sample": 1,
                "pe": 1,
                "elf": 1,
                "section": limits.max_sections,
                "import": limits.max_imports,
                "export": limits.max_exports,
                "resource": limits.max_resources,
                "string": limits.max_strings,
                "signature_match": limits.max_signature_matches,
                "capability": limits.max_capabilities,
                "finding": limits.max_findings,
                "ioc": limits.max_iocs,
            },
            max_lines=settings.analysis_max_result_lines,
        )


@dataclass(frozen=True)
class Expected:
    """The trusted evidence record the sample line must match."""

    sha256: str
    size: int
    md5: str | None = None
    sha1: str | None = None


@dataclass
class Validated:
    header: StaticResultHeader
    sample: SampleInfo
    pe: PeInfo | None
    elf: ElfInfo | None
    counts: Counter[str] = field(default_factory=Counter)  # record kind -> lines


def _record(line: bytes) -> StaticRecordLine:
    try:
        return STATIC_RECORD_ADAPTER.validate_json(line)
    except ValidationError as exc:
        raise InvalidResult("invalid_record") from exc


class _Checker:
    def __init__(self, job_id: uuid.UUID, caps: Caps) -> None:
        self.job_id = job_id
        self.caps = caps
        self.header: StaticResultHeader | None = None
        self.sample: SampleInfo | None = None
        self.pe: PeInfo | None = None
        self.elf: ElfInfo | None = None
        self.counts: Counter[str] = Counter()
        self.findings: set[uuid.UUID] = set()
        self.iocs: set[tuple[str, bytes]] = set()  # ioc_key(): bounded memory

    def first(self, line: bytes) -> None:
        try:
            header = StaticResultHeader.model_validate_json(line)
        except ValidationError as exc:  # incl. another schema's header (e.g. pcap.v1)
            raise InvalidResult("invalid_header") from exc
        if header.job_id != self.job_id:
            raise InvalidResult("header_job_mismatch")
        self.header = header

    def middle(self, line: bytes) -> None:
        if self.header is None:  # unreachable: check_framing feeds the header first
            raise InvalidResult("missing_header")
        record = _record(line)
        kind = record.kind
        self.counts[kind] += 1
        if self.counts[kind] > self.caps.per_kind[kind]:
            raise InvalidResult(f"too_many_{kind}")
        if isinstance(record, SampleInfo):
            self.sample = record
        elif isinstance(record, PeInfo):
            if self.header.file_format != "pe":
                raise InvalidResult("format_mismatch")
            self.pe = record
        elif isinstance(record, ElfInfo):
            if self.header.file_format != "elf":
                raise InvalidResult("format_mismatch")
            self.elf = record
        elif isinstance(record, FindingRecord):
            if record.finding_id in self.findings:
                raise InvalidResult("duplicate_finding")
            self.findings.add(record.finding_id)
        elif isinstance(record, IocRecord):
            key = ioc_key(record.type, record.value)
            if key in self.iocs:
                raise InvalidResult("duplicate_ioc")
            self.iocs.add(key)


def _check_sample(sample: SampleInfo, expected: Expected) -> None:
    if sample.sha256 != expected.sha256 or sample.size != expected.size:
        raise InvalidResult("sample_mismatch")
    if expected.md5 is not None and sample.md5 != expected.md5:
        raise InvalidResult("sample_mismatch")
    if expected.sha1 is not None and sample.sha1 != expected.sha1:
        raise InvalidResult("sample_mismatch")


def validate(path: Path, job_id: uuid.UUID, expected: Expected, caps: Caps) -> Validated:
    """Blocking (run in a worker thread). Raises InvalidResult; never touches the database."""
    check = _Checker(job_id, caps)
    check_framing(
        path,
        max_decompressed=caps.max_decompressed_bytes,
        max_lines=caps.max_lines,
        first=check.first,
        middle=check.middle,
    )
    if check.header is None:
        raise InvalidResult("missing_header")
    if check.sample is None:
        raise InvalidResult("missing_sample")
    _check_sample(check.sample, expected)
    return Validated(check.header, check.sample, check.pe, check.elf, check.counts)


def records(path: Path, caps: Caps) -> Iterator[tuple[StaticRecordLine, int]]:
    """Every row-per-line record of an already validated stream (not sample / pe / elf),
    with the size of its raw line in bytes."""
    for line in body_lines(path, caps.max_decompressed_bytes):
        record = _record(line)
        if record.kind not in SAMPLE_KINDS:
            yield record, len(line)
