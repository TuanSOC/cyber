"""Validation of a downloaded `pcap.v1` result stream (a local gzip NDJSON file).

Everything in the stream comes from the untrusted analyzer. `validate()` reads it once, in
bounded memory, and refuses it as a whole on the first problem: inflated size over the cap
(zip bombs), more lines than the cap, over-long or unterminated lines, a header for another
job, a line that is not exactly a known record (unknown kind or field, oversized text, NUL),
not exactly one stats line, more records of a kind than the job's limits, duplicate findings
or IOCs, timestamps far outside the capture, or a trailer whose line count or sha256 does
not match.

Only after that does `records()` read the same file again to feed the database writes.
"""

import gzip
import hashlib
import uuid
import zlib
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from cyberlab_jobs.results import (
    RECORD_ADAPTER,
    CaptureStats,
    FindingRecord,
    IocRecord,
    RecordLine,
    ResultHeader,
    ResultTrailer,
)
from pydantic import ValidationError

from app.core.config import Settings

# The largest legitimate line (stats: 200 protocol paths of 255 escaped chars) is far below.
MAX_LINE_BYTES = 1024**2
# Record timestamps may sit this far outside [first_ts, last_ts] of the capture.
TS_SLACK = timedelta(days=1)


class InvalidResult(Exception):
    """The stream is refused; `reason` is a short code for logs and tests."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class Caps:
    max_decompressed_bytes: int
    per_kind: dict[str, int]
    max_lines: int  # every line of the stream, header and trailer included

    @classmethod
    def from_settings(cls, settings: Settings) -> "Caps":
        per_kind = settings.analysis_max_records_per_kind
        return cls(
            max_decompressed_bytes=settings.analysis_max_result_decompressed_bytes,
            per_kind={
                "stats": 1,
                "flow": settings.analysis_max_flows,
                "finding": settings.analysis_max_findings,
                **{k: per_kind for k in ("dns", "http", "tls", "alert", "ioc", "timeline")},
            },
            max_lines=settings.analysis_max_result_lines,
        )


@dataclass
class Validated:
    header: ResultHeader
    stats: CaptureStats
    counts: Counter[str] = field(default_factory=Counter)  # record kind -> lines


def _lines(path: Path, max_decompressed: int) -> Iterator[bytes]:
    total = 0
    try:
        with gzip.open(path, "rb") as stream:
            while line := stream.readline(MAX_LINE_BYTES + 1):
                total += len(line)
                if total > max_decompressed:
                    raise InvalidResult("decompressed_too_large")
                if len(line) > MAX_LINE_BYTES:
                    raise InvalidResult("line_too_long")
                if not line.endswith(b"\n"):
                    raise InvalidResult("unterminated_line")
                yield line
    except (OSError, EOFError, zlib.error) as exc:  # not gzip, truncated, corrupt
        raise InvalidResult("bad_gzip") from exc


def ioc_key(ioc_type: str, value: str) -> tuple[str, bytes]:
    """Duplicate key of an IOC: exactly what the unique index compares (job, type, md5(value)).

    Postgres md5(text) hashes the UTF-8 bytes (the database encoding), as this does, so the
    validator refuses everything the index would and nothing it would accept.
    """
    return ioc_type, hashlib.md5(value.encode(), usedforsecurity=False).digest()


def _record(line: bytes) -> RecordLine:
    try:
        return RECORD_ADAPTER.validate_json(line)
    except ValidationError as exc:
        raise InvalidResult("invalid_record") from exc


def _times(record: RecordLine) -> tuple[datetime, ...]:
    if isinstance(record, IocRecord):
        return (record.first_seen, record.last_seen)
    if isinstance(record, FindingRecord) and record.last_seen is not None:
        return (record.ts, record.last_seen)
    if isinstance(record, CaptureStats):
        return ()
    return (record.ts,)


class _Checker:
    def __init__(self, job_id: uuid.UUID, caps: Caps) -> None:
        self.job_id = job_id
        self.caps = caps
        self.header: ResultHeader | None = None
        self.stats: CaptureStats | None = None
        self.counts: Counter[str] = Counter()
        self.findings: set[uuid.UUID] = set()
        self.iocs: set[tuple[str, bytes]] = set()  # ioc_key(): bounded memory
        self.earliest: datetime | None = None
        self.latest: datetime | None = None

    def first(self, line: bytes) -> None:
        try:
            header = ResultHeader.model_validate_json(line)
        except ValidationError as exc:
            raise InvalidResult("invalid_header") from exc
        if header.job_id != self.job_id:
            raise InvalidResult("header_job_mismatch")
        self.header = header

    def middle(self, line: bytes) -> None:
        record = _record(line)
        kind = record.kind
        self.counts[kind] += 1
        if self.counts[kind] > self.caps.per_kind[kind]:
            raise InvalidResult(f"too_many_{kind}")
        if isinstance(record, CaptureStats):
            self.stats = record
        elif isinstance(record, FindingRecord):
            if record.finding_id in self.findings:
                raise InvalidResult("duplicate_finding")
            self.findings.add(record.finding_id)
        elif isinstance(record, IocRecord):
            key = ioc_key(record.type, record.value)
            if key in self.iocs:
                raise InvalidResult("duplicate_ioc")
            self.iocs.add(key)
        for ts in _times(record):
            self.earliest = ts if self.earliest is None else min(self.earliest, ts)
            self.latest = ts if self.latest is None else max(self.latest, ts)

    def window(self, stats: CaptureStats) -> None:
        first, last = stats.first_ts, stats.last_ts
        if first is None or last is None or self.earliest is None or self.latest is None:
            return  # no capture window known, or nothing timestamped
        if self.earliest < first - TS_SLACK or self.latest > last + TS_SLACK:
            raise InvalidResult("timestamp_outside_capture")


def validate(path: Path, job_id: uuid.UUID, caps: Caps) -> Validated:
    """Blocking (run in a worker thread). Raises InvalidResult; never touches the database."""
    check = _Checker(job_id, caps)
    digest = hashlib.sha256()
    lines = 0
    pending: bytes | None = None  # the trailer is only known to be last at end of stream
    for seen, line in enumerate(_lines(path, caps.max_decompressed_bytes), start=1):
        if seen > caps.max_lines:
            raise InvalidResult("too_many_lines")
        if pending is not None:
            digest.update(pending)
            lines += 1
            if lines == 1:
                check.first(pending)
            else:
                check.middle(pending)
        pending = line
    if check.header is None or pending is None:
        raise InvalidResult("missing_header")
    try:
        trailer = ResultTrailer.model_validate_json(pending)
    except ValidationError as exc:
        raise InvalidResult("invalid_trailer") from exc
    if trailer.line_count != lines:
        raise InvalidResult("trailer_count_mismatch")
    if trailer.sha256 != digest.hexdigest():
        raise InvalidResult("trailer_hash_mismatch")
    if check.stats is None:
        raise InvalidResult("missing_stats")
    check.window(check.stats)
    return Validated(check.header, check.stats, check.counts)


def records(path: Path, caps: Caps) -> Iterator[tuple[RecordLine, int]]:
    """Every record of an already validated stream except stats (header/trailer skipped),
    with the size of its raw line in bytes."""
    pending: bytes | None = None
    for index, line in enumerate(_lines(path, caps.max_decompressed_bytes)):
        if pending is not None:
            record = _record(pending)
            if not isinstance(record, CaptureStats):
                yield record, len(pending)
        pending = line if index > 0 else None
