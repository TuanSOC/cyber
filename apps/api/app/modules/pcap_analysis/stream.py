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

import uuid
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
)
from pydantic import ValidationError

from app.core.config import Settings
from app.modules.analysis.result_stream import (
    MAX_LINE_BYTES,
    InvalidResult,
    body_lines,
    check_framing,
    ioc_key,
)

__all__ = ["MAX_LINE_BYTES", "Caps", "InvalidResult", "Validated", "ioc_key", "records", "validate"]

# Record timestamps may sit this far outside [first_ts, last_ts] of the capture.
TS_SLACK = timedelta(days=1)


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
    check_framing(
        path,
        max_decompressed=caps.max_decompressed_bytes,
        max_lines=caps.max_lines,
        first=check.first,
        middle=check.middle,
    )
    if check.header is None:
        raise InvalidResult("missing_header")
    if check.stats is None:
        raise InvalidResult("missing_stats")
    check.window(check.stats)
    return Validated(check.header, check.stats, check.counts)


def records(path: Path, caps: Caps) -> Iterator[tuple[RecordLine, int]]:
    """Every record of an already validated stream except stats (header/trailer skipped),
    with the size of its raw line in bytes."""
    for line in body_lines(path, caps.max_decompressed_bytes):
        record = _record(line)
        if not isinstance(record, CaptureStats):
            yield record, len(line)
