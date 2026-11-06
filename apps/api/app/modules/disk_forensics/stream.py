"""Validation of a downloaded `disk.v1` result stream (a local gzip NDJSON file; M9 phase 7).

Everything in the stream comes from the untrusted disk analyzer, which parsed an
attacker-chosen image. `validate()` reads it once and refuses it as a whole on the first
problem, keeping only bounded sets in memory (keyed digests of the files' natural keys and
refs, the event ordinals, the finding ids, the cited refs), never the records. On top of the
shared framing (result_stream: inflated size, line count, line length, header first, hashed
trailer last) with the disk bounds (`DISK_MAX_RESULT_DECOMPRESSED_BYTES`, lines = the sum of
the caps + 3; RT9), a stream must have:

- a `disk.v1` header naming this job, its profile and its segment count; a media size within
  `DISK_MAX_MEDIA_BYTES`; header blocks that fit their `disk_images` columns;
- every body line exactly one known record (the frozen contract refuses unknown kinds and
  fields, oversized text, NUL and control characters, non-finite floats, bad hashes), in
  `LINE_ORDER` (partitions, files, events, findings, IOCs, timeline);
- no more records of a kind than the job's caps; no duplicate partition index, file natural key
  (partition, meta_addr, meta_seq, stream, parent_addr, name), event ordinal, finding id or IOC;
- files and events on listed partitions only.

References are never refused, only resolved (RT10): an event's file key, a finding's
`file:<partition>:<meta_addr>:<meta_seq>[:<stream>]`, `event:<ordinal>` and `finding:<uuid>`
refs and a timeline line's ref resolve against the stream's own records; what does not resolve
is counted (`unresolved`) and dropped at the write. The write pass (`records()`) re-reads the
validated file (the M2 two-pass framing).

A **diagnostic stream** (`no_supported_filesystem`, `unsupported_disk_format`) is the header,
at most the partitions, and the trailer (`validate_diagnostic`).
"""

import hashlib
import json
import re
import secrets
import uuid
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cyberlab_jobs.disk import (
    DISK_RECORD_ADAPTER,
    LINE_ORDER,
    DiskEventRecord,
    DiskFileRecord,
    DiskPartitionRecord,
    DiskRecordLine,
    DiskResultHeader,
    DiskTimelineEvent,
    FileKey,
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

__all__ = [
    "Caps",
    "InvalidResult",
    "JobFacts",
    "Validated",
    "diagnostic_caps",
    "event_ordinal",
    "file_ref",
    "finding_id",
    "key_of",
    "records",
    "validate",
    "validate_diagnostic",
]

KINDS = ("partition", "file", "event", "finding", "ioc", "timeline")
_RANK = {kind: i for i, kind in enumerate(LINE_ORDER)}
# `disk_images` jsonb columns (0017 checks: octet_length(column::text) <= limit).
COLUMN_BYTES = {"stages": 16_384, "tool_versions": 2_048, "hashsets": 4_096, "ewf_meta": 2_048}
_EVENT_REF = re.compile(r"^event:(0|[1-9][0-9]{0,18})$")
_UUID_TEXT = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_FINDING_REF = re.compile(f"^finding:({_UUID_TEXT})$")
_UUID = re.compile(f"^{_UUID_TEXT}$")
STREAM_REF_MAX = 64


@dataclass(frozen=True)
class Caps:
    max_decompressed_bytes: int
    per_kind: dict[str, int]
    max_lines: int  # every line of the stream, header and trailer included
    max_media_bytes: int

    @classmethod
    def from_settings(cls, settings: Settings) -> "Caps":
        # The very caps the worker was sent (`dispatch.disk_limits` reads the same settings).
        return cls(
            max_decompressed_bytes=settings.disk_max_result_decompressed_bytes,
            per_kind={
                "partition": settings.disk_max_partitions,
                "file": settings.disk_max_files,
                "event": settings.disk_max_events,
                "finding": settings.disk_max_findings,
                "ioc": settings.disk_max_iocs,
                "timeline": settings.disk_max_timeline,
            },
            max_lines=settings.disk_max_result_lines(),
            max_media_bytes=settings.disk_max_media_bytes,
        )


def diagnostic_caps(settings: Settings) -> Caps:
    """Header, at most the partitions, trailer: bounded by the partition cap."""
    lines = settings.disk_max_partitions + 2
    return Caps(
        max_decompressed_bytes=min(
            settings.disk_max_result_decompressed_bytes, lines * MAX_LINE_BYTES
        ),
        per_kind={"partition": settings.disk_max_partitions},
        max_lines=lines,
        max_media_bytes=settings.disk_max_media_bytes,
    )


@dataclass(frozen=True)
class JobFacts:
    """What the job asked for (from our own rows, never from the stream)."""

    job_id: uuid.UUID
    profile: str  # `triage` or `full`
    segments: int  # rows of `analysis_job_segments`


@dataclass
class Validated:
    header: DiskResultHeader
    counts: Counter[str] = field(default_factory=Counter)  # record kind -> lines
    # Worker-form refs that resolve and are cited (by an event's file key, a finding or a
    # timeline line): the write pass maps exactly these to row ids.
    cited_files: frozenset[str] = frozenset()
    cited_events: frozenset[int] = frozenset()
    finding_ids: frozenset[uuid.UUID] = frozenset()
    # Refs that resolve to nothing (dropped at the write): `event_file`, `finding_ref`,
    # `timeline_ref`.
    unresolved: Counter[str] = field(default_factory=Counter)
    hashed_files: int = 0


def file_ref(
    partition_index: int, meta_addr: int, meta_seq: int | None, stream: str | None
) -> str:
    """The worker's ref of a file (disk_worker.detections.base.file_ref, M9 phase 6): a stream
    name that would not fit 64 characters is replaced by `#` + 16 hex digits of its sha256."""
    seq = "" if meta_seq is None else str(meta_seq)
    ref = f"file:{partition_index}:{meta_addr}:{seq}"
    if stream is None:
        return ref
    with_stream = f"{ref}:{stream}"
    if len(with_stream) <= STREAM_REF_MAX:
        return with_stream
    digest = hashlib.sha256(stream.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    return f"{ref}:#{digest}"


def key_of(record: DiskFileRecord | FileKey) -> str:
    return file_ref(record.partition_index, record.meta_addr, record.meta_seq, record.stream)


def event_ordinal(ref: str) -> int | None:
    """`event:<ordinal>` (canonical decimal) -> the ordinal; anything else -> None."""
    found = _EVENT_REF.match(ref)
    return None if found is None else int(found.group(1))


def finding_id(ref: str, *, bare: bool = False) -> uuid.UUID | None:
    """`finding:<uuid>` (canonical lower-case form; with `bare`, also a lone uuid, the
    timeline's finding ref) -> the id; anything else -> None."""
    found = _FINDING_REF.match(ref)
    if found is not None:
        return uuid.UUID(found.group(1))
    if bare and _UUID.match(ref):
        return uuid.UUID(ref)
    return None


def _record(line: bytes) -> DiskRecordLine:
    try:
        return DISK_RECORD_ADAPTER.validate_json(line)
    except ValidationError as exc:
        raise InvalidResult("invalid_record") from exc


def _json_bytes(value: Any) -> int:
    """An upper estimate of `octet_length(value::text)` of the jsonb Postgres stores."""
    return len(json.dumps(value, ensure_ascii=False).encode())


class _Checker:
    def __init__(self, job: JobFacts, caps: Caps, *, diagnostic: bool) -> None:
        self.job = job
        self.caps = caps
        self.diagnostic = diagnostic
        self.header: DiskResultHeader | None = None
        self.counts: Counter[str] = Counter()
        self.rank = _RANK["header"]
        self._key = secrets.token_bytes(16)  # keyed digests: no crafted collisions
        self.partitions: set[int] = set()
        self.natural: set[bytes] = set()
        self.file_refs: set[bytes] = set()
        self.ordinals: set[int] = set()
        self.finding_ids: set[uuid.UUID] = set()
        self.iocs: set[tuple[str, bytes]] = set()
        self.cited_files: set[str] = set()
        self.cited_events: set[int] = set()
        self.finding_refs: list[uuid.UUID] = []  # `finding:<uuid>` refs, resolved at the end
        self.unresolved: Counter[str] = Counter()
        self.hashed = 0

    def _digest(self, value: str) -> bytes:
        data = value.encode("utf-8", "surrogatepass")
        return hashlib.blake2b(data, digest_size=16, key=self._key).digest()

    def first(self, line: bytes) -> None:
        try:
            header = DiskResultHeader.model_validate_json(line)
        except ValidationError as exc:  # incl. another schema's header (e.g. memory.v1)
            raise InvalidResult("invalid_header") from exc
        if header.job_id != self.job.job_id:
            raise InvalidResult("header_job_mismatch")
        if header.profile != self.job.profile:
            raise InvalidResult("header_profile_mismatch")
        if header.image.segments != self.job.segments:
            raise InvalidResult("header_segments_mismatch")
        if header.image.media_size > self.caps.max_media_bytes:
            raise InvalidResult("media_too_large")
        blocks: dict[str, Any] = {
            "stages": [s.model_dump(mode="json") for s in header.stages],
            "tool_versions": dict(header.tool_versions),
            "hashsets": [h.model_dump(mode="json") for h in header.hashsets],
            "ewf_meta": dict(header.image.ewf.meta) if header.image.ewf else {},
        }
        for name, value in blocks.items():
            if _json_bytes(value) > COLUMN_BYTES[name]:
                raise InvalidResult("header_too_large")
        self.header = header

    def _order(self, kind: str) -> None:
        rank = _RANK[kind]
        if rank < self.rank:
            raise InvalidResult("out_of_order")
        self.rank = rank

    def _partition(self, index: int) -> None:
        if index not in self.partitions:
            raise InvalidResult("unknown_partition")

    def _file_cited(self, ref: str) -> bool:
        if self._digest(ref) in self.file_refs:
            self.cited_files.add(ref)
            return True
        return False

    def _event_cited(self, ref: str) -> bool:
        ordinal = event_ordinal(ref)
        if ordinal is None or ordinal not in self.ordinals:
            return False
        self.cited_events.add(ordinal)
        return True

    def _ref(self, ref: str) -> bool:
        """A finding's evidence ref; `finding:` refs are resolved at the end of the stream."""
        if ref.startswith("file:"):
            return self._file_cited(ref)
        if ref.startswith("event:"):
            return self._event_cited(ref)
        finding = finding_id(ref)
        if finding is not None:
            self.finding_refs.append(finding)
            return True
        return False

    def _timeline_ref(self, ref: str) -> bool:
        if ref.startswith("file:"):
            return self._file_cited(ref)
        if ref.startswith("event:"):
            return self._event_cited(ref)
        finding = finding_id(ref, bare=True)
        return finding is not None and finding in self.finding_ids

    def middle(self, line: bytes) -> None:
        if self.header is None:  # unreachable: check_framing feeds the header first
            raise InvalidResult("missing_header")
        record = _record(line)
        kind = record.kind
        if self.diagnostic and kind != "partition":
            raise InvalidResult("diagnostic_with_records")
        self._order(kind)
        self.counts[kind] += 1
        if self.counts[kind] > self.caps.per_kind[kind]:
            raise InvalidResult(f"too_many_{kind}")
        if isinstance(record, DiskPartitionRecord):
            if record.index in self.partitions:
                raise InvalidResult("duplicate_partition")
            self.partitions.add(record.index)
        elif isinstance(record, DiskFileRecord):
            self._partition(record.partition_index)
            natural = repr(
                (
                    record.partition_index,
                    record.meta_addr,
                    record.meta_seq,
                    record.stream,
                    record.parent_addr,
                    record.name,
                )
            )
            digest = self._digest(natural)
            if digest in self.natural:
                raise InvalidResult("duplicate_file")
            self.natural.add(digest)
            self.file_refs.add(self._digest(key_of(record)))
            if record.hash_status == "hashed":
                self.hashed += 1
        elif isinstance(record, DiskEventRecord):
            self._partition(record.partition_index)
            if record.ordinal in self.ordinals:
                raise InvalidResult("duplicate_event")
            self.ordinals.add(record.ordinal)
            if record.file is not None and not self._file_cited(key_of(record.file)):
                self.unresolved["event_file"] += 1
        elif isinstance(record, FindingRecord):
            if record.finding_id in self.finding_ids:
                raise InvalidResult("duplicate_finding")
            self.finding_ids.add(record.finding_id)
            for ref in record.evidence_refs:
                if not self._ref(ref):
                    self.unresolved["finding_ref"] += 1
        elif isinstance(record, IocRecord):
            ioc = ioc_key(record.type, record.value)
            if ioc in self.iocs:
                raise InvalidResult("duplicate_ioc")
            self.iocs.add(ioc)
        elif isinstance(record, DiskTimelineEvent):
            if record.ref is not None and not self._timeline_ref(record.ref):
                self.unresolved["timeline_ref"] += 1

    def result(self) -> Validated:
        if self.header is None:
            raise InvalidResult("missing_header")
        self.unresolved["finding_ref"] += sum(
            1 for ref in self.finding_refs if ref not in self.finding_ids
        )
        return Validated(
            header=self.header,
            counts=self.counts,
            cited_files=frozenset(self.cited_files),
            cited_events=frozenset(self.cited_events),
            finding_ids=frozenset(self.finding_ids),
            unresolved=+self.unresolved,
            hashed_files=self.hashed,
        )


def validate(path: Path, job: JobFacts, caps: Caps) -> Validated:
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
    return check.result()


def validate_diagnostic(path: Path, job: JobFacts, caps: Caps) -> Validated:
    """A diagnostic stream (`no_supported_filesystem` / `unsupported_disk_format`): header, at
    most the partitions, trailer. `caps` is `diagnostic_caps(settings)`."""
    check = _Checker(job, caps, diagnostic=True)
    check_framing(
        path,
        max_decompressed=caps.max_decompressed_bytes,
        max_lines=caps.max_lines,
        first=check.first,
        middle=check.middle,
    )
    return check.result()


def records(path: Path, caps: Caps) -> Iterator[tuple[DiskRecordLine, int]]:
    """Every record of an already validated stream, with the size of its raw line in bytes."""
    for line in body_lines(path, caps.max_decompressed_bytes):
        yield _record(line), len(line)
