"""Trusted ingest of a `disk.v1` result (M9 phase 7).

Run by the disk ingest worker (task `disk.ingest`, queue `ingest_disk`, its own solo process;
RT9), never by the shared ingest worker, which only hands the report off (`handoff.py`):

- `ingest_disk(job, msg, path)`: a `succeeded` report with its downloaded result. Pass 1
  (`stream.validate`, worker thread) validates the whole stream before any write. Pass 2 re-reads
  it (`stream.records`) inside ONE transaction: `disk_images` (from the header),
  `disk_partitions`, `disk_files`, `disk_events` (`file_id` resolved by natural key),
  `analysis_findings` (evidence refs resolved to row ids: `file:<id>`, `event:<id>`,
  `finding:<uuid>`; unresolved refs dropped and counted), `iocs`, `analysis_timeline`, the
  in-org known-hash join, the job summary, the final state, custody `analyzed` on every segment
  and the audit entry.
- `ingest_disk_diagnostic(job, msg, path)`: a `failed` report (`no_supported_filesystem` /
  `unsupported_disk_format`) with its diagnostic stream: `disk_images` + `disk_partitions`
  only, and the job fails with the worker's code.

Rows go in as batched INSERTs (`BATCH_LINES` = 10 000 or 16 MiB of raw lines): Postgres refuses
COPY into tables with row-level security (M2). File and event ids are generated here, so an
event's `file_id` and a finding's refs resolve in memory from the cited refs pass 1 kept (never
the whole listing).

The job row is locked only at the end (FOR UPDATE, after every row is written): the rows'
foreign keys hold a KEY SHARE lock on it meanwhile, which the hand-off and the reaper skip
(SKIP LOCKED) instead of waiting. A job that is no longer active then rolls the whole
transaction back (a redelivered or reaped job: no second copy); a job past its deadline
(`DISK_INGEST_TIMEOUT_S` after the hand-off) rolls back and fails `timed_out`.

Known-hash join (`correlation:disk_known_org_hash@1`, trusted, same transaction): the job's
hashed files are joined (sha256 / sha1 / md5) with the org's `iocs` file-hash values and its
`correlation_keys` hash kinds of OTHER jobs, under the tenant session (RLS, plus an explicit org
filter), in a savepoint with `statement_timeout` = 120 s. One `low` finding per matched file
(at most 500, then one summary finding with the rest); a timeout skips the join
(`known_hash_join: skipped_timeout` in the summary) and never fails the ingest.
"""

import json
import logging
import uuid
from collections import Counter
from collections.abc import Iterator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import anyio
from cyberlab_jobs import IngestMessageV1
from cyberlab_jobs.disk import (
    DiskEventRecord,
    DiskFileRecord,
    DiskPartitionRecord,
    DiskRecordLine,
    DiskResultHeader,
    DiskTimelineEvent,
)
from cyberlab_jobs.results import FindingRecord, IocRecord
from sqlalchemy import Table, insert, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis import lifecycle, result_rows
from app.modules.analysis import repository as repo
from app.modules.analysis.models import ACTIVE, AnalysisJob, AnalysisJobIndex
from app.modules.analysis.result_stream import InvalidResult
from app.modules.disk_forensics import segments as disk_segments
from app.modules.disk_forensics import stream
from app.modules.disk_forensics.models import DiskEvent, DiskFile, DiskImage, DiskPartition
from app.modules.evidence.models import CustodyAction, EvidenceCustodyEvent
from app.modules.pcap_analysis import ingest as pcap_ingest

log = logging.getLogger(__name__)

BATCH_LINES = 10_000
BATCH_BYTES = 16 * 1024**2
# `analysis_jobs.summary` of a disk job.
SUMMARY_MAX_BYTES = 32 * 1024
KNOWN_HASH_METHOD = "correlation:disk_known_org_hash@1"
KNOWN_HASH_TYPE = "disk_known_org_hash"
KNOWN_HASH_MAX_FINDINGS = 500
KNOWN_HASH_TIMEOUT_S: float = 120
# Match refs per finding, and as many job refs (the `[1:10]` slices of KNOWN_HASH_SQL).
KNOWN_HASH_MAX_SOURCES = 10
QUERY_CANCELED = "57014"
FINDING_NAMESPACE = uuid.UUID("5d2f6a0e-7c41-4b8e-9a53-3e1f0c9d7b21")
# The shared surfaces take timestamps in 1970..2100.
_SHARED_EARLIEST = datetime(1970, 1, 1, tzinfo=UTC)
_SHARED_LATEST = datetime(2100, 1, 1, tzinfo=UTC)

COUNT_NAMES = {
    "partition": "partitions",
    "file": "files",
    "event": "events",
    "finding": "findings",
    "ioc": "iocs",
    "timeline": "timeline",
}
IMAGES = cast(Table, DiskImage.__table__)
PARTITIONS = cast(Table, DiskPartition.__table__)
FILES = cast(Table, DiskFile.__table__)
EVENTS = cast(Table, DiskEvent.__table__)


class _Superseded(Exception):
    """The job left the active states while it was ingested: roll everything back."""


class _Overdue(Exception):
    """The ingest outlived the job's deadline: roll back, fail `timed_out`."""


# --- rows -----------------------------------------------------------------------------------


def _u64(value: int | None) -> Decimal | None:
    return None if value is None else Decimal(value)


def normalized_ext(record: DiskFileRecord) -> str | None:
    """Lower case, no leading dot; taken from the name when the worker sent none."""
    ext = record.ext
    if ext is None and record.type == "reg":
        stem, dot, tail = record.name.rpartition(".")
        ext = tail if dot and stem else None
    if ext is None:
        return None
    ext = ext.lstrip(".").lower()
    if not ext or len(ext) > 32 or "\x00" in ext:
        return None
    return ext


def _shared_ts(*candidates: datetime | None) -> datetime:
    for ts in candidates:
        if ts is not None and _SHARED_EARLIEST <= ts < _SHARED_LATEST:
            return ts
    return datetime.now(UTC)


class Resolver:
    """Pass 2: generates file / event ids and maps the cited refs to them (bounded by what
    pass 1 found cited)."""

    def __init__(self, result: stream.Validated) -> None:
        self.cited_files = result.cited_files
        self.cited_events = result.cited_events
        self.finding_ids = result.finding_ids
        self.files: dict[str, uuid.UUID] = {}  # worker ref -> first listed row id
        self.events: dict[int, uuid.UUID] = {}  # ordinal -> row id
        self.dropped: Counter[str] = Counter()

    def file_row(self, record: DiskFileRecord) -> dict[str, Any]:
        row_id = uuid.uuid4()
        ref = stream.key_of(record)
        if ref in self.cited_files and ref not in self.files:
            self.files[ref] = row_id
        return {
            "id": row_id,
            "partition_index": record.partition_index,
            "meta_addr": _u64(record.meta_addr),
            "meta_seq": record.meta_seq,
            "stream": record.stream,
            "path": record.path,
            "parent_addr": _u64(record.parent_addr),
            "name": record.name,
            "ext": normalized_ext(record),
            "type": record.type,
            "flags": record.flags,
            "size": record.size,
            "mode": record.mode,
            "uid": record.uid,
            "gid": record.gid,
            "mtime": record.mtime,
            "atime": record.atime,
            "ctime": record.ctime,
            "crtime": record.crtime,
            "time_basis": record.time_basis,
            "magic": record.magic,
            "hash_status": record.hash_status,
            "md5": record.md5,
            "sha1": record.sha1,
            "sha256": record.sha256,
            "known": record.known,
            "known_set": record.known_set,
            "yara_rules": list(record.yara_rules),
        }

    def event_row(self, record: DiskEventRecord) -> dict[str, Any]:
        row_id = uuid.uuid4()
        if record.ordinal in self.cited_events:
            self.events[record.ordinal] = row_id
        file_id = None
        if record.file is not None:
            file_id = self.files.get(stream.key_of(record.file))
        return {
            "id": row_id,
            "ts": record.ts,
            "ts_desc": record.ts_desc,
            "artifact": record.artifact.value,
            "parser": record.parser,
            "data_type": record.data_type,
            "partition_index": record.partition_index,
            "path": record.path,
            "file_id": file_id,
            "ordinal": record.ordinal,
            "message": record.message,
            "attributes": dict(record.attributes),
        }

    def ref(self, ref: str) -> str | None:
        """A worker ref as stored: `file:<row id>`, `event:<row id>`, `finding:<uuid>`."""
        if ref.startswith("file:"):
            found = self.files.get(ref)
            return None if found is None else f"file:{found}"
        if ref.startswith("event:"):
            ordinal = stream.event_ordinal(ref)
            event = None if ordinal is None else self.events.get(ordinal)
            return None if event is None else f"event:{event}"
        finding = stream.finding_id(ref)
        return f"finding:{finding}" if finding in self.finding_ids else None

    def timeline_ref(self, ref: str | None) -> str | None:
        """As `ref`; a lone uuid (a finding of this stream) stays as it is."""
        if ref is None:
            return None
        if ref.startswith(("file:", "event:", "finding:")):
            return self.ref(ref)
        finding = stream.finding_id(ref, bare=True)
        return ref if finding in self.finding_ids else None

    def to_row(self, record: DiskRecordLine) -> tuple[Table, dict[str, Any]]:
        if isinstance(record, DiskFileRecord):
            return FILES, self.file_row(record)
        if isinstance(record, DiskEventRecord):
            return EVENTS, self.event_row(record)
        if isinstance(record, DiskPartitionRecord):
            return PARTITIONS, partition_row(record)
        if isinstance(record, FindingRecord):
            table, row = pcap_ingest.to_row(record)
            refs = [r for r in (self.ref(ref) for ref in record.evidence_refs) if r is not None]
            self.dropped["finding_ref"] += len(record.evidence_refs) - len(refs)
            return table, {**row, "evidence_refs": refs}
        if isinstance(record, IocRecord):
            return pcap_ingest.to_row(record)
        if isinstance(record, DiskTimelineEvent):
            return pcap_ingest.TIMELINE, {
                "ts": record.ts,
                "event": record.event,
                "title": record.title,
                "severity": record.severity,
                "ref": self.timeline_ref(record.ref),
                "src_ip": None if record.src_ip is None else str(record.src_ip),
                "dst_ip": None,
            }
        raise TypeError(f"no table for record kind {record.kind!r}")


def partition_row(record: DiskPartitionRecord) -> dict[str, Any]:
    return {
        "index": record.index,
        "start_sector": _u64(record.start_sector),
        "length_sectors": _u64(record.length_sectors),
        "description": record.description,
        "vs_flags": record.vs_flags,
        "fs_type": record.fs_type.value if record.fs_type is not None else None,
        "fs_status": record.fs_status,
        "fs_label": record.fs_label,
        "fs_uuid": record.fs_uuid,
        "block_size": record.block_size,
        "os": record.os,
        "os_name": record.os_name,
        "error_code": record.error_code,
        "counts": dict(record.counts),
    }


def counts(result: stream.Validated) -> dict[str, int]:
    return {
        **{name: result.counts[kind] for kind, name in COUNT_NAMES.items()},
        "hashed_files": result.hashed_files,
        "unresolved_event_files": result.unresolved["event_file"],
        "unresolved_finding_refs": result.unresolved["finding_ref"],
        "unresolved_timeline_refs": result.unresolved["timeline_ref"],
    }


def _truncated(header: DiskResultHeader) -> bool:
    return any(header.truncated.values()) or any(s.truncated for s in header.stages)


def image_row(result: stream.Validated) -> dict[str, Any]:
    header = result.header
    image = header.image
    ewf = image.ewf
    return {
        "format": image.format.value,
        "segments": image.segments,
        "media_size": Decimal(image.media_size),
        "sector_size": image.sector_size,
        "media_sha256": image.media_sha256,
        "ewf_md5": ewf.stored_md5 if ewf else None,
        "ewf_sha1": ewf.stored_sha1 if ewf else None,
        # Worker-reported (RT17): never shown as "verified".
        "media_hash_status": ewf.media_hash_status if ewf else None,
        "ewf_meta": dict(ewf.meta) if ewf else {},
        "volume_system": None,  # not in the frozen header
        "stages": [s.model_dump(mode="json") for s in header.stages],
        "counts": counts(result),
        "tool_versions": dict(header.tool_versions),
        "hashsets": [h.model_dump(mode="json") for h in header.hashsets],
        "engine": header.engine,
        "timeline_engine": header.timeline_engine,
        "truncated": _truncated(header),
    }


def build_summary(
    result: stream.Validated, segments: list[disk_segments.Segment]
) -> dict[str, Any]:
    """The job summary (at most 32 KiB): the run facts of the header, the trusted segment
    identity (our own records: count, total size; the media hash is the worker's, RT17) and
    the counts. Raises InvalidResult if it would not fit."""
    header = result.header
    image = header.image
    summary: dict[str, Any] = {
        "schema_version": header.schema_version,
        "profile": header.profile,
        "engine": header.engine,
        "timeline_engine": header.timeline_engine,
        "tool_versions": dict(header.tool_versions),
        "engine_errors": list(header.engine_errors),
        "truncated": dict(header.truncated),
        "image": {
            "format": image.format.value,
            "segments": len(segments),
            "size_bytes": sum(s.size_bytes for s in segments),
            "media_size": image.media_size,
            "sector_size": image.sector_size,
            "media_sha256": image.media_sha256,
            "media_hash_status": image.ewf.media_hash_status if image.ewf else None,
        },
        "hashsets": [h.name for h in header.hashsets],
        "artifacts": [a.model_dump(mode="json") for a in header.artifacts],
        "counts": counts(result),
    }
    if len(json.dumps(summary).encode()) > SUMMARY_MAX_BYTES:
        raise InvalidResult("summary_too_large")
    return summary


async def insert_image(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, result: stream.Validated
) -> None:
    await session.execute(
        insert(IMAGES), [{**image_row(result), "organization_id": org_id, "job_id": job_id}]
    )


async def insert_rows(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    path: Path,
    result: stream.Validated,
    caps: stream.Caps,
) -> tuple[Counter[str], Resolver]:
    """The image row and every record (pass 2); returns the rows written per record kind."""
    await insert_image(session, org_id, job_id, result)
    resolver = Resolver(result)

    def make_batch(
        records: Iterator[tuple[Any, int]], scope: dict[str, Any], written: Counter[str]
    ) -> result_rows.Batch:
        return result_rows.next_batch(
            records, scope, written, resolver.to_row, max_lines=BATCH_LINES, max_bytes=BATCH_BYTES
        )

    written = await result_rows.insert_batches(
        session, org_id, job_id, stream.records(path, caps), make_batch
    )
    return written, resolver


# --- known-hash join --------------------------------------------------------------------------

KNOWN_HASH_SQL = text(
    """
WITH hashed AS (
  SELECT f.id, h.algo, h.value
  FROM disk_files f
  CROSS JOIN LATERAL (VALUES ('sha256', f.sha256), ('sha1', f.sha1), ('md5', f.md5))
    AS h(algo, value)
  WHERE f.organization_id = :org AND f.job_id = :job AND h.value IS NOT NULL
), matches AS (
  SELECT hashed.id AS file_id, hashed.algo, 'ioc' AS source, i.id::text AS source_id,
         i.job_id AS source_job
  FROM hashed
  JOIN iocs i
    ON i.organization_id = :org AND i.job_id <> :job
   AND i.type = 'file_' || hashed.algo AND lower(i.value) = hashed.value
  UNION ALL
  SELECT hashed.id, hashed.algo, 'correlation_key', k.id::text, k.job_id
  FROM hashed
  JOIN correlation_keys k
    ON k.organization_id = :org AND k.job_id <> :job
   AND k.kind = hashed.algo AND k.value_norm = hashed.value
), per_file AS (
  SELECT file_id,
         count(*) AS matches,
         count(DISTINCT source_job) AS jobs,
         array_agg(DISTINCT algo ORDER BY algo) AS algos,
         (array_agg(source || ':' || source_id ORDER BY source, source_id))[1:10] AS refs,
         (array_agg(DISTINCT source_job::text ORDER BY source_job::text))[1:10] AS job_ids
  FROM matches
  GROUP BY file_id
)
SELECT p.file_id, p.matches, p.jobs, p.algos, p.refs, p.job_ids,
       f.path, f.mtime, f.crtime, count(*) OVER () AS total
FROM per_file p
JOIN disk_files f ON f.id = p.file_id AND f.organization_id = :org AND f.job_id = :job
ORDER BY f.path, p.file_id
LIMIT :cap
"""
)

_RTLO = chr(0x202E)


def _shown(path: str, limit: int = 300) -> str:
    """A listed path for a shared surface: bidi overrides made visible, shortened."""
    value = path.replace(_RTLO, "<U+202E>").replace("\r", " ").replace("\n", " ")
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _known_finding(job_id: uuid.UUID, row: Any) -> dict[str, Any]:
    algos = ", ".join(row.algos)
    refs = [f"file:{row.file_id}", *row.refs, *(f"job:{j}" for j in row.job_ids)]
    return {
        "ts": _shared_ts(row.mtime, row.crtime),
        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "flow_ref": None,
        "finding_id": uuid.uuid5(FINDING_NAMESPACE, f"{job_id}|{row.file_id}"),
        "type": KNOWN_HASH_TYPE,
        "title": "File hash also seen elsewhere in this organization",
        "description": (
            f"The {algos} hash of {_shown(row.path)} equals {row.matches} indicator(s) or "
            f"correlation key(s) of {row.jobs} other analysis job(s) of this organization. "
            "A shared hash links the cases; it is an observation, not a verdict on the file."
        ),
        "severity": "low",
        "confidence": 0.5,
        "detection_method": KNOWN_HASH_METHOD,
        "last_seen": None,
        "protocol": None,
        "evidence_refs": refs[:50],
        "attributes": {"algorithms": algos, "matches": int(row.matches), "jobs": int(row.jobs)},
    }


def _summary_finding(job_id: uuid.UUID, more: int) -> dict[str, Any]:
    return {
        "ts": datetime.now(UTC),
        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "flow_ref": None,
        "finding_id": uuid.uuid5(FINDING_NAMESPACE, f"{job_id}|more"),
        "type": KNOWN_HASH_TYPE,
        "title": "More file hashes also seen elsewhere in this organization",
        "description": (
            f"{more} more listed files have a hash equal to an indicator or correlation key "
            f"of another analysis job of this organization (the first "
            f"{KNOWN_HASH_MAX_FINDINGS} have their own finding). Filter the file listing by "
            "hash to review them."
        ),
        "severity": "low",
        "confidence": 0.5,
        "detection_method": KNOWN_HASH_METHOD,
        "last_seen": None,
        "protocol": None,
        "evidence_refs": [],
        "attributes": {"files": more},
    }


def _sqlstate(exc: DBAPIError) -> str | None:
    seen: BaseException | None = exc.orig
    for _ in range(4):
        if seen is None:
            return None
        state = getattr(seen, "sqlstate", None)
        if isinstance(state, str):
            return state
        seen = seen.__cause__
    return None


async def known_hash_join(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, statement_timeout_s: int
) -> dict[str, Any]:
    """Inserts the known-hash findings of a job whose files are written in this transaction.
    Returns `{"known_hash_join": "ok" | "skipped_timeout", "known_hash_files": n,
    "known_hash_findings": n}`."""
    params = {"org": org_id, "job": job_id, "cap": KNOWN_HASH_MAX_FINDINGS}
    try:
        async with session.begin_nested():
            await session.execute(
                text("SELECT set_config('statement_timeout', :t, true)"),
                {"t": f"{int(KNOWN_HASH_TIMEOUT_S * 1000)}ms"},
            )
            rows = (await session.execute(KNOWN_HASH_SQL, params)).all()
            await session.execute(
                text("SELECT set_config('statement_timeout', :t, true)"),
                {"t": f"{statement_timeout_s}s"},
            )
    except DBAPIError as exc:
        if _sqlstate(exc) != QUERY_CANCELED:
            raise
        # The savepoint rolled back (and with it the timeout change).
        log.warning("known-hash join of disk job %s skipped: statement timeout", job_id)
        return {
            "known_hash_join": "skipped_timeout",
            "known_hash_files": 0,
            "known_hash_findings": 0,
        }
    total = int(rows[0].total) if rows else 0
    findings = [_known_finding(job_id, row) for row in rows]
    if total > len(findings):
        findings.append(_summary_finding(job_id, total - len(findings)))
    scope = {"organization_id": org_id, "job_id": job_id}
    if findings:
        await session.execute(insert(pcap_ingest.FINDINGS), [{**f, **scope} for f in findings])
    return {
        "known_hash_join": "ok",
        "known_hash_files": total,
        "known_hash_findings": len(findings),
    }


# --- the transactions -------------------------------------------------------------------------


async def job_facts(job: AnalysisJob) -> tuple[stream.JobFacts, list[disk_segments.Segment]]:
    if job.profile is None:  # the 0017 checks make this unreachable
        raise RuntimeError(f"disk job {job.id} has no profile")
    async with tenant_session(job.organization_id, None) as session:
        segments = await disk_segments.of_job(session, job.organization_id, job.id)
    if not segments or segments[0].evidence_id != job.evidence_id:
        raise RuntimeError(f"disk job {job.id} has no segment set")
    facts = stream.JobFacts(job_id=job.id, profile=job.profile.value, segments=len(segments))
    return facts, segments


async def _lock_active(session: AsyncSession, job: AnalysisJob) -> AnalysisJob:
    """The job FOR UPDATE at the end of the write; raises when it is no longer ours."""
    locked = await repo.get_for_update(session, job.organization_id, job.id)
    if locked is None or locked.status not in ACTIVE:
        raise _Superseded()
    deadline = await session.scalar(
        select(AnalysisJobIndex.deadline_at).where(AnalysisJobIndex.job_id == job.id)
    )
    if deadline is not None and deadline < lifecycle.now():
        raise _Overdue()
    return locked


def _segment_custody(
    locked: AnalysisJob, msg: IngestMessageV1, segments: list[disk_segments.Segment]
) -> list[EvidenceCustodyEvent]:
    """`analyzed` on every segment after the first (the first gets the shared entry)."""
    return [
        EvidenceCustodyEvent(
            organization_id=locked.organization_id,
            evidence_id=s.evidence_id,
            action=CustodyAction.ANALYZED,
            actor_id=locked.requested_by,
            details={
                "job_id": str(locked.id),
                "system": True,
                "worker": msg.worker_version,
                "ordinal": s.ordinal,
            },
        )
        for s in segments[1:]
    ]


async def _run(job: AnalysisJob, write: Any) -> None:
    """One transaction around `write(session)`; the rollback outcomes are handled here."""
    from app.workers import ingest as plumbing

    try:
        async with tenant_session(job.organization_id, None) as session:
            await plumbing._limit_transaction(session, get_settings())
            current = await session.scalar(
                select(AnalysisJob.status).where(
                    AnalysisJob.id == job.id, AnalysisJob.organization_id == job.organization_id
                )
            )
            if current not in ACTIVE:
                return
            await write(session)
    except _Superseded:
        log.info("disk job %s left the active states during its ingest: rolled back", job.id)
    except _Overdue:
        log.warning("disk ingest of analysis job %s outlived its deadline: rolled back", job.id)
        await plumbing._fail_job(job, "timed_out")


async def ingest_disk(job: AnalysisJob, msg: IngestMessageV1, path: Path) -> None:
    """`disk.v1` success: validate the whole stream (worker thread), then write it in one
    transaction."""
    from app.workers import ingest as plumbing

    settings = get_settings()
    caps = stream.Caps.from_settings(settings)
    facts, segments = await job_facts(job)
    try:
        result = await anyio.to_thread.run_sync(stream.validate, path, facts, caps)
        summary = build_summary(result, segments)
    except InvalidResult as exc:
        await plumbing._refuse(job, exc)
        return

    async def write(session: AsyncSession) -> None:
        written, resolver = await insert_rows(
            session, job.organization_id, job.id, path, result, caps
        )
        plumbing._check_written(written, result.counts)
        if resolver.dropped["finding_ref"] != result.unresolved["finding_ref"]:
            raise RuntimeError("finding refs resolved differently in the two passes")
        joined = await known_hash_join(
            session, job.organization_id, job.id, settings.ingest_statement_timeout_s
        )
        summary["known_hash_join"] = joined["known_hash_join"]
        summary["counts"]["known_hash_files"] = joined["known_hash_files"]
        summary["counts"]["known_hash_findings"] = joined["known_hash_findings"]
        locked = await _lock_active(session, job)
        await plumbing._record_success(session, locked, msg, summary)
        session.add_all(_segment_custody(locked, msg, segments))

    await _run(job, write)


async def ingest_disk_diagnostic(job: AnalysisJob, msg: IngestMessageV1, path: Path) -> None:
    """A diagnostic stream: store the image and the partitions, fail the job with the
    worker's code, in one transaction."""
    from app.workers import ingest as plumbing

    settings = get_settings()
    caps = stream.diagnostic_caps(settings)
    facts, segments = await job_facts(job)
    code = msg.error_code or "no_supported_filesystem"
    try:
        result = await anyio.to_thread.run_sync(stream.validate_diagnostic, path, facts, caps)
        summary = build_summary(result, segments)
    except InvalidResult as exc:
        await plumbing._refuse(job, exc)
        return

    async def write(session: AsyncSession) -> None:
        # The rows first: the job guard refuses any write after the final state, and these
        # INSERTs would otherwise flush the transition before the columns set below.
        await insert_image(session, job.organization_id, job.id, result)
        rows = [
            {**partition_row(r), "organization_id": job.organization_id, "job_id": job.id}
            for r, _ in stream.records(path, caps)
            if isinstance(r, DiskPartitionRecord)
        ]
        if rows:
            await session.execute(insert(PARTITIONS), rows)
        locked = await _lock_active(session, job)
        await plumbing._fail(session, locked, code)
        # Flushed in the same UPDATE as the transition.
        locked.result_version_id = msg.result_version_id
        locked.worker_version = msg.worker_version
        locked.summary = summary

    await _run(job, write)
