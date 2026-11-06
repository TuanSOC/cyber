"""Trusted ingest of `memory.v1` results (M8 phase 6). Called from `app.workers.ingest` by the
job's analyzer:

- `ingest_memory(job, msg, path)`: a `succeeded` report with its downloaded result file;
  validate the whole stream (worker thread, `stream.validate`), then write it in one
  transaction: the `memory_images` row, the four bulk `memory_*` tables, findings, IOCs and
  the timeline in the shared tables (same row shape as pcap / static), the job summary, the
  final state, custody `analyzed` and the audit entry;
- `ingest_memory_diagnostic(job, msg, path)`: a `failed` / `symbols_missing` report that
  carries a result version: the diagnostic stream (header, at most the image line, trailer);
  store the image facts and the symbols requirement in `memory_images` and fail the job
  `symbols_missing`, in one transaction.

Any defect fails the job `invalid_result` with no row written. The transaction plumbing (row
lock, statement timeout, final state, custody, audit) is the shared one of
`app.workers.ingest`, imported at call time because that module imports this one.
"""

import json
import uuid
from collections import Counter
from collections.abc import Iterator
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Any, cast

import anyio
from cyberlab_jobs import IngestMessageV1
from cyberlab_jobs.memory import (
    LinuxBanner,
    MemoryArtifactRecord,
    MemoryConnectionRecord,
    MemoryInjectionRecord,
    MemoryProcessRecord,
    MemoryRecordLine,
    MemoryTimelineEvent,
    WindowsPdb,
)
from cyberlab_jobs.results import FindingRecord, IocRecord
from sqlalchemy import Table, insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis import repository as repo
from app.modules.analysis import result_rows
from app.modules.analysis.models import ACTIVE, AnalysisJob
from app.modules.analysis.result_stream import InvalidResult
from app.modules.memory_analysis import stream
from app.modules.memory_analysis.models import (
    SOURCE_BITS,
    MemoryArtifact,
    MemoryConnection,
    MemoryImage,
    MemoryInjection,
    MemoryProcess,
)
from app.modules.pcap_analysis import ingest as pcap_ingest

BATCH_LINES = 1000
BATCH_BYTES = 8 * 1024**2
# `analysis_jobs.summary` of a memory job (plan "Data model").
SUMMARY_MAX_BYTES = 32 * 1024
DIAGNOSTIC_CODE = "symbols_missing"

# Summary counter name per record kind.
COUNT_NAMES = {
    "process": "processes",
    "connection": "connections",
    "injection": "injections",
    "artifact": "artifacts",
    "finding": "findings",
    "ioc": "iocs",
    "timeline": "timeline",
}
IMAGES = cast(Table, MemoryImage.__table__)
PROCESSES = cast(Table, MemoryProcess.__table__)
CONNECTIONS = cast(Table, MemoryConnection.__table__)
INJECTIONS = cast(Table, MemoryInjection.__table__)
ARTIFACTS = cast(Table, MemoryArtifact.__table__)


def _ip(value: IPv4Address | IPv6Address | None) -> str | None:
    return None if value is None else str(value)


def to_row(record: MemoryRecordLine) -> tuple[Table, dict[str, Any]]:
    if isinstance(record, MemoryProcessRecord):
        fields = record.model_dump(mode="python", exclude={"kind", "sources"})
        return PROCESSES, {**fields, "sources": sum(SOURCE_BITS[s] for s in record.sources)}
    if isinstance(record, MemoryConnectionRecord):
        fields = record.model_dump(mode="python", exclude={"kind", "local_addr", "remote_addr"})
        return CONNECTIONS, {
            **fields,
            "local_addr": _ip(record.local_addr),
            "remote_addr": _ip(record.remote_addr),
        }
    if isinstance(record, MemoryInjectionRecord):
        return INJECTIONS, record.model_dump(mode="python", exclude={"kind"})
    if isinstance(record, MemoryArtifactRecord):
        return ARTIFACTS, {
            "type": record.type,
            "pid": record.pid,
            "attributes": dict(record.attributes),
        }
    if isinstance(record, MemoryTimelineEvent):
        # The shared timeline has no pid column: a pid without its own ref becomes the ref.
        ref = record.ref
        if ref is None and record.pid is not None:
            ref = str(record.pid)
        return pcap_ingest.TIMELINE, {
            "ts": record.ts,
            "event": record.event,
            "title": record.title,
            "severity": record.severity,
            "ref": ref,
            "src_ip": None,
            "dst_ip": _ip(record.remote_ip),
        }
    if isinstance(record, FindingRecord | IocRecord):
        return pcap_ingest.to_row(record)  # the shared tables, one row shape
    raise TypeError(f"no table for record kind {record.kind!r}")


def counts(result: stream.Validated) -> dict[str, int]:
    return {
        **{name: result.counts[kind] for kind, name in COUNT_NAMES.items()},
        "orphan_refs": result.orphan_refs,
    }


def image_row(result: stream.Validated) -> dict[str, Any]:
    """The `memory_images` row: image facts, symbols outcome (and requirement), plugins.

    A diagnostic stream's requirement is what an operator must import, so it is what the
    PDB triple / banner columns hold (the worker reports the image's own identity there).
    """
    header, image = result.header, result.image
    pdb = image.pdb if image is not None else None
    banner = image.kernel_banner if image is not None else None
    required = header.symbols.required
    if isinstance(required, WindowsPdb):
        pdb = required
    elif isinstance(required, LinuxBanner):
        banner = required.banner
    return {
        "os": header.os,
        "arch": image.arch if image is not None else None,
        "layer": image.layer if image is not None else None,
        "engine": header.engine,
        "nt_build": image.nt_build if image is not None else None,
        "kernel_banner": banner,
        "pdb_name": pdb.name if pdb is not None else None,
        "pdb_guid": pdb.guid if pdb is not None else None,
        "pdb_age": pdb.age if pdb is not None else None,
        "system_time": image.system_time if image is not None else None,
        "symbols_status": header.symbols.status,
        "isf_sha256": header.symbols.isf_sha256,
        "volatility_version": header.tool_versions.get("volatility3"),
        "plugins": [p.model_dump(mode="json") for p in header.plugins],
        "counts": counts(result),
    }


def build_summary(result: stream.Validated, evidence: stream.Expected) -> dict[str, Any]:
    """The job summary (at most 32 KiB): the run facts of the header, the trusted image
    identity (the evidence record's size and sha256, which the image line had to equal) and
    the counts. Raises InvalidResult if it would not fit."""
    header = result.header.model_dump(mode="json")
    image = result.image
    summary: dict[str, Any] = {
        "schema_version": header["schema_version"],
        "profile": header["profile"],
        "os": header["os"],
        "engine": header["engine"],
        "tool_versions": header["tool_versions"],
        "symbols": header["symbols"],
        "audit_events": header["audit_events"],
        "engine_errors": header["engine_errors"],
        "truncated": header["truncated"],
        "image": {
            "size_bytes": evidence.size,
            "sha256": evidence.sha256,
            "layer": image.layer if image is not None else None,
            "arch": image.arch if image is not None else None,
        },
        "counts": counts(result),
    }
    if len(json.dumps(summary).encode()) > SUMMARY_MAX_BYTES:
        raise InvalidResult("summary_too_large")
    return summary


def _next_batch(
    records: Iterator[tuple[MemoryRecordLine, int]],
    scope: dict[str, Any],
    written: Counter[str],
) -> result_rows.Batch:
    return result_rows.next_batch(
        records, scope, written, to_row, max_lines=BATCH_LINES, max_bytes=BATCH_BYTES
    )


async def insert_image(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, result: stream.Validated
) -> None:
    scope = {"organization_id": org_id, "job_id": job_id}
    await session.execute(insert(IMAGES), [{**image_row(result), **scope}])


async def insert_rows(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    path: Path,
    result: stream.Validated,
    caps: stream.Caps,
) -> Counter[str]:
    """Insert the image row and every record; returns the rows written per record kind (the
    image line, folded into its row, is not counted)."""
    await insert_image(session, org_id, job_id, result)
    return await result_rows.insert_batches(
        session, org_id, job_id, stream.records(path, caps), _next_batch
    )


def job_facts(job: AnalysisJob) -> stream.JobFacts:
    if job.profile is None or job.os_hint is None:  # the 0016 checks make this unreachable
        raise RuntimeError(f"memory job {job.id} has no profile or OS hint")
    return stream.JobFacts(job_id=job.id, profile=job.profile.value, os_hint=job.os_hint.value)


async def _expected(job: AnalysisJob) -> stream.Expected:
    from app.workers import ingest as plumbing

    facts = await plumbing._evidence_facts(job)
    return stream.Expected(sha256=facts.sha256, size=facts.size)


async def ingest_memory(job: AnalysisJob, msg: IngestMessageV1, path: Path) -> None:
    """`memory.v1` success: validate the whole stream, incl. the image identity against the
    evidence record (worker thread), then write it in one transaction."""
    from app.workers import ingest as plumbing

    caps = stream.Caps.from_settings(get_settings())
    expected = await _expected(job)
    try:
        result = await anyio.to_thread.run_sync(
            stream.validate, path, job_facts(job), expected, caps
        )
        summary = build_summary(result, expected)
    except InvalidResult as exc:
        await plumbing._refuse(job, exc)
        return

    async def write(session: AsyncSession) -> dict[str, Any]:
        written = await insert_rows(session, job.organization_id, job.id, path, result, caps)
        plumbing._check_written(written, result.counts, skip=stream.IMAGE_KIND)
        return summary

    await plumbing._persist(job, msg, write)


async def ingest_memory_diagnostic(job: AnalysisJob, msg: IngestMessageV1, path: Path) -> None:
    """`symbols_missing` with its diagnostic stream: store the requirement, fail the job."""
    from app.workers import ingest as plumbing

    expected = await _expected(job)
    try:
        result = await anyio.to_thread.run_sync(
            stream.validate_diagnostic, path, job_facts(job), expected
        )
        summary = build_summary(result, expected)
    except InvalidResult as exc:
        await plumbing._refuse(job, exc)
        return

    settings = get_settings()
    async with tenant_session(job.organization_id, None) as session:
        await plumbing._limit_transaction(session, settings)
        # Under the row lock in this transaction: a redelivered report cannot insert twice.
        locked = await repo.get_for_update(session, job.organization_id, job.id)
        if locked is None or locked.status not in ACTIVE:
            return
        # The row first: the job guard refuses any write after the final state, and this
        # INSERT would otherwise flush the transition before the columns set below.
        await insert_image(session, job.organization_id, job.id, result)
        await plumbing._fail(session, locked, DIAGNOSTIC_CODE)
        # Flushed in the same UPDATE as the transition.
        locked.result_version_id = msg.result_version_id
        locked.worker_version = msg.worker_version
        locked.summary = summary
