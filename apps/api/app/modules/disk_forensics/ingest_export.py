"""Trusted ingest of a `disk-export.v1` result (M9 phase 10; on the disk ingest worker, task
`disk.ingest`, like every disk schema: `workers/ingest.handle_disk_ingest`'s `extract` branch).

`ingest_disk_export(job, msg, path)`: a `succeeded` report of an `extract` job with its
downloaded result stream.

1. **Validate** (worker thread; refused as a whole, `invalid_result`, writing nothing): the
   shared framing (header first, hashed trailer last) bounded to `MAX_STREAM_BYTES` and two
   lines, nothing between them; a `disk-export.v1` header naming this job and reporting each
   of the job's `pending` exports exactly once (no unknown, missing or repeated export id).
2. **Check each exported object** (results bucket, the api user's Get / ListBucketVersions;
   never read here): the key is re-derived (`dispatch.export_key`), never taken from the
   worker; it must hold exactly one version (not a delete marker) whose size is the reported
   size, itself at most the listed size and `DISK_EXPORT_MAX_BYTES`. Otherwise that file is
   `failed` (`invalid_result`). The worker's sha256 is stored as reported: untrusted, display
   only, until the promote re-hashes the exact version (`export_service.promote`).
3. **Write** (one transaction, the job row locked FOR UPDATE and re-checked active and within
   its deadline, the phase-7 rules): each export `ready` (object key, exact version id, size,
   worker sha256) or `failed` (the worker's error code, or `invalid_result`); the job
   `succeeded` when at least one file is ready (summary: counts and tool versions; custody
   `analyzed` on every segment), else `failed` with the files' common code
   (`job_failure_code`).
"""

import logging
import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio
from cyberlab_jobs import IngestMessageV1
from cyberlab_jobs.disk import DISK_ERROR_CODES, DiskExportResultHeader, ExportedFile
from pydantic import ValidationError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.clients import get_minio
from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob
from app.modules.analysis.result_stream import InvalidResult, check_framing
from app.modules.disk_forensics import ingest as disk_ingest
from app.modules.disk_forensics import segments as disk_segments
from app.modules.disk_forensics.dispatch import export_key
from app.modules.disk_forensics.models import DiskExport, DiskExportState, DiskFile

log = logging.getLogger(__name__)

# A header of 20 files and the trailer: far below this.
MAX_STREAM_BYTES = 256 * 1024
MAX_LINES = 2
INVALID = "invalid_result"
# The job's failure code when no file was exported and the files disagree on why.
MIXED_FAILURE = "analyzer_failed"


@dataclass(frozen=True)
class ObjectFacts:
    version_id: str
    size: int


@dataclass(frozen=True)
class Outcome:
    """What one `disk_exports` row becomes."""

    export_id: uuid.UUID
    ready: bool
    size: int | None = None
    sha256: str | None = None
    version_id: str | None = None
    key: str | None = None
    error_code: str | None = None


def validate(path: Path, job_id: uuid.UUID, pending: set[uuid.UUID]) -> DiskExportResultHeader:
    """The whole stream, before any write. Blocking (a worker thread). Raises InvalidResult."""
    found: list[DiskExportResultHeader] = []

    def first(line: bytes) -> None:
        try:
            header = DiskExportResultHeader.model_validate_json(line)
        except ValidationError as exc:  # incl. another schema's header (e.g. disk.v1)
            raise InvalidResult("invalid_header") from exc
        if header.job_id != job_id:
            raise InvalidResult("header_job_mismatch")
        reported = [f.export_id for f in header.files]
        if len(set(reported)) != len(reported) or set(reported) != pending:
            raise InvalidResult("export_ids_mismatch")
        found.append(header)

    def middle(line: bytes) -> None:
        raise InvalidResult("unexpected_line")

    check_framing(
        path, max_decompressed=MAX_STREAM_BYTES, max_lines=MAX_LINES, first=first, middle=middle
    )
    if not found:  # unreachable: check_framing always feeds the first line
        raise InvalidResult("missing_header")
    return found[0]


def object_facts(bucket: str, key: str) -> ObjectFacts | None:
    """The single stored version of `key` (None: absent, several versions or a delete
    marker). Blocking (MinIO)."""
    versions = [
        o
        for o in get_minio().list_objects(bucket, prefix=key, include_version=True)
        if o.object_name == key
    ]
    if len(versions) != 1:
        return None
    only = versions[0]
    if only.is_delete_marker or not only.version_id or only.size is None:
        return None
    return ObjectFacts(version_id=str(only.version_id), size=int(only.size))


def outcome(
    reported: ExportedFile, facts: ObjectFacts | None, key: str, listed_size: int | None
) -> Outcome:
    """One file's row update from the worker's report and the stored object (pure)."""
    if reported.status != "ok":
        return Outcome(reported.export_id, False, error_code=reported.error_code or INVALID)
    cap = get_settings().disk_export_max_bytes
    size = reported.size
    if (
        facts is None
        or size is None
        or reported.sha256 is None
        or facts.size != size
        or size <= 0
        or size > cap
        or (listed_size is not None and size > listed_size)
    ):
        return Outcome(reported.export_id, False, error_code=INVALID)
    return Outcome(
        reported.export_id,
        True,
        size=size,
        sha256=reported.sha256,
        version_id=facts.version_id,
        key=key,
    )


def job_failure_code(outcomes: list[Outcome]) -> str:
    """The code a job with no exported file fails with: the files' common code when it is a
    disk code (e.g. `disk_export_not_allowed`), else `analyzer_failed`."""
    codes = {o.error_code for o in outcomes}
    if len(codes) == 1:
        code = codes.pop()
        if code in DISK_ERROR_CODES or code == INVALID:
            return str(code)
    return MIXED_FAILURE


async def _pending(job: AnalysisJob) -> dict[uuid.UUID, int | None]:
    """The job's `pending` exports and the listed size of each (None: listing gone)."""
    async with tenant_session(job.organization_id, None) as session:
        rows = (
            await session.execute(
                select(DiskExport.id, DiskExport.source_job_id, DiskExport.file_id).where(
                    DiskExport.organization_id == job.organization_id,
                    DiskExport.export_job_id == job.id,
                    DiskExport.state == DiskExportState.PENDING.value,
                )
            )
        ).all()
        sizes: dict[uuid.UUID, int | None] = {}
        if rows:
            sizes = {
                file_id: size
                for file_id, size in (
                    await session.execute(
                        select(DiskFile.id, DiskFile.size).where(
                            DiskFile.organization_id == job.organization_id,
                            DiskFile.job_id == rows[0].source_job_id,
                            DiskFile.id.in_([r.file_id for r in rows]),
                        )
                    )
                ).tuples()
            }
    return {r.id: sizes.get(r.file_id) for r in rows}


async def _apply(session: AsyncSession, org_id: uuid.UUID, outcomes: list[Outcome]) -> None:
    for o in outcomes:
        values: dict[str, Any] = (
            {
                "state": DiskExportState.READY.value,
                "object_key": o.key,
                "object_version_id": o.version_id,
                "size": o.size,
                "worker_sha256": o.sha256,
            }
            if o.ready
            else {"state": DiskExportState.FAILED.value, "error_code": o.error_code}
        )
        await session.execute(
            update(DiskExport)
            .where(
                DiskExport.organization_id == org_id,
                DiskExport.id == o.export_id,
                DiskExport.state == DiskExportState.PENDING.value,
            )
            .values(**values)
            .execution_options(synchronize_session=False)
        )


def build_summary(header: DiskExportResultHeader, outcomes: list[Outcome]) -> dict[str, Any]:
    ready = [o for o in outcomes if o.ready]
    failed: Counter[str] = Counter(o.error_code or INVALID for o in outcomes if not o.ready)
    return {
        "schema_version": header.schema_version,
        "tool_versions": dict(header.tool_versions),
        "counts": {
            "exports": len(outcomes),
            "ready": len(ready),
            "failed": len(outcomes) - len(ready),
            "bytes": sum(o.size or 0 for o in ready),
        },
        "failed_codes": dict(failed),
    }


async def ingest_disk_export(job: AnalysisJob, msg: IngestMessageV1, path: Path) -> None:
    from app.workers import ingest as plumbing

    settings = get_settings()
    pending = await _pending(job)
    try:
        header = await anyio.to_thread.run_sync(validate, path, job.id, set(pending))
    except InvalidResult as exc:
        await plumbing._refuse(job, exc)
        return
    outcomes: list[Outcome] = []
    for reported in header.files:
        key = export_key(job.id, reported.export_id)
        facts = None
        if reported.status == "ok":
            facts = await anyio.to_thread.run_sync(object_facts, settings.results_bucket, key)
        outcomes.append(outcome(reported, facts, key, pending.get(reported.export_id)))
    summary = build_summary(header, outcomes)
    async with tenant_session(job.organization_id, None) as session:
        segments = await disk_segments.of_job(session, job.organization_id, job.id)

    async def write(session: AsyncSession) -> None:
        locked = await disk_ingest._lock_active(session, job)
        await _apply(session, job.organization_id, outcomes)
        if any(o.ready for o in outcomes):
            await plumbing._record_success(session, locked, msg, summary)
            session.add_all(disk_ingest._segment_custody(locked, msg, segments))
            return
        # Set while the job is still active (the failure arm below runs statements after the
        # transition, which would flush these as a refused write to a final job).
        locked.result_version_id = msg.result_version_id
        locked.worker_version = msg.worker_version
        locked.summary = summary
        await plumbing._fail(session, locked, job_failure_code(outcomes))

    await disk_ingest._run(job, write)


__all__ = [
    "MAX_STREAM_BYTES",
    "ObjectFacts",
    "Outcome",
    "build_summary",
    "ingest_disk_export",
    "job_failure_code",
    "object_facts",
    "outcome",
    "validate",
]
