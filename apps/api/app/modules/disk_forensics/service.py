"""Disk read API logic (M9 phase 8): job readiness, the summary, row mapping, one file's
detail, directory listing and the merged timeline page.

- Every read runs under `SET LOCAL statement_timeout = '5s'` (the request's tenant
  transaction; the streamed exports use 120 s in their own session) and answers
  `409 analysis_not_ready` while the job is queued or running; 404 for a job of another org,
  another analyzer or an `extract` job.
- Text is returned exactly as stored (bounded, NUL-free, single line at ingest): paths,
  names, EWF values and messages come from the image and are inert text.
- Unsigned 64-bit values (`meta_addr`, `parent_addr`, sectors, `media_size`) are decimal
  strings (`schemas.U64Text`).
- Worker-reported image hashes are labelled as such (RT17); the segment sha256 values are
  the API's own (the only trusted image hashes).
- No audit per page (the static / memory decision); the interop exports are audited
  (`exports_interop`).
"""

import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal

from cyberlab_jobs.disk import CASE_INSENSITIVE_FS, FILE_FLAG_BITS, never_collect
from pydantic import BaseModel, ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import NotFound
from app.core.pagination import PageParams
from app.modules.analysis.models import ACTIVE, AnalysisJob
from app.modules.disk_forensics import repository as repo
from app.modules.disk_forensics.exports_interop import time_description
from app.modules.disk_forensics.models import DiskEvent, DiskFile, DiskImage, DiskPartition
from app.modules.disk_forensics.schemas import (
    DirPage,
    DiskArtifactStatOut,
    DiskHashSetOut,
    DiskSegmentOut,
    DiskStageOut,
    DiskSummaryOut,
    EventOut,
    FileDetailOut,
    FileOut,
    PartitionOut,
    TimeColumn,
    TimelineItemOut,
)
from app.modules.memory_analysis.service import AnalysisNotReady, ResultsNotAvailable

STATEMENT_TIMEOUT = "SET LOCAL statement_timeout = '5s'"


async def ready_job(session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID) -> AnalysisJob:
    """The org's disk job (404 otherwise) once it is terminal (409 before), with the read
    statement timeout set for the rest of the request's transaction."""
    await session.execute(text(STATEMENT_TIMEOUT))
    job = await repo.ensure_disk_job(session, org_id, job_id)
    if job.status in ACTIVE:
        raise AnalysisNotReady()
    return job


# --- Row mapping ---------------------------------------------------------------------------


def flag_names(bits: int) -> list[str]:
    return [name for name, bit in FILE_FLAG_BITS.items() if bits & bit]


def _file_fields(row: DiskFile) -> dict[str, Any]:
    return {
        "id": row.id,
        "partition_index": row.partition_index,
        "meta_addr": row.meta_addr,
        "meta_seq": row.meta_seq,
        "stream": row.stream,
        "path": row.path,
        "parent_addr": row.parent_addr,
        "name": row.name,
        "ext": row.ext,
        "type": row.type,
        "flags": flag_names(row.flags),
        "size": row.size,
        "mtime": row.mtime,
        "atime": row.atime,
        "ctime": row.ctime,
        "crtime": row.crtime,
        "time_basis": row.time_basis,
        "magic": row.magic,
        "hash_status": row.hash_status,
        "md5": row.md5,
        "sha1": row.sha1,
        "sha256": row.sha256,
        "known": row.known,
        "known_set": row.known_set,
        "yara_rules": list(row.yara_rules or []),
    }


def file_out(row: DiskFile) -> FileOut:
    return FileOut.model_validate(_file_fields(row))


def partition_out(row: DiskPartition) -> PartitionOut:
    return PartitionOut.model_validate(
        {
            "id": row.id,
            "index": row.index,
            "start_sector": row.start_sector,
            "length_sectors": row.length_sectors,
            "description": row.description,
            "vs_flags": row.vs_flags,
            "fs_type": row.fs_type,
            "fs_status": row.fs_status,
            "fs_label": row.fs_label,
            "fs_uuid": row.fs_uuid,
            "block_size": row.block_size,
            "os": row.os,
            "os_name": row.os_name,
            "error_code": row.error_code,
            "counts": _int_map(row.counts),
        }
    )


def event_out(row: DiskEvent) -> EventOut:
    return EventOut.model_validate(
        {
            "id": row.id,
            "ts": row.ts,
            "ts_desc": row.ts_desc,
            "artifact": row.artifact,
            "parser": row.parser,
            "data_type": row.data_type,
            "partition_index": row.partition_index,
            "path": row.path,
            "file_id": row.file_id,
            "message": row.message,
            "attributes": dict(row.attributes or {}),
        }
    )


def timeline_item_out(row: Any) -> TimelineItemOut:
    """A merged-timeline row: a file time (`kind` = the column, the description says when
    a FAT time's zone is unknown) or an event (`kind` = its artifact)."""
    if row.stream == repo.EVENT_STREAM:
        return TimelineItemOut(
            ts=row.ts,
            source="event",
            kind=row.artifact,
            description=row.message,
            path=row.path,
            file_id=row.file_id,
            event_id=row.id,
        )
    return TimelineItemOut(
        ts=row.ts,
        source="file",
        kind=row.stream,
        description=time_description(row.stream, row.time_basis),
        path=row.path,
        file_id=row.id,
    )


# --- Summary -------------------------------------------------------------------------------


def _str_map(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(k): v for k, v in value.items() if isinstance(v, str)}


def _int_map(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    return {str(k): v for k, v in value.items() if isinstance(v, int) and not isinstance(v, bool)}


def _models[M: BaseModel](model: type[M], value: object) -> list[M]:
    """Tolerant: the well-formed entries of a stored JSON list (written by the ingest)."""
    if not isinstance(value, list):
        return []
    out: list[M] = []
    for item in value:
        try:
            out.append(model.model_validate(item))
        except ValidationError:
            continue
    return out


async def summary(session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob) -> DiskSummaryOut:
    """The image facts, the per-stage status, the artifact counts and the hash sets used; the
    row counts are live (stored counts are kept under them). `404 results_not_available` for
    a terminal job without an image row."""
    image: DiskImage | None = await repo.image(session, org_id, job.id)
    if image is None:
        raise ResultsNotAvailable()
    stored: Mapping[str, Any] = job.summary if isinstance(job.summary, Mapping) else {}
    segments = [
        DiskSegmentOut(
            ordinal=ordinal,
            evidence_id=evidence_id,
            original_filename=filename,
            size_bytes=size,
            sha256=sha256 or "",
        )
        for ordinal, evidence_id, filename, size, sha256 in await repo.segments(
            session, org_id, job.id
        )
    ]
    counts = {**_int_map(image.counts), **await repo.live_counts(session, org_id, job.id)}
    tool_versions = _str_map(image.tool_versions) or _str_map(stored.get("tool_versions"))
    assert job.profile is not None  # noqa: S101 - 0017 check: disk jobs have a profile
    profile: Literal["triage", "full"] = "full" if job.profile.value == "full" else "triage"
    return DiskSummaryOut.model_validate(
        {
            "job_id": job.id,
            "profile": profile,
            "format": image.format,  # DB check constraint
            "segments": segments,
            "media_size": image.media_size,
            "sector_size": image.sector_size,
            "media_sha256": image.media_sha256,
            "ewf_md5": image.ewf_md5,
            "ewf_sha1": image.ewf_sha1,
            "media_hash_status": image.media_hash_status,
            "ewf_meta": _str_map(image.ewf_meta),
            "volume_system": image.volume_system,
            "engine": image.engine,
            "timeline_engine": image.timeline_engine,
            "tool_versions": tool_versions,
            "stages": _models(DiskStageOut, image.stages),
            "artifacts": _models(DiskArtifactStatOut, stored.get("artifacts")),
            "hashsets": _models(DiskHashSetOut, image.hashsets),
            "counts": counts,
            "truncated": bool(image.truncated),
        }
    )


# --- One file ------------------------------------------------------------------------------


def export_refusal(
    row: DiskFile, names: Sequence[str], fs_type: str | None, max_bytes: int
) -> str | None:
    """Why "Export" is not offered for this entry (None: it is): not allocated (deleted or
    orphan), not a regular file, size unknown or above `DISK_EXPORT_MAX_BYTES`, or any name
    of the inode on the never-collected list (RT7)."""
    if not row.flags & FILE_FLAG_BITS["allocated"] or row.flags & FILE_FLAG_BITS["deleted"]:
        return "not_allocated"
    if row.type != "reg":
        return "not_regular"
    if row.size is None:
        return "size_unknown"
    if row.size > max_bytes:
        return "too_large"
    case_insensitive = fs_type is not None and fs_type in {fs.value for fs in CASE_INSENSITIVE_FS}
    if never_collect(names, case_insensitive):
        return "never_collected"
    return None


async def file_detail(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, file_id: uuid.UUID
) -> FileDetailOut:
    """One entry with every column, the inode's other names (hard links, RT7) and named
    streams, and whether it can be exported; 404 for a file id of another job."""
    row = await repo.file_row(session, org_id, job_id, file_id)
    if row is None:
        raise NotFound()
    others = await repo.same_inode(session, org_id, job_id, row)
    other_names = sorted({path for path, stream in others if stream is None and path != row.path})
    streams = sorted({stream for _, stream in others if stream is not None} - {row.stream})
    fs_type = await repo.partition_fs_type(session, org_id, job_id, row.partition_index)
    names = [row.path, *(path for path, _ in others)]
    reason = export_refusal(row, names, fs_type, get_settings().disk_export_max_bytes)
    return FileDetailOut.model_validate(
        {
            **_file_fields(row),
            "mode": row.mode,
            "uid": row.uid,
            "gid": row.gid,
            "other_names": other_names,
            "streams": streams,
            "exportable": reason is None,
            "not_exportable_reason": reason,
        }
    )


# --- Directories ---------------------------------------------------------------------------


def _dir_order(item: FileOut) -> tuple[bool, str, str]:
    return (item.type != "dir", item.name.casefold(), item.name)


async def dir_page(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    partition: int | None,
    parent: int | None,
) -> DirPage:
    """The entries whose `parent_addr` is the directory's address (RT13). Without
    `partition`, the lowest partition with listed files; without `parent`, its root (the
    parent of the top-level entries). Pages follow the (job, partition, parent_addr, id)
    index; within a page, directories first, then names."""
    if partition is None:
        partition = await repo.first_partition(session, org_id, job_id)
    if partition is None:
        return DirPage(items=[], total=0)
    address: int | Decimal | None = parent
    if address is None:
        address = await repo.root_addr(session, org_id, job_id, partition)
    if address is None:
        return DirPage(items=[], total=0, partition_index=partition)
    rows, total = await repo.children(
        session, org_id, job_id, page, partition=partition, parent=address
    )
    items = sorted((file_out(r) for r in rows), key=_dir_order)
    return DirPage.model_validate(
        {
            "items": items,
            "total": total,
            "partition_index": partition,
            "parent_addr": address,
        }
    )


# --- Merged timeline -----------------------------------------------------------------------


async def timeline_page(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    source: Literal["file", "event"] | None,
    time: TimeColumn | None,
    artifact: str | None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> tuple[list[TimelineItemOut], int]:
    streams = repo.timeline_streams(source, time, artifact)
    rows, total = await repo.timeline_page(
        session, org_id, job_id, page, streams=streams, since=since, until=until, artifact=artifact
    )
    return [timeline_item_out(r) for r in rows], total
