"""Report snapshot objects in the object-locked `reports` bucket (M6 phase 3, RT6).

- Keys are `{org}/{report}/{version}/snapshot.json`; every read addresses the exact object
  version recorded on the `report_versions` row, so a later PUT to the same key can never
  change what is served or verified.
- The bucket has no default retention: the API sets a per-object GOVERNANCE retention
  (`EVIDENCE_LOCK_DAYS`) on the exact version it stored, right after the put.
- Blocking client calls run on the evidence I/O thread limiter (never the event loop).
- Puts happen outside any database transaction (RT14); an object whose version row is then
  never written is an orphan: logged here and listed by the reconcile script, never served.
"""

import hashlib
import io
import logging
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import anyio
from minio.error import S3Error

from app.core import storage as core_storage
from app.core.clients import get_minio
from app.core.config import get_settings
from app.core.threads import evidence_io_limiter

log = logging.getLogger(__name__)

SNAPSHOT_CONTENT_TYPE = "application/json"
_MISSING = {"NoSuchKey", "NoSuchVersion"}


class SnapshotMissing(Exception):
    """The recorded object version does not exist (or cannot be read)."""


def bucket() -> str:
    return get_settings().reports_bucket


def snapshot_key(org_id: uuid.UUID, report_id: uuid.UUID, version: int) -> str:
    return f"{org_id}/{report_id}/{version}/snapshot.json"


async def _run[T](func: Callable[[], T]) -> T:
    return await anyio.to_thread.run_sync(func, limiter=evidence_io_limiter())


async def put_snapshot(key: str, data: bytes) -> str:
    """Store the canonical bytes; returns the new object version id."""
    result = await _run(
        lambda: get_minio().put_object(
            bucket(), key, io.BytesIO(data), len(data), content_type=SNAPSHOT_CONTENT_TYPE
        )
    )
    if not result.version_id:
        raise RuntimeError("the reports bucket is not versioned: report snapshots need lock")
    return str(result.version_id)


def retention_until(now: datetime | None = None) -> datetime | None:
    """The GOVERNANCE retention date of a new snapshot (None when locking is disabled)."""
    days = get_settings().evidence_lock_days
    if days <= 0:
        return None
    return (now or datetime.now(UTC)) + timedelta(days=days)


async def lock_snapshot(key: str, version_id: str, until: datetime) -> None:
    """Per-object GOVERNANCE retention on exactly this version (RT6)."""
    await core_storage.set_retention(bucket(), key, version_id, until)


async def get_retention(key: str, version_id: str) -> datetime | None:
    return await core_storage.get_retention_until(bucket(), key, version_id)


def _read_sync(bucket_name: str, key: str, version_id: str, max_bytes: int) -> bytes:
    try:
        response = get_minio().get_object(bucket_name, key, version_id=version_id)
    except S3Error as exc:
        if exc.code in _MISSING:
            raise SnapshotMissing(key) from exc
        raise
    chunks: list[bytes] = []
    size = 0
    try:
        while chunk := response.read(core_storage.CHUNK):
            size += len(chunk)
            if size > max_bytes:
                # Never buffer an unbounded object: the stored snapshot is at most the cap.
                raise SnapshotMissing(key)
            chunks.append(chunk)
    finally:
        response.close()
        response.release_conn()
    return b"".join(chunks)


async def read_snapshot(key: str, version_id: str) -> bytes:
    """The exact stored bytes of one version (bounded by the snapshot cap + 1 byte)."""
    limit = get_settings().report_max_snapshot_bytes + 1
    return await _run(lambda: _read_sync(bucket(), key, version_id, limit))


async def hash_snapshot(key: str, version_id: str) -> tuple[int, str] | None:
    """`(size, sha256)` re-hashed from the stored version, or None when it is missing."""
    try:
        size, digests = await core_storage.hash_version(bucket(), key, version_id)
    except core_storage.ObjectMissing:
        return None
    return size, digests["sha256"]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def log_orphan(key: str, version_id: str, reason: str) -> None:
    """A stored snapshot whose version row was never written (RT14); the reconcile script
    lists these. Ids and the reason only."""
    log.warning(
        "orphan report snapshot: bucket=%s key=%s version_id=%s reason=%s",
        bucket(),
        key,
        version_id,
        reason,
    )
