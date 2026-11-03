"""Evidence object storage (MinIO, object-locked bucket).

Every read/verify/delete addresses an exact object version in the bucket recorded on the
evidence row, so a later PUT to the same key (a new version) can never change what is served
or verified. Blocking client calls run on a dedicated thread limiter, so long transfers
cannot starve other threadpool users (argon2 hashing, health checks).
"""

from collections.abc import AsyncGenerator, Callable
from datetime import datetime
from pathlib import Path

import anyio
from minio.commonconfig import GOVERNANCE
from minio.error import S3Error
from minio.retention import Retention

from app.core.clients import get_minio
from app.core.config import get_settings
from app.core.hashing import MultiHasher
from app.core.threads import evidence_io_limiter

CHUNK = 256 * 1024
# minio-py buffers each part in memory: PART_SIZE x PARALLEL_PARTS per active upload.
PART_SIZE = 16 * 1024 * 1024
PARALLEL_PARTS = 2
_MISSING = {"NoSuchKey", "NoSuchVersion"}


class ObjectMissing(Exception):
    pass


def bucket() -> str:
    """Bucket for *new* evidence. Existing evidence is addressed by its stored bucket."""
    return get_settings().minio_bucket


async def _run[T](func: Callable[[], T]) -> T:
    return await anyio.to_thread.run_sync(func, limiter=evidence_io_limiter())


def _translate(exc: S3Error, key: str) -> Exception:
    return ObjectMissing(key) if exc.code in _MISSING else exc


async def put_file(key: str, path: Path) -> str:
    """Upload a local file into the current evidence bucket; returns the new version id."""
    result = await _run(
        lambda: get_minio().fput_object(
            bucket(),
            key,
            str(path),
            content_type="application/octet-stream",
            part_size=PART_SIZE,
            num_parallel_uploads=PARALLEL_PARTS,
        )
    )
    if not result.version_id:
        raise RuntimeError("bucket is not versioned: evidence requires object lock")
    return str(result.version_id)


async def iter_version(bucket_name: str, key: str, version_id: str) -> AsyncGenerator[bytes]:
    try:
        response = await _run(
            lambda: get_minio().get_object(bucket_name, key, version_id=version_id)
        )
    except S3Error as exc:
        raise _translate(exc, key) from exc
    try:
        while chunk := await _run(lambda: response.read(CHUNK)):
            yield chunk
    finally:
        response.close()
        response.release_conn()


def _hash_version_sync(bucket_name: str, key: str, version_id: str) -> tuple[int, dict[str, str]]:
    try:
        response = get_minio().get_object(bucket_name, key, version_id=version_id)
    except S3Error as exc:
        raise _translate(exc, key) from exc
    hasher, size = MultiHasher(), 0
    try:
        while chunk := response.read(CHUNK):
            size += len(chunk)
            hasher.update(chunk)
    finally:
        response.close()
        response.release_conn()
    return size, hasher.hexdigests()


async def hash_version(bucket_name: str, key: str, version_id: str) -> tuple[int, dict[str, str]]:
    """Read + hash in one worker thread (no per-chunk hops, no hashing on the event loop)."""
    return await _run(lambda: _hash_version_sync(bucket_name, key, version_id))


async def delete_version(bucket_name: str, key: str, version_id: str) -> None:
    await _run(lambda: get_minio().remove_object(bucket_name, key, version_id=version_id))


async def set_retention(bucket_name: str, key: str, version_id: str, until: datetime) -> None:
    await _run(
        lambda: get_minio().set_object_retention(
            bucket_name, key, Retention(GOVERNANCE, until), version_id=version_id
        )
    )


async def get_retention_until(bucket_name: str, key: str, version_id: str) -> datetime | None:
    retention = await _run(
        lambda: get_minio().get_object_retention(bucket_name, key, version_id=version_id)
    )
    return retention.retain_until_date if retention else None
