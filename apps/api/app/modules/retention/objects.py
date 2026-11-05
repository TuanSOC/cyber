"""Object calls of the retention worker, as the MinIO purge user `cyberlab-purge` (RT5).

The purge user may read retention and legal holds, set or clear legal holds and delete
object versions; it has no PutObject, no governance bypass and an explicit Deny on report
snapshots. Every call addresses one exact version and runs on a worker thread. The api user
never calls these (it has no legal-hold action at all).
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

import anyio
from minio import Minio
from minio.error import S3Error

from app.core.clients import get_purge_minio

_MISSING = {"NoSuchKey", "NoSuchVersion", "NoSuchObject"}


def client() -> Minio:
    """The purge user's client (tests point this at their purge credentials)."""
    return get_purge_minio()


async def _run[T](func: Callable[[], T]) -> T:
    return await anyio.to_thread.run_sync(func)


def is_missing(exc: S3Error) -> bool:
    return exc.code in _MISSING


@dataclass(frozen=True)
class Lock:
    """What MinIO says about one version right now (never the DB's estimate)."""

    present: bool
    retain_until: datetime | None = None
    legal_hold: bool = False

    def locked(self, now: datetime) -> bool:
        return self.retain_until is not None and self.retain_until > now


async def lock_state(bucket: str, key: str, version_id: str, *, lockable: bool = True) -> Lock:
    """Presence, GOVERNANCE retention and S3 legal hold of a version (`lockable=False` for
    the unlocked results bucket: presence only)."""

    def _state() -> Lock:
        c = client()
        try:
            c.stat_object(bucket, key, version_id=version_id)
        except S3Error as exc:
            if is_missing(exc):
                return Lock(present=False)
            raise
        if not lockable:
            return Lock(present=True)
        retention = c.get_object_retention(bucket, key, version_id=version_id)
        held = c.is_object_legal_hold_enabled(bucket, key, version_id=version_id)
        until = retention.retain_until_date if retention else None
        return Lock(present=True, retain_until=until, legal_hold=bool(held))

    return await _run(_state)


async def present(bucket: str, key: str, version_id: str) -> bool:
    return (await lock_state(bucket, key, version_id, lockable=False)).present


async def delete_version(bucket: str, key: str, version_id: str) -> None:
    """Delete exactly this version; a version already gone counts as deleted."""

    def _delete() -> None:
        try:
            client().remove_object(bucket, key, version_id=version_id)
        except S3Error as exc:
            if not is_missing(exc):
                raise

    await _run(_delete)


async def legal_hold(bucket: str, key: str, version_id: str) -> bool | None:
    """The version's S3 legal hold (None when the version is gone)."""

    def _get() -> bool | None:
        try:
            return bool(client().is_object_legal_hold_enabled(bucket, key, version_id=version_id))
        except S3Error as exc:
            if is_missing(exc):
                return None
            raise

    return await _run(_get)


async def set_legal_hold(bucket: str, key: str, version_id: str, on: bool) -> None:
    def _set() -> None:
        c = client()
        if on:
            c.enable_object_legal_hold(bucket, key, version_id=version_id)
        else:
            c.disable_object_legal_hold(bucket, key, version_id=version_id)

    await _run(_set)
