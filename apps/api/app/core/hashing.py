"""Spool an untrusted byte stream to a size-capped temp file while hashing it.

The bytes are never interpreted here; only the first few KiB are kept for type sniffing.
Writing and hashing run in a worker thread in ~1 MiB batches, so the event loop never does
the CPU-heavy work.
"""

import hashlib
import logging
import os
import tempfile
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

import anyio

from app.core.threads import evidence_io_limiter

log = logging.getLogger(__name__)

SNIFF_BYTES = 8 * 1024
BATCH_BYTES = 1024 * 1024
STALE_SPOOL_S = 3600
ALGORITHMS = ("md5", "sha1", "sha256")


class TooLarge(Exception):
    def __init__(self, limit: int) -> None:
        super().__init__(f"body exceeds {limit} bytes")
        self.limit = limit


class MultiHasher:
    def __init__(self) -> None:
        # md5/sha1 are evidence identifiers (matching external tools), not security controls.
        self._hashers = {name: hashlib.new(name, usedforsecurity=False) for name in ALGORITHMS}

    def update(self, chunk: bytes) -> None:
        for hasher in self._hashers.values():
            hasher.update(chunk)

    def hexdigests(self) -> dict[str, str]:
        return {name: hasher.hexdigest() for name, hasher in self._hashers.items()}


@dataclass(frozen=True)
class Spooled:
    path: Path
    size: int
    hashes: dict[str, str]
    head: bytes


def _write_and_hash(out: BinaryIO, hasher: MultiHasher, data: bytes) -> None:
    hasher.update(data)
    out.write(data)


async def spool(chunks: AsyncIterator[bytes], directory: str, max_bytes: int) -> Spooled:
    """Write chunks to a new temp file in `directory`. The file is removed on any failure."""
    fd, name = tempfile.mkstemp(prefix="evidence-", suffix=".part", dir=directory)
    path = Path(name)
    hasher = MultiHasher()
    head = bytearray()
    batch = bytearray()
    size = 0

    async def flush(out: BinaryIO) -> None:
        if batch:
            data = bytes(batch)
            batch.clear()
            await anyio.to_thread.run_sync(
                _write_and_hash, out, hasher, data, limiter=evidence_io_limiter()
            )

    try:
        with os.fdopen(fd, "wb") as out:
            async for chunk in chunks:
                if not chunk:
                    continue
                size += len(chunk)
                if size > max_bytes:
                    raise TooLarge(max_bytes)
                if len(head) < SNIFF_BYTES:
                    head.extend(chunk[: SNIFF_BYTES - len(head)])
                batch.extend(chunk)
                if len(batch) >= BATCH_BYTES:
                    await flush(out)
            await flush(out)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return Spooled(path=path, size=size, hashes=hasher.hexdigests(), head=bytes(head))


def sweep_stale_spools(directory: str, max_age_s: int = STALE_SPOOL_S) -> int:
    """Remove spool files left by a crash. Safe with several API replicas sharing the volume:
    an active upload rewrites its file at least every few seconds, far below max_age_s."""
    removed = 0
    cutoff = time.time() - max_age_s
    for path in Path(directory).glob("evidence-*.part"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        except FileNotFoundError:
            continue
    if removed:
        log.warning("removed %d stale evidence spool files", removed)
    return removed
