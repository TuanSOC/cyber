import hashlib
import os
import time
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from starlette.requests import ClientDisconnect

from app.core.hashing import SNIFF_BYTES, MultiHasher, TooLarge, spool, sweep_stale_spools


async def _chunks(data: bytes, size: int) -> AsyncIterator[bytes]:
    for i in range(0, len(data), size):
        yield data[i : i + size]


def _reference(data: bytes) -> dict[str, str]:
    return {name: hashlib.new(name, data).hexdigest() for name in ("md5", "sha1", "sha256")}


def test_multihasher_known_vectors() -> None:
    hasher = MultiHasher()
    hasher.update(b"abc")
    assert hasher.hexdigests() == {
        "md5": "900150983cd24fb0d6963f7d28e17f72",
        "sha1": "a9993e364706816aba3e25717850c26c9cd0d89d",
        "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    }


@pytest.mark.parametrize(
    ("chunk_size", "length"),
    [(1, 20_001), (7, 20_001), (4096, 300_001), (65536, 300_001), (1 << 20, 300_001)],
)
async def test_spool_matches_hashlib_across_chunk_boundaries(
    tmp_path: Path, chunk_size: int, length: int
) -> None:
    data = os.urandom(length)  # always > SNIFF_BYTES
    spooled = await spool(_chunks(data, chunk_size), str(tmp_path), max_bytes=len(data))
    assert spooled.hashes == _reference(data)
    assert spooled.size == len(data)
    assert spooled.head == data[:SNIFF_BYTES]
    assert spooled.path.read_bytes() == data


async def test_spool_empty_stream(tmp_path: Path) -> None:
    spooled = await spool(_chunks(b"", 1), str(tmp_path), max_bytes=10)
    assert spooled.size == 0 and spooled.hashes == _reference(b"")


async def test_spool_over_limit_removes_temp_file(tmp_path: Path) -> None:
    with pytest.raises(TooLarge):
        await spool(_chunks(b"x" * 101, 10), str(tmp_path), max_bytes=100)
    assert list(tmp_path.iterdir()) == []


async def test_spool_client_disconnect_removes_temp_file(tmp_path: Path) -> None:
    async def interrupted() -> AsyncIterator[bytes]:
        yield b"partial data"
        raise ClientDisconnect()

    with pytest.raises(ClientDisconnect):
        await spool(interrupted(), str(tmp_path), max_bytes=1000)
    assert list(tmp_path.iterdir()) == []


def test_sweep_removes_only_stale_spools(tmp_path: Path) -> None:
    stale = tmp_path / "evidence-old.part"
    fresh = tmp_path / "evidence-new.part"
    other = tmp_path / "keep.txt"
    for path in (stale, fresh, other):
        path.write_bytes(b"x")
    old = time.time() - 7200
    os.utime(stale, (old, old))
    os.utime(other, (old, old))
    assert sweep_stale_spools(str(tmp_path)) == 1
    assert sorted(p.name for p in tmp_path.iterdir()) == ["evidence-new.part", "keep.txt"]
