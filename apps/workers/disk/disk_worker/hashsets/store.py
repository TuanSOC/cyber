"""The read-only hash-set store the worker matches against (M9 phase 5).

`HashSetStore(root)` loads `<root>/manifest.json` (`HashSetManifestV1`), checks every listed
file's size against `count × width` (cheap; the full re-hash is the tool's `verify`), and mmaps
the files read-only. `match(sha256, sha1, md5)` binary-searches the sets in `known_bad` →
`notable` → `known_good` order (manifest order within a kind; sha256, then sha1, then md5
within a set); the first hit wins and names the set, its kind and the matching algorithm.

- A missing or empty store is valid: `status == "empty"`, nothing matches.
- A manifest or file that fails validation disables **all** matching (`status == "invalid"`,
  `error` says why); the job reports it in its header and goes on (never a job failure).
- `known = good` means "listed in a reference set", not benign: NSRL also lists dual-use tools
  and vulnerable drivers (RT18); it never suppresses a heuristic or a YARA scan of a file in a
  user-writable path.
"""

import bisect
import contextlib
import mmap
import os
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, overload

from cyberlab_jobs.disk import DiskFileRecord, HashSetManifestV1, HashSetRef

from disk_worker.hashsets import manifest as mf

StoreStatus = Literal["ok", "empty", "invalid"]
# HashSetKind -> DiskFileRecord.known
KNOWN_BY_KIND: dict[str, Literal["good", "bad", "notable"]] = {
    "known_good": "good",
    "known_bad": "bad",
    "notable": "notable",
}


@dataclass(frozen=True)
class HashSetHit:
    name: str
    kind: str  # known_good | known_bad | notable
    algo: str  # the algorithm that matched

    @property
    def known(self) -> Literal["good", "bad", "notable"]:
        return KNOWN_BY_KIND[self.kind]


class HashSetsCorrupt(RuntimeError):
    """A store file does not match its manifest entry."""


class _Records(Sequence[bytes]):
    """Fixed-width records of a read-only map, as a sequence `bisect` can search."""

    def __init__(self, data: mmap.mmap | bytes, width: int, count: int) -> None:
        self._data = data
        self._width = width
        self._count = count

    def __len__(self) -> int:
        return self._count

    @overload
    def __getitem__(self, index: int) -> bytes: ...

    @overload
    def __getitem__(self, index: slice) -> Sequence[bytes]: ...

    def __getitem__(self, index: int | slice) -> bytes | Sequence[bytes]:
        if isinstance(index, slice):
            raise TypeError("slicing is not supported")
        if not 0 <= index < self._count:
            raise IndexError(index)
        start = index * self._width
        return bytes(self._data[start : start + self._width])

    def __contains__(self, value: object) -> bool:
        if not isinstance(value, bytes) or len(value) != self._width:
            return False
        i = bisect.bisect_left(self, value)
        return i < self._count and self[i] == value


@dataclass
class _LoadedSet:
    name: str
    kind: str
    records: dict[str, _Records]


def _digest(value: str | None, algo: str) -> bytes | None:
    if value is None or len(value) != 2 * mf.WIDTH[algo]:
        return None
    try:
        return bytes.fromhex(value.lower())
    except ValueError:
        return None


class HashSetStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.status: StoreStatus = "empty"
        self.error: str | None = None
        self._manifest = HashSetManifestV1()
        self._sets: list[_LoadedSet] = []
        self._maps: list[mmap.mmap] = []
        try:
            self._load()
        except (mf.ManifestInvalid, HashSetsCorrupt, OSError, ValueError) as exc:
            self.close()
            self._manifest = HashSetManifestV1()
            self.status = "invalid"
            self.error = str(exc)[:255] or type(exc).__name__

    # --- loading -----------------------------------------------------------------------------

    def _open(self, rel: str, width: int, count: int) -> _Records:
        fd = os.open(self.root / rel, mf.READ_FLAGS)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise HashSetsCorrupt(f"{rel} is not a regular file")
            if st.st_size != count * width:
                raise HashSetsCorrupt(f"{rel}: {st.st_size} bytes, expected {count} × {width}")
            if count == 0:
                return _Records(b"", width, 0)
            data = mmap.mmap(fd, st.st_size, access=mmap.ACCESS_READ)
        finally:
            os.close(fd)
        self._maps.append(data)
        return _Records(data, width, count)

    def _load(self) -> None:
        if not self.root.is_dir():
            return  # no store mounted: valid, nothing matches
        manifest = mf.load(self.root)
        loaded = []
        for s in manifest.sets:
            records = {f.algo: self._open(f.path, mf.WIDTH[f.algo], f.count) for f in s.files}
            loaded.append(_LoadedSet(name=s.name, kind=s.kind, records=records))
        rank = {k: i for i, k in enumerate(mf.KIND_ORDER)}
        self._sets = sorted(loaded, key=lambda s: rank[s.kind])  # stable: manifest order
        self._manifest = manifest
        self.status = "ok" if loaded else "empty"

    def close(self) -> None:
        self._sets = []
        for data in self._maps:
            with contextlib.suppress(BufferError):  # an exported view still alive; GC closes it
                data.close()
        self._maps = []

    def __enter__(self) -> "HashSetStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- queries -----------------------------------------------------------------------------

    def manifest(self) -> HashSetManifestV1:
        """The loaded manifest (empty for an empty store). Raises `HashSetsCorrupt` when the
        store is invalid."""
        if self.status == "invalid":
            raise HashSetsCorrupt(self.error or "invalid hash-set store")
        return self._manifest

    def refs(self) -> list[HashSetRef]:
        """The header's `hashsets` (empty when the store is empty or invalid)."""
        return [] if self.status == "invalid" else mf.refs(self._manifest)

    def match(self, sha256: str | None, sha1: str | None, md5: str | None) -> HashSetHit | None:
        if not self._sets:
            return None
        wanted = [
            (algo, digest)
            for algo, value in (("sha256", sha256), ("sha1", sha1), ("md5", md5))
            if (digest := _digest(value, algo)) is not None
        ]
        for loaded in self._sets:
            for algo, digest in wanted:
                records = loaded.records.get(algo)
                if records is not None and digest in records:
                    return HashSetHit(name=loaded.name, kind=loaded.kind, algo=algo)
        return None

    def annotate(self, record: DiskFileRecord) -> DiskFileRecord:
        """`record` with `known` / `known_set` set from the first matching set (hashed files
        only; others are returned unchanged)."""
        if record.hash_status != "hashed":
            return record
        hit = self.match(record.sha256, record.sha1, record.md5)
        if hit is None:
            return record
        return record.model_copy(update={"known": hit.known, "known_set": hit.name})
