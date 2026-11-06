"""External sort of fixed-width records with deduplication (bounded memory; M9 phase 5).

Records are buffered in memory up to `chunk_records`, sorted, deduplicated and spilled to a
run file in `tmp_dir`; `finish()` k-way merges the runs (in passes of at most `MAX_FANIN` open
files) and yields every distinct record in ascending unsigned byte order, which is the order
`HashSetStore` binary-searches.

Memory: CPython holds a 32-byte `bytes` in ~65 bytes plus an 8-byte list slot, so the plan's
"64 Mi records" chunk would not fit the tool's 2 GiB `RLIMIT_AS`; the default is 4 Mi records
(≈ 300 MiB for sha256), and the importer splits that between the algorithms it sorts at once.
Temp space is about the size of the output per algorithm (plus one merge pass when there are
more than `MAX_FANIN` runs).
"""

import contextlib
import heapq
import os
import secrets
from collections.abc import Iterable, Iterator
from pathlib import Path

DEFAULT_CHUNK_RECORDS = 4 * 1024**2
MAX_FANIN = 64
READ_RECORDS = 8192


class SortOrderError(RuntimeError):
    """A run or the output is not strictly ascending (a bug or a modified temp file)."""


def _read_run(path: Path, width: int) -> Iterator[bytes]:
    with open(path, "rb") as f:
        while True:
            block = f.read(width * READ_RECORDS)
            if not block:
                return
            if len(block) % width:
                raise SortOrderError(f"{path.name}: truncated record")
            for i in range(0, len(block), width):
                yield block[i : i + width]


def unique(records: Iterable[bytes]) -> Iterator[bytes]:
    """Drop adjacent duplicates of an ascending stream; refuse a descending step."""
    previous: bytes | None = None
    for record in records:
        if previous is not None:
            if record == previous:
                continue
            if record < previous:
                raise SortOrderError("records are not ascending")
        previous = record
        yield record


class ExternalSorter:
    def __init__(self, width: int, tmp_dir: Path, chunk_records: int = DEFAULT_CHUNK_RECORDS):
        if width <= 0 or chunk_records <= 0:
            raise ValueError("width and chunk_records are positive")
        self.width = width
        self.tmp_dir = tmp_dir
        self.chunk_records = chunk_records
        self._buf: list[bytes] = []
        self._runs: list[Path] = []
        self.added = 0

    def add(self, record: bytes) -> None:
        if len(record) != self.width:
            raise ValueError("record width mismatch")
        self._buf.append(record)
        self.added += 1
        if len(self._buf) >= self.chunk_records:
            self._spill()

    def _write_run(self, records: Iterable[bytes]) -> Path:
        path = self.tmp_dir / f"run-{self.width}-{secrets.token_hex(6)}.bin"
        with open(path, "xb") as f:
            batch: list[bytes] = []
            for record in records:
                batch.append(record)
                if len(batch) >= READ_RECORDS:
                    f.write(b"".join(batch))
                    batch.clear()
            f.write(b"".join(batch))
        return path

    def _spill(self) -> None:
        self._buf.sort()
        self._runs.append(self._write_run(unique(self._buf)))
        self._buf = []

    def _merge(self, runs: list[Path]) -> Iterator[bytes]:
        return unique(heapq.merge(*(_read_run(r, self.width) for r in runs)))

    def finish(self) -> Iterator[bytes]:
        """Every distinct record, ascending. The run files are removed afterwards."""
        if not self._runs:
            self._buf.sort()
            buf, self._buf = self._buf, []
            yield from unique(buf)
            return
        if self._buf:
            self._spill()
        try:
            while len(self._runs) > MAX_FANIN:
                group, self._runs = self._runs[:MAX_FANIN], self._runs[MAX_FANIN:]
                self._runs.append(self._write_run(self._merge(group)))
                for run in group:
                    os.unlink(run)
            yield from self._merge(self._runs)
        finally:
            self.discard()

    def discard(self) -> None:
        self._buf = []
        for run in self._runs:
            with contextlib.suppress(OSError):
                os.unlink(run)
        self._runs = []
