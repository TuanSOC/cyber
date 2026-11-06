"""`walk --fs i`: every name of one file system as bounded JSONL rows (probe side).

- **Iterative** (no recursion): a stack of directories and a visited set of directory
  meta_addrs (the root included); TSK's own loop guard lives only in `tsk_fs_dir_walk`, which
  is not used. Depth <= 64, <= `max_dir_entries` per directory, the files cap (rows) and the
  byte cap.
  Only allocated directories (and TSK's `$OrphanFiles`) are entered; symlinks are never
  followed (their targets are never read).
- **Every name** is its own row (`parent_addr` = the walked directory's meta_addr), so an
  inode with several names (NTFS or ext hard links) appears once per name; root groups them
  by (partition, meta_addr) for the never-collected check (RT7). `hard_linked` is set here
  for an ext regular file with nlink > 1 (NTFS link counts include the 8.3 name, so root sets
  it from the grouping instead).
- Deleted names (`TSK_FS_NAME_FLAG_UNALLOC`), orphans (under `$OrphanFiles`) and
  reallocated entries (a deleted name whose metadata is allocated again, or a sequence that
  differs) are flagged; their content is never read.
- NTFS named `$DATA` streams are rows of their own (<= `max_streams` per file;
  `Zone.Identifier` included).
- Per allocated regular file / stream: the magic class of the first 512 bytes and, within the
  hashing rule, md5 + sha1 + sha256 in one pass. Executables and scripts are hashed during the
  walk; every other eligible file is hashed afterwards in walk order while the byte budget
  lasts (`hashes.jsonl`, keyed by row number `n`). `hash_status`: `hashed`, `pending` (root
  resolves it from `hashes.jsonl`, else `budget`), `too_large`, `budget`, `not_allocated`,
  `not_regular`, `error`.
- A soft deadline (`deadline_s` from root, below the stage timeout) stops the walk with
  `truncated` (reason `deadline`) so the status is always written.
"""

import hashlib
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol

from disk_worker.probe import names
from disk_worker.probe.magic import HEAD_BYTES, magic_class
from disk_worker.probe.rows import RowWriter
from disk_worker.probe.tsk import RawEntry, Stream

HASH_CHUNK = 1024 * 1024
MAX_DEPTH = 64
EXECUTABLE_CLASSES = frozenset({"pe", "elf", "script"})
DEADLINE_CHECK_EVERY = 256


class WalkFs(Protocol):
    """What the walker needs from a file system (`tsk.Fs`; fakes in the unit tests)."""

    @property
    def family(self) -> str: ...

    @property
    def root_addr(self) -> int: ...

    @property
    def orphan_addr(self) -> int: ...

    def list_dir(self, addr: int) -> Iterator[RawEntry]: ...

    def is_virtual(self, e: RawEntry) -> bool: ...

    def streams(self, e: RawEntry, limit: int) -> list[Stream]: ...

    def open_meta(self, addr: int) -> RawEntry: ...

    @staticmethod
    def read(e: RawEntry, offset: int, length: int, stream: Stream | None = None) -> bytes: ...


@dataclass
class WalkArgs:
    max_rows: int
    max_bytes: int
    max_dir_entries: int = 200_000
    max_streams: int = 16
    hash_max_file_bytes: int = 0
    hash_budget_bytes: int = 0
    deadline_s: float = 3600.0


@dataclass(slots=True)
class Pending:
    n: int
    meta_addr: int
    meta_seq: int | None
    stream: Stream | None
    size: int


@dataclass
class WalkStats:
    dirs: int = 0
    entries: int = 0
    deleted: int = 0
    orphans: int = 0
    streams: int = 0
    dir_errors: int = 0
    read_errors: int = 0
    loops: int = 0
    depth_capped: int = 0
    dir_capped: int = 0
    hashed_bytes: int = 0
    hashed_files: int = 0
    truncated: bool = False
    reason: str | None = None
    pending: list[Pending] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        keys = (
            "dirs",
            "entries",
            "deleted",
            "orphans",
            "streams",
            "dir_errors",
            "read_errors",
            "loops",
            "depth_capped",
            "dir_capped",
            "hashed_bytes",
            "hashed_files",
        )
        return {k: int(getattr(self, k)) for k in keys}


def _hashes(
    fs: WalkFs, e: RawEntry, stream: Stream | None, size: int
) -> tuple[str, str, str] | None:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()  # noqa: S324
    offset = 0
    while offset < size:
        chunk = fs.read(e, offset, min(HASH_CHUNK, size - offset), stream)
        if not chunk:
            return None  # a short read: the content is not what the metadata says
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)
        offset += len(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def _times(meta_times: dict[str, tuple[int, int] | None]) -> dict[str, list[int] | None]:
    return {k: (list(v) if v is not None else None) for k, v in meta_times.items()}


class Walker:
    def __init__(
        self,
        fs: WalkFs,
        args: WalkArgs,
        files: RowWriter,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.fs = fs
        self.args = args
        self.files = files
        self.clock = clock
        self.deadline = clock() + args.deadline_s
        self.stats = WalkStats()
        self.budget = args.hash_budget_bytes
        self.n = 0

    # --- the walk ------------------------------------------------------------------------

    def _expired(self) -> bool:
        if self.stats.entries % DEADLINE_CHECK_EVERY == 0 and self.clock() > self.deadline:
            self.stats.truncated, self.stats.reason = True, "deadline"
        return self.stats.truncated

    def run(self) -> WalkStats:
        stack: list[tuple[int, str, int, bool]] = [(self.fs.root_addr, "", 0, False)]
        # Keyed on meta_addr alone (stricter than (addr, seq): within one snapshot an address
        # is one inode, and stale names are never entered anyway).
        visited: set[int] = {self.fs.root_addr}
        while stack and not self.stats.truncated:
            addr, path, depth, orphan = stack.pop()
            self.stats.dirs += 1
            children: list[tuple[int, str, int, bool]] = []
            try:
                self._list(addr, path, depth, orphan, visited, children)
            except MemoryError:
                raise
            except (OSError, RuntimeError, ValueError):
                self.stats.dir_errors += 1
            # Reverse so the walk visits subdirectories in listing order.
            stack.extend(reversed(children))
        if self.files.truncated:
            self.stats.truncated = True
            self.stats.reason = self.stats.reason or "files_cap"
        return self.stats

    def _list(
        self,
        addr: int,
        path: str,
        depth: int,
        orphan_dir: bool,
        visited: set[int],
        children: list[tuple[int, str, int, bool]],
    ) -> None:
        in_orphans = orphan_dir or addr == self.fs.orphan_addr
        seen = 0
        for e in self.fs.list_dir(addr):
            if e.name in (b".", b"..") or self.fs.is_virtual(e):
                continue
            seen += 1
            if seen > self.args.max_dir_entries:
                self.stats.dir_capped += 1
                return
            self.stats.entries += 1
            if self._expired():
                return
            name, lossy = names.display_name(e.name)
            full = names.join_path(path, name)
            if (
                e.meta_addr == self.fs.orphan_addr
                and addr == self.fs.root_addr
                and e.name == b"$OrphanFiles"
            ):
                # TSK's virtual `$OrphanFiles`: walked, never listed itself.
                children.append((e.meta_addr, full, depth + 1, True))
                continue
            if not self._emit(e, name, lossy, full, addr, in_orphans):
                return
            if self._enter(e, depth, visited):
                children.append((e.meta_addr, full, depth + 1, in_orphans))

    def _enter(self, e: RawEntry, depth: int, visited: set[int]) -> bool:
        meta = e.meta
        if meta is None or meta.type != "dir" or e.name_type not in ("dir", "other"):
            return False
        if not (e.name_allocated and meta.allocated):
            return False
        key = meta.addr
        if key in visited:
            self.stats.loops += 1
            return False
        if depth + 1 > MAX_DEPTH:
            self.stats.depth_capped += 1
            return False
        visited.add(key)
        return True

    # --- one name ------------------------------------------------------------------------

    def _flags(self, e: RawEntry, in_orphans: bool) -> dict[str, bool]:
        meta = e.meta
        meta_alloc = meta is not None and meta.allocated
        seq_differs = (
            meta is not None
            and e.meta_seq is not None
            and meta.seq is not None
            and self.fs.family == "ntfs"
            and e.meta_seq != meta.seq
        )
        allocated = e.name_allocated and meta_alloc and not seq_differs and not in_orphans
        reallocated = (not e.name_allocated and meta_alloc) or seq_differs
        hard_linked = (
            self.fs.family == "ext" and meta is not None and meta.type == "reg" and meta.nlink > 1
        )
        return {
            "allocated": allocated,
            "deleted": not allocated,
            "orphan": in_orphans,
            "reallocated": reallocated,
            "hard_linked": hard_linked,
        }

    def _emit(
        self, e: RawEntry, name: str, lossy: bool, full: str, parent: int, in_orphans: bool
    ) -> bool:
        meta = e.meta
        flags = self._flags(e, in_orphans)
        ftype = meta.type if meta is not None else e.name_type
        if ftype not in ("reg", "dir", "lnk"):
            ftype = "other"
        path, cut = names.bounded_path(full)
        ext = name.rsplit(".", 1)[1][:32] if "." in name.strip(".") else None
        row: dict[str, Any] = {
            "meta_addr": e.meta_addr,
            "meta_seq": e.meta_seq,
            "stream": None,
            "path": path,
            "path_truncated": cut,
            "parent_addr": parent,
            "name": name,
            "name_lossy": lossy,
            "ext": ext.casefold() if ext else None,
            "type": ftype,
            **flags,
            "size": meta.size if meta is not None else None,
            "mode": meta.mode if meta is not None else None,
            "uid": meta.uid if meta is not None else None,
            "gid": meta.gid if meta is not None else None,
            "times": _times(meta.times) if meta is not None else {},
            "time_basis": "local_unknown" if self.fs.family == "fat" else "utc",
            "magic": None,
        }
        if flags["deleted"]:
            self.stats.deleted += 1
        if in_orphans:
            self.stats.orphans += 1
        regular = ftype == "reg" and meta is not None
        self._content(e, row, None, meta.size if regular and meta else None, flags, regular)
        if not self._write(row, e, None):
            return False
        if regular and flags["allocated"] and self.fs.family == "ntfs":
            try:
                streams = self.fs.streams(e, self.args.max_streams)
            except (OSError, RuntimeError, ValueError):
                self.stats.read_errors += 1
                streams = []
            for stream in streams:
                self.stats.streams += 1
                sname, _ = names.display_name(stream.name)
                srow = {**row, "stream": names.cut_utf8(sname, 255)[0] or "_", "size": stream.size}
                self._content(e, srow, stream, stream.size, flags, True)
                if not self._write(srow, e, stream):
                    return False
        return True

    def _content(
        self,
        e: RawEntry,
        row: dict[str, Any],
        stream: Stream | None,
        size: int | None,
        flags: dict[str, bool],
        regular: bool,
    ) -> None:
        row.update(hash_status=None, md5=None, sha1=None, sha256=None)
        if not regular:
            row["hash_status"] = "not_regular"
            return
        if not flags["allocated"]:
            row["hash_status"] = "not_allocated"
            return
        size = max(0, size or 0)
        try:
            head = self.fs.read(e, 0, min(HEAD_BYTES, size), stream) if size else b""
        except (OSError, RuntimeError, ValueError):
            self.stats.read_errors += 1
            row["hash_status"] = "error"
            return
        row["magic"] = magic_class(head, size)
        if size > self.args.hash_max_file_bytes:
            row["hash_status"] = "too_large"
        elif row["magic"] in EXECUTABLE_CLASSES or size == 0:
            self._hash_now(e, row, stream, size)  # executables first; empty files cost nothing
        else:
            row["hash_status"] = "pending"

    def _hash_now(self, e: RawEntry, row: dict[str, Any], stream: Stream | None, size: int) -> None:
        if size > self.budget:
            row["hash_status"] = "budget"
            return
        try:
            digests = _hashes(self.fs, e, stream, size)
        except (OSError, RuntimeError, ValueError):
            digests = None
        self.budget -= size
        if digests is None:
            self.stats.read_errors += 1
            row["hash_status"] = "error"
            return
        self.stats.hashed_bytes += size
        self.stats.hashed_files += 1
        row.update(hash_status="hashed", md5=digests[0], sha1=digests[1], sha256=digests[2])

    def _write(self, row: dict[str, Any], e: RawEntry, stream: Stream | None) -> bool:
        row["n"] = self.n
        if not self.files.write(row):
            self.stats.truncated, self.stats.reason = True, "files_cap"
            return False
        if row["hash_status"] == "pending":
            self.stats.pending.append(
                Pending(self.n, e.meta_addr, e.meta_seq, stream, int(row["size"] or 0))
            )
        self.n += 1
        return True

    # --- the deferred hashing ------------------------------------------------------------

    def hash_pending(self, out: RowWriter) -> None:
        """Hash the queued files in walk order while the budget and the deadline last."""
        for item in self.stats.pending:
            if self.clock() > self.deadline:
                self.stats.truncated, self.stats.reason = True, self.stats.reason or "deadline"
                return
            if item.size > self.budget:
                out.write({"n": item.n, "hash_status": "budget"})
                continue
            try:
                e = self.fs.open_meta(item.meta_addr)
                if (
                    e.meta is None
                    or not e.meta.allocated
                    or (
                        item.meta_seq is not None
                        and e.meta.seq is not None
                        and self.fs.family == "ntfs"
                        and e.meta.seq != item.meta_seq
                    )
                ):
                    raise ValueError("the entry changed")
                digests = _hashes(self.fs, e, item.stream, item.size)
            except (OSError, RuntimeError, ValueError):
                digests = None
            self.budget -= item.size
            if digests is None:
                self.stats.read_errors += 1
                out.write({"n": item.n, "hash_status": "error"})
                continue
            self.stats.hashed_bytes += item.size
            self.stats.hashed_files += 1
            out.write(
                {
                    "n": item.n,
                    "hash_status": "hashed",
                    "md5": digests[0],
                    "sha1": digests[1],
                    "sha256": digests[2],
                }
            )
        self.stats.pending = []


__all__ = ["MAX_DEPTH", "Pending", "WalkArgs", "WalkFs", "WalkStats", "Walker"]
