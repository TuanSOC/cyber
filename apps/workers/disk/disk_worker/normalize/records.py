"""Probe rows → `disk.v1` records (root side, pure).

- `partition_record`: a validated `PartitionRow` → `DiskPartitionRecord`; a failed walk makes
  the partition `error` with the walk's code (e.g. `walk_memory`, RT30). The probe's refusal
  reason (`bitlocker`, `overlap`, ...) is kept by root for the stage report only.
- `file_record`: a validated `FileRow` (+ its deferred `HashRow`) → `DiskFileRecord`; the
  image-controlled integers are clamped to the contract's ranges (a hostile mode / uid / time
  costs that field, never the row); times outside 1601..2200 become null.
- `NameIndex`: every name of each inode, per partition (RT7): the never-collected check runs
  over **all** of them (a named stream inherits its file's names), and an inode with more
  than one allocated name gets `hard_linked` on every row.
"""

from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from typing import cast

from cyberlab_jobs.disk import (
    FILE_FLAG_BITS,
    DiskFileRecord,
    DiskPartitionRecord,
    HashStatus,
    never_collect,
)

from disk_worker.normalize.models import TIME_KEYS, FileRow, HashRow, PartitionRow

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
EARLIEST = datetime(1601, 1, 1, tzinfo=UTC)
LATEST = datetime(2200, 1, 1, tzinfo=UTC)
U32 = 2**32 - 1
MODE_MAX = 0o177777
FileKey = tuple[int, int]  # (partition_index, meta_addr)


def _text(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    raw = value.encode("utf-8")
    return raw[:limit].decode("utf-8", "ignore")[:limit] or None


def partition_record(row: PartitionRow, walk_error: str | None = None) -> DiskPartitionRecord:
    status = row.fs_status
    fs_type = row.fs_type
    if walk_error is not None:
        status = "error"
    if status != "ok" and status != "truncated" and status != "error":
        fs_type = None
    if status == "ok" and fs_type is None:
        status = "undetermined"
    return DiskPartitionRecord(
        index=row.index,
        start_sector=row.start_sector,
        length_sectors=row.length_sectors,
        description=_text(row.description, 128),
        fs_type=fs_type,
        fs_status=status,
        block_size=row.block_size,
        os=row.os if status == "ok" else "none",
        os_name=_text(row.os_name, 128) if status == "ok" else None,
        counts={k: v for k, v in row.counts.items() if v < 2**63},
        error_code=walk_error,
    )


def to_time(pair: list[int] | None) -> datetime | None:
    if pair is None:
        return None
    seconds, nanos = pair
    if not 0 <= nanos < 10**9:
        nanos = 0
    try:
        value = EPOCH + timedelta(seconds=seconds, microseconds=nanos // 1000)
    except OverflowError:
        return None
    return value if EARLIEST <= value < LATEST else None


def _bounded(value: int | None, high: int) -> int | None:
    return value if value is not None and 0 <= value <= high else None


def _flags(row: FileRow, hard_linked: bool) -> int:
    allocated = row.allocated and not row.deleted
    flags = 0
    flags |= FILE_FLAG_BITS["allocated"] if allocated else FILE_FLAG_BITS["deleted"]
    if row.orphan:
        flags |= FILE_FLAG_BITS["orphan"]
    if row.reallocated:
        flags |= FILE_FLAG_BITS["reallocated"]
    if row.name_lossy:
        flags |= FILE_FLAG_BITS["name_lossy"]
    if row.path_truncated:
        flags |= FILE_FLAG_BITS["path_truncated"]
    if hard_linked or row.hard_linked:
        flags |= FILE_FLAG_BITS["hard_linked"]
    return flags


def file_record(
    row: FileRow, partition_index: int, deferred: HashRow | None, hard_linked: bool = False
) -> DiskFileRecord:
    """Raises `ValueError` (pydantic's `ValidationError`) for a row the contract refuses."""
    flags = _flags(row, hard_linked)
    allocated = bool(flags & FILE_FLAG_BITS["allocated"])
    status: str | None = row.hash_status
    md5, sha1, sha256 = row.md5, row.sha1, row.sha256
    if status == "pending":
        if deferred is not None and deferred.hash_status == "hashed":
            status, md5, sha1, sha256 = "hashed", deferred.md5, deferred.sha1, deferred.sha256
        else:
            status = deferred.hash_status if deferred is not None else "budget"
            md5 = sha1 = sha256 = None
    if status == "hashed" and (not allocated or None in (md5, sha1, sha256)):
        status, md5, sha1, sha256 = "error", None, None, None
    if status != "hashed":
        md5 = sha1 = sha256 = None
    times = {k: to_time(row.times.get(k)) for k in TIME_KEYS}  # type: ignore[call-overload]
    return DiskFileRecord(
        partition_index=partition_index,
        meta_addr=row.meta_addr,
        meta_seq=_bounded(row.meta_seq, U32),
        stream=row.stream,
        path=row.path,
        parent_addr=row.parent_addr,
        name=row.name,
        ext=_text(row.ext, 32),
        type=row.type,
        flags=flags,
        size=_bounded(row.size, 2**63 - 1),
        mode=_bounded(row.mode, MODE_MAX),
        uid=_bounded(row.uid, U32),
        gid=_bounded(row.gid, U32),
        mtime=times["mtime"],
        atime=times["atime"],
        ctime=times["ctime"],
        crtime=times["crtime"],
        time_basis=row.time_basis,
        magic=row.magic if allocated else None,
        hash_status=cast(HashStatus | None, status),
        md5=md5,
        sha1=sha1,
        sha256=sha256,
    )


class NameIndex:
    """Every name of each inode, per partition (RT7), and the allocated-name count."""

    def __init__(self) -> None:
        self._paths: dict[FileKey, set[str]] = defaultdict(set)
        self._names: dict[FileKey, set[tuple[int | None, str]]] = defaultdict(set)
        self._unsafe: set[FileKey] = set()

    def add(self, record: DiskFileRecord) -> None:
        key = (record.partition_index, record.meta_addr)
        self._paths[key].add(record.path)
        if record.has_flag("path_truncated"):
            self._unsafe.add(key)  # the cut part could hide a refused name: refuse
        if record.stream is None and record.has_flag("allocated"):
            self._names[key].add((record.parent_addr, record.name))

    def names_of(self, partition_index: int, meta_addr: int) -> set[str]:
        return set(self._paths.get((partition_index, meta_addr), ()))

    def hard_linked(self, partition_index: int, meta_addr: int) -> bool:
        return len(self._names.get((partition_index, meta_addr), ())) > 1

    def refused(self, partition_index: int, meta_addr: int, case_insensitive: bool) -> bool:
        key = (partition_index, meta_addr)
        if key in self._unsafe:
            return True
        return never_collect(self._paths.get(key, ()), case_insensitive)


def with_hard_links(records: Sequence[DiskFileRecord], index: NameIndex) -> list[DiskFileRecord]:
    bit = FILE_FLAG_BITS["hard_linked"]
    out = []
    for r in records:
        if not r.flags & bit and index.hard_linked(r.partition_index, r.meta_addr):
            r = r.model_copy(update={"flags": r.flags | bit})
        out.append(r)
    return out


def build_index(records: Iterable[DiskFileRecord]) -> NameIndex:
    index = NameIndex()
    for r in records:
        index.add(r)
    return index


__all__ = [
    "NameIndex",
    "build_index",
    "file_record",
    "partition_record",
    "to_time",
    "with_hard_links",
]
