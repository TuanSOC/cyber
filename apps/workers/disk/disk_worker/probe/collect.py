"""`collect --fs i` and `extract` (probe side): copy listed files out of the image.

`collect` copies root's plan (natural keys chosen from the walk listing, already filtered by
`never_collect()` over every name of each inode, RT7) into the mirrored tree
`out/artifacts/p<i>/<sanitized relative path>` that Plaso reads:
- allocated regular files and named streams only (no symlinks, devices, directories);
  `meta_seq` re-checked on NTFS (a reallocated entry is skipped);
- names from `names.sanitize_relative` (canonical case table, reduced alphabet + hash suffix,
  <= 255 bytes, empty / all-dot refused; RT31), a `_cN` suffix on a collision;
- directories created with `mkdir` relative to the parent's descriptor and re-opened with
  `O_DIRECTORY | O_NOFOLLOW`; files with `O_CREAT | O_EXCL | O_NOFOLLOW`, so nothing ever
  resolves outside the out dir;
- per-file and total byte caps (RLIMIT_FSIZE is the per-file backstop);
- the manifest `collected.jsonl`: target path → natural key, original path, artifact, size.

`extract` writes one allocated regular file or named stream (by natural key, `meta_seq`
re-checked: a reallocated entry is `disk_export_not_allowed`) whose size is at most the
expected size (<= 64 MiB) to `out/export/<n>`, with its sha256 computed here.
"""

import errno
import hashlib
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from disk_worker.probe import names
from disk_worker.probe.rows import RowWriter
from disk_worker.probe.tsk import RawEntry, Stream
from disk_worker.probe.walk import WalkFs

CHUNK = 1024 * 1024
MAX_COLLISIONS = 32
# Linux flags (the probe runs only there); `getattr` lets the module import on other hosts
# for the pure unit tests, where these paths are never exercised.
DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
MAX_EXPORT_BYTES = 64 * 1024**2


class Refused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _same_seq(fs: WalkFs, e: RawEntry, seq: int | None) -> bool:
    if fs.family != "ntfs" or seq is None or e.meta is None or e.meta.seq is None:
        return True
    return e.meta.seq == seq


def resolve(
    fs: WalkFs, meta_addr: int, meta_seq: int | None, stream: str | None, max_streams: int = 16
) -> tuple[RawEntry, Stream | None, int]:
    """The entry (and stream) of a natural key, refusing anything but an allocated regular
    file with the listed sequence."""
    e = fs.open_meta(meta_addr)
    meta = e.meta
    if meta is None or not meta.allocated:
        raise Refused("not_allocated")
    if meta.type != "reg":
        raise Refused("not_regular")
    if not _same_seq(fs, e, meta_seq):
        raise Refused("reallocated")
    if stream is None:
        return e, None, max(0, meta.size or 0)
    for s in fs.streams(e, max_streams):
        shown, _ = names.display_name(s.name)
        if names.cut_utf8(shown, 255)[0] == stream:
            return e, s, s.size
    raise Refused("no_stream")


def _open_dir(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    return os.open(name, DIR_FLAGS, dir_fd=parent_fd)


def _subdir(parent_fd: int, name: str) -> tuple[int, str]:
    for n in range(1, MAX_COLLISIONS + 1):
        candidate = name if n == 1 else names.with_collision_suffix(name, n)
        try:
            return _open_dir(parent_fd, candidate), candidate
        except OSError as exc:
            if exc.errno not in (errno.ENOTDIR, errno.ELOOP, errno.EEXIST):
                raise
    raise Refused("collision")


def _create(dir_fd: int, name: str) -> tuple[int, str]:
    for n in range(1, MAX_COLLISIONS + 1):
        candidate = name if n == 1 else names.with_collision_suffix(name, n)
        try:
            return os.open(candidate, FILE_FLAGS, 0o600, dir_fd=dir_fd), candidate
        except FileExistsError:
            continue
    raise Refused("collision")


def copy_into(fs: WalkFs, e: RawEntry, stream: Stream | None, size: int, fd: int) -> str:
    """Copy `size` bytes; returns the sha256 (a short read is an error)."""
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = fs.read(e, offset, min(CHUNK, size - offset), stream)
        if not chunk:
            raise OSError(errno.EIO, "short read")
        os.write(fd, chunk)
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


@dataclass
class CollectStats:
    files: int = 0
    bytes: int = 0
    refused: int = 0
    errors: int = 0
    truncated: bool = False
    reason: str | None = None

    def counts(self) -> dict[str, int]:
        return {
            "files": self.files,
            "bytes": self.bytes,
            "refused": self.refused,
            "errors": self.errors,
        }


def collect(
    fs: WalkFs,
    out: Path,
    args: dict[str, Any],
    manifest: RowWriter,
    clock: Callable[[], float] = time.monotonic,
) -> CollectStats:
    stats = CollectStats()
    deadline = clock() + float(args["deadline_s"])
    partition = int(args["partition_index"])
    case_insensitive = bool(args["case_insensitive"])
    max_total = int(args["max_total_bytes"])
    max_files = int(args["max_files"])
    out_fd = os.open(out, DIR_FLAGS)
    try:
        artifacts_fd, _ = _subdir(out_fd, "artifacts")
        try:
            base_fd, base = _subdir(artifacts_fd, f"p{partition}")
        finally:
            os.close(artifacts_fd)
    finally:
        os.close(out_fd)
    try:
        for item in args["items"]:
            if clock() > deadline:
                stats.truncated, stats.reason = True, "deadline"
                break
            if stats.files >= max_files:
                stats.truncated, stats.reason = True, "max_files"
                break
            try:
                row = _collect_one(fs, base_fd, item, case_insensitive, max_total - stats.bytes)
            except Refused as exc:
                stats.refused += 1
                manifest.write({"n": item["n"], "status": "refused", "reason": exc.reason})
                continue
            except (OSError, RuntimeError, ValueError):
                stats.errors += 1
                manifest.write({"n": item["n"], "status": "error", "reason": None})
                continue
            stats.files += 1
            stats.bytes += int(row["size"])
            if not manifest.write(row):
                stats.truncated, stats.reason = True, "manifest_cap"
                break
    finally:
        os.close(base_fd)
    if base != f"p{partition}":
        stats.truncated, stats.reason = True, "base_collision"
    return stats


def _collect_one(
    fs: WalkFs, base_fd: int, item: dict[str, Any], case_insensitive: bool, left: int
) -> dict[str, Any]:
    try:
        parts = names.sanitize_relative(str(item["path"]), case_insensitive)
    except names.UnsafeName as exc:
        raise Refused("unsafe_name") from exc
    if item.get("stream"):
        # A named stream is mirrored beside its file: `<name>_<stream>` keeps it distinct.
        parts[-1] = names.sanitize_component(f"{parts[-1]}:{item['stream']}", False)
    e, stream, size = resolve(fs, int(item["meta_addr"]), item.get("meta_seq"), item.get("stream"))
    if size > int(item["max_bytes"]):
        raise Refused("too_large")
    if size > left:
        raise Refused("budget")
    dir_fd = os.dup(base_fd)
    made: list[str] = []
    try:
        for part in parts[:-1]:
            next_fd, actual = _subdir(dir_fd, part)
            os.close(dir_fd)
            dir_fd = next_fd
            made.append(actual)
        fd, leaf = _create(dir_fd, parts[-1])
        try:
            copy_into(fs, e, stream, size, fd)
        except BaseException:
            os.close(fd)
            os.unlink(leaf, dir_fd=dir_fd)
            raise
        os.close(fd)
    finally:
        os.close(dir_fd)
    return {
        "n": item["n"],
        "status": "ok",
        "target": "/".join([*made, leaf]),
        "meta_addr": int(item["meta_addr"]),
        "meta_seq": item.get("meta_seq"),
        "stream": item.get("stream"),
        "path": item["path"],
        "artifact": item["artifact"],
        "size": size,
    }


def extract(fs: WalkFs, out: Path, args: dict[str, Any]) -> dict[str, Any]:
    """One file to `out/export/<n>`; returns the status facts (`size`, `sha256`)."""
    expected = int(args["expected_size"])
    if not 0 < expected <= MAX_EXPORT_BYTES:
        raise Refused("expected_size")
    try:
        e, stream, size = resolve(
            fs, int(args["meta_addr"]), args.get("meta_seq"), args.get("stream")
        )
    except Refused as exc:
        raise Refused("disk_export_not_allowed") from exc
    if size > expected:
        raise Refused("disk_export_not_allowed")
    out_fd = os.open(out, DIR_FLAGS)
    try:
        export_fd, _ = _subdir(out_fd, "export")
    finally:
        os.close(out_fd)
    try:
        fd = os.open(str(int(args["n"])), FILE_FLAGS, 0o600, dir_fd=export_fd)
        try:
            sha256 = copy_into(fs, e, stream, size, fd)
        finally:
            os.close(fd)
    finally:
        os.close(export_fd)
    return {"size": size, "sha256": sha256}


__all__ = ["CollectStats", "Refused", "collect", "copy_into", "extract", "resolve"]
