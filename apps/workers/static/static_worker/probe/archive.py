"""`archive` mode (tool uid): what will ClamAV not look at? (RT2)

ClamAV 1.4 silently trims zip members above `--max-filesize` (no limit alert), does not scan
zip64 members, extracts members from local file headers it finds anywhere in a file
(prefixed data, PE + appended zip "SFX", an embedded zip, no central directory at all), and
inflates the real deflate stream whatever size the headers declare. So this check:

- sweeps every complete local file header (`PK\\x03\\x04` + 30 bytes) with a known
  compression method in the bytes, whatever its version or name length;
- reads the central directory (`zipfile`, which accepts leading data) for declared sizes;
- inflates every stored / deflated member itself from its data offset (bounded) and measures
  the REAL output size and the compressed bytes actually consumed; a size that differs from
  what the headers declare is `unchecked`;
- treats local headers outside every central-directory member as orphans: one that yields
  any data is `unchecked`; noise that does not inflate is ignored;
- looks inside every member's real bytes the same way (nesting).

It reports declared sizes / depth / encryption and `unchecked` for anything it could not
map or measure (zip64, size mismatches, orphans, other compression methods, the inflate
budget, 7z / RAR magic at offset 0). The analyzer turns any of that into
`av_not_fully_scanned`. tar / gzip / bzip2 / xz are not handled here: ClamAV raises its
own `Heuristics.Limits.Exceeded.*` alert for them (covered by an integration test).
"""

import bisect
import hashlib
import io
import mmap
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Protocol

from static_worker.probe.common import emit

LOCAL = b"PK\x03\x04"
LOCAL_HEADER = struct.Struct("<4sHHHHHIIIHH")  # 30 bytes
ZIP64_EXTRA = 0x0001
ZIP64_MARKER = 0xFFFFFFFF
FLAG_ENCRYPTED = 0x1
FLAG_DESCRIPTOR = 0x8
STORED, DEFLATED = 0, 8
# Compression methods of the zip spec (store, shrink..implode, deflate, deflate64, bzip2,
# lzma, zstd, mp3, xz, jpeg, wavpack, ppmd, AES): anything else is a chance byte match.
METHODS = {0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 14, 18, 19, 93, 94, 95, 96, 97, 98, 99}
SEVENZ = b"7z\xbc\xaf\x27\x1c"
RAR = b"Rar!\x1a\x07"

MAX_DEPTH = 20
MAX_MEMBERS = 100_000
MAX_HEADERS = 100_000
MAX_MEMBER_BYTES = 64 * 1024**2  # = clamscan --max-filesize (engines/clamav.py; test compares)
NESTED_MAX_BYTES = 8 * 1024**2  # members up to this size are held and checked in memory
INFLATE_BUDGET = 256 * 1024**2  # total bytes this check may inflate (= clamscan max-scansize)
CHUNK = 1024 * 1024


class Buffer(Protocol):
    def find(self, sub: bytes, start: int = ..., end: int = ...) -> int: ...
    def __getitem__(self, key: slice, /) -> bytes: ...
    def __len__(self) -> int: ...


@dataclass
class Header:
    flags: int
    method: int
    csize: int
    usize: int
    data_start: int
    zip64: bool


@dataclass
class Measured:
    size: int = 0  # real (uncompressed) bytes, up to the member cap
    consumed: int = 0  # compressed bytes actually used
    complete: bool = False  # stream ended cleanly (deflate EOF / stored data present)
    data: bytes | None = None  # the real bytes when small enough to look inside
    contains_zip: bool = False  # a local header signature in bytes too large to hold


@dataclass
class ArchiveCheck:
    format: str = "none"
    members: int = 0
    declared_bytes: int = 0
    largest_member: int = 0
    depth: int = 0
    encrypted: bool = False
    unchecked: bool = False
    inflated: int = 0
    headers: int = 0
    reasons: list[str] = field(default_factory=list)  # tests / debugging only (not emitted)

    def flag(self, reason: str) -> None:
        self.unchecked = True
        if reason not in self.reasons and len(self.reasons) < 20:
            self.reasons.append(reason)

    def check_file(self, sample: Path) -> str | None:
        """Check the file; returns the sha256 of the bytes checked (None when unread)."""
        try:
            with open(sample, "rb") as f:
                head = f.read(8)
                if not head:
                    return hashlib.sha256(b"").hexdigest()
                for magic, name in ((SEVENZ, "7z"), (RAR, "rar")):
                    if head.startswith(magic):
                        self.format = name
                        self.flag("container_not_inspectable")
                f.seek(0)
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as view:
                    digest = hashlib.sha256(view).hexdigest()
                    if self.format == "none":
                        # mmap for the sweep and inflation; the file object for zipfile
                        # (Python 3.12's zipfile needs `seekable()`, mmap has it from 3.13).
                        self.check(view, f, 1)
                    return digest
        except Exception as exc:  # never lose the record: an error is "unchecked"
            self.flag(f"check_failed:{type(exc).__name__}")
            return None

    def check(self, data: Buffer, fp: IO[bytes], depth: int) -> None:
        """One blob (the file, or a member's real bytes) at nesting level `depth`."""
        headers = self._sweep(data)
        if not headers:
            return
        self.depth = max(self.depth, depth)
        if any(h.zip64 for h in headers.values()):
            self.flag("zip64")
        # local header offset -> [data start, end of the data really used): only member DATA
        # is covered; a header hidden in a member's name / extra field is still an orphan.
        covered: dict[int, tuple[int, int]] = {}
        for info in self._central_directory(fp):
            self.members += 1
            if self.members > MAX_MEMBERS:
                self.flag("members")
                return
            self.format = "zip"
            self.declared_bytes += info.file_size
            self.largest_member = max(self.largest_member, info.file_size)
            header = headers.get(info.header_offset)
            if header is None:  # the central directory points at no local header
                self.flag("dangling_entry")
                continue
            if has_zip64(info.extra):
                self.flag("zip64")
            if (info.flag_bits | header.flags) & FLAG_ENCRYPTED:
                self.encrypted = True
                covered[info.header_offset] = (
                    header.data_start,
                    header.data_start + info.compress_size,
                )
                continue
            measured = self._measure(data, header, info.compress_size)
            if measured is None:
                covered[info.header_offset] = (
                    header.data_start,
                    header.data_start + info.compress_size,
                )
                continue
            covered[info.header_offset] = (header.data_start, header.data_start + measured.consumed)
            sizes = {info.file_size}
            if not header.flags & FLAG_DESCRIPTOR:
                sizes.add(header.usize)
            if (
                not measured.complete
                or sizes != {measured.size}
                or measured.consumed != info.compress_size
            ):
                self.flag("size_mismatch")  # ClamAV inflates the real stream, not the header
            self._inside(measured, depth)
        self._orphans(data, headers, covered, depth)

    def _central_directory(self, fp: IO[bytes]) -> list[zipfile.ZipInfo]:
        try:
            with zipfile.ZipFile(fp) as archive:
                return archive.infolist()
        except Exception:  # no / broken central directory: every local header is an orphan
            return []

    def _orphans(
        self,
        data: Buffer,
        headers: dict[int, Header],
        covered: dict[int, tuple[int, int]],
        depth: int,
    ) -> None:
        """Local headers outside every central-directory member's real data."""
        merged: list[list[int]] = []  # disjoint [start, end) ranges of member data
        for start, end in sorted(covered.values()):
            if merged and start <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        starts = [start for start, _ in merged]
        for offset, header in sorted(headers.items()):
            if offset in covered:
                continue
            i = bisect.bisect_right(starts, offset) - 1
            if i >= 0 and offset < merged[i][1]:
                continue  # inside a member's data: its own nesting level handles it
            if header.flags & FLAG_ENCRYPTED:
                self.encrypted = True
                return
            measured = self._measure(data, header, header.csize)
            if measured is None or measured.size or measured.consumed:
                # Zip content outside every central-directory member: ClamAV extracts it.
                self.format = "zip"
                self.flag("orphan_local_header")
                if measured is not None:
                    self.largest_member = max(self.largest_member, measured.size)
                return

    def _sweep(self, data: Buffer) -> dict[int, Header]:
        """Every complete local file header with a known method in `data` (bounded)."""
        found: dict[int, Header] = {}
        pos = data.find(LOCAL)
        while pos != -1:
            raw = data[pos : pos + LOCAL_HEADER.size]
            if len(raw) < LOCAL_HEADER.size:
                break
            fields = LOCAL_HEADER.unpack(raw)
            flags, method, csize, usize, nlen, xlen = (
                fields[2], fields[3], fields[7], fields[8], fields[9], fields[10],
            )  # fmt: skip
            if method in METHODS:
                self.headers += 1
                if self.headers > MAX_HEADERS:
                    self.flag("headers")
                    break
                start = pos + LOCAL_HEADER.size + nlen
                extra = data[start : start + xlen]
                zip64 = has_zip64(extra) or ZIP64_MARKER in (csize, usize)
                found[pos] = Header(flags, method, csize, usize, start + xlen, zip64)
            pos = data.find(LOCAL, pos + 4)
        return found

    def _measure(self, data: Buffer, header: Header, csize: int) -> Measured | None:
        """The member's real size, from its own data (None: cannot be measured here)."""
        if header.method == DEFLATED:
            return self._inflate(data, header.data_start)
        if header.method != STORED:
            self.flag(f"method_{header.method}")  # ClamAV may decode it; we cannot measure
            return None
        if header.flags & FLAG_DESCRIPTOR and csize == 0:
            self.flag("stored_unknown_size")  # stored + data descriptor: no size to trust
            return None
        if header.csize != header.usize and not header.flags & FLAG_DESCRIPTOR:
            self.flag("size_mismatch")
        start = header.data_start
        end = min(start + csize, len(data))
        size = max(0, end - start)
        measured = Measured(size=size, consumed=size, complete=end == start + csize)
        if size <= NESTED_MAX_BYTES:
            measured.data = data[start:end]
        else:
            measured.contains_zip = data.find(LOCAL, start, end) != -1
        return measured

    def _inflate(self, data: Buffer, start: int) -> Measured:
        """Raw-deflate from `start` until the stream ends (bounded output and budget)."""
        out = Measured()
        decoder = zlib.decompressobj(-zlib.MAX_WBITS)
        held = bytearray()
        tail = b""
        pos = start
        pending = b""
        stalled = False
        try:
            while not decoder.eof:
                if not pending:
                    pending = data[pos : pos + CHUNK]
                    pos += len(pending)
                    if not pending and stalled:
                        break  # input ended before the stream did
                # With no new input this drains output zlib still holds (max_length cut).
                chunk = decoder.decompress(pending, CHUNK)
                pending = decoder.unconsumed_tail
                stalled = not chunk
                out.size += len(chunk)
                self.inflated += len(chunk)
                if len(held) <= NESTED_MAX_BYTES:
                    held += chunk[: NESTED_MAX_BYTES + 1 - len(held)]
                if LOCAL in tail + chunk[:3] or LOCAL in chunk:
                    out.contains_zip = True
                tail = (tail + chunk)[-3:]
                if out.size > MAX_MEMBER_BYTES:
                    self.flag("member_too_large")
                    break
                if self.inflated > INFLATE_BUDGET:
                    self.flag("inflate_budget")
                    break
        except zlib.error:
            pass  # a broken stream: `complete` stays False
        out.complete = decoder.eof
        # At EOF the input after the stream is in unused_data (unconsumed_tail may repeat it).
        left = len(decoder.unused_data) if decoder.eof else len(pending)
        out.consumed = pos - start - left
        if out.size <= NESTED_MAX_BYTES:
            out.data = bytes(held)
        return out

    def _inside(self, measured: Measured, depth: int) -> None:
        """Look inside a member's real bytes as ClamAV would (nested zips)."""
        if measured.data is None:
            if measured.contains_zip:
                self.flag("large_nested_zip")  # too large to hold: cannot be checked here
            return
        if LOCAL not in measured.data:
            return
        if depth >= MAX_DEPTH:
            self.flag("depth")
            return
        self.check(measured.data, io.BytesIO(measured.data), depth + 1)

    def record(self, sha256: str | None) -> dict[str, int | bool | str | None]:
        return {
            "kind": "archive",
            "sha256": sha256,
            "format": self.format,
            "members": self.members,
            "declared_bytes": self.declared_bytes,
            "largest_member": self.largest_member,
            "depth": self.depth,
            "encrypted": self.encrypted,
            "unchecked": self.unchecked,
        }


def has_zip64(extra: bytes) -> bool:
    """A zip64 extended-information field (0x0001) in a zip extra-field block."""
    pos = 0
    while pos + 4 <= len(extra):
        tag, size = struct.unpack_from("<HH", extra, pos)
        if tag == ZIP64_EXTRA:
            return True
        pos += 4 + size
    return False


def check(sample: Path) -> tuple[ArchiveCheck, str | None]:
    result = ArchiveCheck()
    digest = result.check_file(sample)
    return result, digest


def run(sample: Path) -> None:
    result, digest = check(sample)
    emit(result.record(digest))
