"""EWF (EnCase 6, `E01`) sets through `ewfacquirestream`, and our own section patcher.

Acquisition (tool, dev / test target only): the raw image is streamed to `ewfacquirestream`
with fixed case data; libewf stores the MD5 (and SHA1) of the media in the `hash` / `digest`
sections. The acquiry and system dates in the header sections are the tool's clock: EWF sets
are the plan's determinism exception (their media hash and content are deterministic).

The patcher (pure Python) walks the EWF1 section chain (13-byte file header, then 76-byte
section descriptors: type[16], next u64, size u64, padding[40], Adler-32 of the first 72) and
rewrites a field with its Adler-32 fixed, for:
- `ewf_bad_hash`: a changed stored MD5 (`hash` and `digest` sections);
- hostile mode: a claimed media size above `DISK_MAX_MEDIA_BYTES` (`volume` / `disk` / `data`
  sections) and a lying segment number in a segment file header.
"""

import struct
import zlib
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from samples.diskgen import tools

SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
FILE_HEADER = 13
DESCRIPTOR = 76
VOLUME_TYPES = (b"volume", b"disk", b"data")
VOLUME_DATA = 1052
CASE = {"case": "CL-DISKGEN-0001", "examiner": "cyberlab-diskgen", "evidence": "EV-1"}


@dataclass(frozen=True)
class Section:
    offset: int  # of the descriptor
    type: bytes
    next: int
    size: int

    @property
    def data(self) -> int:
        return self.offset + DESCRIPTOR


def adler(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def descriptor(kind: bytes, next_offset: int, size: int) -> bytes:
    head = kind.ljust(16, b"\x00") + struct.pack("<QQ", next_offset, size) + bytes(40)
    return head + struct.pack("<I", adler(head))


def sections(segment: bytes) -> Iterator[Section]:
    if segment[:8] != SIGNATURE:
        raise ValueError("not an EWF1 segment")
    offset = FILE_HEADER
    seen: set[int] = set()
    while offset + DESCRIPTOR <= len(segment) and offset not in seen:
        seen.add(offset)
        raw = segment[offset : offset + DESCRIPTOR]
        if adler(raw[:72]) != struct.unpack_from("<I", raw, 72)[0]:
            raise ValueError(f"bad section descriptor checksum at {offset}")
        kind = raw[:16].rstrip(b"\x00")
        nxt, size = struct.unpack_from("<QQ", raw, 16)
        yield Section(offset, kind, nxt, size)
        if kind in (b"done", b"next") or nxt <= offset:
            return
        offset = nxt


def _refresh(buf: bytearray, start: int, length: int) -> None:
    """Rewrite the Adler-32 stored right after `buf[start:start+length]`."""
    struct.pack_into("<I", buf, start + length, adler(bytes(buf[start : start + length])))


def patch_md5(segment: bytes, md5: bytes) -> bytes:
    """Replace the stored MD5 in the `hash` (md5[16] unknown[16] adler) and `digest`
    (md5[16] sha1[20] padding[40] adler) sections."""
    buf = bytearray(segment)
    found = False
    for s in sections(segment):
        if s.type == b"hash":
            buf[s.data : s.data + 16] = md5
            _refresh(buf, s.data, 32)
            found = True
        elif s.type == b"digest":
            buf[s.data : s.data + 16] = md5
            _refresh(buf, s.data, 76)
            found = True
    if not found:
        raise ValueError("no hash or digest section in this segment")
    return bytes(buf)


def patch_media_sectors(segment: bytes, sectors: int) -> bytes:
    """Claim `sectors` media sectors in every volume-shaped section (number_of_sectors u64 at
    16, number_of_chunks u32 at 4; checksum at 1048)."""
    buf = bytearray(segment)
    found = False
    for s in sections(segment):
        if s.type in VOLUME_TYPES and s.size >= DESCRIPTOR + VOLUME_DATA:
            per_chunk = struct.unpack_from("<I", buf, s.data + 8)[0] or 64
            struct.pack_into("<I", buf, s.data + 4, min(0xFFFFFFFF, -(-sectors // per_chunk)))
            struct.pack_into("<Q", buf, s.data + 16, sectors)
            _refresh(buf, s.data, VOLUME_DATA - 4)
            found = True
    if not found:
        raise ValueError("no volume section in this segment")
    return bytes(buf)


def patch_segment_number(segment: bytes, number: int) -> bytes:
    if segment[:8] != SIGNATURE:
        raise ValueError("not an EWF1 segment")
    return segment[:9] + struct.pack("<H", number) + segment[11:]


def stored_md5(segment: bytes) -> bytes | None:
    for s in sections(segment):
        if s.type == b"hash":
            return segment[s.data : s.data + 16]
    return None


def acquire(
    sources: Sequence[Path], target: Path, *, segment_bytes: int | None = None
) -> list[Path]:
    """`ewfacquirestream` of the concatenated `sources` into `target`.E01... A segment size
    implies no compression (so small segments really give several files); otherwise only
    empty blocks are compressed (a small single segment)."""
    tools.require("ewfacquirestream")
    data = b"".join(p.read_bytes() for p in sources)
    level = "none" if segment_bytes is not None else "empty-block"
    argv = [
        "ewfacquirestream", "-q", "-f", "encase6", "-c", level, "-d", "sha1",
        "-b", "64", "-P", "512", "-m", "fixed", "-M", "physical",
        "-C", CASE["case"], "-e", CASE["examiner"], "-E", CASE["evidence"],
        "-D", "cyberlab synthetic image", "-N", "generated by cyberlab-diskgen",
        "-t", str(target),
    ]  # fmt: skip
    if segment_bytes is not None:
        argv += ["-S", str(segment_bytes)]
    tools.run(argv, stdin=data, timeout=600)
    return sorted(target.parent.glob(target.name + ".E[0-9][0-9]"))
