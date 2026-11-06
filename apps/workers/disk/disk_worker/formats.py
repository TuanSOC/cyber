"""Root's image-format check (M9 phase 2): magic bytes only, before any probe runs.

Root never parses image bytes beyond this: the first 4 KiB of segment 0 and the last 512
bytes of the last segment (a VHD footer). Accepted: EWF (`EVF\\x09\\x0d\\x0a\\xff\\x00`, EWF1
only) and raw (anything else not refused). Refused (`unsupported_disk_format`): compressed
and archive containers, VMDK, VHD / VHDX, QCOW, AFF, EWF2 and LEF / L01 (libewf's L01 parser
has CVE-2026-111159).

The segment file names the probes open are fixed here, by the job's order: `image.raw`, or
`image.001`, `image.002` ... for a split raw set, or `image.E01` ... `image.E64` for EWF
(`pyewf.glob` then finds exactly the set root downloaded).
"""

from collections.abc import Sequence
from pathlib import Path

from cyberlab_jobs.disk import ImageFormat

HEAD_BYTES = 4096
FOOTER_BYTES = 512
EWF1 = b"EVF\x09\x0d\x0a\xff\x00"

# (offset, magic, name): checked against segment 0.
_REFUSED_HEAD: tuple[tuple[int, bytes, str], ...] = (
    (0, b"\x1f\x8b", "gzip"),
    (0, b"BZh", "bzip2"),
    (0, b"\xfd7zXZ\x00", "xz"),
    (0, b"\x28\xb5\x2f\xfd", "zstd"),
    (0, b"PK\x03\x04", "zip"),
    (0, b"PK\x05\x06", "zip"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z"),
    (0, b"Rar!\x1a\x07", "rar"),
    (0, b"MSCF", "cab"),
    (0, b"\x04\x22\x4d\x18", "lz4"),
    (0, b"KDMV", "vmdk"),
    (0, b"COWD", "vmdk"),
    (0, b"# Disk DescriptorFile", "vmdk"),
    (0, b"vhdxfile", "vhdx"),
    (0, b"conectix", "vhd"),
    (0, b"QFI\xfb", "qcow"),
    (0, b"AFF10", "aff"),
    (0, b"EVF2\r\n\x81\x00", "ewf2"),
    (0, b"LEF2\r\n\x81\x00", "lef2"),
    (0, b"LVF\x09\x0d\x0a\xff\x00", "lef"),
    (0, b"EVF2", "ewf2"),
)


class UnsupportedFormat(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def detect(head: bytes, last_footer: bytes, segments: int) -> ImageFormat:
    """The accepted format of a segment set from root's two bounded reads."""
    for offset, magic, name in _REFUSED_HEAD:
        if head[offset : offset + len(magic)] == magic:
            raise UnsupportedFormat(name)
    if last_footer[:8] == b"conectix":
        raise UnsupportedFormat("vhd")
    if head.startswith(EWF1):
        return ImageFormat.EWF
    return ImageFormat.RAW if segments == 1 else ImageFormat.SPLIT_RAW


def read_magic(segments: Sequence[Path]) -> tuple[bytes, bytes]:
    """Segment 0's head and the last segment's final 512 bytes (root-owned files)."""
    with open(segments[0], "rb") as f:
        head = f.read(HEAD_BYTES)
    with open(segments[-1], "rb") as f:
        size = f.seek(0, 2)
        f.seek(max(0, size - FOOTER_BYTES))
        footer = f.read(FOOTER_BYTES)
    return head, footer


def segment_name(fmt: ImageFormat, ordinal: int, count: int) -> str:
    if fmt == ImageFormat.EWF:
        if not 0 <= ordinal < 99:
            raise ValueError("EWF segment ordinals are 0..98 here (E01..E99)")
        return f"image.E{ordinal + 1:02d}"
    if fmt == ImageFormat.RAW and count == 1:
        return "image.raw"
    return f"image.{ordinal + 1:03d}"


__all__ = ["EWF1", "UnsupportedFormat", "detect", "read_magic", "segment_name"]
