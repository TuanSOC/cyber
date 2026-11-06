"""`layout`: volume system, partitions, file systems and OS markers (probe side).

- Volume system: `Volume_Info(img, type, offset)` (type before offset; RT16) with
  `TSK_VS_TYPE_GPT`, then `TSK_VS_TYPE_DOS` (GPT first: a GPT disk's protective MBR would
  otherwise parse as one DOS partition of type 0xEE). Neither: one pseudo-partition at 0.
- Per allocated partition (RT15), in order:
  1. outside the media, or overlapping an earlier one: `error`, never opened;
  2. the refusal signatures (`REFUSALS`): `encrypted` / `unsupported`, never offered to a
     parser;
  3. the explicit families (`tsk.FAMILY_CONSTANTS`), the one hinted by the MBR type byte or
     the GPT type GUID first, then NTFS, FAT (incl. exFAT), ext;
  4. nothing opened: `undetermined` ("unknown or encrypted"; no entropy guess).
- OS markers on an opened file system: Windows = `Windows/System32/config/SYSTEM`; Linux =
  `etc/os-release` or `etc/debian_version`. `os_name` only from `PRETTY_NAME` in
  `etc/os-release` (or `usr/lib/os-release` when the former is a link; never followed), at
  most 4 KiB read, kept as inert escaped text.
"""

import re
import struct
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from disk_worker.probe import names
from disk_worker.probe.image import Reader, tsk_int
from disk_worker.probe.tsk import Fs

OS_RELEASE_MAX = 4096
TEXT128 = 128

# (offset within the partition, magic, fs_status, reason)
REFUSALS: tuple[tuple[int, bytes, str, str], ...] = (
    (3, b"-FVE-FS-", "encrypted", "bitlocker"),
    (0, b"LUKS\xba\xbe", "encrypted", "luks"),
    (32, b"NXSB", "unsupported", "apfs"),
    (512, b"LABELONE", "unsupported", "lvm"),
    (0, b"LABELONE", "unsupported", "lvm"),
    (1024, b"LABELONE", "unsupported", "lvm"),
    (1536, b"LABELONE", "unsupported", "lvm"),
    (1024, b"H+", "unsupported", "hfsplus"),
    (1024, b"HX", "unsupported", "hfsplus"),
    (32769, b"CD001", "unsupported", "iso9660"),
)
DEFAULT_ORDER = ("ntfs", "fat", "ext")
MBR_HINTS: dict[int, str] = {
    0x07: "ntfs",  # NTFS / exFAT: NTFS first, then FAT_DETECT (exFAT)
    0x01: "fat",
    0x04: "fat",
    0x06: "fat",
    0x0B: "fat",
    0x0C: "fat",
    0x0E: "fat",
    0xEF: "fat",
    0x83: "ext",
}
GPT_HINTS: dict[str, str] = {
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "ntfs",  # Microsoft basic data
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "fat",  # EFI system partition
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "ext",  # Linux file system
}
_MBR_DESC = re.compile(r"\(0x([0-9a-fA-F]{2})\)\s*$")
GPT_MAX_ENTRIES = 256


@dataclass
class Part:
    index: int
    start: int  # sectors
    length: int  # sectors
    description: str | None
    hint: str | None


def family_order(hint: str | None) -> tuple[str, ...]:
    if hint not in DEFAULT_ORDER:
        return DEFAULT_ORDER
    return (hint, *(f for f in DEFAULT_ORDER if f != hint))


def refusal(reader: Reader, offset: int) -> tuple[str, str] | None:
    for rel, magic, status, reason in REFUSALS:
        if reader.read(offset + rel, len(magic)) == magic:
            return status, reason
    return None


def gpt_types(reader: Reader, sector: int) -> dict[int, str]:
    """First LBA → partition type GUID, read from the GPT header root never trusts beyond
    these bounds (≤ 256 entries of 128..4096 bytes)."""
    header = reader.read(sector, 92)
    if len(header) < 92 or header[:8] != b"EFI PART":
        return {}
    entries_lba, count, size = struct.unpack_from("<QII", header, 72)
    if not (0 < count <= GPT_MAX_ENTRIES and 128 <= size <= 4096 and size % 8 == 0):
        return {}
    table = reader.read(entries_lba * sector, count * size)
    out: dict[int, str] = {}
    for i in range(len(table) // size):
        raw = table[i * size : i * size + 48]
        if raw[:16] == b"\x00" * 16:
            continue
        first_lba = struct.unpack_from("<Q", raw, 32)[0]
        out[first_lba] = str(uuid.UUID(bytes_le=raw[:16]))
    return out


def _text(raw: Any, limit: int = TEXT128) -> str | None:
    if raw is None:
        return None
    data = raw if isinstance(raw, bytes) else str(raw).encode("utf-8", "replace")
    data = data.split(b"\x00", 1)[0]
    text, _ = names.display_name(data)
    text, _ = names.cut_utf8(text, limit)
    text = text[:limit]
    return text or None


def volume_parts(img: Any, reader: Reader) -> tuple[str, int, list[Part]]:
    """(volume system, sector size, allocated partitions); `none` gives one pseudo-partition."""
    import pytsk3  # noqa: PLC0415

    for vs_name, const_name in (("gpt", "TSK_VS_TYPE_GPT"), ("dos", "TSK_VS_TYPE_DOS")):
        vs_type = getattr(pytsk3, const_name)
        try:
            volume = pytsk3.Volume_Info(img, vs_type, 0)
        except (OSError, RuntimeError):
            continue
        sector = tsk_int(volume.info.block_size) or reader.sector_size
        hints = gpt_types(reader, sector) if vs_name == "gpt" else {}
        alloc = tsk_int(pytsk3.TSK_VS_PART_FLAG_ALLOC)
        parts: list[Part] = []
        for part in volume:
            if not tsk_int(part.flags) & alloc:
                continue
            desc = _text(part.desc)
            hint: str | None
            if vs_name == "gpt":
                hint = GPT_HINTS.get(hints.get(tsk_int(part.start), ""))
            else:
                m = _MBR_DESC.search(desc or "")
                hint = MBR_HINTS.get(int(m.group(1), 16)) if m else None
            parts.append(Part(len(parts), tsk_int(part.start), tsk_int(part.len), desc, hint))
        if parts:
            return vs_name, sector, parts
    sector = reader.sector_size
    return "none", sector, [Part(0, 0, reader.size // sector, None, None)]


def os_markers(fs: Fs) -> tuple[str, str | None]:
    if fs.family in ("ntfs", "fat"):
        e = fs.open_path("/Windows/System32/config/SYSTEM")
        if e is not None and e.meta is not None and e.meta.type == "reg":
            return "windows", None
        return "none", None
    present = [fs.open_path(p) for p in ("/etc/os-release", "/etc/debian_version")]
    if not any(e is not None for e in present):
        return "none", None
    return "linux", _pretty_name(fs)


def _pretty_name(fs: Fs) -> str | None:
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        e = fs.open_path(path)
        if e is None or e.meta is None or e.meta.type != "reg" or not e.meta.allocated:
            continue
        try:
            data = Fs.read(e, 0, min(e.meta.size or 0, OS_RELEASE_MAX))
        except (OSError, RuntimeError):
            return None
        for line in data.splitlines():
            if line.startswith(b"PRETTY_NAME="):
                value = line.split(b"=", 1)[1].strip().strip(b"\"'")
                return _text(value)
        return None
    return None


def check_bounds(parts: list[Part], media_sectors: int) -> dict[int, str]:
    """Partition index → `error` reason for parts outside the media or overlapping."""
    errors: dict[int, str] = {}
    ordered = sorted(parts, key=lambda p: (p.start, p.index))
    end_so_far = -1
    for p in ordered:
        if p.length <= 0 or p.start + p.length > media_sectors:
            errors[p.index] = "beyond_media"
            continue
        if p.start < end_so_far:
            errors[p.index] = "overlap"
            continue
        end_so_far = p.start + p.length
    return errors


def run(img: Any, reader: Reader, args: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """One row per allocated partition (at most `max_partitions`; opened file systems at most
    `max_filesystems`, the rest `truncated`)."""
    vs, sector, parts = volume_parts(img, reader)
    media_sectors = reader.size // sector
    errors = check_bounds(parts, media_sectors)
    opened = 0
    for p in parts[: int(args["max_partitions"])]:
        row: dict[str, Any] = {
            "index": p.index,
            "start_sector": p.start,
            "length_sectors": p.length,
            "sector_size": sector,
            "volume_system": vs,
            "description": p.description,
            "fs_type": None,
            "fs_status": "undetermined",
            "reason": None,
            "block_size": None,
            "os": "none",
            "os_name": None,
            "counts": {},
        }
        if p.index in errors:
            row.update(fs_status="error", reason=errors[p.index])
            yield row
            continue
        offset = p.start * sector
        refused = refusal(reader, offset)
        if refused is not None:
            row.update(fs_status=refused[0], reason=refused[1])
            yield row
            continue
        if opened >= int(args["max_filesystems"]):
            row.update(fs_status="truncated", reason="max_filesystems")
            yield row
            continue
        for family in family_order(p.hint):
            try:
                fs = Fs(img, offset, family)
            except (OSError, RuntimeError):
                continue
            opened += 1
            os_name = os_markers(fs)
            row.update(
                fs_type=fs.fs_type,
                fs_status="ok",
                block_size=fs.block_size or None,
                os=os_name[0],
                os_name=os_name[1],
                counts={"blocks": max(0, fs.block_count), "inodes": max(0, fs.inode_count)},
            )
            break
        yield row


__all__ = ["REFUSALS", "check_bounds", "family_order", "gpt_types", "os_markers", "refusal", "run"]
