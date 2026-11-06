"""Partition tables and image assembly in pure Python (no sfdisk on a loop device, no dd).

- `mbr()`: a DOS partition table (LBA only; CHS fields set to the 1023/254/63 "use LBA" value);
- `gpt()`: a protective MBR, the primary header and 128-entry array at LBA 1-33 and the backup
  array and header at the end of the disk, CRC32s as UEFI 2.x specifies;
- `assemble()`: a sparse disk file with the partition contents written at their offsets;
- `split()`: a raw image cut into `image.001`, `image.002`... parts.
"""

import struct
import uuid
import zlib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

SECTOR = 512
CHS_LBA = b"\xfe\xff\xff"
GPT_ENTRIES = 128
GPT_ENTRY_SIZE = 128
GPT_ARRAY_SECTORS = GPT_ENTRIES * GPT_ENTRY_SIZE // SECTOR  # 32

# GPT partition type GUIDs (UEFI / vendor registries).
GUID_BASIC_DATA = uuid.UUID("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7")
GUID_LINUX_FS = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
GUID_HFS_PLUS = uuid.UUID("48465300-0000-11aa-aa11-00306543ecac")
GUID_LINUX_LUKS = uuid.UUID("ca7d7ccb-63ed-4c53-861c-1742536059cc")
GUID_EFI_SYSTEM = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")

MBR_FAT12 = 0x01
MBR_FAT16 = 0x06
MBR_FAT32_LBA = 0x0C
MBR_NTFS_EXFAT = 0x07
MBR_LINUX = 0x83
MBR_GPT_PROTECTIVE = 0xEE


@dataclass(frozen=True)
class Part:
    start: int  # LBA
    sectors: int
    mbr_type: int = MBR_LINUX
    gpt_type: uuid.UUID = GUID_LINUX_FS
    guid: uuid.UUID = uuid.UUID(int=0)
    name: str = ""
    bootable: bool = False


def mbr(parts: Sequence[Part], disk_signature: int) -> bytes:
    if len(parts) > 4:
        raise ValueError("an MBR holds four primary partitions")
    b = bytearray(SECTOR)
    struct.pack_into("<I", b, 440, disk_signature)
    for i, p in enumerate(parts):
        entry = (
            bytes([0x80 if p.bootable else 0])
            + CHS_LBA
            + bytes([p.mbr_type])
            + CHS_LBA
            + struct.pack("<II", p.start & 0xFFFFFFFF, p.sectors & 0xFFFFFFFF)
        )
        b[446 + 16 * i : 462 + 16 * i] = entry
    b[510:512] = b"\x55\xaa"
    return bytes(b)


def _gpt_header(
    current: int, backup: int, total: int, disk: uuid.UUID, array_lba: int, array_crc: int
) -> bytes:
    def pack(crc: int) -> bytes:
        return struct.pack(
            "<8sIIIIQQQQ16sQIII",
            b"EFI PART",
            0x00010000,
            92,
            crc,
            0,
            current,
            backup,
            34,
            total - 34,
            disk.bytes_le,
            array_lba,
            GPT_ENTRIES,
            GPT_ENTRY_SIZE,
            array_crc,
        )

    header = pack(zlib.crc32(pack(0)))
    return header.ljust(SECTOR, b"\x00")


def gpt_array(parts: Sequence[Part]) -> bytes:
    out = bytearray(GPT_ENTRIES * GPT_ENTRY_SIZE)
    for i, p in enumerate(parts):
        name = p.name.encode("utf-16-le")[:72]
        struct.pack_into(
            "<16s16sQQQ72s",
            out,
            i * GPT_ENTRY_SIZE,
            p.gpt_type.bytes_le,
            p.guid.bytes_le,
            p.start,
            p.start + p.sectors - 1,
            0,
            name,
        )
    return bytes(out)


def gpt(parts: Sequence[Part], total: int, disk: uuid.UUID) -> tuple[bytes, bytes]:
    """(LBA 0-33: protective MBR, header, array; the last 33 LBAs: backup array, header)."""
    protective = Part(1, min(total - 1, 0xFFFFFFFF), mbr_type=MBR_GPT_PROTECTIVE)
    array = gpt_array(parts)
    crc = zlib.crc32(array)
    last = total - 1
    primary = mbr([protective], 0) + _gpt_header(1, last, total, disk, 2, crc) + array
    backup = array + _gpt_header(last, 1, total, disk, last - GPT_ARRAY_SECTORS, crc)
    return primary, backup


def assemble(
    out: Path,
    total_sectors: int,
    head: bytes,
    contents: Sequence[tuple[int, Path | bytes]],
    tail: bytes = b"",
) -> None:
    """Write a sparse disk image: `head` at LBA 0, each (LBA, file or bytes) at its offset,
    `tail` ending exactly at the end of the disk."""
    with out.open("wb") as f:
        f.truncate(total_sectors * SECTOR)
        f.seek(0)
        f.write(head)
        for lba, content in contents:
            f.seek(lba * SECTOR)
            if isinstance(content, bytes):
                f.write(content)
                continue
            with content.open("rb") as src:
                while chunk := src.read(1024 * 1024):
                    f.write(chunk)
        if tail:
            f.seek(total_sectors * SECTOR - len(tail))
            f.write(tail)


def split(image: Path, part_bytes: int) -> list[Path]:
    """`image.raw` → `image.001`, `image.002`... in the same directory (the source is removed)."""
    parts: list[Path] = []
    with image.open("rb") as src:
        n = 1
        while chunk := src.read(part_bytes):
            part = image.with_name(f"image.{n:03d}")
            part.write_bytes(chunk)
            parts.append(part)
            n += 1
    image.unlink()
    return parts
