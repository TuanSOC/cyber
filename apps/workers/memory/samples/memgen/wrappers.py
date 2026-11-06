"""Container formats around the synthetic physical memory (M8 phase 4): raw, LiME and an ELF64
core, written from the public format descriptions (LiME: a 32-byte header per range,
`magic, version, start, end (inclusive), reserved`; ELF64 core: one `PT_LOAD` per range,
physical address in `p_paddr`). All three must stack in Volatility to the same physical view.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable
from pathlib import Path

from samples.memgen.image import MemoryImage

LIME_MAGIC = 0x4C694D45
LIME_VERSION = 1
LIME_HEADER = struct.Struct("<IIQQQ")
ELF_HEADER = struct.Struct("<4sBBBBB7sHHIQQQIHHHHHH")
ELF_PHDR = struct.Struct("<IIQQQQQQ")
ET_CORE, EM_X86_64, PT_LOAD = 4, 62, 1
DIRECT_MAP = 0xFFFF888000000000  # where x86-64 Linux maps physical memory (p_vaddr)
FORMATS = ("raw", "lime", "elf")


def raw(img: MemoryImage) -> bytes:
    return bytes(img.phys)


def lime_header(start: int, end_inclusive: int, magic: int = LIME_MAGIC,
                version: int = LIME_VERSION) -> bytes:  # fmt: skip
    return LIME_HEADER.pack(magic, version, start, end_inclusive, 0)


def lime(img: MemoryImage, ranges: Iterable[tuple[int, int]] | None = None) -> bytes:
    out = bytearray()
    for start, end in ranges or img.ranges:
        out += lime_header(start, end - 1)
        out += img.phys[start:end]
    return bytes(out)


def elf(img: MemoryImage, ranges: Iterable[tuple[int, int]] | None = None) -> bytes:
    spans = list(ranges or img.ranges)
    phoff = ELF_HEADER.size
    data_at = (phoff + ELF_PHDR.size * len(spans) + 0xFFF) & ~0xFFF
    ident_pad = b"\x00" * 7
    header = ELF_HEADER.pack(b"\x7fELF", 2, 1, 1, 0, 0, ident_pad, ET_CORE, EM_X86_64, 1,
                             0, phoff, 0, 0, ELF_HEADER.size, ELF_PHDR.size, len(spans),
                             0, 0, 0)  # fmt: skip
    out = bytearray(header)
    offset = data_at
    for start, end in spans:
        size = end - start
        out += ELF_PHDR.pack(PT_LOAD, 7, offset, DIRECT_MAP + start, start, size, size, 0x1000)
        offset += size
    out += b"\x00" * (data_at - len(out))
    for start, end in spans:
        out += img.phys[start:end]
    return bytes(out)


def wrap(img: MemoryImage, fmt: str) -> bytes:
    if fmt == "raw":
        return raw(img)
    if fmt == "lime":
        return lime(img)
    if fmt == "elf":
        return elf(img)
    raise ValueError(f"unknown format {fmt!r} (one of {', '.join(FORMATS)})")


def write(img: MemoryImage, fmt: str, path: Path) -> int:
    data = wrap(img, fmt)
    path.write_bytes(data)
    return len(data)


__all__ = ["ELF_HEADER", "ELF_PHDR", "FORMATS", "LIME_HEADER", "LIME_MAGIC", "elf", "lime",
           "lime_header", "raw", "wrap", "write"]  # fmt: skip
