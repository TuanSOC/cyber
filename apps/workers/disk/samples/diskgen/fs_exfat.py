"""exFAT through exfatprogs' `mkfs.exfat` on an image file (no mount).

exfatprogs has no userspace copy tool, so the volume stays empty (the plan's fallback: listing
only; recorded as a gap). mkfs.exfat derives the volume serial number from the clock: it is
patched to a fixed value afterwards in the main and backup boot regions, whose boot checksum
sector is recomputed (`boot_checksum`, exFAT specification §3.4), so the image is deterministic.
"""

import struct
from pathlib import Path

from samples.diskgen import tools

SECTOR = 512
REGION_SECTORS = 12  # main boot region: sectors 0-11, backup: 12-23
SERIAL_AT = 100


def boot_checksum(region: bytes, sector: int = SECTOR) -> int:
    """The checksum of boot sectors 0-10, skipping VolumeFlags (106-107) and PercentInUse (112)."""
    value = 0
    for i, byte in enumerate(region[: 11 * sector]):
        if i in (106, 107, 112):
            continue
        value = (((value << 31) | (value >> 1)) + byte) & 0xFFFFFFFF
    return value


def patch_serial(image: bytearray, serial: int, offset: int = 0) -> None:
    """Set the volume serial number of both boot regions and recompute their checksums."""
    if image[offset + 3 : offset + 11] != b"EXFAT   ":
        raise ValueError("not an exFAT boot sector")
    shift = image[offset + 108]
    sector = 1 << shift
    for base in (offset, offset + REGION_SECTORS * sector):
        struct.pack_into("<I", image, base + SERIAL_AT, serial)
        region = bytes(image[base : base + REGION_SECTORS * sector])
        value = boot_checksum(region, sector)
        image[base + 11 * sector : base + 12 * sector] = struct.pack("<I", value) * (sector // 4)


def build(out: Path, size: int, *, label: str, serial: int) -> None:
    tools.require("mkfs.exfat")
    with out.open("wb") as f:
        f.truncate(size)
    tools.run(["mkfs.exfat", "-L", label, str(out)])
    data = bytearray(out.read_bytes())
    patch_serial(data, serial)
    out.write_bytes(bytes(data))
