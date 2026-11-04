"""Capture format detection by magic number (no libmagic, no parsing)."""

import enum


class CaptureFormat(enum.StrEnum):
    PCAP = "pcap"
    PCAPNG = "pcapng"


_PCAP_MAGICS = (
    bytes.fromhex("a1b2c3d4"),  # microsecond, big endian
    bytes.fromhex("d4c3b2a1"),  # microsecond, little endian
    bytes.fromhex("a1b23c4d"),  # nanosecond, big endian
    bytes.fromhex("4d3cb2a1"),  # nanosecond, little endian
)
_PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")  # section header block

# Containers TShark would open transparently but Zeek would not: refused, never inflated.
COMPRESSED_MAGICS = {
    bytes.fromhex("1f8b"): "gzip",
    bytes.fromhex("28b52ffd"): "zstd",
    bytes.fromhex("04224d18"): "lz4",
    bytes.fromhex("fd377a585a00"): "xz",
    b"BZh": "bzip2",
}


def capture_format(head: bytes) -> CaptureFormat | None:
    """pcap / pcapng from the first bytes, or None (including compressed captures)."""
    if head[:4] in _PCAP_MAGICS:
        return CaptureFormat.PCAP
    if head[:4] == _PCAPNG_MAGIC:
        return CaptureFormat.PCAPNG
    return None


def compression(head: bytes) -> str | None:
    return next((name for magic, name in COMPRESSED_MAGICS.items() if head.startswith(magic)), None)


class ExecutableFormat(enum.StrEnum):
    PE = "pe"
    ELF = "elf"


ELF_MAGIC = bytes.fromhex("7f454c46")
ET_CORE = 4


def executable_format(head: bytes) -> ExecutableFormat | None:
    """PE (MZ + in-bounds PE header) or non-core ELF from the first bytes, else None.

    Mach-O is not recognised (no parser in M3); fat Mach-O magic is also Java class files.
    """
    if head[:2] == b"MZ" and len(head) >= 0x40:
        e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
        if 0x40 <= e_lfanew <= len(head) - 4 and head[e_lfanew : e_lfanew + 4] == b"PE" + bytes(2):
            return ExecutableFormat.PE
        return None
    if head[:4] == ELF_MAGIC and len(head) >= 18:
        byteorder = "little" if head[5] == 1 else "big"
        if int.from_bytes(head[16:18], byteorder) != ET_CORE:
            return ExecutableFormat.ELF
    return None
