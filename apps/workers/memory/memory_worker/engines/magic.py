"""Root's magic check before any probe runs (RT19; pure Python).

Volatility's `ResourceAccessor` decompresses a location transparently (xz, bz2, gzip by
libmagic or by extension; zip through `jar:`), so a small bomb would become a CPU / disk
DoS inside the probe. Root reads only the first bytes of the image (no parsing) and refuses
compressed and archived files with `unsupported_memory_format`. Memory images are raw, LiME,
AVML, ELF core, VMware or crash dumps: none starts with these signatures.
"""

from pathlib import Path

HEAD_BYTES = 16
SIGNATURES: tuple[tuple[str, bytes], ...] = (
    ("gzip", b"\x1f\x8b"),
    ("bzip2", b"BZh"),
    ("xz", b"\xfd7zXZ\x00"),
    ("zstd", b"\x28\xb5\x2f\xfd"),
    ("zip", b"PK\x03\x04"),
    ("zip", b"PK\x05\x06"),
    ("zip", b"PK\x07\x08"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
    ("rar", b"Rar!\x1a\x07"),
)


def compressed_format(head: bytes) -> str | None:
    """The archive / compression format named by these leading bytes, else None."""
    for name, magic in SIGNATURES:
        if head.startswith(magic):
            if name == "bzip2" and not (len(head) > 3 and head[3:4] in b"123456789"):
                continue
            return name
    return None


def image_format(path: Path) -> str | None:
    with open(path, "rb") as f:
        return compressed_format(f.read(HEAD_BYTES))


__all__ = ["SIGNATURES", "compressed_format", "image_format"]
