"""The magic class of a file from its first bytes (pure Python, no libmagic in the probe).

Coarse on purpose: the classes drive YARA candidates (`pe`), the detections (PE / ELF in odd
places) and root's refusal of compressed / archive content in the mirrored tree (RT11).
"""

from typing import Literal

MagicClass = Literal["pe", "elf", "script", "archive", "document", "other", "empty"]
HEAD_BYTES = 512

_ARCHIVE = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"\x1f\x8b",  # gzip
    b"BZh",
    b"\xfd7zXZ\x00",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07",
    b"\x28\xb5\x2f\xfd",  # zstd
    b"MSCF",  # cab
    b"\x04\x22\x4d\x18",  # lz4 frame
)
_DOCUMENT = (b"%PDF-", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"{\\rtf")


def magic_class(head: bytes, size: int | None = None) -> MagicClass:
    if size == 0 or not head:
        return "empty"
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"#!"):
        return "script"
    if head.startswith(_ARCHIVE) or (len(head) > 262 and head[257:262] == b"ustar"):
        return "archive"
    if head.startswith(_DOCUMENT):
        return "document"
    return "other"


__all__ = ["HEAD_BYTES", "MagicClass", "magic_class"]
