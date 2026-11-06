"""Declared (extension) vs detected (content) file families of an upload (M7 phase 6).

Recorded at insert as `evidence.declared_type` and `evidence.type_mismatch` (write-once).
A mismatch is a flag for the analyst (and the audit `evidence.type_mismatch`), never a
reason to reject: an evidence platform must accept whatever an analyst collected, disguised
malware included. Routing to the analyzers is unchanged (it reads the content only).

M8 phase 6: the family `memory` (a memory image). It is declared by a `kind=memory` upload
or by the image extensions below. A raw image has no magic, so `memory` + unknown content is
not a mismatch; the analyzers' routing never sends anything to the memory analyzer (a memory
run is always an explicit request).

Pure functions on untrusted input: they never raise on a hostile name or MIME string.
"""

from typing import Final, Literal

from cyberlab_jobs.capture import capture_format, executable_format

Family = Literal[
    "pcap", "pe", "elf", "pdf", "zip", "office_legacy", "image", "text", "archive", "memory"
]
MEMORY: Final = "memory"

_EXTENSIONS: Final[dict[str, Family]] = {
    **dict.fromkeys(("pcap", "pcapng", "cap"), "pcap"),
    **dict.fromkeys(("exe", "dll", "sys", "scr", "cpl", "ocx"), "pe"),
    **dict.fromkeys(("so", "elf"), "elf"),
    "pdf": "pdf",
    **dict.fromkeys(("zip", "jar", "apk", "docx", "xlsx", "pptx"), "zip"),
    **dict.fromkeys(("doc", "xls", "ppt"), "office_legacy"),
    **dict.fromkeys(
        ("png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff", "ico", "svg"), "image"
    ),
    **dict.fromkeys(("txt", "log", "csv", "json"), "text"),
    **dict.fromkeys(("7z", "rar", "gz", "tar"), "archive"),
    # M8: raw / padded, LiME, VMware, Windows crash dump and ELF core images.
    **dict.fromkeys(("raw", "mem", "vmem", "lime", "dmp", "core"), "memory"),
}

# libmagic MIME types (lower case, parameters stripped) -> family. `image/*` and `text/*` are
# matched by prefix below; `application/octet-stream`, `inode/x-empty` and anything unknown
# give None (unknown never counts as a mismatch).
_MIMES: Final[dict[str, Family]] = {
    "application/vnd.tcpdump.pcap": "pcap",
    "application/x-pcap": "pcap",
    "application/x-pcapng": "pcap",
    "application/x-dosexec": "pe",
    "application/vnd.microsoft.portable-executable": "pe",
    "application/x-msdownload": "pe",
    "application/x-executable": "elf",
    "application/x-sharedlib": "elf",
    "application/x-pie-executable": "elf",
    "application/x-elf": "elf",
    "application/pdf": "pdf",
    "application/zip": "zip",
    "application/java-archive": "zip",
    "application/vnd.android.package-archive": "zip",
    "application/msword": "office_legacy",
    "application/vnd.ms-excel": "office_legacy",
    "application/vnd.ms-powerpoint": "office_legacy",
    "application/vnd.ms-office": "office_legacy",
    "application/cdfv2": "office_legacy",
    "application/x-ole-storage": "office_legacy",
    "application/json": "text",
    "application/csv": "text",
    "application/x-7z-compressed": "archive",
    "application/x-rar": "archive",
    "application/x-rar-compressed": "archive",
    "application/vnd.rar": "archive",
    "application/gzip": "archive",
    "application/x-gzip": "archive",
    "application/x-tar": "archive",
    "application/x-ustar": "archive",
    "application/x-xz": "archive",
    "application/x-bzip2": "archive",
    "application/zstd": "archive",
    "application/x-lz4": "archive",
}
_OOXML_PREFIX = "application/vnd.openxmlformats-officedocument."

# The content routing of the analyzers (`analysis.service.auto_choice` through
# `cyberlab_jobs.capture`): `capture_format` / `executable_format` values. Authoritative over
# libmagic, which only sees the first bytes.
_ROUTES: Final[dict[str, Family]] = {"pcap": "pcap", "pcapng": "pcap", "pe": "pe", "elf": "elf"}

# (declared, detected) pairs that differ but are not suspicious: a zip-based container named
# as a generic archive and the reverse (OOXML, JAR and APK are already `zip`).
BENIGN_PAIRS: Final[frozenset[tuple[str, str]]] = frozenset(
    {("archive", "zip"), ("zip", "archive")}
)

MAX_EXTENSION = 16


def declared_family(filename: str, *, kind: str | None = None) -> str | None:
    """The family the file's name claims (its last extension), or None (no or unknown one).

    The stored name is already sanitized; trailing dots and spaces are ignored like Windows
    does (`evil.exe.` opens as an `.exe`). A leading-dot name (`.pcap`) has no extension.
    An upload declared `kind=memory` (M8) is a memory image whatever its name.
    """
    if kind == MEMORY:
        return MEMORY
    name = filename.rstrip(" .").replace("\\", "/").rsplit("/", 1)[-1]
    stem, dot, ext = name.rpartition(".")
    if not dot or not stem or not 0 < len(ext) <= MAX_EXTENSION:
        return None
    return _EXTENSIONS.get(ext.lower())


def detected_family(mime: str | None, magic_route: str | None) -> str | None:
    """The family the content shows: the analyzers' magic routing first, then libmagic."""
    if magic_route is not None and (routed := _ROUTES.get(str(magic_route).lower())):
        return routed
    if not mime:
        return None
    base = mime.split(";", 1)[0].strip().lower()
    if family := _MIMES.get(base):
        return family
    if base.startswith(_OOXML_PREFIX):
        return "zip"
    if base.startswith("image/"):
        return "image"
    if base.startswith("text/"):
        return "text"
    return None


def magic_route(head: bytes) -> str | None:
    """The analyzers' content routing of the first bytes (pcap / pcapng / pe / elf)."""
    found = capture_format(head) or executable_format(head)
    return found.value if found is not None else None


def type_mismatch(declared: str | None, detected: str | None) -> bool:
    """True only when both families are known, differ, and the pair is not benign."""
    if declared is None or detected is None or declared == detected:
        return False
    return (declared, detected) not in BENIGN_PAIRS
