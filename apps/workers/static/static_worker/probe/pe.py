"""`pe` mode: pefile facts as `static.v1` records (pe, section, import, export, resource).

Every part is parsed independently: a malformed directory yields an `error` line and the
other parts are still reported (partial results, never a crash of the whole probe).
"""

import hashlib
import struct
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pefile

from static_worker.probe.common import emit, entropy, error, text, u64

MACHINES = {
    0x014C: "i386", 0x8664: "amd64", 0x01C0: "arm", 0x01C4: "armnt", 0xAA64: "arm64",
    0x0200: "ia64", 0x0EBC: "efi_bytecode", 0x5064: "riscv64",
}  # fmt: skip
SECTION_FLAGS = (
    ("code", 0x00000020), ("idata", 0x00000040), ("udata", 0x00000080),
    ("discardable", 0x02000000), ("shared", 0x10000000), ("execute", 0x20000000),
    ("read", 0x40000000), ("write", 0x80000000),
)  # fmt: skip
MAX_RESOURCE_READ = 32 * 1024**2
MAX_TLS_CALLBACKS = 256
DIRECTORIES = [
    pefile.DIRECTORY_ENTRY[name]
    for name in (
        "IMAGE_DIRECTORY_ENTRY_IMPORT",
        "IMAGE_DIRECTORY_ENTRY_EXPORT",
        "IMAGE_DIRECTORY_ENTRY_RESOURCE",
        "IMAGE_DIRECTORY_ENTRY_TLS",
        "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
    )
]


def run(
    sample: Path, *, max_sections: int, max_imports: int, max_exports: int, max_resources: int
) -> None:
    file_size = sample.stat().st_size
    try:
        pe = pefile.PE(str(sample), fast_load=True)
    except pefile.PEFormatError as exc:
        error("pe_parse_error", str(exc))
        return
    try:
        pe.parse_data_directories(directories=DIRECTORIES)
    except Exception as exc:  # pefile raises many types on hostile input
        error("pe_partial", f"data directories: {type(exc).__name__}")
    truncated: dict[str, bool] = {}

    _part("header", lambda: emit(_header(pe, file_size)))
    _part("sections", lambda: _limited(_sections(pe), max_sections, "sections", truncated))
    _part("imports", lambda: _limited(_imports(pe), max_imports, "imports", truncated))
    _part("exports", lambda: _limited(_exports(pe), max_exports, "exports", truncated))
    _part("resources", lambda: _limited(_resources(pe), max_resources, "resources", truncated))
    emit({"kind": "summary", "truncated": truncated})


def _part(name: str, action: Callable[[], None]) -> None:
    try:
        action()
    except Exception as exc:
        error("pe_partial", f"{name}: {type(exc).__name__}")


def _limited(
    records: Iterator[dict[str, Any]], limit: int, key: str, truncated: dict[str, bool]
) -> None:
    for count, record in enumerate(records):
        if count >= limit:
            truncated[key] = True
            return
        emit(record)


def _section_of(pe: Any, rva: int) -> Any:
    for section in pe.sections:
        start = section.VirtualAddress
        size = max(section.Misc_VirtualSize, section.SizeOfRawData)
        if start <= rva < start + size:
            return section
    return None


def _name(section: Any) -> str:
    return text(section.Name.rstrip(b"\x00"), 64)


def _flags(table: dict[Any, Any], prefix: str, value: int) -> list[str]:
    names = [
        name[len(prefix) :].lower()
        for name, flag in pefile.retrieve_flags(table, prefix)
        if isinstance(flag, int) and flag and value & flag == flag
    ]
    return [text(n, 64) for n in names[:32]]


def _header(pe: Any, file_size: int) -> dict[str, Any]:
    opt = pe.OPTIONAL_HEADER
    fh = pe.FILE_HEADER
    entry = u64(opt.AddressOfEntryPoint)
    entry_section = _section_of(pe, entry)
    subsystem = pefile.SUBSYSTEM_TYPE.get(opt.Subsystem)
    imphash = rich_hash = None
    try:
        imphash = pe.get_imphash() or None
    except Exception:
        error("pe_partial", "imphash")
    try:
        # fast_load skips the Rich header; same digest as pefile's get_rich_header_hash().
        rich = pe.parse_rich_header()
        if rich and isinstance(rich.get("clear_data"), bytes):
            rich_hash = hashlib.md5(rich["clear_data"]).hexdigest()  # noqa: S324 - an ID
    except Exception:
        error("pe_partial", "rich header")
    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ]
    cert_offset, cert_size = security.VirtualAddress, security.Size
    has_cert = cert_size > 0 and 0 < cert_offset and cert_offset + cert_size <= file_size
    return {
        "kind": "pe",
        "machine": MACHINES.get(fh.Machine, f"0x{fh.Machine:04x}"),
        "bits": 64 if opt.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 32,
        "is_dll": bool(fh.Characteristics & 0x2000),
        "subsystem": text(subsystem.removeprefix("IMAGE_SUBSYSTEM_"), 64) if subsystem else None,
        "compile_timestamp": fh.TimeDateStamp,
        "entry_point": entry,
        "entry_section": _name(entry_section) if entry_section is not None else None,
        "image_base": u64(opt.ImageBase),
        "imphash": imphash if imphash and len(imphash) == 32 else None,
        "rich_header_hash": rich_hash if rich_hash and len(rich_hash) == 32 else None,
        "tls_callbacks": _tls_callbacks(pe),
        "has_authenticode": has_cert,
        "overlay_size": _overlay_size(pe, file_size, cert_offset if has_cert else 0, cert_size),
        "characteristics": _flags(pefile.IMAGE_CHARACTERISTICS, "IMAGE_FILE_", fh.Characteristics),
        "dll_characteristics": _flags(
            pefile.DLL_CHARACTERISTICS, "IMAGE_DLLCHARACTERISTICS_", opt.DllCharacteristics
        ),
    }


def _overlay_size(pe: Any, file_size: int, cert_offset: int, cert_size: int) -> int:
    """Bytes after the last section's raw data, not counting an Authenticode blob."""
    end = pe.OPTIONAL_HEADER.SizeOfHeaders
    for section in pe.sections:
        if section.SizeOfRawData:
            end = max(end, section.PointerToRawData + section.SizeOfRawData)
    end = min(end, file_size)
    overlay = file_size - end
    if cert_size and cert_offset >= end:
        overlay -= min(file_size, cert_offset + cert_size) - cert_offset
    return max(int(overlay), 0)


def _tls_callbacks(pe: Any) -> int:
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if tls is None:
        return 0
    address = tls.struct.AddressOfCallBacks
    if not address or address < pe.OPTIONAL_HEADER.ImageBase:
        return 0
    rva = address - pe.OPTIONAL_HEADER.ImageBase
    pointer = 8 if pe.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 4
    try:
        data = pe.get_data(rva, pointer * MAX_TLS_CALLBACKS)
    except pefile.PEFormatError:
        return 0
    count = 0
    fmt = "<Q" if pointer == 8 else "<I"
    for offset in range(0, len(data) - pointer + 1, pointer):
        if struct.unpack_from(fmt, data, offset)[0] == 0:
            break
        count += 1
    return count


def _sections(pe: Any) -> Iterator[dict[str, Any]]:
    for index, section in enumerate(pe.sections):
        flags = [n for n, bit in SECTION_FLAGS if section.Characteristics & bit]
        yield {
            "kind": "section",
            "index": index,
            "name": _name(section),
            "virtual_address": u64(section.VirtualAddress),
            "virtual_size": u64(section.Misc_VirtualSize),
            "raw_size": u64(section.SizeOfRawData),
            "entropy": round(min(max(section.get_entropy(), 0.0), 8.0), 4),
            "flags": flags,
        }


def _imports(pe: Any) -> Iterator[dict[str, Any]]:
    entries = [
        *getattr(pe, "DIRECTORY_ENTRY_IMPORT", []),
        *getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []),
    ]
    for entry in entries:
        library = text(entry.dll or b"", 255)
        for imp in entry.imports:
            ordinal = imp.ordinal if isinstance(imp.ordinal, int) else None
            yield {
                "kind": "import",
                "library": library,
                "function": text(imp.name, 255) if imp.name else None,
                "ordinal": ordinal if ordinal is not None and 0 <= ordinal <= 65535 else None,
            }


def _exports(pe: Any) -> Iterator[dict[str, Any]]:
    directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if directory is None:
        return
    for symbol in directory.symbols:
        ordinal = symbol.ordinal if isinstance(symbol.ordinal, int) else 0
        yield {
            "kind": "export",
            "name": text(symbol.name, 255) if symbol.name else None,
            "ordinal": ordinal if 0 <= ordinal < 2**32 else 0,
            "address": u64(symbol.address),
        }


def _resources(pe: Any) -> Iterator[dict[str, Any]]:
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return
    for type_entry in root.entries:
        rtype = _label(type_entry, pefile.RESOURCE_TYPE)
        for name_entry in getattr(getattr(type_entry, "directory", None), "entries", []):
            name = _label(name_entry, {})
            for lang_entry in getattr(getattr(name_entry, "directory", None), "entries", []):
                data = getattr(lang_entry, "data", None)
                if data is None:
                    continue
                yield _resource(pe, rtype, name, data)


def _label(entry: Any, names: dict[Any, Any]) -> str:
    if entry.name is not None:
        return text(str(entry.name), 64)
    known = names.get(entry.id)
    return text(known if isinstance(known, str) else str(entry.id), 64)


def _resource(pe: Any, rtype: str, name: str, data: Any) -> dict[str, Any]:
    size = u64(data.struct.Size)
    blob = b""
    try:
        blob = pe.get_data(data.struct.OffsetToData, min(size, MAX_RESOURCE_READ))
    except pefile.PEFormatError:
        error("pe_partial", "resource data outside the file")
    complete = len(blob) == size
    language = None
    try:
        language = pefile.get_sublang_name_for_lang(data.lang, data.sublang)
    except Exception:
        language = None
    return {
        "kind": "resource",
        "type": rtype,
        "name": text(name, 255),
        "language": text(language, 64) if language else None,
        "size": size,
        "entropy": entropy(blob),
        "sha256": hashlib.sha256(blob).hexdigest() if complete else None,
    }
