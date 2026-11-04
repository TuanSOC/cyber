"""`elf` mode: pyelftools facts as `static.v1` records (elf, section, import, export)."""

from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, BinaryIO

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from static_worker.probe.common import emit, entropy, error, text, u64

MAX_SECTION_READ = 64 * 1024**2
UNRESOLVED = "(unresolved)"


def run(sample: Path, *, max_sections: int, max_imports: int, max_exports: int) -> None:
    with open(sample, "rb") as f:
        try:
            elf = ELFFile(f)
        except (ELFError, ValueError, OSError) as exc:
            error("elf_parse_error", str(exc))
            return
        truncated: dict[str, bool] = {}
        _part("header", lambda: emit(_header(elf)))
        _part("sections", lambda: _limited(_sections(elf, f), max_sections, "sections", truncated))
        _part("symbols", lambda: _symbols(elf, max_imports, max_exports, truncated))
        emit({"kind": "summary", "truncated": truncated})


def _part(name: str, action: Callable[[], None]) -> None:
    try:
        action()
    except Exception as exc:  # pyelftools raises many types on hostile input
        error("elf_partial", f"{name}: {type(exc).__name__}")


def _limited(
    records: Iterator[dict[str, Any]], limit: int, key: str, truncated: dict[str, bool]
) -> None:
    for count, record in enumerate(records):
        if count >= limit:
            truncated[key] = True
            return
        emit(record)


def _header(elf: Any) -> dict[str, Any]:
    interpreter = None
    needed: list[str] = []
    for segment in elf.iter_segments():
        if segment["p_type"] == "PT_INTERP":
            interpreter = text(segment.get_interp_name(), 255)
            break
    dynamic = elf.get_section_by_name(".dynamic")
    if dynamic is not None and hasattr(dynamic, "iter_tags"):
        for tag in dynamic.iter_tags():
            if tag.entry.d_tag == "DT_NEEDED" and len(needed) < 256:
                needed.append(text(tag.needed, 255))
    stripped = not any(s["sh_type"] == "SHT_SYMTAB" for s in elf.iter_sections())
    return {
        "kind": "elf",
        "elf_class": elf.elfclass,
        "machine": text(elf["e_machine"], 64),
        "elf_type": text(elf["e_type"], 16),
        "entry_point": u64(elf["e_entry"]),
        "interpreter": interpreter,
        "needed": needed,
        "stripped": stripped,
    }


def _sections(elf: Any, f: BinaryIO) -> Iterator[dict[str, Any]]:
    for index, section in enumerate(elf.iter_sections()):
        if index == 0 and section["sh_type"] == "SHT_NULL":
            continue
        nobits = section["sh_type"] == "SHT_NOBITS"
        size = u64(section["sh_size"])
        data = b""
        if not nobits and size:
            f.seek(section["sh_offset"])
            data = f.read(min(size, MAX_SECTION_READ))
        flags = section["sh_flags"]
        yield {
            "kind": "section",
            "index": index,
            "name": text(section.name, 64),
            "virtual_address": u64(section["sh_addr"]),
            "virtual_size": size,
            "raw_size": 0 if nobits else min(size, len(data)) if data else 0,
            "entropy": entropy(data),
            "flags": [
                name
                for name, bit in (("alloc", 0x2), ("write", 0x1), ("execute", 0x4))
                if flags & bit
            ],  # fmt: skip
        }


def _versions(elf: Any) -> dict[int, str]:
    """Symbol version index -> library, from .gnu.version_r (when present)."""
    mapping: dict[int, str] = {}
    for section in elf.iter_sections():
        if section["sh_type"] != "SHT_GNU_verneed":
            continue
        for verneed, auxiliaries in section.iter_versions():
            for aux in auxiliaries:
                mapping[aux.entry.vna_other] = text(verneed.name, 255)
    return mapping


def _symbols(elf: Any, max_imports: int, max_exports: int, truncated: dict[str, bool]) -> None:
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is None or not hasattr(dynsym, "iter_symbols"):
        return
    versions = _versions(elf)
    versym = next((s for s in elf.iter_sections() if s["sh_type"] == "SHT_GNU_versym"), None)
    needed = [
        t.needed for t in getattr(elf.get_section_by_name(".dynamic"), "iter_tags", list)()
        if t.entry.d_tag == "DT_NEEDED"
    ]  # fmt: skip
    default = text(needed[0], 255) if len(needed) == 1 else UNRESOLVED
    imports = exports = 0
    for index, symbol in enumerate(dynsym.iter_symbols()):
        if not symbol.name or symbol["st_info"]["type"] not in {"STT_FUNC", "STT_OBJECT"}:
            continue
        if symbol["st_shndx"] == "SHN_UNDEF":
            if imports >= max_imports:
                truncated["imports"] = True
                continue
            imports += 1
            library = default
            if versym is not None:
                idx = versym.get_symbol(index)["ndx"]
                library = versions.get(idx if isinstance(idx, int) else -1, default)
            emit({"kind": "import", "library": library, "function": text(symbol.name, 255)})
        elif symbol["st_info"]["bind"] in {"STB_GLOBAL", "STB_WEAK"}:
            if exports >= max_exports:
                truncated["exports"] = True
                continue
            exports += 1
            emit(
                {
                    "kind": "export",
                    "name": text(symbol.name, 255),
                    "ordinal": index if index < 2**32 else 0,
                    "address": u64(symbol["st_value"]),
                }
            )
