"""Engine facts -> contract values (pure Python; used by the Ghidra probe, unit-tested on any
host). Names follow Ghidra 12.2 [I: the engine smoke confirms them on the real install].

- `name_source`: Ghidra's `SourceType` of the function's primary symbol plus what root-side
  code cannot see (an external entry point, a thunk to an external function, a Function ID
  match) -> `NameSource`. `IMPORTED` covers symbol tables and debug info alike (Ghidra does
  not tell them apart), so it maps to `symbol`.
- `string_encoding`: Ghidra's string data type name -> `StringEncoding`.
- `ordinal_of`: Ghidra names ordinal-only imports `Ordinal_<n>`.
"""

import re

from cyberlab_jobs.reverse import NameSource, StringEncoding

ORDINAL = re.compile(r"^Ordinal_(\d{1,5})$")
UTF16_TYPES = frozenset({"unicode", "TerminatedUnicode", "PascalUnicode", "PascalUnicode255"})
UTF32_TYPES = frozenset({"unicode32", "TerminatedUnicode32"})


def name_source(
    source: str, *, is_export: bool, imports_external: bool, is_fid: bool
) -> NameSource:
    if imports_external:
        return NameSource.IMPORT
    if is_export:
        return NameSource.EXPORT
    if is_fid:
        return NameSource.FID_LIBRARY
    if source == "DEFAULT":
        return NameSource.GENERATED
    if source in ("IMPORTED", "USER_DEFINED"):
        return NameSource.SYMBOL
    return NameSource.GENERATED  # ANALYSIS (and anything newer): derived, not from the file


def string_encoding(type_name: str, value: str, *, big_endian: bool) -> StringEncoding:
    if type_name in UTF16_TYPES:
        return "utf16be" if big_endian else "utf16le"
    if type_name in UTF32_TYPES:
        return "utf32"
    return "ascii" if value.isascii() else "utf8"


def ordinal_of(name: str) -> int | None:
    match = ORDINAL.match(name)
    if match is None:
        return None
    value = int(match.group(1))
    return value if value <= 65535 else None


__all__ = ["name_source", "ordinal_of", "string_encoding"]
