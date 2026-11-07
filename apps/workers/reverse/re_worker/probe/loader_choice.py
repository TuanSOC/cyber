"""The loader root chose and its options (M10 phase 2; RT20). Pure Python, unit-tested.

Root's magic check names the format (`pe` / `elf`); the probe loads the sample with exactly
that Ghidra loader class, never an opinion-based, filesystem or archive loader, and never a
`.gzf` / `.xml` / project archive.

**Loader options fail closed** (RT20): the probe enumerates the chosen loader's default
options for this file, then
- every boolean option that loads, links or searches libraries (`LIBRARY_PATTERN`) is
  passed as `false` (`loader_args`);
- `check_options` fails the stage `re_parse_failed` (reason `loader_option`) if such an
  option would still be enabled, or if an option name is not in `KNOWN_OPTIONS[format]`
  (a Ghidra upgrade that adds or renames an option stops here instead of silently loading
  with a new default).

`KNOWN_OPTIONS` holds the 12.x names as far as they are known without the install [I]:
PROVISIONAL until the phase-2 spike records the exact 12.2 list (`status.loader_options` of
the engine smoke prints it); the parent then pins it here.
"""

import re
from collections.abc import Iterable

LOADER_CLASSES = {
    "pe": "ghidra.app.util.opinion.PeLoader",
    "elf": "ghidra.app.util.opinion.ElfLoader",
}
LIBRARY_PATTERN = re.compile(r"librar|link|search", re.IGNORECASE)

_COMMON = frozenset(
    {
        # AbstractProgramLoader
        "Apply Processor Defined Labels",
        "Anchor Processor Defined Labels",
        # AbstractLibrarySupportLoader (11.x / 12.x names) [I]
        "Load Libraries From Disk",
        "Load Local Libraries From Disk",
        "Load System Libraries From Disk",
        "Recursive Library Load Depth",
        "Library Destination Folder",
        "Link Existing Project Libraries",
        "Project Library Search Folder",
        "Mirror Library Disk Layout",
    }
)
KNOWN_OPTIONS: dict[str, frozenset[str]] = {
    "pe": _COMMON
    | {
        "Show Debug Line Number Info",
        "Parse CLI headers (if present)",
        "Parse CLI headers",
    },
    "elf": _COMMON
    | {
        "Perform Symbol Relocations",
        "Apply Undefined Symbol Data",
        "Image Base",
        "Data Image Base",
        "Include Other Blocks",
        "Max Zero-Segment Discard Size",
        "Import Symbols",
    },
}
TRUE_VALUES = frozenset({"true", "1", "yes"})


def is_enabled(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in TRUE_VALUES


def is_boolean(value: object) -> bool:
    return isinstance(value, bool) or str(value).strip().lower() in ("true", "false")


def is_library_option(name: str) -> bool:
    return LIBRARY_PATTERN.search(name) is not None


def loader_args(options: Iterable[tuple[str, object]]) -> list[tuple[str, str]]:
    """`(name, "false")` for every boolean library option among the defaults."""
    return [
        (name, "false") for name, value in options if is_library_option(name) and is_boolean(value)
    ]


def check_options(fmt: str, options: Iterable[tuple[str, object]]) -> list[str]:
    """Problems with the effective options (after `loader_args`), empty when loading may
    proceed: `unknown:<name>` or `enabled:<name>`."""
    known = KNOWN_OPTIONS[fmt]
    options = list(options)
    forced = dict(loader_args(options))
    problems: list[str] = []
    for name, value in options:
        if name not in known:
            problems.append(f"unknown:{name}")
            continue
        effective = forced.get(name, value)
        if is_library_option(name) and is_boolean(value) and is_enabled(effective):
            problems.append(f"enabled:{name}")
    return problems


__all__ = [
    "KNOWN_OPTIONS",
    "LIBRARY_PATTERN",
    "LOADER_CLASSES",
    "check_options",
    "is_enabled",
    "is_library_option",
    "loader_args",
]
