"""The frozen auto-analysis options (M10 phase 2; RT19). Pure Python, unit-tested.

Set on the program's `Program.ANALYSIS_PROPERTIES` before `analyze`; everything else stays
at Ghidra's defaults:
- "Decompiler Parameter ID" off (it runs the decompiler over every function: slow, and the
  decompile stage does that work under its own limits);
- "Aggressive Instruction Finder" off (disassembles data as code on hostile inputs);
- "PDB Universal" / "PDB MSDIA" off: the PE CodeView path is attacker-chosen and is never
  opened (the spike's strace checks a PE whose PDB path is `/etc/passwd`);
- "Embedded Media" off;
- ELF: "DWARF" on (the binary's own sections only); no external debug-file search and no
  debuginfod (nothing configured in the stage's fresh home, and no network at all).

`plan(fmt, available)` returns the values to set and the names that are missing. A missing
REQUIRED name fails the stage `re_parse_failed` (reason `unknown_analysis_option`), so a
Ghidra upgrade cannot silently drop a setting; OPTIONAL names are analyzers Ghidra registers
only on some platforms or formats (set when present). Names are 12.x [I: PROVISIONAL until
the spike confirms them on 12.2].
"""

from collections.abc import Iterable

REQUIRED: dict[str, dict[str, bool]] = {
    "pe": {
        "Decompiler Parameter ID": False,
        "Aggressive Instruction Finder": False,
        "PDB Universal": False,
        "Embedded Media": False,
    },
    "elf": {
        "Decompiler Parameter ID": False,
        "Aggressive Instruction Finder": False,
        "Embedded Media": False,
        "DWARF": True,
    },
}
OPTIONAL: dict[str, dict[str, bool]] = {
    "pe": {"PDB MSDIA": False, "PDB": False},
    "elf": {"PDB Universal": False, "PDB MSDIA": False},
}


def plan(fmt: str, available: Iterable[str]) -> tuple[dict[str, bool], list[str]]:
    names = set(available)
    required = REQUIRED[fmt]
    missing = sorted(name for name in required if name not in names)
    values = dict(required)
    values.update({n: v for n, v in OPTIONAL[fmt].items() if n in names})
    return {n: v for n, v in values.items() if n in names}, missing


__all__ = ["OPTIONAL", "REQUIRED", "plan"]
