"""The frozen auto-analysis options (pure Python; RT19): the dangerous analyzers are off, a
missing required name fails the stage, optional names are set only when present."""

from re_worker.probe.analysis_options import OPTIONAL, REQUIRED, plan

PE_AVAILABLE = [
    "Decompiler Parameter ID",
    "Aggressive Instruction Finder",
    "PDB Universal",
    "Embedded Media",
    "Function ID",
    "Stack",
]


def test_pe_plan() -> None:
    values, missing = plan("pe", PE_AVAILABLE)
    assert missing == []
    assert values == {
        "Decompiler Parameter ID": False,
        "Aggressive Instruction Finder": False,
        "PDB Universal": False,
        "Embedded Media": False,
    }
    with_msdia, _ = plan("pe", [*PE_AVAILABLE, "PDB MSDIA"])
    assert with_msdia["PDB MSDIA"] is False


def test_missing_required_names_are_reported() -> None:
    values, missing = plan("elf", ["Decompiler Parameter ID", "DWARF"])
    assert missing == ["Aggressive Instruction Finder", "Embedded Media"]
    assert values == {"Decompiler Parameter ID": False, "DWARF": True}


def test_pdb_is_never_enabled() -> None:
    for fmt in ("pe", "elf"):
        for table in (REQUIRED, OPTIONAL):
            for name, value in table[fmt].items():
                if "PDB" in name or name in ("Aggressive Instruction Finder", "Embedded Media"):
                    assert value is False, name
