"""Loader choice and its options (pure Python; RT20): only PeLoader / ElfLoader, library
loading forced off, and any unknown or still-enabled library option fails closed."""

from re_worker.probe.loader_choice import (
    KNOWN_OPTIONS,
    LOADER_CLASSES,
    check_options,
    is_library_option,
    loader_args,
)

PE_DEFAULTS: list[tuple[str, object]] = [
    ("Apply Processor Defined Labels", True),
    ("Anchor Processor Defined Labels", True),
    ("Load Local Libraries From Disk", False),
    ("Load System Libraries From Disk", True),
    ("Recursive Library Load Depth", "1"),
    ("Library Destination Folder", "/"),
    ("Link Existing Project Libraries", True),
    ("Project Library Search Folder", ""),
    ("Show Debug Line Number Info", False),
]


def test_only_the_two_loader_classes() -> None:
    assert LOADER_CLASSES == {
        "pe": "ghidra.app.util.opinion.PeLoader",
        "elf": "ghidra.app.util.opinion.ElfLoader",
    }


def test_library_booleans_are_forced_off() -> None:
    forced = dict(loader_args(PE_DEFAULTS))
    assert forced == {
        "Load Local Libraries From Disk": "false",
        "Load System Libraries From Disk": "false",
        "Link Existing Project Libraries": "false",
    }
    assert check_options("pe", PE_DEFAULTS) == []


def test_unknown_options_fail_closed() -> None:
    problems = check_options("pe", [*PE_DEFAULTS, ("Fetch Symbols From Server", False)])
    assert problems == ["unknown:Fetch Symbols From Server"]
    assert check_options("elf", [("Show Debug Line Number Info", False)]) == [
        "unknown:Show Debug Line Number Info"
    ]


def test_library_pattern_and_known_sets() -> None:
    assert is_library_option("Load System Libraries From Disk")
    assert is_library_option("Link Existing Project Libraries")
    assert not is_library_option("Perform Symbol Relocations")
    assert "Perform Symbol Relocations" in KNOWN_OPTIONS["elf"]
    assert "Perform Symbol Relocations" not in KNOWN_OPTIONS["pe"]
