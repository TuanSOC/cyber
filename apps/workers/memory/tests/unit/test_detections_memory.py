# ruff: noqa: E501 - test data tables (long literal command lines, paths and regions)
"""Memory-region and module detectors: private executable regions (malfind) and modules
unlinked from all loader lists (ldrmodules)."""

from typing import Any

import pytest
from cyberlab_jobs.memory import MemoryInjectionRecord, MemoryOs, MemoryProfile

from dataset.baselines import WIN, Draft, ldr, region
from dataset.scenarios import LIMITS, MZ_HEAD, SHELLCODE_HEAD
from memory_worker import detections
from memory_worker.detections.injected import pe_header
from memory_worker.view import DetectionOutput

IMAGE: dict[str, Any] = {
    "kind": "image",
    "size_bytes": 1024,
    "sha256": "b" * 64,
    "layer": "WindowsIntel32e",
    "arch": "x64",
    "system_time": "2026-11-01T10:00:00Z",
}


def draft(os: MemoryOs = "windows") -> Draft:
    d = Draft(os=os, profile=MemoryProfile.FULL, image=dict(IMAGE))
    d.add_process(3040, 2900, "explorer.exe", "C:\\Windows\\explorer.exe", 5)
    d.add_process(4400, 3040, "msedge.exe", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", 6)
    d.add_process(5300, 3040, "notepad.exe", WIN + "notepad.exe", 7)
    return d


def run(d: Draft) -> DetectionOutput:
    return detections.run(d.view(), LIMITS)


def found(out: DetectionOutput) -> list[tuple[str, str, object]]:
    return [(f.type, f.severity, f.attributes.get("pid")) for f in out.findings]


# --- private executable regions -------------------------------------------------------


def test_region_with_mz_header_is_medium() -> None:
    d = draft()
    d.injections.append(region(3040, "explorer.exe", 0x520000, 0x1D000, "PAGE_EXECUTE_READWRITE", MZ_HEAD))
    out = run(d)
    assert found(out) == [("mem_private_exec_pe", "medium", 3040)]
    finding = out.findings[0]
    assert finding.title == "Private executable memory region with a PE header"
    assert "region:0x520000-0x53cfff" in finding.evidence_refs


def test_pe_signature_at_in_bounds_e_lfanew() -> None:
    head = bytearray(64)
    head[0:2] = b"MZ"
    head[0x3C:0x40] = (0x30).to_bytes(4, "little")
    head[0x30:0x34] = b"PE\0\0"
    d = draft()
    d.injections.append(region(5300, "notepad.exe", 0x10000, 0x1000, "PAGE_EXECUTE_READWRITE", head.hex()))
    out = run(d)
    assert found(out) == [("mem_private_exec_pe", "medium", 5300)]
    assert "a PE header" in out.findings[0].description


def test_without_mz_the_e_lfanew_field_is_not_trusted() -> None:
    head = bytearray(64)
    head[0x3C:0x40] = (0x30).to_bytes(4, "little")
    head[0x30:0x34] = b"PE\0\0"
    # No MZ, and a region smaller than e_lfanew + 4: neither rule holds.
    record = MemoryInjectionRecord(pid=1, start=0, end=0x2F, head_hex=head.hex()[:96])
    assert pe_header(record) is None


def test_shellcode_region_without_header_is_low() -> None:
    d = draft()
    d.injections.append(region(5300, "notepad.exe", 0x1F45A300000, 0x1000, "PAGE_EXECUTE_READWRITE", SHELLCODE_HEAD))
    assert found(run(d)) == [("mem_private_exec_region", "low", 5300)]


def test_jit_host_region_without_header_is_skipped_but_with_header_is_not() -> None:
    d = draft()
    d.injections.append(region(4400, "msedge.exe", 0x2A400000000, 0x10000, "PAGE_EXECUTE_READWRITE", SHELLCODE_HEAD))
    assert run(d).findings == []
    d.injections.append(region(4400, "msedge.exe", 0x2A500000000, 0x10000, "PAGE_EXECUTE_READWRITE", MZ_HEAD))
    assert found(run(d)) == [("mem_private_exec_pe", "medium", 4400)]


@pytest.mark.parametrize(
    ("protection", "private"),
    [
        ("PAGE_EXECUTE_READ", True),  # not writable
        ("PAGE_READWRITE", True),  # not executable
        ("PAGE_EXECUTE_WRITECOPY", False),  # image-backed
        (None, True),
    ],
)
def test_regions_outside_the_rule(protection: str | None, private: bool) -> None:
    d = draft()
    record = region(5300, "notepad.exe", 0x10000, 0x1000, protection or "", MZ_HEAD, private=private)
    record["protection"] = protection
    d.injections.append(record)
    assert run(d).findings == []


def test_private_flag_missing_falls_back_to_the_vads_tag() -> None:
    d = draft()
    record = region(5300, "notepad.exe", 0x10000, 0x1000, "PAGE_EXECUTE_READWRITE", SHELLCODE_HEAD)
    record["private"] = None
    d.injections.append(record)
    assert found(run(d)) == [("mem_private_exec_region", "low", 5300)]


def test_linux_rwx_flags() -> None:
    d = draft("linux")
    d.injections.append(region(5300, "notepad.exe", 0x10000, 0x1000, "rwx", SHELLCODE_HEAD))
    d.injections.append(region(5300, "notepad.exe", 0x20000, 0x1000, "r-x", SHELLCODE_HEAD))
    assert found(run(d)) == [("mem_private_exec_region", "low", 5300)]


def test_no_title_says_injected_code() -> None:
    d = draft()
    d.injections.append(region(5300, "notepad.exe", 0x10000, 0x1000, "PAGE_EXECUTE_READWRITE", SHELLCODE_HEAD))
    d.injections.append(region(3040, "explorer.exe", 0x20000, 0x1000, "PAGE_EXECUTE_READWRITE", MZ_HEAD))
    for finding in run(d).findings:
        assert "inject" not in (finding.title + finding.description).lower()


# --- unlinked modules -----------------------------------------------------------------


def test_module_missing_from_all_lists_is_reported() -> None:
    d = draft()
    d.artifacts.append(ldr(3040, "C:\\Users\\alice\\AppData\\Local\\Temp\\msupd.dll", 0x6A400000, False, False, False))
    out = run(d)
    assert found(out) == [("mem_unlinked_module", "medium", 3040)]
    assert "msupd.dll" in out.findings[0].description


@pytest.mark.parametrize(
    ("path", "lists"),
    [
        (WIN + "ntdll.dll", (True, True, True)),
        (WIN + "evil.dll", (False, True, False)),  # in one list: not unlinked from all three
        (WIN + "en-US\\explorer.exe.mui", (False, False, False)),  # mapped data file
        (WIN + "locale.nls", (False, False, False)),
        ("C:\\Windows\\explorer.exe", (False, False, False)),  # the process's own image
        ("", (False, False, False)),  # no mapped path
    ],
)
def test_modules_outside_the_rule(path: str, lists: tuple[bool, bool, bool]) -> None:
    d = draft()
    d.artifacts.append(ldr(3040, path, 0x10000, *lists))
    assert run(d).findings == []


def test_own_image_by_name_when_paths_differ() -> None:
    d = draft()
    d.artifacts.append(ldr(5300, "\\Device\\HarddiskVolume3\\Windows\\System32\\notepad.exe", 0x10000, False, False, False))
    assert run(d).findings == []
