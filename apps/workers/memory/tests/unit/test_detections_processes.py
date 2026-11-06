"""Process detectors: hidden process, lineage, masquerade (positive, near-miss, boundary)."""

from typing import Any

import pytest
from cyberlab_jobs.memory import MemoryPlugin, MemoryProfile

from dataset.baselines import WIN, Draft
from dataset.scenarios import LIMITS
from memory_worker import detections
from memory_worker.detections import masquerade
from memory_worker.view import DetectionOutput

IMAGE: dict[str, Any] = {
    "kind": "image",
    "size_bytes": 1024,
    "sha256": "a" * 64,
    "layer": "WindowsIntel32e",
    "arch": "x64",
    "system_time": "2026-11-01T10:00:00Z",
}


def core_draft() -> Draft:
    d = Draft(os="windows", profile=MemoryProfile.TRIAGE, image=dict(IMAGE))
    d.add_process(4, 0, "System", None, 0, cmdline="")
    d.add_process(356, 4, "smss.exe", "\\SystemRoot\\System32\\smss.exe", 0)
    d.add_process(460, 356, "smss.exe", "\\SystemRoot\\System32\\smss.exe", 0)
    d.add_process(544, 460, "wininit.exe", WIN + "wininit.exe", 0)
    d.add_process(552, 460, "csrss.exe", WIN + "csrss.exe", 0)
    d.add_process(676, 544, "services.exe", WIN + "services.exe", 0)
    d.add_process(696, 544, "lsass.exe", WIN + "lsass.exe", 0)
    d.add_process(800, 676, "svchost.exe", WIN + "svchost.exe", 1)
    d.add_process(3040, 2900, "explorer.exe", "C:\\Windows\\explorer.exe", 5)
    return d


def run(d: Draft) -> DetectionOutput:
    return detections.run(d.view(), LIMITS)


def kinds(out: DetectionOutput) -> list[tuple[str, object]]:
    return sorted((f.type, f.attributes.get("pid")) for f in out.findings)


def test_clean_core_tree_has_no_finding() -> None:
    assert run(core_draft()).findings == []


# --- hidden ---------------------------------------------------------------------------


def test_psscan_only_running_process_is_reported() -> None:
    d = core_draft()
    d.add_process(7000, 3040, "tool.exe", "C:\\tools\\tool.exe", 9, sources=("psscan",), threads=1)
    out = run(d)
    assert kinds(out) == [("mem_hidden_process", 7000)]
    finding = out.findings[0]
    assert finding.severity == "medium" and finding.detection_method.startswith("heuristic:")
    assert "pid:7000" in finding.evidence_refs


@pytest.mark.parametrize(
    "extra",
    [
        {"exit_minute": 9},  # exited
        {"threads": 0},  # pool remnant
    ],
)
def test_exited_or_threadless_psscan_process_is_not_hidden(extra: dict[str, Any]) -> None:
    d = core_draft()
    d.add_process(7000, 3040, "tool.exe", "C:\\tools\\tool.exe", 9, sources=("psscan",), **extra)
    assert run(d).findings == []


def test_same_process_merged_twice_is_not_hidden() -> None:
    d = core_draft()
    listed = d.add_process(7000, 3040, "tool.exe", "C:\\tools\\tool.exe", 9)
    twin = dict(listed, sources=["psscan"], offset=0x1E3A_0080)
    d.processes.append(twin)
    assert run(d).findings == []


def test_capped_pslist_silences_the_hidden_rule() -> None:
    d = core_draft()
    d.add_process(7000, 3040, "tool.exe", "C:\\tools\\tool.exe", 9, sources=("psscan",), threads=2)
    d.truncated.add(MemoryPlugin.WINDOWS_PSLIST.value)
    assert run(d).findings == []


def test_linux_views_never_report_hidden_processes() -> None:
    d = Draft(os="linux", profile=MemoryProfile.TRIAGE, image=dict(IMAGE, layer="LimeLayer"))
    d.add_process(1, 0, "systemd", None, 0, sources=("psscan",), threads=1)
    assert run(d).findings == []


# --- lineage --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pid", "new_ppid"),
    [
        (696, 676),  # lsass.exe under services.exe
        (800, 544),  # svchost.exe under wininit.exe
        (544, 4),  # wininit.exe under System
        (676, 356),  # services.exe under smss.exe
    ],
)
def test_unexpected_parent(pid: int, new_ppid: int) -> None:
    d = core_draft()
    d.proc(pid)["ppid"] = new_ppid
    out = run(d)
    assert kinds(out) == [("mem_process_lineage", pid)]
    assert out.findings[0].attributes["ppid"] == new_ppid


def test_parent_pid_held_by_a_later_process_is_a_reused_pid() -> None:
    d = core_draft()
    d.proc(676)["ppid"] = 3040  # explorer.exe was created after services.exe
    assert run(d).findings == []


def test_parent_created_before_child_but_wrong_fires() -> None:
    d = core_draft()
    d.add_process(7100, 3040, "lsass.exe", WIN + "lsass.exe", 9)
    found = kinds(run(d))
    assert ("mem_process_lineage", 7100) in found
    assert ("mem_core_process_count", None) in found


def test_missing_parent_never_fires() -> None:
    d = core_draft()
    d.proc(544)["ppid"] = 9999
    d.proc(552)["ppid"] = 9999
    d.proc(696)["ppid"] = 9999
    assert run(d).findings == []


def test_exited_session_smss_parent_is_fine() -> None:
    d = core_draft()
    d.proc(460)["exit_time"] = "2026-11-01T08:00:40Z"
    d.proc(460)["sources"] = ["psscan"]
    assert run(d).findings == []


def test_smss_must_descend_from_system_pid_4() -> None:
    d = core_draft()
    d.processes.insert(0, {**d.proc(4), "pid": 8, "name": "System", "offset": 1})
    d.proc(356)["ppid"] = 8
    assert kinds(run(d)) == [("mem_process_lineage", 356)]


def test_singleton_count_boundary() -> None:
    d = core_draft()
    d.add_process(7200, 544, "services.exe", WIN + "services.exe", 9, exit_minute=9)
    assert run(d).findings == []  # an exited second instance is not running
    d.add_process(7204, 544, "services.exe", WIN + "services.exe", 9)
    out = run(d)
    assert kinds(out) == [("mem_core_process_count", None)]
    assert out.findings[0].attributes["count"] == 2


# --- masquerade -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "core"),
    [
        ("scvhost.exe", "svchost.exe"),
        ("lsas.exe", "lsass.exe"),
        ("svch0st.exe", "svchost.exe"),
        ("SVCHOST.EX", "svchost.exe"),
        ("expl0rer.exe", "explorer.exe"),
    ],
)
def test_lookalike_names(name: str, core: str) -> None:
    d = core_draft()
    d.add_process(7300, 676, name, f"C:\\Windows\\{name}", 9)
    out = run(d)
    assert kinds(out) == [("mem_name_similar_to_core", 7300)]
    assert out.findings[0].attributes["core_name"] == core


@pytest.mark.parametrize(
    "name",
    ["LsaIso.exe", "sihost.exe", "iexplore.exe", "taskhost.exe", "dllhost.exe", "conhost.exe",
     "csrss.exe", "svchost.exe", "fontdrvhost.exe", "notepad.exe", "scvhosts.exes"],
)
def test_names_that_are_not_lookalikes(name: str) -> None:
    d = core_draft()
    d.add_process(7300, 676, name, WIN + name, 9)
    assert [f for f in run(d).findings if f.type == "mem_name_similar_to_core"] == []


@pytest.mark.parametrize(
    "path",
    [
        "C:\\Users\\Public\\svchost.exe",
        "C:\\Windows\\Temp\\svchost.exe",
        "C:\\Users\\Public\\Windows\\System32\\svchost.exe",  # a fake System32 deeper down
        "C:\\Windows\\System32\\drivers\\svchost.exe",
    ],
)
def test_core_name_from_an_unexpected_directory(path: str) -> None:
    d = core_draft()
    d.proc(800)["image_path"] = path
    assert kinds(run(d)) == [("mem_core_name_unexpected_path", 800)]


@pytest.mark.parametrize(
    "path",
    [
        "C:\\Windows\\System32\\svchost.exe",
        "D:\\WINDOWS\\system32\\svchost.exe",
        "\\SystemRoot\\System32\\svchost.exe",
        "\\??\\C:\\Windows\\system32\\svchost.exe",
        "\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\SysWOW64\\svchost.exe",
    ],
)
def test_core_name_in_its_directory(path: str) -> None:
    d = core_draft()
    d.proc(800)["image_path"] = path
    assert run(d).findings == []


def test_explorer_lives_in_the_windows_directory() -> None:
    assert masquerade.directory("C:\\Windows\\explorer.exe") in masquerade.CORE_DIRS["explorer.exe"]
    d = core_draft()
    d.proc(3040)["image_path"] = "C:\\Windows\\System32\\explorer.exe"
    assert kinds(run(d)) == [("mem_core_name_unexpected_path", 3040)]


def test_edit_distance_bound() -> None:
    assert masquerade.distance("svchost.exe", "svchost.exe") == 0
    assert masquerade.distance("scvhost.exe", "svchost.exe") == 2
    assert masquerade.distance("abcdefgh.exe", "svchost.exe") == masquerade.MAX_DISTANCE + 1
