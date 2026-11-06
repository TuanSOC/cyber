# ruff: noqa: E501 - literal rows
"""Windows normalizers over the replay row fixtures (pure Python): the stream validates
against the frozen contract, reproduces the phase-1 fixture counts, and carries the attribute
keys the phase-3 detectors read (services name / state / binary / type; ldr_unlinked
in_load / in_init / in_mem / path / base)."""

from pathlib import Path
from typing import Any

from cyberlab_jobs.memory import MemoryPlugin

from memory_worker.normalize.models import COLUMNS
from tests.replay_helpers import (
    LIMITS,
    artifact_types,
    contract_fixture_counts,
    kinds,
    normalized,
    run_scenario,
    scenario_rows,
)

P = MemoryPlugin
RECORD_KINDS = ("process", "connection", "injection", "artifact")


def _row(plugin: MemoryPlugin, **values: Any) -> dict[str, Any]:
    return {column: None for column in COLUMNS[plugin]} | values


def test_full_profile_matches_the_phase_1_fixture_counts(tmp_path: Path) -> None:
    lines = run_scenario("windows", "full", tmp_path / "r.gz")
    fixture, fixture_artifacts = contract_fixture_counts("windows_triage.ndjson")
    got = kinds(lines)
    assert {k: got[k] for k in RECORD_KINDS} == {k: fixture[k] for k in RECORD_KINDS}
    assert artifact_types(lines) == fixture_artifacts
    assert lines[0].kind == "header" and lines[0].engine == "replay"
    assert lines[1].kind == "image" and lines[-1].kind == "trailer"
    assert [p.status for p in lines[0].plugins] == ["ok"] * 11
    assert lines[0].engine_errors == [] and lines[0].truncated == {}


def test_triage_is_the_fixture_without_the_loader_check(tmp_path: Path) -> None:
    lines = run_scenario("windows", "triage", tmp_path / "r.gz")
    _, fixture_artifacts = contract_fixture_counts("windows_triage.ndjson")
    del fixture_artifacts["ldr_unlinked"]
    assert artifact_types(lines) == fixture_artifacts
    assert len(lines[0].plugins) == 10


def test_image_facts_come_from_identify_and_info(tmp_path: Path) -> None:
    image = run_scenario("windows", "triage", tmp_path / "r.gz")[1]
    assert image.layer == "WindowsCrashDump64Layer>WindowsIntel32e" and image.arch == "x64"
    assert image.nt_build == "19041"
    assert image.system_time.isoformat() == "2026-11-01T09:30:00+00:00"
    assert image.pdb.name == "ntkrnlmp.pdb" and image.kernel_banner is None


def test_processes_merge_scan_and_list_and_join_cmdline_and_image() -> None:
    out = normalized("windows", scenario_rows("windows"))
    by_pid = {p.pid: p for p in out.processes}
    assert len(out.processes) == 40
    assert by_pid[6112].sources == ["psscan"] and by_pid[6112].cmdline is None
    assert all(p.sources == ["pslist", "psscan"] for p in out.processes if p.pid != 6112)
    assert (by_pid[5260].cmdline or "").startswith("powershell.exe -nop -w hidden -enc")
    assert by_pid[3040].image_path == "C:\\Windows\\Explorer.EXE"
    assert by_pid[4].image_path is None and by_pid[4].exit_time is None
    assert by_pid[4].offset == 0xFFFF_A08F_0000_0000


def test_a_scan_hit_under_another_offset_is_the_same_process() -> None:
    rows = scenario_rows("windows")
    twin = dict(rows[P.WINDOWS_PSSCAN][0])
    twin["Offset(V)"] = 0x1234_0000  # physical-looking offset, same pid and create time
    rows[P.WINDOWS_PSSCAN] = [twin, *rows[P.WINDOWS_PSSCAN][1:]]
    out = normalized("windows", rows)
    system = [p for p in out.processes if p.pid == 4]
    assert len(system) == 1 and system[0].sources == ["pslist", "psscan"]


def test_service_artifacts_carry_the_detector_keys() -> None:
    out = normalized("windows", scenario_rows("windows"))
    services = {a.attributes["name"]: a for a in out.artifacts if a.type == "service"}
    spooler = services["Spooler"]
    assert {"name", "state", "binary", "type"} <= set(spooler.attributes)
    assert spooler.pid == 1388 and spooler.attributes["state"] == "SERVICE_RUNNING"
    assert spooler.attributes["type"] == "SERVICE_WIN32_OWN_PROCESS"
    # No Binary column value: the registry ImagePath is used; no PID: none.
    updater = services["UpdaterSvc"]
    assert updater.attributes["binary"] == "C:\\ProgramData\\Updater\\upd.exe"
    assert updater.pid is None and "dll" not in updater.attributes


def test_loader_rows_carry_the_detector_keys_and_linked_modules_are_dropped() -> None:
    out = normalized("windows", scenario_rows("windows"))
    unlinked = [a for a in out.artifacts if a.type == "ldr_unlinked"]
    assert len(unlinked) == 1
    assert unlinked[0].pid == 6112
    assert unlinked[0].attributes == {
        "base": 4194304,
        "in_load": False,
        "in_init": False,
        "in_mem": False,
        "path": "C:\\Users\\Public\\x.dll",
    }


def test_other_artifacts() -> None:
    out = normalized("windows", scenario_rows("windows"))
    by_type = {a.type: a for a in out.artifacts}
    assert by_type["module"].attributes["path"] == "C:\\Windows\\System32\\ntdll.dll"
    assert by_type["module"].pid == 4388  # the main images are the processes' image_path
    # A kernel address above the bigint range is kept as text.
    assert by_type["hive"].attributes["offset"] == "0xfffff8a000024010"
    ua = by_type["userassist"].attributes
    assert ua["path"] == "C:\\Users\\Public\\svch0st.exe" and ua["count"] == 3
    assert ua["last_updated"] == "2026-11-01T08:59:00Z"


def test_connections_and_injections() -> None:
    out = normalized("windows", scenario_rows("windows"))
    tcp, listen, udp = out.connections
    assert (tcp.proto, str(tcp.remote_addr), tcp.remote_port, tcp.state) == (
        "tcp",
        "203.0.113.50",
        443,
        "ESTABLISHED",
    )
    assert listen.remote_addr is None and listen.remote_port is None and listen.state == "LISTENING"
    assert udp.proto == "udp" and udp.remote_addr is None and udp.state is None
    (region,) = out.injections
    assert region.has_pe and region.private and region.head_hex.startswith("4d5a")
    assert (region.start, region.end, region.tag) == (0x400000, 0x40FFFF, "VadS")


def test_bad_rows_are_skipped_and_counted_never_fatal() -> None:
    rows = scenario_rows("windows")
    rows[P.WINDOWS_PSLIST] = [
        *rows[P.WINDOWS_PSLIST],
        _row(P.WINDOWS_PSLIST, PID="6666", ImageFileName="x.exe"),  # string pid
        _row(P.WINDOWS_PSLIST, PID=7777, ImageFileName={"nested": "x"}),  # nested object
        _row(P.WINDOWS_PSLIST, PID=True, ImageFileName="bool.exe"),  # bool for an int
        _row(P.WINDOWS_PSLIST, PID=8888, ImageFileName="ok.exe", Extra=1),  # unknown column
        _row(P.WINDOWS_PSLIST, PID=2**40, ImageFileName="huge.exe"),  # pid out of range
    ]
    rows[P.WINDOWS_MALFIND] = [_row(P.WINDOWS_MALFIND, PID=1, **{"Start VPN": 10, "End VPN": 5})]
    out = normalized("windows", rows)
    assert out.skipped["windows.pslist"] == 3 and out.unknown_columns["windows.pslist"] == 1
    assert out.skipped["windows.malware.malfind"] == 1 and out.injections == []
    pids = {p.pid for p in out.processes}
    assert 8888 in pids and 2**40 not in pids


def test_caps_bound_every_kind() -> None:
    limits = LIMITS.model_copy(
        update={"max_processes": 5, "max_artifacts": 2, "max_connections": 1}
    )
    out = normalized("windows", scenario_rows("windows"), limits)
    assert len(out.processes) == 5 and len(out.artifacts) == 2 and len(out.connections) == 1
    assert out.capped == {"processes", "artifacts", "connections"}


def test_oversized_attributes_are_shortened_to_fit_the_column() -> None:
    wide = "\u8def" * 1024  # 3 bytes each in UTF-8: three of them exceed the 4 KiB column
    value = _row(P.WINDOWS_USERASSIST, Type="Value", Name=wide, **{"Hive Name": wide, "Path": wide})
    (entry,) = normalized("windows", {P.WINDOWS_USERASSIST: [value]}).artifacts
    assert entry.type == "userassist" and len(str(entry.attributes["path"])) == 256
