# ruff: noqa: E501 - test data tables (long literal command lines, paths and regions)
"""Unexpected-network and service-path detectors."""

from typing import Any

import pytest
from cyberlab_jobs.memory import MemoryProfile

from dataset.baselines import DEFENDER, WIN, Draft, driver, service, tcp, udp
from dataset.scenarios import LIMITS
from memory_worker import detections
from memory_worker.view import DetectionOutput

IMAGE: dict[str, Any] = {
    "kind": "image",
    "size_bytes": 1024,
    "sha256": "d" * 64,
    "layer": "WindowsIntel32e",
    "arch": "x64",
    "system_time": "2026-11-01T10:00:00Z",
}


def draft() -> Draft:
    d = Draft(os="windows", profile=MemoryProfile.TRIAGE, image=dict(IMAGE))
    d.add_process(544, 460, "wininit.exe", WIN + "wininit.exe", 0)
    d.add_process(696, 544, "lsass.exe", WIN + "lsass.exe", 0)
    d.add_process(3040, 2900, "explorer.exe", "C:\\Windows\\explorer.exe", 5)
    d.add_process(5300, 3040, "notepad.exe", WIN + "notepad.exe", 7)
    d.add_process(4400, 3040, "msedge.exe", "C:\\Program Files\\Edge\\msedge.exe", 6)
    return d


def run(d: Draft) -> DetectionOutput:
    return detections.run(d.view(), LIMITS)


def found(out: DetectionOutput) -> list[tuple[str, str, object]]:
    return [(f.type, f.severity, f.attributes.get("pid")) for f in out.findings]


# --- unexpected network ---------------------------------------------------------------


@pytest.mark.parametrize("remote", ["203.0.113.80", "198.51.100.1", "8.8.8.8", "2001:db8::5"])
def test_external_connection_of_a_quiet_program(remote: str) -> None:
    d = draft()
    d.connections.append(tcp(696, "lsass.exe", "10.0.0.15", 50433, remote, 443, minute=9))
    out = run(d)
    assert found(out) == [("mem_unexpected_network", "medium", 696)]
    assert str(out.findings[0].dst_ip) == remote and out.findings[0].dst_port == 443


def test_one_finding_per_process_lists_every_remote() -> None:
    d = draft()
    d.connections += [
        tcp(5300, "notepad.exe", "10.0.0.15", 50001, "203.0.113.1", 443),
        tcp(5300, "notepad.exe", "10.0.0.15", 50002, "203.0.113.2", 8443),
    ]
    out = run(d)
    assert found(out) == [("mem_unexpected_network", "medium", 5300)]
    assert out.findings[0].attributes["connections"] == 2
    assert "203.0.113.2:8443" in out.findings[0].description


@pytest.mark.parametrize(
    "conn",
    [
        tcp(696, "lsass.exe", "10.0.0.15", 49720, "10.0.0.2", 389),  # internal peer
        tcp(696, "lsass.exe", "10.0.0.15", 49721, "100.64.1.1", 389),  # CGNAT
        tcp(696, "lsass.exe", "127.0.0.1", 49722, "127.0.0.1", 389),  # loopback
        tcp(696, "lsass.exe", "0.0.0.0", 49664, state="LISTENING"),  # a listener
        tcp(696, "lsass.exe", "10.0.0.15", 49723, "203.0.113.9", 443, state="CLOSE_WAIT"),
        tcp(4400, "msedge.exe", "10.0.0.15", 49810, "203.0.113.44", 443),  # browsers talk
        udp(696, "lsass.exe", "0.0.0.0", 389),
    ],
)
def test_connections_outside_the_rule(conn: dict[str, Any]) -> None:
    d = draft()
    d.connections.append(conn)
    assert run(d).findings == []


def test_owner_falls_back_to_the_process_name() -> None:
    d = draft()
    conn = tcp(696, "lsass.exe", "10.0.0.15", 50433, "203.0.113.80", 443)
    conn["owner"] = None
    d.connections.append(conn)
    assert found(run(d)) == [("mem_unexpected_network", "medium", 696)]


# --- service paths --------------------------------------------------------------------


@pytest.mark.parametrize(
    "binary",
    [
        "C:\\ProgramData\\Updater\\upd.exe",
        '"C:\\Users\\Public\\svc.exe" -run',
        "C:\\Windows\\Temp\\x.exe",
        "C:\\Users\\bob\\AppData\\Roaming\\svc\\svc.exe /service",
    ],
)
def test_service_under_a_user_writable_directory(binary: str) -> None:
    d = draft()
    d.artifacts.append(service("UpdaterSvc", binary))
    out = run(d)
    assert [(f.type, f.severity) for f in out.findings] == [
        ("mem_service_user_writable_path", "low")
    ]
    assert "UpdaterSvc" in out.findings[0].description


@pytest.mark.parametrize(
    "binary",
    [
        f'"{DEFENDER}MsMpEng.exe"',
        "C:\\ProgramData\\Microsoft\\Windows Defender Advanced Threat Protection\\Platform\\10.8760\\MsSense.exe",
        "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
        '"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe"',
        "",
    ],
)
def test_services_outside_the_rule(binary: str) -> None:
    d = draft()
    d.artifacts.append(service("Svc", binary))
    assert run(d).findings == []


def test_defender_exclusion_needs_the_platform_directory() -> None:
    d = draft()
    d.artifacts.append(service("Fake", "C:\\ProgramData\\Microsoft\\Windows Defender\\evil.exe"))
    assert [f.type for f in run(d).findings] == ["mem_service_user_writable_path"]


@pytest.mark.parametrize(
    "binary",
    ["C:\\Users\\Public\\drv.sys", "\\SystemRoot\\Temp\\rk.sys", "\\??\\C:\\Windows\\drv.sys"],
)
def test_driver_outside_the_drivers_directory(binary: str) -> None:
    d = draft()
    d.artifacts.append(driver("drv", binary))
    assert [(f.type, f.severity) for f in run(d).findings] == [
        ("mem_driver_unexpected_path", "low")
    ]


@pytest.mark.parametrize(
    "binary",
    [
        "\\Driver\\Tcpip",
        "\\FileSystem\\Ntfs",
        "\\SystemRoot\\System32\\drivers\\tcpip.sys",
        "System32\\drivers\\vmci.sys",
        "\\SystemRoot\\system32\\drivers\\wd\\WdFilter.sys",
        "\\SystemRoot\\System32\\DriverStore\\FileRepository\\nv.inf_amd64_1\\nvlddmkm.sys",
    ],
)
def test_drivers_outside_the_rule(binary: str) -> None:
    d = draft()
    d.artifacts.append(driver("drv", binary))
    assert run(d).findings == []


def test_sys_binary_without_a_type_is_treated_as_a_driver() -> None:
    d = draft()
    record = driver("drv", "C:\\Users\\Public\\drv.sys")
    del record["attributes"]["type"]
    d.artifacts.append(record)
    assert [f.type for f in run(d).findings] == ["mem_driver_unexpected_path"]
