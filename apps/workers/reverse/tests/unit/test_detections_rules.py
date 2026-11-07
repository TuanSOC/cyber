"""Run-time API resolution, network-string functions, IOCs from referenced strings, caps and
determinism (M10 phase 5)."""

from cyberlab_worker.apisets import api_names

from dataset.generate import LIMITS, PIE_BASE, Builder, build
from re_worker import detections
from re_worker.detections.api_names import API_NAMES
from re_worker.detections.base import METHOD_NETWORK, METHOD_RESOLUTION


def _resolver(*strings: str, resolver: str = "GetProcAddress") -> Builder:
    b = Builder()
    b.fn("resolve", 0x100)
    b.imp(resolver, "resolve")
    for value in strings:
        b.string(value, "resolve")
    return b


def test_api_name_list() -> None:
    assert 1_500 <= len(API_NAMES) <= 2_500
    assert api_names() <= API_NAMES
    assert {"CreateFileA", "CreateFileW", "ZwMapViewOfSection", "dlsym", "socket"} <= API_NAMES
    assert "CreateFile" not in API_NAMES and "kernel32.dll" not in API_NAMES


def test_resolution_low_medium_and_near_misses() -> None:
    [low] = detections.run(_resolver("Sleep", "GetTickCount64", "lstrlenW").view(), LIMITS).findings
    assert (low.detection_method, low.severity, low.attributes["api_strings"]) == (
        METHOD_RESOLUTION,
        "low",
        3,
    )
    [medium] = detections.run(
        _resolver("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread").view(), LIMITS
    ).findings
    assert medium.severity == "medium" and medium.attributes["set"] == "api_injection"
    assert "3 of them belong to the process-injection set" in medium.description
    assert detections.run(_resolver("Sleep", "VirtualAllocEx").view(), LIMITS).findings == []
    no_resolver = _resolver("Sleep", "GetTickCount64", "lstrlenW", resolver="LoadLibraryW")
    assert detections.run(no_resolver.view(), LIMITS).findings == []
    # Exact names only: a sentence containing API names is not an API name.
    near = _resolver("call Sleep now", "GetTickCount64 ", "lstrlenW", "Sleep")
    assert detections.run(near.view(), LIMITS).findings == []


def test_dlsym_resolution() -> None:
    [finding] = detections.run(
        _resolver("socket", "connect", "execve", resolver="dlsym").view(), LIMITS
    ).findings
    assert finding.type == "runtime_api_resolution" and finding.severity == "low"


def test_network_string_function_and_near_misses() -> None:
    [finding] = detections.run(build("pos_network_elf").view, LIMITS).findings
    assert (finding.detection_method, finding.severity) == (METHOD_NETWORK, "low")
    assert finding.attributes["indicators"] == "192.0.2.10"
    assert "connect" in finding.attributes["apis"]
    assert detections.run(build("nm_network_api_no_string").view, LIMITS).findings == []
    assert detections.run(build("nm_url_no_network_api").view, LIMITS).findings == []
    b = Builder()
    b.fn("updater", 0x80)
    b.imp("WinHttpSendRequest", "updater", library="WINHTTP.dll")
    b.string("https://cyberlab-re.example/u", "updater")
    [winhttp] = detections.run(b.view(), LIMITS).findings
    assert winhttp.type == "network_string_function"


def test_iocs_come_from_referenced_strings_only() -> None:
    b = Builder()
    b.fn("user", 0x40)
    b.string("http://198.51.100.9/a", "user")
    b.string("http://198.51.100.10/unreferenced")
    b.string("HKCU\\Software\\CyberLab\\x", "user")  # registry keys are not RE IOCs
    out = detections.run(b.view(), LIMITS)
    assert {(i.type, i.value) for i in out.iocs} == {
        ("url", "http://198.51.100.9/a"),
        ("ip", "198.51.100.9"),
    }
    assert all(i.source == "re_string" for i in out.iocs)


def test_caps_set_truncated() -> None:
    b = Builder()
    for i in range(5):
        b.fn(f"f{i}", 0x40)
        b.imp("IsDebuggerPresent", f"f{i}")
        b.imp("NtQueryInformationProcess", f"f{i}")
        b.string(f"http://198.51.100.{i + 1}/x", f"f{i}")
    limits = LIMITS.model_copy(update={"max_findings": 2, "max_iocs": 3})
    out = detections.run(b.view(), limits)
    assert len(out.findings) == 2 and len(out.iocs) == 3 and out.truncated
    full = detections.run(b.view(), LIMITS)
    assert len(full.findings) == 5 and len(full.iocs) == 10 and not full.truncated


def test_findings_are_deterministic_and_well_formed() -> None:
    view = build("pos_injection").view
    first = detections.run(view, LIMITS)
    second = detections.run(view, LIMITS)
    assert [f.finding_id for f in first.findings] == [f.finding_id for f in second.findings]
    for finding in first.findings:
        entry = int(str(finding.attributes["function_entry"]), 16)
        assert entry in view.functions
        assert finding.evidence_refs[0] == f"function:0x{entry:x}"


def test_elf_findings_cite_engine_addresses() -> None:
    view = build("pos_network_elf").view
    [finding] = detections.run(view, LIMITS).findings
    assert int(str(finding.attributes["function_entry"]), 16) > PIE_BASE
