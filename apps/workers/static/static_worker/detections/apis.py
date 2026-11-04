"""Suspicious API *sets* (heuristic:suspicious_api@1).

Each category fires only on a combination of API groups (`any_of`: every group of one
combination present), never on a single API: one API name says nothing on its own. Import
evidence alone is capped at `medium`.
"""

from dataclasses import dataclass

from static_worker.detections.base import HEURISTIC_MAX, Finding, Severity, cap, joined, refs

METHOD = "heuristic:suspicious_api@1"
RUN_KEY_FLAG = "string:run_key"  # pseudo-API: a Run / RunOnce registry path is in the strings


def _aw(*names: str) -> frozenset[str]:
    """Both ANSI and wide variants of each name."""
    return frozenset(n + suffix for n in names for suffix in ("A", "W"))


@dataclass(frozen=True)
class ApiSet:
    type: str
    severity: Severity
    confidence: float
    groups: dict[str, frozenset[str]]
    any_of: tuple[frozenset[str], ...]


API_SETS = (
    ApiSet(
        "api_injection", "medium", 0.7,
        {
            "remote_memory": frozenset({
                "VirtualAllocEx", "VirtualAllocExNuma", "NtAllocateVirtualMemory",
                "ZwAllocateVirtualMemory", "NtMapViewOfSection", "ZwMapViewOfSection",
                "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
            }),
            "remote_write": frozenset({
                "WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory",
            }),
            "remote_execute": frozenset({
                "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
                "ZwCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread",
                "SetThreadContext", "NtSetContextThread", "Wow64SetThreadContext",
            }),
        },
        (frozenset({"remote_memory", "remote_write", "remote_execute"}),),
    ),
    ApiSet(
        "api_keylogging", "medium", 0.6,
        {
            "hook": _aw("SetWindowsHookEx"),
            "key_state": frozenset({"GetAsyncKeyState", "GetKeyState", "GetKeyboardState"}),
            "raw_input": frozenset({"RegisterRawInputDevices", "GetRawInputData"}),
        },
        (frozenset({"hook", "key_state"}), frozenset({"hook", "raw_input"})),
    ),
    ApiSet(
        "api_anti_debug", "low", 0.5,
        {
            "check": frozenset({"IsDebuggerPresent", "CheckRemoteDebuggerPresent"}),
            "query": frozenset({
                "NtQueryInformationProcess", "ZwQueryInformationProcess",
                "NtSetInformationThread", "ZwSetInformationThread",
            }),
        },
        (frozenset({"check", "query"}),),
    ),
    ApiSet(
        "api_credential_access", "medium", 0.6,
        {
            "vault": _aw("CredEnumerate", "CredRead"),
            "dpapi": frozenset({"CryptUnprotectData"}),
            "lsa": frozenset({
                "LsaRetrievePrivateData", "LsaEnumerateLogonSessions", "SamIConnect",
                "SamrQueryInformationUser",
            }),
            "dump": frozenset({"MiniDumpWriteDump"}),
        },
        tuple(
            frozenset({a, b})
            for i, a in enumerate(("vault", "dpapi", "lsa", "dump"))
            for b in ("vault", "dpapi", "lsa", "dump")[i + 1 :]
        ),
    ),
    ApiSet(
        "api_persistence", "low", 0.5,
        {
            "registry_write": _aw("RegSetValueEx", "RegSetKeyValue", "RegCreateKeyEx"),
            "run_key": frozenset({RUN_KEY_FLAG}),
            "service_create": _aw("CreateService"),
            "service_manager": _aw("OpenSCManager"),
        },
        (
            frozenset({"registry_write", "run_key"}),
            frozenset({"service_create", "service_manager"}),
        ),
    ),
    ApiSet(
        "api_downloader", "low", 0.5,
        {
            "download": _aw("URLDownloadToFile", "URLDownloadToCacheFile", "InternetOpenUrl",
                            "HttpOpenRequest") | frozenset({"WinHttpOpenRequest"}),
            "execute": _aw("ShellExecute", "ShellExecuteEx", "CreateProcess")
            | frozenset({"WinExec"}),
        },
        (frozenset({"download", "execute"}),),
    ),
)  # fmt: skip


def detect(apis: set[str]) -> list[Finding]:
    """`apis`: imported function names (plus pseudo-API flags such as RUN_KEY_FLAG)."""
    findings = []
    for api_set in API_SETS:
        present = {name: sorted(group & apis) for name, group in api_set.groups.items()}
        combos = [c for c in api_set.any_of if all(present[g] for g in c)]
        if not combos:
            continue
        groups = sorted(set().union(*combos))
        matched = [api for g in groups for api in present[g] if api != RUN_KEY_FLAG]
        evidence = matched + (["Run-key path in strings"] if RUN_KEY_FLAG in apis else [])
        findings.append(
            Finding(
                type=api_set.type,
                severity=cap(api_set.severity, HEURISTIC_MAX),
                confidence=min(0.9, api_set.confidence + 0.05 * (len(matched) - len(groups))),
                method=METHOD,
                values={"apis": joined(evidence, 900)},
                refs=refs([f"import:{api}" for api in matched]),
                attributes={
                    "apis": joined(evidence),
                    "api_count": len(matched),
                    "groups": joined(groups),
                },
            )
        )
    return findings
