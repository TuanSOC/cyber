"""Suspicious API *sets*: the M3 data (`heuristic:suspicious_api@1`), lifted into the kit in
M10 phase 1 (RT7, the M8 IOC-extractor precedent) so the RE worker's per-function rule
(`heuristic:re_api_set_function@1`, phase 5) uses the same sets and semantics. Data only, no
finding logic: the static worker's `detections/apis.py` re-exports it unchanged.

Semantics: a set fires when every group of one `any_of` combination has at least one name
present; names carry both A / W variants where Windows has them; `RUN_KEY_FLAG` is a
pseudo-API (a Run / RunOnce registry path in the strings; for the RE rule: a Run-key string
referenced by the function).
"""

from dataclasses import dataclass
from typing import Literal

Severity = Literal["info", "low", "medium", "high"]
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


def api_names() -> frozenset[str]:
    """Every API name of every set (the pseudo-API excluded)."""
    return frozenset(
        name
        for api_set in API_SETS
        for group in api_set.groups.values()
        for name in group
        if name != RUN_KEY_FLAG
    )


__all__ = ["API_SETS", "RUN_KEY_FLAG", "ApiSet", "Severity", "api_names"]
