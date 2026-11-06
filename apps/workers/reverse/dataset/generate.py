# ruff: noqa: E501 - synthetic record builders, one record per line
"""Labelled RE scenarios (M10 phase 5): generated `ReView`s, no engine, no binary.

    build(name) -> Scenario(view, job)      SCENARIOS: name -> builder

Each scenario is a small synthetic program written as `re.v1` records through `Builder`
(functions laid out from the image base, imports with their calling functions, strings with
their referencing functions). Kinds (the labels are in `labels.json`, hand-written):
- baselines: file I/O, GUI-like imports, CRT library code calling injection APIs (library
  functions are never cited), and a networked updater that references its own URL and calls
  WinHttp: expected `re_network_string_function` low, a true positive *of the rule* (not of
  maliciousness);
- positives for every M3 set (direct imports and through thunks) and for both string rules;
- near misses: one API short of each set, the injection groups split across two functions
  (no finding per function, while M3's file-level rule would fire), a Run-key string in
  another function, a resolver with 2 names, API names without a resolver, a network API
  without a string, a URL without a network API;
- priority cases: requested addresses (one missing), capa file VAs on a rebased ELF PIE,
  exports and the entry point, the caps.

Documentation addresses only (RFC 5737 / RFC 2606 names); every scenario is synthetic.
"""

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from cyberlab_jobs.reverse import (
    BodyRange,
    ReCallEdgeRecord,
    ReFunctionRecord,
    ReImportRecord,
    ReImportRefRecord,
    ReJobV1,
    ReLimits,
    ReProgramRecord,
    ReStringRecord,
    ReStringRefRecord,
)

from re_worker.view import ReView

PE_BASE = 0x140000000
PIE_BASE = 0x100000  # Ghidra's rebase of an ELF PIE (preferred base 0)
LIMITS = ReLimits(
    max_bytes=16 * 1024**2, timeout_s=3600, tool_timeout_s=1800, analysis_timeout_s=1500,
    decompile_timeout_s=30, quick_timeout_s=300, max_functions=20_000, max_call_edges=100_000,
    max_imports=10_000, max_import_refs=50_000, max_strings=20_000, max_string_refs=50_000,
    max_decompiled=300, max_code_bytes=64 * 1024, max_code_total_bytes=32 * 1024**2,
    max_findings=2_000, max_iocs=10_000, max_result_bytes=256 * 1024**2,
    max_work_bytes=2 * 1024**3,
)  # fmt: skip
RUN_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"


@dataclass
class Builder:
    """A synthetic program as validated records."""

    format: str = "pe"
    image_base: int = PE_BASE
    preferred_base: int | None = None
    entry_name: str | None = None
    functions: dict[str, ReFunctionRecord] = field(default_factory=dict)
    edges: list[ReCallEdgeRecord] = field(default_factory=list)
    imports: list[ReImportRecord] = field(default_factory=list)
    import_refs: list[ReImportRefRecord] = field(default_factory=list)
    strings: list[ReStringRecord] = field(default_factory=list)
    string_refs: list[ReStringRefRecord] = field(default_factory=list)
    _next_rva: int = 0x1000

    def fn(
        self,
        name: str,
        size: int = 0x80,
        *,
        source: str = "symbol",
        thunk: bool = False,
        external: bool = False,
        library: bool = False,
    ) -> int:
        rva = self._next_rva
        self._next_rva += max(0x10, (size + 0xF) // 0x10 * 0x10)
        self.functions[name] = ReFunctionRecord(
            entry=self.image_base + rva, rva=rva, name=name, name_source=source, size=size,
            body=[] if external else [BodyRange(start=rva, end=rva + size)],
            is_thunk=thunk, is_external=external, is_library=library,
        )  # fmt: skip
        return self.image_base + rva

    def entry(self, name: str) -> int:
        return self.functions[name].entry

    def call(self, caller: str, *callees: str) -> None:
        for callee in callees:
            self.edges.append(ReCallEdgeRecord(caller=self.entry(caller), callee=self.entry(callee)))

    def imp(self, name: str, *callers: str, library: str = "KERNEL32.dll") -> int:
        index = len(self.imports)
        self.imports.append(ReImportRecord(index=index, library=library, name=name))
        for caller in callers:
            self.import_refs.append(ReImportRefRecord(import_index=index, function_entry=self.entry(caller)))
        return index

    def thunk(self, name: str, *callers: str, library: str = "KERNEL32.dll") -> None:
        """An import reached only through a thunk function (no direct import reference)."""
        self.fn(name, 0x8, source="import", thunk=True)
        index = len(self.imports)
        self.imports.append(ReImportRecord(index=index, library=library, name=name))
        self.import_refs.append(ReImportRefRecord(import_index=index, function_entry=self.entry(name)))
        for caller in callers:
            self.call(caller, name)

    def string(self, value: str, *referrers: str) -> int:
        index = len(self.strings)
        address = self.image_base + 0x40000 + 0x100 * index
        self.strings.append(ReStringRecord(index=index, address=address, encoding="ascii",
                                           value=value, length=len(value)))  # fmt: skip
        for referrer in referrers:
            self.string_refs.append(ReStringRefRecord(string_index=index, function_entry=self.entry(referrer)))
        return index

    def view(self) -> ReView:
        entry = self.entry(self.entry_name) if self.entry_name else None
        program = ReProgramRecord(
            format=self.format, arch="x86_64", bits=64, endianness="little",
            image_base=self.image_base,
            preferred_base=self.image_base if self.preferred_base is None else self.preferred_base,
            entry=entry, sha256="5" * 64, size_bytes=4096, analysis_status="complete",
        )  # fmt: skip
        return ReView.build(
            program, self.functions.values(), self.edges, self.imports, self.import_refs,
            self.strings, self.string_refs,
        )  # fmt: skip


def job(
    *,
    file_format: str = "pe",
    decompile_addresses: list[int] | None = None,
    capa_file_vas: list[int] | None = None,
    max_decompiled: int = 300,
) -> ReJobV1:
    return ReJobV1.model_validate(
        {
            "job_id": str(uuid.UUID(int=1)),
            "organization_id": str(uuid.UUID(int=2)),
            "evidence_id": str(uuid.UUID(int=3)),
            "source_job_id": str(uuid.UUID(int=4)),
            "expected_sha256": "5" * 64,
            "size_bytes": 4096,
            "evidence_url": "http://minio:9000/evidence/x?X-Amz-Signature=synthetic",
            "result_post": {"url": "http://minio:9000/analysis-results", "fields": {"key": "k"}},
            "ingest_token": "t" * 43,
            "profile": "full",
            "file_format": file_format,
            "decompile_addresses": decompile_addresses or [],
            "capa_file_vas": sorted(capa_file_vas or []),
            "limits": LIMITS.model_copy(update={"max_decompiled": max_decompiled}).model_dump(),
        }
    )


@dataclass
class Scenario:
    view: ReView
    job: ReJobV1


Recipe = Callable[[Builder], ReJobV1 | None]


def _program(b: Builder) -> None:
    """The common skeleton: an exported entry point, main and a few plain functions."""
    b.entry_name = "start"
    b.fn("start", 0x40, source="export")
    b.fn("main", 0x200)
    b.fn("parse_args", 0x60)
    b.fn("cleanup", 0x30)
    b.call("start", "main")
    b.call("main", "parse_args", "cleanup")


# --- baselines --------------------------------------------------------------------------------


def baseline_file_io(b: Builder) -> None:
    _program(b)
    b.fn("load_settings", 0x120)
    b.fn("save_settings", 0x100)
    b.call("main", "load_settings", "save_settings")
    for api in ("CreateFileW", "ReadFile", "GetFileSizeEx", "CloseHandle"):
        b.imp(api, "load_settings")
    for api in ("CreateFileW", "WriteFile", "FlushFileBuffers"):
        b.imp(api, "save_settings")
    b.string("C:\\ProgramData\\CyberLab\\settings.ini", "load_settings", "save_settings")


def baseline_gui(b: Builder) -> None:
    _program(b)
    b.fn("window_loop", 0x180)
    b.call("main", "window_loop")
    for api in ("RegisterClassExW", "CreateWindowExW", "GetMessageW", "TranslateMessage",
                "DispatchMessageW", "GetKeyState", "MessageBoxW"):  # fmt: skip
        b.imp(api, "window_loop", library="USER32.dll")
    b.string("CyberLab sample window class", "window_loop")


def baseline_crt_library(b: Builder) -> None:
    """FID-recognized runtime code calling the injection set: never cited."""
    _program(b)
    b.fn("__crt_debugger_hook", 0x90, source="fid_library", library=True)
    b.call("main", "__crt_debugger_hook")
    for api in ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"):
        b.imp(api, "__crt_debugger_hook")


def baseline_updater(b: Builder) -> None:
    """A networked updater: the network rule fires (a true positive of the rule only)."""
    _program(b)
    b.fn("check_updates", 0x140)
    b.call("main", "check_updates")
    for api in ("WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest"):
        b.imp(api, "check_updates", library="WINHTTP.dll")
    b.string("https://updates.cyberlab-app.example/latest.json", "check_updates")


# --- positives --------------------------------------------------------------------------------


def _set_positive(apis: tuple[str, ...], strings: tuple[str, ...] = ()) -> Recipe:
    def recipe(b: Builder) -> None:
        _program(b)
        b.fn("target_fn", 0x160)
        b.call("main", "target_fn")
        for api in apis:
            b.imp(api, "target_fn")
        for value in strings:
            b.string(value, "target_fn")

    return recipe


def pos_injection_via_thunks(b: Builder) -> None:
    _program(b)
    b.fn("target_fn", 0x160)
    b.call("main", "target_fn")
    for api in ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"):
        b.thunk(api, "target_fn")


def pos_resolution_dlsym(b: Builder) -> None:
    b.format, b.image_base, b.preferred_base = "elf", PIE_BASE, 0
    _program(b)
    b.fn("target_fn", 0x100)
    b.call("main", "target_fn")
    b.imp("dlopen", "target_fn", library="libc.so.6")
    b.imp("dlsym", "target_fn", library="libc.so.6")
    for name in ("socket", "connect", "getaddrinfo", "libcyberlab.so.1"):
        b.string(name, "target_fn")


def pos_network_elf(b: Builder) -> None:
    b.format, b.image_base, b.preferred_base = "elf", PIE_BASE, 0
    _program(b)
    b.fn("target_fn", 0x100)
    b.call("main", "target_fn")
    for api in ("socket", "inet_pton", "connect", "close"):
        b.imp(api, "target_fn", library="libc.so.6")
    b.string("192.0.2.10", "target_fn")


# --- near misses ------------------------------------------------------------------------------


def nm_injection_split(b: Builder) -> None:
    """The injection groups across two functions: M3's file-level rule would fire."""
    _program(b)
    b.fn("prepare_fn", 0x100)
    b.fn("start_fn", 0x80)
    b.call("main", "prepare_fn", "start_fn")
    b.imp("VirtualAllocEx", "prepare_fn")
    b.imp("WriteProcessMemory", "prepare_fn")
    b.imp("CreateRemoteThread", "start_fn")


def nm_run_key_elsewhere(b: Builder) -> None:
    _program(b)
    b.fn("target_fn", 0x100)
    b.fn("describe_fn", 0x40)
    b.call("main", "target_fn", "describe_fn")
    b.imp("RegSetValueExW", "target_fn", library="ADVAPI32.dll")
    b.string(RUN_KEY, "describe_fn")


def nm_network_api_no_string(b: Builder) -> None:
    b.format, b.image_base, b.preferred_base = "elf", PIE_BASE, 0
    _program(b)
    b.fn("target_fn", 0x100)
    b.call("main", "target_fn")
    for api in ("socket", "connect"):
        b.imp(api, "target_fn", library="libc.so.6")
    b.string("connection refused, retrying", "target_fn")


def nm_url_no_network_api(b: Builder) -> None:
    _program(b)
    b.fn("target_fn", 0x80)
    b.call("main", "target_fn")
    b.imp("lstrlenW", "target_fn")
    b.string("https://docs.cyberlab-app.example/help.html", "target_fn")


# --- priority ---------------------------------------------------------------------------------


def prio_classes(b: Builder) -> ReJobV1:
    """One function per class, plus a thunk and a library function that are never ranked."""
    _program(b)
    b.fn("exported_api", 0x40, source="export")
    b.fn("capa_hit", 0x100)
    b.fn("suspicious_caller", 0x80)
    b.fn("ioc_user", 0x60)
    b.fn("big_plain", 0x400)
    b.fn("library_fn", 0x900, source="fid_library", library=True)
    b.call("main", "capa_hit", "suspicious_caller", "ioc_user", "big_plain", "library_fn")
    b.thunk("VirtualAllocEx", "suspicious_caller")
    b.string("http://198.51.100.7/status", "ioc_user")
    capa = b.functions["capa_hit"].entry + 0x20
    return job(capa_file_vas=[capa], decompile_addresses=[b.entry("cleanup"), 0x1])


def prio_pie_capa(b: Builder) -> ReJobV1:
    """RT8: a capa file VA on a rebased PIE (engine base 0x100000, preferred base 0)."""
    b.format, b.image_base, b.preferred_base = "elf", PIE_BASE, 0
    _program(b)
    b.fn("capa_hit", 0x100)
    b.fn("other", 0x300)
    b.call("main", "capa_hit", "other")
    rva = b.functions["capa_hit"].rva
    return job(file_format="elf", capa_file_vas=[rva + 0x10])


def prio_cap(b: Builder) -> ReJobV1:
    """Requested addresses beyond the cap are never cut; the rest is."""
    _program(b)
    for i in range(6):
        b.fn(f"plain_{i}", 0x40 + 0x10 * i)
        b.call("main", f"plain_{i}")
    requested = [b.entry("plain_0"), b.entry("plain_1"), b.entry("plain_2")]
    return job(decompile_addresses=requested, max_decompiled=2)


SCENARIOS: dict[str, Recipe] = {
    "baseline_file_io": baseline_file_io,
    "baseline_gui": baseline_gui,
    "baseline_crt_library": baseline_crt_library,
    "baseline_updater": baseline_updater,
    "pos_injection": _set_positive(("OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
                                    "CreateRemoteThread", "CloseHandle")),  # fmt: skip
    "pos_injection_via_thunks": pos_injection_via_thunks,
    "pos_keylogging_hook": _set_positive(("SetWindowsHookExW", "GetAsyncKeyState")),
    "pos_keylogging_raw": _set_positive(("SetWindowsHookExA", "RegisterRawInputDevices")),
    "pos_anti_debug": _set_positive(("IsDebuggerPresent", "NtQueryInformationProcess")),
    "pos_credential_access": _set_positive(("CredEnumerateW", "CryptUnprotectData")),
    "pos_persistence_run_key": _set_positive(("RegOpenKeyExW", "RegSetValueExW"), (RUN_KEY,)),
    "pos_persistence_service": _set_positive(("OpenSCManagerW", "CreateServiceW")),
    "pos_downloader": _set_positive(("URLDownloadToFileW", "ShellExecuteW")),
    "pos_resolution_low": _set_positive(
        ("GetModuleHandleA", "GetProcAddress"), ("GetTickCount64", "lstrlenW", "Sleep")
    ),
    "pos_resolution_medium": _set_positive(
        ("GetModuleHandleA", "GetProcAddress"),
        ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "kernel32.dll"),
    ),
    "pos_resolution_dlsym": pos_resolution_dlsym,
    "pos_network_elf": pos_network_elf,
    "pos_network_wininet": _set_positive(
        ("InternetOpenW", "InternetOpenUrlW", "InternetReadFile"),
        ("http://203.0.113.20/feed", "Mozilla/5.0 (CyberLab)"),
    ),
    "nm_injection_two_groups": _set_positive(("VirtualAllocEx", "WriteProcessMemory")),
    "nm_injection_split": nm_injection_split,
    "nm_keylogging_hook_only": _set_positive(("SetWindowsHookExW", "CallNextHookEx")),
    "nm_anti_debug_check_only": _set_positive(("IsDebuggerPresent", "OutputDebugStringW")),
    "nm_credential_one_group": _set_positive(("CredReadW", "CredFree")),
    "nm_persistence_no_run_key": _set_positive(
        ("RegSetValueExW",), ("Software\\CyberLab\\Sample\\Settings",)
    ),
    "nm_run_key_elsewhere": nm_run_key_elsewhere,
    "nm_downloader_download_only": _set_positive(("URLDownloadToFileW", "DeleteFileW")),
    "nm_resolver_two_names": _set_positive(("GetProcAddress",), ("VirtualAllocEx", "Sleep")),
    "nm_names_without_resolver": _set_positive(
        ("LoadLibraryW",), ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")
    ),
    "nm_network_api_no_string": nm_network_api_no_string,
    "nm_url_no_network_api": nm_url_no_network_api,
    "prio_classes": prio_classes,
    "prio_pie_capa": prio_pie_capa,
    "prio_cap": prio_cap,
}


def build(name: str) -> Scenario:
    builder = Builder()
    made = SCENARIOS[name](builder)
    view = builder.view()
    return Scenario(view, made if made is not None else job(file_format=view.program.format))


def entry_names(view: ReView) -> dict[int, str]:
    return {entry: f.name for entry, f in view.functions.items()}
