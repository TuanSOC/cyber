"""`memory.v1`: memory forensics of one evidence file (a memory image), M8.

Same framing as `pcap.v1` / `static.v1` (gzip NDJSON, header first, hashed trailer last) and
the same value bounds: every value is derived from an attacker-controlled image, read by an
untrusted analyzer. The contract is tool-agnostic (no Volatility type appears here, VSL
isolation): plugin names are the analyzer's allow-list, not an API.

A **diagnostic stream** (`symbols_missing`) holds the header (with `symbols.status = missing`
and `symbols.required`), at most one `image` line and the trailer; it is uploaded with a
`failed` / `symbols_missing` ingest report (`check_diagnostic_kinds`).

Frozen at the end of M8 phase 1: change only together with the trusted ingest (parent).
"""

import enum
import json
import string
import uuid
from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Annotated, Literal, Self, get_args

from pydantic import (
    AfterValidator,
    BeforeValidator,
    Field,
    StrictBool,
    StrictInt,
    TypeAdapter,
    model_validator,
)

from cyberlab_jobs.base import ErrorCode, Sha256, ShortText, Strict, Token
from cyberlab_jobs.messages import PresignedPost, Url
from cyberlab_jobs.results import (
    NO_NUL,
    Count,
    FindingRecord,
    Ip,
    IocRecord,
    Port,
    ResultTrailer,
    Text16,
    Text64,
    Text255,
    Timestamp,
    ToolVersions,
)

MEMORY_SCHEMA = "memory.v1"

GIB = 1024**3
MIB = 1024**2
# Hard ceilings of the contract; the API's settings may only lower them (RT9, RT14).
MAX_IMAGE_BYTES = 16 * GIB
MAX_RESULT_BYTES = 256 * MIB
CAP_PROCESSES = 20_000
CAP_CONNECTIONS = 50_000
CAP_INJECTIONS = 5_000
CAP_ARTIFACTS = 50_000
CAP_FINDINGS = 5_000
CAP_IOCS = 20_000
CAP_TIMELINE = 5_000

Text1024 = Annotated[str, Field(max_length=1024, pattern=NO_NUL)]
Text4096 = Annotated[str, Field(max_length=4096, pattern=NO_NUL)]
Address = Annotated[int, Field(ge=0, le=2**64 - 1)]  # unsigned 64-bit (numeric(20,0) columns)
Pid = Annotated[int, Field(ge=0, le=2**32 - 1)]
HeadHex = Annotated[str, Field(pattern=r"^[0-9a-f]{0,128}$")]  # at most 64 bytes, lowercase


class MemoryProfile(enum.StrEnum):
    TRIAGE = "triage"  # the triage plugins of the OS
    FULL = "full"  # triage plus the slower module / hook checks


class OsHint(enum.StrEnum):
    AUTO = "auto"
    WINDOWS = "windows"
    LINUX = "linux"


MemoryOs = Literal["windows", "linux"]


class MemoryPlugin(enum.StrEnum):
    """The allow-list (Volatility 3 v2.28.2 names, never the deprecated shims). No
    `windows.handles` (RT9), no YARA scanner (RT8), no credential, envars, dump or extraction
    plugin: nothing else can ever be requested or reported."""

    WINDOWS_INFO = "windows.info"
    WINDOWS_PSLIST = "windows.pslist"
    WINDOWS_PSSCAN = "windows.psscan"
    WINDOWS_CMDLINE = "windows.cmdline"
    WINDOWS_DLLLIST = "windows.dlllist"
    WINDOWS_NETSCAN = "windows.netscan"
    WINDOWS_MALFIND = "windows.malware.malfind"
    WINDOWS_SVCSCAN = "windows.svcscan"
    WINDOWS_HIVELIST = "windows.registry.hivelist"
    WINDOWS_USERASSIST = "windows.registry.userassist"
    WINDOWS_LDRMODULES = "windows.malware.ldrmodules"
    LINUX_PSLIST = "linux.pslist"
    LINUX_PSAUX = "linux.psaux"
    LINUX_BASH = "linux.bash"
    LINUX_SOCKSTAT = "linux.sockstat"
    LINUX_LSOF = "linux.lsof"
    LINUX_MALFIND = "linux.malware.malfind"
    LINUX_CHECK_SYSCALL = "linux.malware.check_syscall"
    LINUX_HIDDEN_MODULES = "linux.malware.hidden_modules"


_P = MemoryPlugin
_WINDOWS_TRIAGE = (
    _P.WINDOWS_INFO,
    _P.WINDOWS_PSLIST,
    _P.WINDOWS_PSSCAN,
    _P.WINDOWS_CMDLINE,
    _P.WINDOWS_DLLLIST,
    _P.WINDOWS_NETSCAN,
    _P.WINDOWS_MALFIND,
    _P.WINDOWS_SVCSCAN,
    _P.WINDOWS_HIVELIST,
    _P.WINDOWS_USERASSIST,
)
_LINUX_TRIAGE = (_P.LINUX_PSLIST, _P.LINUX_PSAUX, _P.LINUX_BASH, _P.LINUX_SOCKSTAT)
# The fixed run order per (OS, profile); the process list comes first after `info`.
PLUGINS_BY_PROFILE: Mapping[tuple[MemoryOs, MemoryProfile], tuple[MemoryPlugin, ...]] = (
    MappingProxyType(
        {
            ("windows", MemoryProfile.TRIAGE): _WINDOWS_TRIAGE,
            ("windows", MemoryProfile.FULL): (*_WINDOWS_TRIAGE, _P.WINDOWS_LDRMODULES),
            ("linux", MemoryProfile.TRIAGE): _LINUX_TRIAGE,
            ("linux", MemoryProfile.FULL): (
                *_LINUX_TRIAGE,
                _P.LINUX_LSOF,
                _P.LINUX_MALFIND,
                _P.LINUX_CHECK_SYSCALL,
                _P.LINUX_HIDDEN_MODULES,
            ),
        }
    )
)
# The job succeeds only when identify and this plugin are `ok` (plan "Job success").
PROCESS_LIST_PLUGIN: Mapping[MemoryOs, MemoryPlugin] = MappingProxyType(
    {"windows": _P.WINDOWS_PSLIST, "linux": _P.LINUX_PSLIST}
)

# Every code the memory analyzer, its ingest and the API may store or answer (classified in
# the API's ops/error_classes.py; its test fails on a missing one).
MemoryErrorCode = Literal[
    "not_implemented",
    "symbols_missing",
    "symbols_corrupt",
    "memory_parse_failed",
    "os_undetermined",
    "unsupported_memory_format",
    "memory_image_too_large",
    "memory_image_empty",
    "insufficient_disk",
    "identify_timeout",
    "plugin_timeout",
    "plugin_failed",
    "engine_unavailable",
]
MEMORY_ERROR_CODES: tuple[str, ...] = get_args(MemoryErrorCode)


class MemoryLimits(Strict):
    """Resource limits the API attaches to every memory job; the worker enforces them."""

    max_bytes: int = Field(gt=0, le=MAX_IMAGE_BYTES)
    timeout_s: int = Field(gt=0, le=6 * 3600)
    identify_timeout_s: int = Field(gt=0, le=3600)
    tool_timeout_s: int = Field(gt=0)  # one plugin process
    max_processes: int = Field(gt=0, le=CAP_PROCESSES)
    max_connections: int = Field(gt=0, le=CAP_CONNECTIONS)
    max_injections: int = Field(gt=0, le=CAP_INJECTIONS)
    max_artifacts: int = Field(gt=0, le=CAP_ARTIFACTS)
    max_findings: int = Field(gt=0, le=CAP_FINDINGS)
    max_iocs: int = Field(gt=0, le=CAP_IOCS)
    max_timeline: int = Field(gt=0, le=CAP_TIMELINE)
    max_result_bytes: int = Field(gt=0, le=MAX_RESULT_BYTES)

    @model_validator(mode="after")
    def _tools_within_job(self) -> Self:
        if self.tool_timeout_s >= self.timeout_s or self.identify_timeout_s >= self.timeout_s:
            raise ValueError("tool_timeout_s and identify_timeout_s must be below timeout_s")
        return self

    def max_lines(self) -> int:
        """Upper bound of a stream's lines at these caps (header + image + trailer + records)."""
        return 3 + sum(
            (
                self.max_processes,
                self.max_connections,
                self.max_injections,
                self.max_artifacts,
                self.max_findings,
                self.max_iocs,
                self.max_timeline,
            )
        )


class MemoryJobV1(Strict):
    """API -> memory analyzer (queue `memory`)."""

    schema_version: Literal["memory.v1"] = MEMORY_SCHEMA
    job_id: uuid.UUID
    organization_id: uuid.UUID
    evidence_id: uuid.UUID
    expected_sha256: Sha256
    size_bytes: int = Field(ge=0)
    evidence_url: Url
    result_post: PresignedPost
    ingest_token: Token
    profile: MemoryProfile
    os_hint: OsHint
    limits: MemoryLimits


# --- kernel identity (symbols) --------------------------------------------------------------

# Kernel PDBs only: a hostile image cannot make the symbol tool request any other file.
KERNEL_PDB_NAMES: frozenset[str] = frozenset(
    {"ntkrnlmp.pdb", "ntoskrnl.pdb", "ntkrnlpa.pdb", "ntkrpamp.pdb"}
)
_PRINTABLE = frozenset(string.printable) - frozenset("\t\n\r\x0b\x0c")


def _kernel_pdb(value: str) -> str:
    if value not in KERNEL_PDB_NAMES:
        raise ValueError("not a Windows kernel PDB name")
    return value


def _printable(value: str) -> str:
    if not value or any(ch not in _PRINTABLE for ch in value):
        raise ValueError("banner must be non-empty printable ASCII (no control characters)")
    return value


class WindowsPdb(Strict):
    """The kernel PDB identity read from the image (attacker-controlled, strictly bounded)."""

    name: Annotated[str, AfterValidator(_kernel_pdb)]
    guid: Annotated[str, Field(pattern=r"^[0-9A-F]{32}$")]
    age: Annotated[int, Field(ge=0, le=65_535)]


class LinuxBanner(Strict):
    """The Linux kernel banner read from the image (attacker-chosen text: shown inert, never
    put into a command, RT12)."""

    banner: Annotated[str, Field(max_length=512), AfterValidator(_printable)]


KernelIdentity = WindowsPdb | LinuxBanner


def identity_os(identity: KernelIdentity) -> MemoryOs:
    return "windows" if isinstance(identity, WindowsPdb) else "linux"


# --- result lines ---------------------------------------------------------------------------


class SymbolsInfo(Strict):
    status: Literal["resolved", "missing"]
    isf_sha256: Sha256 | None = None  # the ISF the run loaded (resolved)
    required: KernelIdentity | None = None  # what an operator must import (missing)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.status == "resolved" and (self.isf_sha256 is None or self.required is not None):
            raise ValueError("resolved symbols name the ISF sha256 and no requirement")
        if self.status == "missing" and (self.required is None or self.isf_sha256 is not None):
            raise ValueError("missing symbols name the requirement and no ISF")
        return self


PluginRunStatus = Literal["ok", "failed", "timeout", "skipped", "unsupported"]


class PluginStatus(Strict):
    plugin: MemoryPlugin
    status: PluginRunStatus
    rows: Count = 0
    truncated: bool = False
    duration_ms: Count = 0
    error_code: ErrorCode | None = None


class MemoryResultHeader(Strict):
    kind: Literal["header"] = "header"
    schema_version: Literal["memory.v1"] = MEMORY_SCHEMA
    job_id: uuid.UUID
    profile: MemoryProfile
    os: MemoryOs
    # `replay` is the test-profile-only engine (hand-written rows, never real analysis).
    engine: Literal["volatility3", "replay"]
    tool_versions: ToolVersions
    symbols: SymbolsInfo
    plugins: Annotated[list[PluginStatus], Field(max_length=32)] = []
    # PEP 578 audit-hook refusals per event family (socket, subprocess, ...): zero expected.
    audit_events: Annotated[dict[Text64, Count], Field(max_length=16)] = {}
    engine_errors: Annotated[list[ErrorCode], Field(max_length=32)] = []
    truncated: Annotated[dict[ShortText, bool], Field(max_length=32)] = {}

    @model_validator(mode="after")
    def _plugins_allowed(self) -> Self:
        names = [p.plugin for p in self.plugins]
        if len(set(names)) != len(names):
            raise ValueError("a plugin is reported twice")
        allowed = set(PLUGINS_BY_PROFILE[(self.os, self.profile)])
        if not set(names) <= allowed:
            raise ValueError("a reported plugin is not in the profile's allow-list")
        if self.symbols.status == "missing":
            if self.plugins:
                raise ValueError("a diagnostic (symbols missing) header reports no plugin run")
            assert self.symbols.required is not None  # noqa: S101 - SymbolsInfo checked it
            if identity_os(self.symbols.required) != self.os:
                raise ValueError("the required symbols are for another OS")
        return self


class MemoryImageRecord(Strict):
    """Exactly one per full result, at most one per diagnostic stream. `size_bytes` and
    `sha256` must equal the evidence record (checked by ingest)."""

    kind: Literal["image"] = "image"
    size_bytes: Count
    sha256: Sha256
    layer: Text64  # the layer chain, e.g. "LimeLayer>Intel32e"
    arch: Literal["x86", "x64"]
    nt_build: Text64 | None = None
    pdb: WindowsPdb | None = None
    kernel_banner: Annotated[str, Field(max_length=512), AfterValidator(_printable)] | None = None
    system_time: Timestamp | None = None


ProcessSource = Literal["pslist", "psscan", "pstree"]


class MemoryProcessRecord(Strict):
    kind: Literal["process"] = "process"
    pid: Pid
    ppid: Pid | None = None
    name: Text64
    offset: Address | None = None
    create_time: Timestamp | None = None
    exit_time: Timestamp | None = None
    threads: Count | None = None
    handles: Count | None = None
    session_id: Pid | None = None
    wow64: bool | None = None
    sources: Annotated[list[ProcessSource], Field(min_length=1, max_length=3)]
    cmdline: Text4096 | None = None
    image_path: Text1024 | None = None

    @model_validator(mode="after")
    def _unique_sources(self) -> Self:
        if len(set(self.sources)) != len(self.sources):
            raise ValueError("duplicate process source")
        return self


class MemoryConnectionRecord(Strict):
    kind: Literal["connection"] = "connection"
    proto: Literal["tcp", "udp", "raw", "unix", "other"]
    local_addr: Ip | None = None
    local_port: Port | None = None
    remote_addr: Ip | None = None
    remote_port: Port | None = None
    state: Text16 | None = None
    pid: Pid | None = None
    owner: Text64 | None = None
    created: Timestamp | None = None
    offset: Address | None = None


class MemoryInjectionRecord(Strict):
    """A private executable region (`malfind`): an observation, never a verdict."""

    kind: Literal["injection"] = "injection"
    pid: Pid
    process: Text64 | None = None
    start: Address
    end: Address
    protection: Text64 | None = None
    tag: Text16 | None = None
    private: bool | None = None
    commit_charge: Count | None = None
    has_pe: bool = False
    head_hex: HeadHex = ""
    disasm: Text1024 | None = None

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.end < self.start:
            raise ValueError("region end is below its start")
        return self


ArtifactType = Literal[
    "module",
    "service",
    "hive",
    "userassist",
    "ldr_unlinked",
    "bash",
    "open_file",
    "syscall_hook",
    "hidden_module",
]
ARTIFACT_TYPES: tuple[str, ...] = get_args(ArtifactType)
WINDOWS_ARTIFACTS = frozenset({"module", "service", "hive", "userassist", "ldr_unlinked"})
LINUX_ARTIFACTS = frozenset({"bash", "open_file", "syscall_hook", "hidden_module"})


def _bigint(value: object) -> object:
    if isinstance(value, int) and not isinstance(value, bool) and not -(2**63) <= value < 2**63:
        raise ValueError("integer attribute outside the bigint range")
    return value


# Scalars only (bool first; no float, no nested value): the jsonb check in 0016 agrees.
ArtifactValue = Annotated[
    StrictBool | StrictInt | Annotated[str, Field(max_length=1024, pattern=NO_NUL)] | None,
    BeforeValidator(_bigint),
]


# `memory_artifacts.attributes` is checked `octet_length(attributes::text) <= 4096` (0016).
# Postgres prints jsonb with ", " and ": " separators: two bytes more per entry than compact.
MAX_ATTRIBUTES_BYTES = 4096


class MemoryArtifactRecord(Strict):
    kind: Literal["artifact"] = "artifact"
    type: ArtifactType
    pid: Pid | None = None
    attributes: Annotated[dict[Text64, ArtifactValue], Field(max_length=32)] = {}

    @model_validator(mode="after")
    def _fits_the_column(self) -> Self:
        compact = json.dumps(self.attributes, ensure_ascii=False, separators=(",", ":"))
        if len(compact.encode()) + 2 * len(self.attributes) > MAX_ATTRIBUTES_BYTES:
            raise ValueError("artifact attributes exceed 4 KiB")
        return self


class MemoryTimelineEvent(Strict):
    kind: Literal["timeline"] = "timeline"
    ts: Timestamp
    event: Literal["system_time", "process_start", "process_exit", "connection", "finding"]
    title: Text255
    severity: Literal["info", "low", "medium", "high"] | None = None
    ref: Text64 | None = None  # finding id, pid or connection offset
    pid: Pid | None = None
    remote_ip: Ip | None = None


MemoryRecordLine = Annotated[
    MemoryImageRecord
    | MemoryProcessRecord
    | MemoryConnectionRecord
    | MemoryInjectionRecord
    | MemoryArtifactRecord
    | FindingRecord
    | IocRecord
    | MemoryTimelineEvent,
    Field(discriminator="kind"),
]
MemoryAnyLine = Annotated[
    MemoryResultHeader
    | MemoryImageRecord
    | MemoryProcessRecord
    | MemoryConnectionRecord
    | MemoryInjectionRecord
    | MemoryArtifactRecord
    | FindingRecord
    | IocRecord
    | MemoryTimelineEvent
    | ResultTrailer,
    Field(discriminator="kind"),
]
MEMORY_RECORD_ADAPTER: TypeAdapter[MemoryRecordLine] = TypeAdapter(MemoryRecordLine)
MEMORY_LINE_ADAPTER: TypeAdapter[MemoryAnyLine] = TypeAdapter(MemoryAnyLine)

DIAGNOSTIC_KINDS = ("header", "image", "trailer")


def check_diagnostic_kinds(kinds: Iterable[str]) -> None:
    """The diagnostic-stream rule: header, at most one image line, trailer (in that order)."""
    seq = list(kinds)
    if len(seq) not in (2, 3) or seq[0] != "header" or seq[-1] != "trailer":
        raise ValueError("a diagnostic stream is header, [image], trailer")
    if len(seq) == 3 and seq[1] != "image":
        raise ValueError("a diagnostic stream carries only the image line")


# --- symbol store manifest (shared by the worker and the trusted `memory-symbols` tool) ----


def _relative(value: str) -> str:
    parts = value.split("/")
    if value.startswith("/") or any(p in ("", ".", "..") for p in parts):
        raise ValueError("a manifest path is relative, without empty, . or .. segments")
    return value


ManifestPath = Annotated[
    str,
    Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._/-]+$"),
    AfterValidator(_relative),
]
SymbolSource = Annotated[str, Field(pattern=r"^(msdl|operator|zip:[0-9a-f]{64})$")]


class SymbolFile(Strict):
    path: ManifestPath
    sha256: Sha256
    os: MemoryOs
    identity: KernelIdentity
    source: SymbolSource
    imported_at: Timestamp
    tool_version: ShortText

    @model_validator(mode="after")
    def _os_matches(self) -> Self:
        if identity_os(self.identity) != self.os:
            raise ValueError("identity does not match the file's OS")
        return self


class SymbolManifestV1(Strict):
    """`/symbols/manifest.json`: written only by the `memory-symbols` tool."""

    version: Literal[1] = 1
    volatility_version: ShortText
    files: Annotated[list[SymbolFile], Field(max_length=100_000)] = []
    # sha256 of `.cache/volatility3/identifier.cache` as `reindex` installed it (review fix):
    # the worker seeds a probe's cache only from a file with this hash; None = no cache seeded.
    identifier_cache_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def _unique_paths(self) -> Self:
        paths = [f.path for f in self.files]
        if len(set(paths)) != len(paths):
            raise ValueError("a manifest path is listed twice")
        return self


__all__ = [
    "ARTIFACT_TYPES",
    "DIAGNOSTIC_KINDS",
    "KERNEL_PDB_NAMES",
    "LINUX_ARTIFACTS",
    "MAX_ATTRIBUTES_BYTES",
    "MEMORY_ERROR_CODES",
    "MEMORY_LINE_ADAPTER",
    "MEMORY_RECORD_ADAPTER",
    "MEMORY_SCHEMA",
    "PLUGINS_BY_PROFILE",
    "PROCESS_LIST_PLUGIN",
    "WINDOWS_ARTIFACTS",
    "ArtifactType",
    "KernelIdentity",
    "LinuxBanner",
    "MemoryAnyLine",
    "MemoryArtifactRecord",
    "MemoryConnectionRecord",
    "MemoryErrorCode",
    "MemoryImageRecord",
    "MemoryInjectionRecord",
    "MemoryJobV1",
    "MemoryLimits",
    "MemoryOs",
    "MemoryPlugin",
    "MemoryProcessRecord",
    "MemoryProfile",
    "MemoryRecordLine",
    "MemoryResultHeader",
    "MemoryTimelineEvent",
    "OsHint",
    "PluginStatus",
    "SymbolFile",
    "SymbolManifestV1",
    "SymbolsInfo",
    "WindowsPdb",
    "check_diagnostic_kinds",
    "identity_os",
]
