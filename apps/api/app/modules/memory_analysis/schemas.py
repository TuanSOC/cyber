"""Read models of memory analysis results and the memory sensitivity routes (M8 phase 1,
FROZEN; phases 7 and 8 implement the routes). Tool-agnostic: nothing here names Volatility
(VSL isolation, plan "License")."""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Literal

from cyberlab_jobs.memory import MemoryPlugin, MemoryProfile
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from app.modules.pcap_analysis.schemas import CappedPage


def _to_hex(value: object) -> object:
    """An unsigned 64-bit address as `0x...` lowercase hex text. Kernel addresses are above
    2**63, and a JSON number above 2**53 loses its low bits in the browser, so the API never
    sends an address as a number (review fix)."""
    if isinstance(value, Decimal):
        value = int(value)
    if isinstance(value, int) and not isinstance(value, bool):
        if not 0 <= value < 2**64:
            raise ValueError("address outside the unsigned 64-bit range")
        return f"0x{value:x}"
    return value


# Unsigned 64-bit addresses are NUMERIC in the database (Decimal from the driver); the API
# speaks hex strings.
Address = Annotated[
    str, BeforeValidator(_to_hex), Field(pattern=r"^0x[0-9a-f]{1,16}$", examples=["0xfffff8000000"])
]

# Largest integer a browser reads exactly (Number.MAX_SAFE_INTEGER).
JS_SAFE_INT = 2**53 - 1
# Artifact attributes that hold an address (the normalizers' `addr()` keys): always sent as
# hex text, whatever their size.
ADDRESS_ATTRIBUTES = frozenset({"base", "offset", "table_address", "handler"})


def _attributes_out(value: object) -> object:
    """Address attributes as hex text; other integers are left as they are (the UI marks a
    number above 2**53 as approximate)."""
    if not isinstance(value, dict):
        return value
    out: dict[str, Any] = {}
    for key, item in value.items():
        if (
            key in ADDRESS_ATTRIBUTES
            and isinstance(item, int)
            and not isinstance(item, bool)
            and 0 <= item < 2**64
        ):
            out[key] = f"0x{item:x}"
        else:
            out[key] = item
    return out


MemoryOsName = Literal["windows", "linux"]
SymbolsStatus = Literal["resolved", "missing"]
PluginRunState = Literal["ok", "failed", "timeout", "skipped", "unsupported"]
MemoryArtifactType = Literal[
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
ProcessSourceName = Literal["pslist", "psscan", "pstree"]


class _Row(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class PluginStatusOut(BaseModel):
    plugin: MemoryPlugin
    status: PluginRunState
    rows: int
    truncated: bool
    duration_ms: int
    error_code: str | None = None


class WindowsPdbOut(BaseModel):
    """Validated at ingest (kernel PDB allow-list, 32 hex GUID, age); the UI may build the
    operator's `fetch-windows` command from these fields only (RT12)."""

    name: str
    guid: str
    age: int


class LinuxBannerOut(BaseModel):
    """Attacker-chosen text: shown inert, never put into a command (RT12)."""

    banner: str


class SymbolsOut(BaseModel):
    status: SymbolsStatus
    isf_sha256: str | None = None
    windows_pdb: WindowsPdbOut | None = None
    linux_banner: LinuxBannerOut | None = None


class MemorySummaryOut(BaseModel):
    """`GET /analyses/{job}/memory`: the image facts, the symbols outcome and every plugin's
    status (a partial run is never shown as complete)."""

    job_id: uuid.UUID
    evidence_id: uuid.UUID
    profile: MemoryProfile
    os: MemoryOsName
    arch: str | None
    layer: str | None
    engine: Literal["volatility3", "replay"]
    nt_build: str | None
    system_time: datetime | None
    # Trusted values: the evidence record's size and sha256 (the image line must equal them).
    size_bytes: int
    sha256: str
    symbols: SymbolsOut
    tool_versions: dict[str, str]
    plugins: list[PluginStatusOut]
    counts: dict[str, int]
    truncated: dict[str, bool]
    engine_errors: list[str]


class ProcessOut(_Row):
    id: uuid.UUID
    pid: int
    ppid: int | None
    name: str
    offset: Address | None
    create_time: datetime | None
    exit_time: datetime | None
    threads: int | None
    handles: int | None
    session_id: int | None
    wow64: bool | None
    sources: list[ProcessSourceName]
    # Raw command line (job pages only, evidence.read; secrets masked only on shared surfaces).
    cmdline: str | None
    image_path: str | None
    children: int = 0


class ProcessPage(CappedPage[ProcessOut]):
    pass


class ConnectionOut(_Row):
    id: uuid.UUID
    proto: str
    local_addr: str | None
    local_port: int | None
    remote_addr: str | None
    remote_port: int | None
    state: str | None
    pid: int | None
    owner: str | None
    created: datetime | None
    offset: Address | None


class ConnectionPage(CappedPage[ConnectionOut]):
    pass


class InjectionOut(_Row):
    id: uuid.UUID
    pid: int
    process: str | None
    start: Address
    end: Address
    protection: str | None
    tag: str | None
    private: bool | None
    commit_charge: int | None
    has_pe: bool
    head_hex: str
    disasm: str | None


class InjectionPage(CappedPage[InjectionOut]):
    pass


class ArtifactOut(_Row):
    id: uuid.UUID
    type: MemoryArtifactType
    pid: int | None
    # Scalars only; address keys (`ADDRESS_ATTRIBUTES`) arrive as `0x...` text.
    attributes: Annotated[dict[str, Any], BeforeValidator(_attributes_out)]


class ArtifactPage(CappedPage[ArtifactOut]):
    pass


class ProcessDetailOut(BaseModel):
    """One process with what references it (bounded lists)."""

    process: ProcessOut
    parent: ProcessOut | None
    children: list[ProcessOut]
    connections: list[ConnectionOut]
    injections: list[InjectionOut]
    artifacts: list[ArtifactOut]
    # Every pslist / psscan instance with this pid (pids are reused across a capture).
    instances: int


class MemorySensitivityOut(BaseModel):
    """`GET /evidence/{id}/memory-sensitivity`: `none` when the evidence was never marked."""

    evidence_id: uuid.UUID
    state: Literal["none", "restricted", "released"]
    defaulted_at: datetime | None = None
    released_at: datetime | None = None
    released_by_name: str | None = None
    release_reason: str | None = None


class ReleaseIn(BaseModel):
    """Admin release of restricted memory evidence (once, audited; phase 8). The analyst
    then clears the share-policy flags through the M6 route."""

    model_config = ConfigDict(extra="forbid")

    acknowledge: bool = Field(
        description="Must be true: the image may hold passwords, keys and personal data."
    )
    reason: Annotated[str, Field(min_length=1, max_length=500)]


__all__ = [
    "ArtifactOut",
    "ArtifactPage",
    "ConnectionOut",
    "ConnectionPage",
    "InjectionOut",
    "InjectionPage",
    "LinuxBannerOut",
    "MemoryArtifactType",
    "MemorySensitivityOut",
    "MemorySummaryOut",
    "PluginStatusOut",
    "ProcessDetailOut",
    "ProcessOut",
    "ProcessPage",
    "ReleaseIn",
    "SymbolsOut",
    "WindowsPdbOut",
]
