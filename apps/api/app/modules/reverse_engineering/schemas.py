"""Read models of reverse-engineering results (M10 phase 1, FROZEN; phase 8 implements the
routes). Addresses are sent as `0x…` lowercase hex text (a JSON number above 2**53 loses its
low bits in the browser, the M8 lesson). Names, signatures, string values and code are
attacker-influenced text: the web renders them as text only (phase 10's tokenizer).

No call-graph schema (RT24): the callers / callees lists give the navigation.
"""

import uuid
from decimal import Decimal
from typing import Annotated, Literal

from cyberlab_jobs.reverse import CodeKind, DecompileStatus, NameSource, ReEngine, ReStage
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from app.modules.pcap_analysis.schemas import CappedPage
from app.modules.static_analysis.schemas import CapabilityOut


def _to_hex(value: object) -> object:
    if isinstance(value, Decimal):
        value = int(value)
    if isinstance(value, int) and not isinstance(value, bool):
        if not 0 <= value < 2**64:
            raise ValueError("address outside the unsigned 64-bit range")
        return f"0x{value:x}"
    return value


HexAddress = Annotated[
    str, BeforeValidator(_to_hex), Field(pattern=r"^0x[0-9a-f]{1,16}$", examples=["0x401000"])
]
# Path / query form of an address (`/functions/{entry}`, `decompile_addresses`): `0x` hex.
HEX_ADDRESS_PATTERN = r"^0x[0-9a-fA-F]{1,16}$"

ReProfileName = Literal["quick", "full"]
StageState = Literal["ok", "timeout", "failed", "skipped"]
AnalysisState = Literal["complete", "timeout", "failed", "not_run"]
FunctionDecompileState = Literal[
    "ok", "timeout", "failed", "truncated", "skipped_budget", "not_selected"
]
# Why a function is (or is not) on the decompile list: phase 5's priority classes.
PriorityReason = Literal[
    "requested", "entry_or_export", "capability", "suspicious_import", "ioc_string", "size"
]


class _Row(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ReStageOut(BaseModel):
    stage: ReStage
    status: StageState
    duration_ms: int = 0
    error_code: str | None = None
    truncated: bool = False
    peak_memory_bytes: int | None = None  # cgroup, measured by root (RT14)


class ReSummaryOut(BaseModel):
    """`GET /analyses/{job}/reverse`: the program header, the stage strip and the counts (a
    partial run is never shown as complete)."""

    job_id: uuid.UUID
    evidence_id: uuid.UUID
    source_job_id: uuid.UUID
    profile: ReProfileName
    engine: ReEngine
    engine_version: str | None = None
    code_kind: CodeKind
    format: Literal["pe", "elf"]
    arch: Literal["x86", "x86_64", "other"]
    machine: str | None = None
    bits: int
    endianness: Literal["little", "big"]
    language_id: str | None = None
    compiler_spec: str | None = None
    image_base: HexAddress
    preferred_base: HexAddress
    entry: HexAddress | None = None
    analysis_status: AnalysisState
    peak_memory_bytes: int | None = None
    stages: list[ReStageOut] = []
    counts: dict[str, int] = {}
    truncated: dict[str, bool] = {}
    tool_versions: dict[str, str] = {}
    decompile_addresses: list[HexAddress] = []  # what the request asked first (RT10)
    # The newest later RE job of the same evidence (the old job page links to it, RT10).
    newer_job_id: uuid.UUID | None = None


class FunctionRef(_Row):
    """A link to a function of the same job (callers / callees / referencing functions)."""

    entry: HexAddress
    name: str


class FunctionOut(_Row):
    id: uuid.UUID
    entry: HexAddress
    rva: HexAddress
    name: str
    name_source: NameSource
    size: int
    is_thunk: bool
    is_external: bool
    is_library: bool
    signature: str | None
    calling_convention: str | None
    instructions: int
    callers: int
    callees: int
    decompile_status: FunctionDecompileState
    priority_rank: int | None
    priority_reason: PriorityReason | None = None
    capabilities: int = 0  # linked capa capabilities (RT8 join)


class FunctionPage(CappedPage[FunctionOut]):
    pass


class BodyRangeOut(BaseModel):
    start: HexAddress  # RVA
    end: HexAddress


class LinkedCapabilityOut(BaseModel):
    """A capa capability of the source static job located in this function."""

    capability_id: uuid.UUID
    static_job_id: uuid.UUID
    name: str
    namespace: str | None
    attack: list[str] = []
    file_va: HexAddress


class DecompilationMetaOut(_Row):
    status: DecompileStatus
    code_kind: CodeKind
    lines: int
    code_sha256: str | None
    truncated_bytes: int
    duration_ms: int


class ImportOut(_Row):
    id: uuid.UUID
    library: str
    name: str | None
    ordinal: int | None
    address: HexAddress | None
    function_count: int = 0
    functions: list[FunctionRef] = []  # <= 20 calling functions


class ImportPage(CappedPage[ImportOut]):
    pass


class StringOut(_Row):
    id: uuid.UUID
    address: HexAddress
    encoding: Literal["ascii", "utf8", "utf16le", "utf16be", "utf32"]
    value: str
    length: int
    function_count: int = 0
    functions: list[FunctionRef] = []  # <= 20 referencing functions


class StringPage(CappedPage[StringOut]):
    pass


class FunctionDetailOut(BaseModel):
    """One function with what links to it (bounded lists, each <= 200)."""

    function: FunctionOut
    body: list[BodyRangeOut] = []
    body_truncated: bool = False
    callers: list[FunctionRef] = []
    callees: list[FunctionRef] = []
    imports: list[ImportOut] = []
    strings: list[StringOut] = []
    capabilities: list[LinkedCapabilityOut] = []
    finding_ids: list[uuid.UUID] = []  # findings whose `attributes.function_entry` is this
    decompilation: DecompilationMetaOut | None = None


class FunctionCodeOut(BaseModel):
    """`…/functions/{entry}/code`: the decompiled text (untrusted; rendered as text)."""

    entry: HexAddress
    name: str
    status: DecompileStatus
    code_kind: CodeKind
    code: str | None = None
    lines: int = 0
    code_sha256: str | None = None
    truncated_bytes: int = 0


class CapabilityFunctionRef(BaseModel):
    re_job_id: uuid.UUID
    function: FunctionRef
    file_va: HexAddress


class CapabilityFunctionsOut(BaseModel):
    """`GET /analyses/{static_job}/capabilities/{id}/functions`: the functions of the newest
    succeeded RE job of the same sample that contain the capability's locations. Empty
    `locations` = a static job from before M10 ("re-run static analysis to link")."""

    capability: CapabilityOut
    locations: list[HexAddress] = []
    re_job_id: uuid.UUID | None = None
    functions: list[CapabilityFunctionRef] = []
    unlocated: int = 0  # locations no function body contains
