"""`re.v1`: reverse engineering of one PE / ELF sample (never executed), M10.

Same framing as the other analyzers (gzip NDJSON, header first, hashed trailer last) and the
same value bounds: every value is derived from an attacker-controlled binary, read by an
untrusted analyzer (Ghidra 12.2 headless through PyGhidra, or radare2 for `quick`). Names,
signatures, string values and decompiled code are attacker-influenced text: bounded and
NUL-free here, rendered as text only, sent to the AI only through the M5 transforms.

Line order (`LINE_ORDER`): header, program, function*, call_edge*, import*, import_ref*,
string*, string_ref*, decompiled*, finding*, ioc*, trailer. Imports and strings carry a
stream-local `index`; their references point at it (the ingest maps it to the row id).

A **diagnostic stream** (`unsupported_architecture`, `unsupported_managed_code`) is header,
program, trailer, uploaded with a `failed` ingest report (`check_diagnostic_kinds`).

Cross-record rules (`StreamChecker` / `validate_stream`, shared with the trusted ingest):
every reference names a known function, import or string; call edges join known functions;
decompiled entries are functions; at most one record per key; the decompiled code kind is
the header's; the per-kind caps and the code byte budget hold.

Frozen at the end of M10 phase 1: change only together with the trusted ingest (parent).
"""

import enum
import hashlib
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Annotated, Literal, Self, get_args

from pydantic import AfterValidator, BaseModel, Field, TypeAdapter, model_validator

from cyberlab_jobs.base import ErrorCode, Sha256, ShortText, Strict, Token
from cyberlab_jobs.messages import PresignedPost, Url
from cyberlab_jobs.results import (
    NO_NUL,
    Count,
    FindingRecord,
    IocRecord,
    ResultTrailer,
    Text64,
    Text128,
    Text255,
    Text512,
    ToolVersions,
)

RE_SCHEMA = "re.v1"

KIB = 1024
MIB = 1024**2
GIB = 1024**3
# Hard ceilings of the contract; the API's settings may only lower them.
MAX_SAMPLE_BYTES = 64 * MIB  # = STATIC_MAX_BYTES (RE_MAX_BYTES defaults to 16 MiB)
MAX_RESULT_BYTES = 256 * MIB
MAX_WORK_BYTES = 16 * GIB  # RE_MAX_WORK_BYTES (2 GiB default, RT5)
CAP_FUNCTIONS = 20_000
CAP_CALL_EDGES = 100_000
CAP_IMPORTS = 10_000
CAP_IMPORT_REFS = 50_000
CAP_STRINGS = 20_000
CAP_STRING_REFS = 50_000
CAP_DECOMPILED = 2_000
DEFAULT_DECOMPILED = 300
CAP_FINDINGS = 2_000
CAP_IOCS = 10_000
MAX_CODE_BYTES = 64 * KIB  # one function's code (UTF-8)
MAX_CODE_TOTAL_BYTES = 32 * MIB  # every function's code of one job
MAX_DECOMPILE_ADDRESSES = 64  # requested first (RT10)
MAX_CAPA_FILE_VAS = 512  # capa locations of the source static job (RT8)
MAX_BODY_RANGES = 16
MAX_JVM_ARGS = 64
MIN_STRING_CHARS = 5
MAX_STRING_CHARS = 1024
DISASM_MAX_INSTRUCTIONS = 400  # `code_kind = disasm` (radare2 / the no-go fallback)
MAX_JOB_TIMEOUT_S = 6 * 3600
# The marker the worker writes where it cut a code text (on a line boundary).
TRUNCATION_MARKER = "/* [cyberlab: truncated {n} bytes] */"

Address = Annotated[int, Field(ge=0, le=2**64 - 1)]  # unsigned 64-bit (numeric(20,0) columns)
Text32 = Annotated[str, Field(max_length=32, pattern=NO_NUL)]
Rank = Annotated[int, Field(ge=0, lt=CAP_FUNCTIONS)]


class ReProfile(enum.StrEnum):
    QUICK = "quick"  # radare2: functions, imports, strings, xrefs; no decompilation (phase 3)
    FULL = "full"  # Ghidra analysis + decompilation of the priority list (RT10: no `targeted`)


class ReEngine(enum.StrEnum):
    GHIDRA = "ghidra"
    RADARE2 = "radare2"
    REPLAY = "replay"  # test-profile only: hand-written stage outputs, never real analysis


class CodeKind(enum.StrEnum):
    PSEUDO_C = "pseudo_c"  # Ghidra's decompiler
    DISASM = "disasm"  # radare2 / the no-go fallback, <= DISASM_MAX_INSTRUCTIONS


class ReStage(enum.StrEnum):
    ANALYZE = "analyze"  # Ghidra: import + auto-analysis + export (one JVM)
    DECOMPILE = "decompile"  # Ghidra: a second JVM, the priority list
    R2 = "r2"  # radare2: one non-interactive run of the fixed script (RT9)


class NameSource(enum.StrEnum):
    EXPORT = "export"
    IMPORT = "import"
    SYMBOL = "symbol"
    DEBUG = "debug"
    FID_LIBRARY = "fid_library"
    GENERATED = "generated"  # FUN_00401000 / fcn.00401000


class DecompileStatus(enum.StrEnum):
    OK = "ok"
    TIMEOUT = "timeout"
    FAILED = "failed"
    TRUNCATED = "truncated"  # code cut at MAX_CODE_BYTES on a line boundary (marker added)
    SKIPPED_BUDGET = "skipped_budget"  # the job's code budget or deadline was exhausted


CODE_STATUSES = frozenset({DecompileStatus.OK, DecompileStatus.TRUNCATED})

StageRunStatus = Literal["ok", "timeout", "failed", "skipped"]
FileFormat = Literal["pe", "elf"]
ReArch = Literal["x86", "x86_64", "other"]  # `other` only in an unsupported_architecture stream
AnalysisStatus = Literal["complete", "timeout", "failed", "not_run"]
StringEncoding = Literal["ascii", "utf8", "utf16le", "utf16be", "utf32"]

# Every code the RE analyzer, its ingest and the API may store or answer (classified in the
# API's ops/error_classes.py; its test fails on a missing one).
ReErrorCode = Literal[
    "not_implemented",
    "unsupported_architecture",
    "unsupported_managed_code",
    "unsupported_format",
    "re_sample_too_large",
    "re_out_of_memory",  # cgroup OOM kill or the JVM's ExitOnOutOfMemoryError (RT14)
    "re_work_too_large",  # the root disk watchdog (RT5)
    "re_parse_failed",
    "jvm_start_failed",
    "analysis_timeout",
    "decompile_timeout",
    "insufficient_disk",
    "profile_unavailable",
    "static_analysis_required",
    "engine_unavailable",
]
RE_ERROR_CODES: tuple[str, ...] = get_args(ReErrorCode)
DIAGNOSTIC_ERROR_CODES: frozenset[str] = frozenset(
    {"unsupported_architecture", "unsupported_managed_code"}
)


def _utf8_bounded(limit: int) -> AfterValidator:
    def check(value: str) -> str:
        if "\x00" in value:
            raise ValueError("NUL characters are not stored")
        try:
            size = len(value.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise ValueError("lone surrogates are not valid UTF-8") from exc
        if size > limit:
            raise ValueError(f"longer than {limit} UTF-8 bytes")
        return value

    return AfterValidator(check)


Code = Annotated[str, _utf8_bounded(MAX_CODE_BYTES)]
StringValue = Annotated[
    str, Field(min_length=MIN_STRING_CHARS, max_length=MAX_STRING_CHARS, pattern=NO_NUL)
]


# --- limits and job ---------------------------------------------------------------------------


class ReLimits(Strict):
    """Resource limits the API attaches to every RE job; the worker enforces them."""

    max_bytes: int = Field(gt=0, le=MAX_SAMPLE_BYTES)
    timeout_s: int = Field(gt=0, le=MAX_JOB_TIMEOUT_S)  # the whole job
    tool_timeout_s: int = Field(gt=0)  # one stage process (wall)
    analysis_timeout_s: int = Field(gt=0)  # Ghidra's auto-analysis monitor
    decompile_timeout_s: int = Field(gt=0, le=600)  # one function
    quick_timeout_s: int = Field(gt=0)  # the radare2 run (phase 3)
    max_functions: int = Field(gt=0, le=CAP_FUNCTIONS)
    max_call_edges: int = Field(gt=0, le=CAP_CALL_EDGES)
    max_imports: int = Field(gt=0, le=CAP_IMPORTS)
    max_import_refs: int = Field(gt=0, le=CAP_IMPORT_REFS)
    max_strings: int = Field(gt=0, le=CAP_STRINGS)
    max_string_refs: int = Field(gt=0, le=CAP_STRING_REFS)
    max_decompiled: int = Field(ge=0, le=CAP_DECOMPILED)
    max_code_bytes: int = Field(gt=0, le=MAX_CODE_BYTES)
    max_code_total_bytes: int = Field(gt=0, le=MAX_CODE_TOTAL_BYTES)
    max_findings: int = Field(gt=0, le=CAP_FINDINGS)
    max_iocs: int = Field(gt=0, le=CAP_IOCS)
    max_result_bytes: int = Field(gt=0, le=MAX_RESULT_BYTES)
    max_work_bytes: int = Field(gt=0, le=MAX_WORK_BYTES)

    @model_validator(mode="after")
    def _timeouts_nest(self) -> Self:
        if not self.decompile_timeout_s < self.tool_timeout_s < self.timeout_s:
            raise ValueError("decompile_timeout_s < tool_timeout_s < timeout_s is required")
        if self.analysis_timeout_s > self.tool_timeout_s:
            raise ValueError("analysis_timeout_s must not exceed tool_timeout_s")
        if self.quick_timeout_s > self.tool_timeout_s:
            raise ValueError("quick_timeout_s must not exceed tool_timeout_s")
        return self

    def max_lines(self) -> int:
        """Upper bound of a stream's lines at these caps (header + program + trailer + records)."""
        return 3 + sum(
            (
                self.max_functions,
                self.max_call_edges,
                self.max_imports,
                self.max_import_refs,
                self.max_strings,
                self.max_string_refs,
                self.max_decompiled,
                self.max_findings,
                self.max_iocs,
            )
        )


class ReJobV1(Strict):
    """API -> RE analyzer (queue `reverse`, task `reverse.analyze`)."""

    schema_version: Literal["re.v1"] = RE_SCHEMA
    job_id: uuid.UUID
    organization_id: uuid.UUID
    evidence_id: uuid.UUID
    source_job_id: uuid.UUID  # the succeeded static `full` job of the same evidence
    expected_sha256: Sha256
    size_bytes: int = Field(ge=0)
    evidence_url: Url
    result_post: PresignedPost
    ingest_token: Token
    profile: ReProfile
    file_format: FileFormat
    # Engine virtual addresses decompiled first (priority class 1; `full` only, RT10).
    decompile_addresses: Annotated[list[Address], Field(max_length=MAX_DECOMPILE_ADDRESSES)] = []
    # capa match locations of the source job as file virtual addresses (RT8), sorted, unique.
    capa_file_vas: Annotated[list[Address], Field(max_length=MAX_CAPA_FILE_VAS)] = []
    limits: ReLimits

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if len(set(self.decompile_addresses)) != len(self.decompile_addresses):
            raise ValueError("decompile_addresses must be unique")
        if self.decompile_addresses and self.profile != ReProfile.FULL:
            raise ValueError("decompile_addresses are only accepted with profile full")
        if self.capa_file_vas != sorted(set(self.capa_file_vas)):
            raise ValueError("capa_file_vas must be sorted and unique")
        if self.size_bytes > self.limits.max_bytes:
            raise ValueError("the sample is above limits.max_bytes")
        return self


# --- result lines -----------------------------------------------------------------------------


class StageReport(Strict):
    stage: ReStage
    status: StageRunStatus
    duration_ms: Count = 0
    error_code: ErrorCode | None = None
    truncated: bool = False
    # Measured by root from the container cgroup (`memory.peak` / polled `memory.current`,
    # RT14), never reported by the tool.
    peak_memory_bytes: Count | None = None


class ReResultHeader(Strict):
    kind: Literal["header"] = "header"
    schema_version: Literal["re.v1"] = RE_SCHEMA
    job_id: uuid.UUID
    profile: ReProfile
    engine: ReEngine
    code_kind: CodeKind
    tool_versions: ToolVersions
    stages: Annotated[list[StageReport], Field(max_length=8)] = []
    # PEP 578 audit-hook refusals per event family (socket, subprocess, ...): zero expected;
    # the decompile stage's child executables are recorded under `child:*` keys (RT15).
    audit: Annotated[dict[Text64, Count], Field(max_length=16)] = {}
    # The JVM's effective input arguments (`RuntimeMXBean.getInputArguments()`, RT1).
    jvm_args: Annotated[list[Text512], Field(max_length=MAX_JVM_ARGS)] = []
    engine_errors: Annotated[list[ErrorCode], Field(max_length=32)] = []
    truncated: Annotated[dict[ShortText, bool], Field(max_length=32)] = {}

    @model_validator(mode="after")
    def _engine_rules(self) -> Self:
        stages = [s.stage for s in self.stages]
        if len(set(stages)) != len(stages):
            raise ValueError("a stage is reported twice")
        if self.engine == ReEngine.GHIDRA:
            if self.code_kind != CodeKind.PSEUDO_C:
                raise ValueError("ghidra produces pseudo_c")
            if ReStage.R2 in stages:
                raise ValueError("a ghidra run has no r2 stage")
        if self.engine == ReEngine.RADARE2:
            if self.code_kind != CodeKind.DISASM:
                raise ValueError("radare2 produces disasm")
            if set(stages) - {ReStage.R2}:
                raise ValueError("a radare2 run has only the r2 stage")
            if self.jvm_args:
                raise ValueError("a radare2 run starts no JVM")
        if self.profile == ReProfile.QUICK:
            if self.engine == ReEngine.GHIDRA:
                raise ValueError("the quick profile is radare2 (or replay)")
            if ReStage.DECOMPILE in stages:
                raise ValueError("the quick profile decompiles nothing")
        return self


class BodyRange(Strict):
    """A half-open RVA range [start, end) of a function body."""

    start: Address
    end: Address

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if not self.start < self.end:
            raise ValueError("a body range is half-open with start < end")
        return self


class ReProgramRecord(Strict):
    """Exactly one, the second line. `sha256` / `size_bytes` must equal the evidence
    (checked by ingest). `preferred_base` is the file's own base (PE ImageBase; ELF lowest
    PT_LOAD p_vaddr, page-aligned); `image_base` is the engine's (Ghidra rebases ELF PIE):
    file_va = va - (image_base - preferred_base) (RT8)."""

    kind: Literal["program"] = "program"
    format: FileFormat
    arch: ReArch
    machine: Text64 | None = None  # the raw machine name (diagnostics)
    bits: Literal[16, 32, 64]
    endianness: Literal["little", "big"]
    language_id: Text64 | None = None  # Ghidra, e.g. x86:LE:64:default
    compiler_spec: Text32 | None = None
    image_base: Address
    preferred_base: Address
    entry: Address | None = None
    sha256: Sha256
    size_bytes: Count
    analysis_status: AnalysisStatus
    counts: Annotated[dict[Text64, Count], Field(max_length=32)] = {}

    def to_file_va(self, va: int) -> int:
        return va - (self.image_base - self.preferred_base)

    def to_va(self, file_va: int) -> int:
        return file_va + (self.image_base - self.preferred_base)


class ReFunctionRecord(Strict):
    kind: Literal["function"] = "function"
    entry: Address  # engine virtual address (the key)
    rva: Address
    name: Text255
    name_source: NameSource
    size: Count
    body: Annotated[list[BodyRange], Field(max_length=MAX_BODY_RANGES)] = []
    body_truncated: bool = False
    is_thunk: bool = False
    is_external: bool = False
    is_library: bool = False
    signature: Text512 | None = None
    calling_convention: Text32 | None = None
    instructions: Count = 0
    callers: Count = 0
    callees: Count = 0
    # Root's deterministic decompile priority (phase 5); None = not ranked (thunk, external,
    # library, or the quick profile).
    priority_rank: Rank | None = None


class ReCallEdgeRecord(Strict):
    kind: Literal["call_edge"] = "call_edge"
    caller: Address
    callee: Address
    sites: Annotated[int, Field(ge=1, le=2**63 - 1)] = 1


class ReImportRecord(Strict):
    kind: Literal["import"] = "import"
    index: Annotated[int, Field(ge=0, lt=CAP_IMPORTS)]
    library: Text128
    name: Text255 | None = None
    ordinal: Annotated[int, Field(ge=0, le=65535)] | None = None
    address: Address | None = None  # thunk / IAT / PLT address

    @model_validator(mode="after")
    def _named(self) -> Self:
        if self.name is None and self.ordinal is None:
            raise ValueError("an import has a name or an ordinal")
        return self


class ReImportRefRecord(Strict):
    """An import called (directly or through a thunk) from a function: one per pair."""

    kind: Literal["import_ref"] = "import_ref"
    import_index: Annotated[int, Field(ge=0, lt=CAP_IMPORTS)]
    function_entry: Address
    count: Annotated[int, Field(ge=1, le=2**63 - 1)] = 1


class ReStringRecord(Strict):
    kind: Literal["string"] = "string"
    index: Annotated[int, Field(ge=0, lt=CAP_STRINGS)]
    address: Address
    encoding: StringEncoding
    value: StringValue
    length: Count  # characters in the binary (may exceed the stored value)


class ReStringRefRecord(Strict):
    kind: Literal["string_ref"] = "string_ref"
    string_index: Annotated[int, Field(ge=0, lt=CAP_STRINGS)]
    function_entry: Address
    count: Annotated[int, Field(ge=1, le=2**63 - 1)] = 1


def code_lines(code: str) -> int:
    return len(code.splitlines())


def code_sha256(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


class ReDecompiledRecord(Strict):
    kind: Literal["decompiled"] = "decompiled"
    function_entry: Address
    status: DecompileStatus
    code_kind: CodeKind
    code: Code | None = None
    lines: Count = 0
    code_sha256: Sha256 | None = None
    truncated_bytes: Count = 0  # bytes cut (status truncated)
    duration_ms: Count = 0

    @model_validator(mode="after")
    def _code(self) -> Self:
        has_code = self.status in CODE_STATUSES
        if has_code != (self.code is not None):
            raise ValueError("code is present iff the status is ok or truncated")
        if self.code is None:
            if self.code_sha256 is not None or self.lines or self.truncated_bytes:
                raise ValueError("a record without code has no sha256, lines or cut bytes")
            return self
        if self.code_sha256 != code_sha256(self.code):
            raise ValueError("code_sha256 does not match the code")
        if self.lines != code_lines(self.code):
            raise ValueError("lines does not match the code")
        if (self.status == DecompileStatus.TRUNCATED) != (self.truncated_bytes > 0):
            raise ValueError("a truncated record (and only that) reports the cut bytes")
        return self


ReRecordLine = Annotated[
    ReProgramRecord
    | ReFunctionRecord
    | ReCallEdgeRecord
    | ReImportRecord
    | ReImportRefRecord
    | ReStringRecord
    | ReStringRefRecord
    | ReDecompiledRecord
    | FindingRecord
    | IocRecord,
    Field(discriminator="kind"),
]
ReAnyLine = Annotated[
    ReResultHeader
    | ReProgramRecord
    | ReFunctionRecord
    | ReCallEdgeRecord
    | ReImportRecord
    | ReImportRefRecord
    | ReStringRecord
    | ReStringRefRecord
    | ReDecompiledRecord
    | FindingRecord
    | IocRecord
    | ResultTrailer,
    Field(discriminator="kind"),
]
RE_RECORD_ADAPTER: TypeAdapter[ReRecordLine] = TypeAdapter(ReRecordLine)
RE_LINE_ADAPTER: TypeAdapter[ReAnyLine] = TypeAdapter(ReAnyLine)

# The order of line kinds in a full stream (equal kinds are contiguous).
LINE_ORDER: tuple[str, ...] = (
    "header",
    "program",
    "function",
    "call_edge",
    "import",
    "import_ref",
    "string",
    "string_ref",
    "decompiled",
    "finding",
    "ioc",
    "trailer",
)
_RANK = {kind: i for i, kind in enumerate(LINE_ORDER)}
DIAGNOSTIC_KINDS = ("header", "program", "trailer")


def check_diagnostic_kinds(kinds: Iterable[str]) -> None:
    """The diagnostic-stream rule: exactly header, program, trailer."""
    if tuple(kinds) != DIAGNOSTIC_KINDS:
        raise ValueError("a diagnostic stream is header, program, trailer")


class StreamRefused(ValueError):
    """A stream broke a framing or cross-record rule (the message names the rule only)."""


@dataclass
class StreamChecker:
    """Incremental cross-record validation of parsed `re.v1` lines (header to trailer).

    Holds only keys (entries, indexes), never the records: the ingest feeds it while it
    streams rows. `finish()` checks the deferred rules (references to functions may only be
    resolved once every function line was seen, but functions come first, so they are
    resolved eagerly here; the deferred part is the trailer and the per-stream totals).
    """

    job_id: uuid.UUID | None = None
    limits: ReLimits | None = None
    diagnostic: bool = False
    header: ReResultHeader | None = None
    program: ReProgramRecord | None = None
    functions: set[int] = field(default_factory=set)
    edges: set[tuple[int, int]] = field(default_factory=set)
    imports: set[int] = field(default_factory=set)
    import_refs: set[tuple[int, int]] = field(default_factory=set)
    strings: set[int] = field(default_factory=set)
    string_refs: set[tuple[int, int]] = field(default_factory=set)
    decompiled: set[int] = field(default_factory=set)
    code_bytes: int = 0
    findings: int = 0
    iocs: int = 0
    kinds: list[str] = field(default_factory=list)
    _last_rank: int = 0
    _done: bool = False

    def feed(self, line: BaseModel) -> None:
        if self._done:
            raise StreamRefused("a line after the trailer")
        kind = str(getattr(line, "kind", ""))
        if kind not in _RANK:
            raise StreamRefused("unknown line kind")
        rank = _RANK[kind]
        if not self.kinds and kind != "header":
            raise StreamRefused("the header is the first line")
        if self.kinds and kind == "header":
            raise StreamRefused("one header")
        if len(self.kinds) == 1 and kind != "program":
            raise StreamRefused("the program is the second line")
        if rank < self._last_rank or (kind == "program" and self.program is not None):
            raise StreamRefused(f"`{kind}` line out of order")
        self._last_rank = rank
        self.kinds.append(kind)
        if self.diagnostic and kind not in DIAGNOSTIC_KINDS:
            raise StreamRefused("a diagnostic stream is header, program, trailer")
        handler = getattr(self, f"_on_{kind}")
        handler(line)

    # --- per kind -------------------------------------------------------------------------

    def _on_header(self, line: ReResultHeader) -> None:
        if self.job_id is not None and line.job_id != self.job_id:
            raise StreamRefused("the header names another job")
        self.header = line

    def _on_program(self, line: ReProgramRecord) -> None:
        if line.arch == "other" and not self.diagnostic:
            raise StreamRefused("an unsupported architecture is a diagnostic stream")
        self.program = line

    def _cap(self, count: int, name: str) -> None:
        if self.limits is not None and count > getattr(self.limits, name):
            raise StreamRefused(f"more records than {name}")

    def _on_function(self, line: ReFunctionRecord) -> None:
        if line.entry in self.functions:
            raise StreamRefused("a function is listed twice")
        self.functions.add(line.entry)
        self._cap(len(self.functions), "max_functions")

    def _known(self, entry: int) -> None:
        if entry not in self.functions:
            raise StreamRefused("a reference names an unknown function")

    def _on_call_edge(self, line: ReCallEdgeRecord) -> None:
        self._known(line.caller)
        self._known(line.callee)
        key = (line.caller, line.callee)
        if key in self.edges:
            raise StreamRefused("a call edge is listed twice")
        self.edges.add(key)
        self._cap(len(self.edges), "max_call_edges")

    def _on_import(self, line: ReImportRecord) -> None:
        if line.index in self.imports:
            raise StreamRefused("an import index is listed twice")
        self.imports.add(line.index)
        self._cap(len(self.imports), "max_imports")

    def _on_import_ref(self, line: ReImportRefRecord) -> None:
        if line.import_index not in self.imports:
            raise StreamRefused("an import reference names an unknown import")
        self._known(line.function_entry)
        key = (line.import_index, line.function_entry)
        if key in self.import_refs:
            raise StreamRefused("an import reference is listed twice")
        self.import_refs.add(key)
        self._cap(len(self.import_refs), "max_import_refs")

    def _on_string(self, line: ReStringRecord) -> None:
        if line.index in self.strings:
            raise StreamRefused("a string index is listed twice")
        self.strings.add(line.index)
        self._cap(len(self.strings), "max_strings")

    def _on_string_ref(self, line: ReStringRefRecord) -> None:
        if line.string_index not in self.strings:
            raise StreamRefused("a string reference names an unknown string")
        self._known(line.function_entry)
        key = (line.string_index, line.function_entry)
        if key in self.string_refs:
            raise StreamRefused("a string reference is listed twice")
        self.string_refs.add(key)
        self._cap(len(self.string_refs), "max_string_refs")

    def _on_decompiled(self, line: ReDecompiledRecord) -> None:
        assert self.header is not None  # noqa: S101 - feed() put the header first
        if self.header.profile == ReProfile.QUICK:
            raise StreamRefused("the quick profile carries no decompiled line")
        if line.code_kind != self.header.code_kind:
            raise StreamRefused("a decompiled line's code kind differs from the header's")
        self._known(line.function_entry)
        if line.function_entry in self.decompiled:
            raise StreamRefused("a function is decompiled twice")
        self.decompiled.add(line.function_entry)
        self._cap(len(self.decompiled), "max_decompiled")
        if line.code is not None:
            size = len(line.code.encode("utf-8"))
            if self.limits is not None and size > self.limits.max_code_bytes:
                raise StreamRefused("a code text is above max_code_bytes")
            self.code_bytes += size
            total = self.limits.max_code_total_bytes if self.limits else MAX_CODE_TOTAL_BYTES
            if self.code_bytes > total:
                raise StreamRefused("the code texts exceed max_code_total_bytes")

    def _on_finding(self, line: FindingRecord) -> None:
        self.findings += 1
        self._cap(self.findings, "max_findings")

    def _on_ioc(self, line: IocRecord) -> None:
        self.iocs += 1
        self._cap(self.iocs, "max_iocs")

    def _on_trailer(self, line: ResultTrailer) -> None:
        self._done = True

    def finish(self) -> None:
        if not self._done:
            raise StreamRefused("the trailer is the last line")
        if self.program is None:
            raise StreamRefused("the program line is missing")
        if self.diagnostic:
            try:
                check_diagnostic_kinds(self.kinds)
            except ValueError as exc:
                raise StreamRefused(str(exc)) from exc


def validate_stream(
    lines: Iterable[BaseModel],
    *,
    job_id: uuid.UUID | None = None,
    limits: ReLimits | None = None,
    diagnostic: bool = False,
) -> StreamChecker:
    """Every cross-record rule over parsed lines (header to trailer, in order). The trailer's
    line count and digest are checked on the raw bytes by the framing reader."""
    checker = StreamChecker(job_id=job_id, limits=limits, diagnostic=diagnostic)
    for line in lines:
        checker.feed(line)
    checker.finish()
    return checker


__all__ = [
    "CAP_CALL_EDGES",
    "CAP_DECOMPILED",
    "CAP_FINDINGS",
    "CAP_FUNCTIONS",
    "CAP_IMPORTS",
    "CAP_IMPORT_REFS",
    "CAP_IOCS",
    "CAP_STRINGS",
    "CAP_STRING_REFS",
    "CODE_STATUSES",
    "DEFAULT_DECOMPILED",
    "DIAGNOSTIC_ERROR_CODES",
    "DIAGNOSTIC_KINDS",
    "DISASM_MAX_INSTRUCTIONS",
    "LINE_ORDER",
    "MAX_BODY_RANGES",
    "MAX_CAPA_FILE_VAS",
    "MAX_CODE_BYTES",
    "MAX_CODE_TOTAL_BYTES",
    "MAX_DECOMPILE_ADDRESSES",
    "MAX_JVM_ARGS",
    "MAX_RESULT_BYTES",
    "MAX_SAMPLE_BYTES",
    "MAX_WORK_BYTES",
    "RE_ERROR_CODES",
    "RE_LINE_ADAPTER",
    "RE_RECORD_ADAPTER",
    "RE_SCHEMA",
    "TRUNCATION_MARKER",
    "BodyRange",
    "CodeKind",
    "DecompileStatus",
    "FileFormat",
    "NameSource",
    "ReAnyLine",
    "ReArch",
    "ReCallEdgeRecord",
    "ReDecompiledRecord",
    "ReEngine",
    "ReErrorCode",
    "ReFunctionRecord",
    "ReImportRecord",
    "ReImportRefRecord",
    "ReJobV1",
    "ReLimits",
    "ReProfile",
    "ReProgramRecord",
    "ReRecordLine",
    "ReResultHeader",
    "ReStage",
    "ReStringRecord",
    "ReStringRefRecord",
    "StageReport",
    "StageRunStatus",
    "StreamChecker",
    "StreamRefused",
    "check_diagnostic_kinds",
    "code_lines",
    "code_sha256",
    "validate_stream",
]
