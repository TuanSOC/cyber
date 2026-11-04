"""Shared AI analyst contracts (M5 phase 1, FROZEN).

Every group-B phase builds on these names and shapes; only the parent changes them. They are
pure data: no DB, no network, no SDK imports, so the API, the analyst worker and the tests
all import this module.

ai-mock wire protocol (mirrored by `infra/ai-mock/server.py`, stdlib only; phase 2 owns the
server, phase 3 the client in `providers/mock.py`):
- every request carries `X-Mock-Key: <key>`; a wrong key answers 401 `{"error": "auth"}`.
- `POST /v1/analyze` body `{model, system, user, schema, max_output_tokens}` ->
  200 `{output: <object|string>, usage: {input_tokens, output_tokens}, stop_reason:
  "end_turn"|"max_tokens"|"refusal", refusal_category?: str, model: str}`;
  errors: 429 (`Retry-After` header optional; body `{"error": "rate_limited"}` or
  `{"error": "spend_limit"}`), 529 `{"error": "overloaded"}`, 401, 500.
- `POST /v1/count_tokens` body as analyze -> `{input_tokens: int}`.
- `GET /v1/verify` -> 200 `{ok: true}` or 401.
- Behaviour markers anywhere in the evidence text select a scripted answer: `ai-mock:429`,
  `ai-mock:429-nora`, `ai-mock:529`, `ai-mock:spend`, `ai-mock:401`, `ai-mock:500`,
  `ai-mock:slow`, `ai-mock:oversize`, `ai-mock:malformed`, `ai-mock:schema`,
  `ai-mock:refuse`, `ai-mock:maxtokens`, `ai-mock:fabricate`, `ai-mock:echo`,
  `ai-mock:inject` (see phase 2).
"""

import enum
import hashlib
import json
import unicodedata
import uuid
from typing import Any, Literal, Protocol, Self, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.modules.ai.output_schema import AnalysisOutput

# --- enums ---------------------------------------------------------------------------------


class AiProviderName(enum.StrEnum):
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    MOCK = "mock"  # dev/test only (refused when ENV=prod)


class AiTask(enum.StrEnum):
    EXPLAIN_FINDING = "explain_finding"
    EXPLAIN_ALERT = "explain_alert"
    SUMMARIZE_PCAP = "summarize_pcap"
    EXPLAIN_STATIC = "explain_static"
    IOC_CORRELATION = "ioc_correlation"
    ATTACK_MAPPING = "attack_mapping"
    INCIDENT_SUMMARY = "incident_summary"
    JOB_DIGEST = "job_digest"  # internal child of an incident; never requested directly


# Tasks a user may request (job_digest is created by the API for incident children only).
REQUESTABLE_TASKS = frozenset(AiTask) - {AiTask.JOB_DIGEST}
# Tasks whose target is one row of the job (finding / alert) and needs `target_id`.
TARGETED_TASKS = frozenset({AiTask.EXPLAIN_FINDING, AiTask.EXPLAIN_ALERT})
JOB_ONLY_TASKS = frozenset(
    {AiTask.EXPLAIN_FINDING, AiTask.EXPLAIN_ALERT, AiTask.SUMMARIZE_PCAP, AiTask.EXPLAIN_STATIC}
)
INVESTIGATION_ONLY_TASKS = frozenset({AiTask.INCIDENT_SUMMARY})


class AiScope(enum.StrEnum):
    JOB = "job"
    INVESTIGATION = "investigation"


class AiRunStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    REFUSED = "refused"


RUN_ACTIVE = (AiRunStatus.QUEUED, AiRunStatus.RUNNING, AiRunStatus.WAITING)
RUN_FINAL = (
    AiRunStatus.COMPLETED,
    AiRunStatus.PARTIAL,
    AiRunStatus.FAILED,
    AiRunStatus.REFUSED,
)


class AiErrorCode(enum.StrEnum):
    """`ai_runs.error_code` (stable strings; the UI maps them to messages)."""

    NOT_IMPLEMENTED = "not_implemented"
    DEADLINE = "deadline"
    AI_DISABLED = "ai_disabled"
    PROVIDER_DISABLED = "provider_disabled"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    AUTH_FAILED = "auth_failed"
    SPEND_LIMIT = "spend_limit"
    OVERLOADED = "overloaded"
    MAX_TOKENS = "max_tokens"
    INVALID_OUTPUT = "invalid_output"
    CONTEXT_TOO_LARGE = "context_too_large"
    BUDGET_EXHAUSTED = "budget_exhausted"
    PROVIDER_ERROR = "provider_error"
    CANARY_LEAK = "canary_leak"
    NO_DIGEST = "no_digest"
    REFUSED = "refused"


class RefKind(enum.StrEnum):
    """Kinds of context items; each has a one-letter label prefix (`prefix`)."""

    JOB = "job"  # J: job summary
    FINDING = "finding"  # F
    ALERT = "alert"  # A
    FLOW = "flow"  # N: keyed by (job_id, flow_ref), never flow_ref alone (RT16)
    RECORD = "record"  # R: dns / http / tls record
    IOC = "ioc"  # I
    TI_RESULT = "ti_result"  # T: never sole evidence
    SAMPLE = "sample"  # M
    SIGNATURE = "signature"  # S: signature match
    CAPABILITY = "capability"  # C
    PE_SUMMARY = "pe_summary"  # P
    STRING = "string"  # X: FLOSS string, opt-in
    TIMELINE = "timeline"  # E: timeline entry
    EVIDENCE = "evidence"  # K: evidence or custody
    INVESTIGATION = "investigation"  # V
    DIGEST_CLAIM = "digest_claim"  # D: child digest claim, never valid as evidence

    @property
    def prefix(self) -> str:
        return _PREFIX[self]

    @classmethod
    def from_prefix(cls, prefix: str) -> "RefKind | None":
        return _BY_PREFIX.get(prefix)


_PREFIX: dict[RefKind, str] = {
    RefKind.JOB: "J",
    RefKind.FINDING: "F",
    RefKind.ALERT: "A",
    RefKind.FLOW: "N",
    RefKind.RECORD: "R",
    RefKind.IOC: "I",
    RefKind.TI_RESULT: "T",
    RefKind.SAMPLE: "M",
    RefKind.SIGNATURE: "S",
    RefKind.CAPABILITY: "C",
    RefKind.PE_SUMMARY: "P",
    RefKind.STRING: "X",
    RefKind.TIMELINE: "E",
    RefKind.EVIDENCE: "K",
    RefKind.INVESTIGATION: "V",
    RefKind.DIGEST_CLAIM: "D",
}
_BY_PREFIX = {p: k for k, p in _PREFIX.items()}


class Confidence(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CitationStatus(enum.StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    INVALID = "invalid"


class ClaimStatus(enum.StrEnum):
    SUPPORTED = "supported"  # backed by cited evidence (never "true", RT21)
    UNSUPPORTED = "unsupported"  # hidden by default in the UI
    HYPOTHESIS = "hypothesis"


class CitationReason(enum.StrEnum):
    """Why a citation is not verified, or why a claim is unsupported."""

    # invalid
    UNKNOWN_LABEL = "unknown_label"
    DIGEST_NOT_EVIDENCE = "digest_not_evidence"
    FIELD_NOT_ALLOWED = "field_not_allowed"
    OUT_OF_SCOPE = "out_of_scope"
    ROW_MISSING = "row_missing"
    # unverified
    QUOTE_MISMATCH = "quote_mismatch"
    QUOTE_TOO_SHORT = "quote_too_short"  # RT1
    QUOTE_REQUIRED = "quote_required"
    # claim-level
    WEAK_ANCHOR = "weak_anchor"  # RT1
    NO_VERIFIED_CITATION = "no_verified_citation"
    INVALID_ATTACK = "invalid_attack"
    NO_TIMESTAMP = "no_timestamp"


class OutputFlag(enum.StrEnum):
    CANARY_LEAK = "canary_leak"
    VERDICT_LANGUAGE = "verdict_language"
    COMMAND_LIKE = "command_like"
    EXTERNAL_URL = "external_url"


class ProviderErrorKind(enum.StrEnum):
    RATE_LIMITED = "rate_limited"
    OVERLOADED = "overloaded"
    SPEND_LIMIT = "spend_limit"
    AUTH_FAILED = "auth_failed"
    REFUSED = "refused"
    MAX_TOKENS = "max_tokens"
    INVALID_OUTPUT = "invalid_output"
    CONTEXT_TOO_LARGE = "context_too_large"
    BAD_REQUEST = "bad_request"
    TIMEOUT = "timeout"
    TRANSPORT = "transport"
    PROVIDER_ERROR = "provider_error"


class VerifyStatus(enum.StrEnum):
    UNVERIFIED = "unverified"
    VALID = "valid"
    INVALID = "invalid"
    ERROR = "error"


ContextStage = Literal["base", "reduce"]
ContextBuildCode = Literal[
    "job_not_ready", "target_not_found", "task_not_applicable", "context_empty"
]
FieldValue = str | int | float | bool | None

_FROZEN = ConfigDict(extra="forbid", frozen=True)

# --- run request and scope -----------------------------------------------------------------


class AiRunRequest(BaseModel):
    """What a user asks for (the phase-7 request body reuses it). Exactly one of `job_id` /
    `investigation_id`; `target_id` only (and always) for the explain tasks."""

    model_config = _FROZEN

    task: AiTask
    job_id: uuid.UUID | None = None
    investigation_id: uuid.UUID | None = None
    target_id: uuid.UUID | None = None
    provider: AiProviderName | None = None
    model: str | None = Field(default=None, min_length=1, max_length=64)
    regenerate: bool = False

    @model_validator(mode="after")
    def _shape(self) -> Self:
        if self.task not in REQUESTABLE_TASKS:
            raise ValueError("task_not_requestable")
        if (self.job_id is None) == (self.investigation_id is None):
            raise ValueError("exactly one of job_id or investigation_id is required")
        if self.task in JOB_ONLY_TASKS and self.job_id is None:
            raise ValueError("this task needs job_id")
        if self.task in INVESTIGATION_ONLY_TASKS and self.investigation_id is None:
            raise ValueError("this task needs investigation_id")
        if (self.task in TARGETED_TASKS) != (self.target_id is not None):
            raise ValueError("target_id is required for explain_finding/explain_alert only")
        return self

    @property
    def scope(self) -> AiScope:
        return AiScope.JOB if self.job_id is not None else AiScope.INVESTIGATION


class RunScope(BaseModel):
    """The rows a run may cite: its job(s), and for investigation scope the investigation and
    its evidence. The verifier re-queries every cited row inside this scope."""

    model_config = _FROZEN

    scope: AiScope
    job_ids: tuple[uuid.UUID, ...] = ()
    investigation_id: uuid.UUID | None = None
    evidence_ids: tuple[uuid.UUID, ...] = ()


# --- context -------------------------------------------------------------------------------


class ContextItem(BaseModel):
    """One labelled item exactly as sent. `fields` keys are the only valid citation `field`
    values for this item; values are already sanitized, pseudonymized, defanged, truncated."""

    model_config = _FROZEN

    label: str = Field(max_length=16)
    kind: RefKind
    fields: dict[str, FieldValue]


class ContextRef(BaseModel):
    """Server-side map label -> row (stored in `ai_context_refs`; never sent)."""

    model_config = _FROZEN

    label: str = Field(max_length=16)
    kind: RefKind
    ref_table: str = Field(max_length=64)
    ref_id: str = Field(max_length=128)  # uuid text, or the Zeek uid for flows
    job_id: uuid.UUID | None = None  # set for every job-scoped row (flows always, RT16)
    fields_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stage: ContextStage = "base"


class KindStats(BaseModel):
    model_config = _FROZEN

    included: int = Field(ge=0)
    total: int = Field(ge=0)


class ContextStats(BaseModel):
    """`ai_runs.context_stats` (≤ 16 KiB). Keys are kind values / category names only: never
    field names, titles or filenames (RT4)."""

    model_config = _FROZEN

    per_kind: dict[RefKind, KindStats] = {}
    omitted: int = Field(default=0, ge=0)
    est_tokens: int = Field(default=0, ge=0)
    truncated: bool = False
    truncated_fields: dict[RefKind, int] = {}
    dropped_keys: int = Field(default=0, ge=0)  # hostile attribute keys (RT4)
    pseudonymized: dict[str, int] = {}  # {"ip": n, "host": n, "user": n}
    neutralized: int = Field(default=0, ge=0)  # planted pseudonym-shaped tokens (RT15)
    stripped: dict[str, int] = {}  # StripCounts by category
    jobs_omitted: int = Field(default=0, ge=0)  # incident: jobs over AI_MAX_JOBS_PER_INCIDENT


CONTEXT_VERSION = "ctx.v1"


class FrozenContext(BaseModel):
    """The context of one run stage. `canonical_json()` / `sha256` cover only
    `{version, task, items}`; `refs`, `scope`, `stats` and `pseudonym_map` are server-side."""

    model_config = _FROZEN

    version: str = CONTEXT_VERSION
    task: AiTask
    scope: RunScope
    items: tuple[ContextItem, ...]
    refs: tuple[ContextRef, ...] = ()
    stats: ContextStats = ContextStats()
    # {pseudonym: original}: stored in ai_run_inputs.pseudonym_map only; never sent.
    pseudonym_map: dict[str, str] = Field(default_factory=dict, repr=False)

    def canonical_json(self) -> str:
        """Sorted keys, no whitespace, NFC, non-ASCII kept."""
        payload = {
            "version": self.version,
            "task": self.task.value,
            "items": [item.model_dump(mode="json") for item in self.items],
        }
        text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return unicodedata.normalize("NFC", text)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_json().encode()).hexdigest()

    def item(self, label: str) -> ContextItem | None:
        return next((i for i in self.items if i.label == label), None)


class BuiltRun(BaseModel):
    """What the builder returns: the root context and, for an incident, one `job_digest`
    child context per job (each with `scope.job_ids == (job_id,)`)."""

    model_config = _FROZEN

    root: FrozenContext
    children: tuple[FrozenContext, ...] = ()


# --- prompt and provider -------------------------------------------------------------------


class PromptParts(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    system: str
    user: str
    delimiter: str = Field(repr=False)
    canary: str = Field(repr=False)


class ProviderRequest(BaseModel):
    """One provider call. Adapters send `system` and `user` only; `context` is an in-process
    reference for the in-process providers (Fake, Hostile, Replay) and is never serialized.
    No `fallback` field (RT10)."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, arbitrary_types_allowed=True, hide_input_in_errors=True
    )

    model: str
    system: str = Field(repr=False)
    user: str = Field(repr=False)
    output_schema: dict[str, Any] = Field(repr=False)
    max_output_tokens: int = Field(ge=1)
    effort: str | None = None
    context: FrozenContext | None = Field(default=None, exclude=True, repr=False)


class ProviderUsage(BaseModel):
    model_config = _FROZEN

    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cache_read_tokens: int = Field(default=0, ge=0)
    cache_write_tokens: int = Field(default=0, ge=0)

    @property
    def total(self) -> int:
        return (
            self.input_tokens
            + self.output_tokens
            + self.cache_read_tokens
            + self.cache_write_tokens
        )


class ProviderResult(BaseModel):
    """A successful call: the parsed JSON object (never raw text)."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    parsed: dict[str, Any] = Field(repr=False)
    usage: ProviderUsage
    served_model: str
    stop_reason: str = Field(max_length=32)
    refusal_category: str | None = Field(default=None, max_length=32)
    request_id: str | None = Field(default=None, max_length=128)


class ProviderError(Exception):
    """A typed provider failure. Fixed message (the kind); never a key, body or cause."""

    def __init__(
        self,
        kind: ProviderErrorKind,
        *,
        http_status: int | None = None,
        retry_after_s: float | None = None,
        category: str | None = None,
        request_sent: bool = False,
    ) -> None:
        super().__init__(kind.value)
        self.kind = kind
        self.http_status = http_status
        self.retry_after_s = retry_after_s
        # Refusal category: an open string, cut to 32 characters (RT24).
        self.category = category[:32] if category else None
        # True once the request left the process: a timeout may have been billed (RT2).
        self.request_sent = request_sent

    def __repr__(self) -> str:
        return (
            f"ProviderError(kind={self.kind.value!r}, http_status={self.http_status}, "
            f"retry_after_s={self.retry_after_s}, category={self.category!r}, "
            f"request_sent={self.request_sent})"
        )


class VerifyOutcome(BaseModel):
    model_config = _FROZEN

    status: VerifyStatus
    error_code: str | None = Field(default=None, max_length=64)


@runtime_checkable
class LlmProvider(Protocol):
    """Every provider (adapters, FakeProvider, eval providers). No tools, ever."""

    name: str

    async def analyze(self, request: ProviderRequest) -> ProviderResult: ...

    async def count_tokens(self, request: ProviderRequest) -> int | None: ...

    async def verify(self) -> VerifyOutcome: ...

    async def aclose(self) -> None: ...


# --- verification --------------------------------------------------------------------------

Section = Literal[
    "observed",
    "interpretation",
    "hypotheses",
    "next_steps",
    "attack_techniques",
    "timeline",
]


class CitationResult(BaseModel):
    """One checked citation (one `ai_citations` row). `claim_path` like
    `observed[2].citations[0]`, `hypotheses[0].supporting[1]`, `next_steps[1].refs[0]`."""

    model_config = _FROZEN

    claim_path: str = Field(max_length=128)
    section: Section
    claim_id: str | None = Field(default=None, max_length=32)
    label: str = Field(max_length=32)
    kind: RefKind | None = None  # None when the label is unknown
    ref_id: str | None = Field(default=None, max_length=128)
    job_id: uuid.UUID | None = None
    field: str | None = Field(default=None, max_length=64)
    quote: str | None = Field(default=None, max_length=256)
    status: CitationStatus
    reason: CitationReason | None = None
    stale: bool = False  # the row changed after the run (fields_sha256 differs)


class ClaimVerdict(BaseModel):
    model_config = _FROZEN

    status: ClaimStatus
    reason: CitationReason | None = None


class OutputVerification(BaseModel):
    """`ai_outputs.verification` (frozen stored shape, RT12)."""

    model_config = _FROZEN

    version: Literal["v1"] = "v1"
    # claim id -> verdict, for every observed / interpretation / hypothesis / timeline /
    # attack_techniques entry (attack entries keyed by `attack:<technique_id>`, timeline
    # entries by `timeline:<index>`).
    claims: dict[str, ClaimVerdict] = {}
    citations: dict[CitationStatus, int] = {}
    dropped_refs: int = Field(default=0, ge=0)  # invalid next_steps / hypothesis refs (RT21)
    invalid_attack: int = Field(default=0, ge=0)
    truncation: dict[str, int] = {}  # coerce_caps counts (RT19)
    reused_from_run_id: uuid.UUID | None = None  # digest reuse (phase 2)


class RunMetrics(BaseModel):
    """`ai_runs.metrics` (≤ 4 KiB; frozen stored shape, RT12). Rates are None when their
    denominator is zero."""

    model_config = _FROZEN

    version: Literal["v1"] = "v1"
    citations_total: int = Field(default=0, ge=0)
    citations_verified: int = Field(default=0, ge=0)
    citations_unverified: int = Field(default=0, ge=0)
    citations_invalid: int = Field(default=0, ge=0)
    citation_accuracy: float | None = Field(default=None, ge=0, le=1)
    by_reason: dict[CitationReason, int] = {}
    claims_total: int = Field(default=0, ge=0)  # observed + interpretation
    claims_unsupported: int = Field(default=0, ge=0)
    unsupported_claim_rate: float | None = Field(default=None, ge=0, le=1)
    weak_anchor: int = Field(default=0, ge=0)
    invalid_ref_rate: float | None = Field(default=None, ge=0, le=1)
    invalid_attack: int = Field(default=0, ge=0)
    truncation: dict[str, int] = {}
    strip_counts: dict[str, int] = {}  # from the model output
    flags: tuple[OutputFlag, ...] = ()
    # Worker-side (phase 2).
    refusal_category: str | None = Field(default=None, max_length=32)
    usage_unknown: bool = False  # timeout after the request was sent (RT2)
    cost_estimated: bool = False  # served model has no price in the catalog
    canary_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    repaired: bool = False  # the schema-repair retry was used
    replayed: bool = False  # eval ReplayProvider output


class VerifiedOutput(BaseModel):
    """What `verify_output` returns: the sanitized body (stored in `ai_outputs.body`), every
    citation result (`ai_citations` rows), the stored `verification` (claim statuses inside),
    the flags and the metrics."""

    model_config = _FROZEN

    body: AnalysisOutput
    citations: tuple[CitationResult, ...]
    verification: OutputVerification
    flags: tuple[OutputFlag, ...] = ()
    metrics: RunMetrics

    @property
    def claims(self) -> dict[str, ClaimVerdict]:
        return self.verification.claims


class DigestInput(BaseModel):
    """One completed child digest feeding an incident reduce (phase 2 builds it from the
    child's stored output; phase 4's `build_reduce_context` consumes it). Failed, refused and
    canary-leak children are never turned into a DigestInput (RT23)."""

    model_config = _FROZEN

    run_id: uuid.UUID
    job_id: uuid.UUID
    job_label: str = Field(pattern=r"^J\d{1,3}$")  # the child's prefix in the reduce context
    context: FrozenContext  # the child's base context (cited items are copied from it)
    body: AnalysisOutput
    claims: dict[str, ClaimVerdict]
    citations: tuple[CitationResult, ...]
    flags: tuple[OutputFlag, ...] = ()  # carried into the D items (RT23)


# --- exceptions ----------------------------------------------------------------------------


class ValidationFailed(Exception):
    """The model output failed the schema (raised by `verify_output`, caught by the worker
    for the one repair retry). `errors` are JSON paths + error types only, never values."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__("invalid_output")
        self.errors = errors


class ContextBuildError(Exception):
    """Raised by the context builder, mapped to HTTP codes by the routes (phase 7)."""

    def __init__(self, code: ContextBuildCode) -> None:
        super().__init__(code)
        self.code = code
