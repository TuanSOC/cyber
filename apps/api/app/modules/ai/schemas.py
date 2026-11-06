"""HTTP models of the AI analyst routes (M5 phase 7).

Write-only secrets: `api_key` is a `SecretStr` in the provider request model only; no
response model carries a key, a ciphertext or a sealing column other than `key_last4`, and
validators never put a submitted value in their message (the error envelope echoes
loc/msg/type only). The output read model has no free-form URL field: links exist only as
server-built internal deep-link descriptors (`AiDeepLink`) on verified citations.
"""

import ipaddress
import uuid
from datetime import date, datetime
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    StringConstraints,
)
from pydantic.config import JsonDict

from app.core.pagination import Page
from app.core.sealbox import MAX_KEY_CHARS, MIN_KEY_CHARS
from app.modules.ai.contracts import (
    AiProviderName,
    AiRunRequest,
    AiRunStatus,
    AiScope,
    AiTask,
    CitationReason,
    CitationStatus,
    ClaimStatus,
    ContextItem,
    ContextStats,
    OutputFlag,
    RefKind,
    RunMetrics,
    VerifyStatus,
)
from app.modules.ai.models import MAX_LIST_ENTRIES
from app.modules.threat_intel.normalize import normalize_suffix

UnavailableReason = Literal["ai_disabled_platform", "prod_mock", "gemini_billing_required"]
ConfidenceLevel = Literal["low", "medium", "high"]
DeepLinkRoute = Literal["pcap", "malware", "memory", "forensics", "evidence", "investigation"]
# The result tabs a deep link may name (pcap, static and memory job pages); anything else is
# dropped. A memory job's findings, IOCs and timeline use the shared tab names (M8).
DeepLinkTab = Literal[
    "overview",
    "findings",
    "alerts",
    "flows",
    "dns",
    "http",
    "tls",
    "iocs",
    "timeline",
    "signatures",
    "capabilities",
    "sections",
    "strings",
]
ContextStageName = Literal["base", "reduce"]
PseudonymMode = Literal["reversed", "kept"]

_KEY_RULE = f"api_key must be {MIN_KEY_CHARS}-{MAX_KEY_CHARS} printable ASCII characters"
MAX_BUDGET = 10**12


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _no_default(schema: JsonDict) -> None:
    """Optional booleans without a `default` in the JSON schema (openapi-typescript would
    otherwise make them required properties of the generated request type)."""
    schema.pop("default", None)


def _api_key(value: SecretStr) -> SecretStr:
    """Strip, then 8-256 printable ASCII (the seal's own rule). Never echoes the value."""
    text = value.get_secret_value().strip()
    if not MIN_KEY_CHARS <= len(text) <= MAX_KEY_CHARS or not all(
        0x20 <= ord(c) <= 0x7E for c in text
    ):
        raise ValueError(_KEY_RULE)
    return SecretStr(text)


ApiKey = Annotated[SecretStr, AfterValidator(_api_key)]


# --- providers -----------------------------------------------------------------------


class AiModelPrice(BaseModel):
    """USD per million tokens (an estimate: prices change; see `price_version`)."""

    input: float
    output: float
    cache_read: float
    cache_write: float


class AiModelOut(BaseModel):
    id: str
    label: str
    price: AiModelPrice
    # False until the id was listed through the provider's Models API.
    verified: bool


class AiLimitsOut(BaseModel):
    # Requests per minute per org (token bucket on the broker).
    per_minute: int


class AiLimitsIn(_In):
    """The org's own limits: an admin may set any value from 1 up to the ceiling."""

    per_minute: int | None = Field(default=None, ge=1, le=1_000_000)


class AiProviderOut(BaseModel):
    name: AiProviderName
    label: str
    models: list[AiModelOut]
    default_model: str
    price_version: str
    tos_note: str
    privacy_note: str
    available: bool
    unavailable_reason: UnavailableReason | None
    # The dev/test platform key covers this provider (never in prod).
    platform_key: bool
    # Gemini: the first enable needs `acknowledge_paid_tier` (RT5).
    requires_paid_tier_ack: bool
    # A sealed key is stored (shown only as its last four characters).
    configured: bool
    enabled: bool
    # None: the catalog default model.
    model: str | None
    key_last4: str | None
    verify_status: VerifyStatus | None
    verified_at: datetime | None
    last_error_code: str | None
    terms_ack_at: datetime | None
    paid_tier_ack_at: datetime | None
    default_limits: AiLimitsOut
    # The catalog ceiling, or the operator's `AI_CEILINGS.per_minute` override.
    ceilings: AiLimitsOut
    # The org's own limits, if any, as applied (capped by the current ceiling).
    limits: AiLimitsOut | None


class AiProviderPage(Page[AiProviderOut]):
    # The operator switch (`AI_ENABLED`); per-org opt-in is in `/ai/settings`.
    platform_ai_enabled: bool


class AiProviderSaved(AiProviderOut):
    """A PUT's answer plus whether a key check (`ai.verify`) was queued: only after a new
    key, within the per-provider verify limit, and when the broker took it."""

    verify_queued: bool


class AiProviderUpdate(_In):
    # Write-only: never part of any response, audit row or log line.
    api_key: ApiKey | None = None
    enabled: bool | None = None
    acknowledge_terms: bool = Field(default=False, json_schema_extra=_no_default)
    # Gemini only: the admin attests that the key belongs to a paid-tier project (RT5).
    acknowledge_paid_tier: bool = Field(default=False, json_schema_extra=_no_default)
    # A catalog model id; null resets to the catalog default.
    model: Annotated[str, StringConstraints(min_length=1, max_length=64)] | None = None
    # Replaces the org's limits; `{}` resets them to the catalog defaults.
    limits: AiLimitsIn | None = None


class AiVerifyQueued(BaseModel):
    provider: AiProviderName
    status: Literal["queued"] = "queued"


# --- settings ------------------------------------------------------------------------


def _cidrs(values: list[str]) -> list[str]:
    out: list[str] = []
    for index, value in enumerate(values):
        try:
            network = ipaddress.ip_network(value.strip(), strict=False)
        except ValueError:
            raise ValueError(f"internal_cidrs[{index}] is not a valid CIDR") from None
        text = str(network)
        if text not in out:
            out.append(text)
    return out


def _suffixes(values: list[str]) -> list[str]:
    out: list[str] = []
    for index, value in enumerate(values):
        normalized = normalize_suffix(value)
        if normalized is None:
            raise ValueError(f"internal_suffixes[{index}] is not a valid domain suffix")
        if normalized not in out:
            out.append(normalized)
    return out


Budget = Annotated[int, Field(ge=1, le=MAX_BUDGET)]


class AiCeilingsOut(BaseModel):
    """Operator ceilings over the per-org budgets (`AI_CEILINGS`)."""

    daily_token_budget: int
    run_token_cap: int
    incident_token_cap: int


class AiSettingsOut(BaseModel):
    ai_enabled: bool
    platform_ai_enabled: bool
    privacy_ack_at: datetime | None
    privacy_ack_by: uuid.UUID | None
    default_provider: AiProviderName | None
    pseudonymize_internal: bool
    internal_cidrs: list[str]
    internal_suffixes: list[str]
    include_strings: bool
    include_ti: bool
    include_case_text: bool
    daily_token_budget: int
    run_token_cap: int
    incident_token_cap: int
    ceilings: AiCeilingsOut
    privacy_notice: str
    updated_at: datetime | None


class AiSettingsUpdate(_In):
    """Partial update. Turning AI on, and widening the disclosure later (strings or case text
    on, pseudonymization off), needs `acknowledge_privacy` (RT22)."""

    ai_enabled: bool | None = None
    acknowledge_privacy: bool = Field(default=False, json_schema_extra=_no_default)
    # null clears it (the platform default provider applies).
    default_provider: AiProviderName | None = None
    pseudonymize_internal: bool | None = None
    internal_cidrs: (
        Annotated[
            list[Annotated[str, StringConstraints(max_length=64)]],
            Field(max_length=MAX_LIST_ENTRIES),
            AfterValidator(_cidrs),
        ]
        | None
    ) = None
    internal_suffixes: (
        Annotated[
            list[Annotated[str, StringConstraints(max_length=255)]],
            Field(max_length=MAX_LIST_ENTRIES),
            AfterValidator(_suffixes),
        ]
        | None
    ) = None
    include_strings: bool | None = None
    include_ti: bool | None = None
    include_case_text: bool | None = None
    daily_token_budget: Budget | None = None
    run_token_cap: Budget | None = None
    incident_token_cap: Budget | None = None


# --- context -------------------------------------------------------------------------


class AiRunCreate(AiRunRequest):
    """`POST /ai/runs` and `/ai/context-preview` (the frozen `AiRunRequest`; `regenerate`
    without a schema default)."""

    regenerate: bool = Field(default=False, json_schema_extra=_no_default)


class AiInclusions(BaseModel):
    pseudonymize_internal: bool
    include_strings: bool
    include_ti: bool
    include_case_text: bool


class AiContextPreviewOut(BaseModel):
    """What a run would send (pseudonyms shown, never the map). Nothing is persisted."""

    task: AiTask
    provider: AiProviderName
    model: str
    context_sha256: str
    context_stats: ContextStats
    items: list[ContextItem]
    # The categories of data that would leave the platform (e.g. `finding_text`).
    categories: list[str]
    inclusions: AiInclusions


class AiContextStageOut(BaseModel):
    stage: ContextStageName
    context_sha256: str
    version: str
    task: AiTask
    items: list[ContextItem]
    stats: ContextStats | None
    # `?reveal=true` only: {pseudonym: original}.
    pseudonym_map: dict[str, str] | None


class AiRunContextOut(BaseModel):
    run_id: uuid.UUID
    context_sha256: str
    revealed: bool
    stages: list[AiContextStageOut]


# --- runs ----------------------------------------------------------------------------


class AiTokenUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    total_tokens: int = 0


class AiRunOut(BaseModel):
    id: uuid.UUID
    task: AiTask
    scope: AiScope
    job_id: uuid.UUID | None
    investigation_id: uuid.UUID | None
    target_kind: Literal["finding", "alert"] | None
    target_id: uuid.UUID | None
    parent_run_id: uuid.UUID | None
    supersedes_run_id: uuid.UUID | None
    provider: AiProviderName
    model: str
    served_model: str | None
    prompt_version: str
    output_schema: str
    status: AiRunStatus
    error_code: str | None
    refusal_category: str | None
    context_sha256: str
    deadline_at: datetime
    resume_at: datetime | None
    usage: AiTokenUsage
    # USD micros; always an estimate (`cost_estimated` also when the served model is unpriced).
    cost_micros: int | None
    cost_estimated: bool
    price_version: str | None
    citation_accuracy: float | None
    claims_unsupported: int | None
    children: int
    requested_by: uuid.UUID
    requested_by_name: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class AiRunPage(Page[AiRunOut]):
    pass


class AiRunCreated(BaseModel):
    run: AiRunOut
    # An identical active or completed run was returned instead of a new one.
    deduplicated: bool


class AiDeepLink(BaseModel):
    """An internal deep link (never a URL): the web app maps it to its own route."""

    route: DeepLinkRoute
    job_id: uuid.UUID | None
    tab: DeepLinkTab | None
    ref: str | None


class AiCitationOut(BaseModel):
    label: str
    kind: RefKind | None
    status: CitationStatus
    reason: CitationReason | None
    field: str | None
    quote: str | None
    ref_id: str | None
    job_id: uuid.UUID | None
    stale: bool
    # Verified citations only.
    link: AiDeepLink | None


class AiClaimOut(BaseModel):
    id: str
    text: str
    confidence: ConfidenceLevel
    status: ClaimStatus
    reason: CitationReason | None
    citations: list[AiCitationOut]


class AiHypothesisOut(BaseModel):
    id: str
    text: str
    confidence: ConfidenceLevel
    status: ClaimStatus
    reason: CitationReason | None
    supporting: list[AiCitationOut]
    contradicting: list[AiCitationOut]


class AiOverallConfidenceOut(BaseModel):
    level: ConfidenceLevel
    rationale: str


class AiNextStepOut(BaseModel):
    text: str
    rationale: str
    refs: list[AiCitationOut]


class AiAttackOut(BaseModel):
    technique_id: str
    rationale: str
    status: ClaimStatus
    reason: CitationReason | None
    citations: list[AiCitationOut]


class AiTimelineOut(BaseModel):
    # From the row of the entry's first verified citation (never from model text).
    ts: datetime | None
    text: str
    status: ClaimStatus
    reason: CitationReason | None
    citations: list[AiCitationOut]


class AiVerificationOut(BaseModel):
    citations: dict[CitationStatus, int]
    dropped_refs: int
    invalid_attack: int
    truncation: dict[str, int]
    reused_from_run_id: uuid.UUID | None


class AiOutputOut(BaseModel):
    """The verified output, display-ready: claim statuses, resolved citations, and the text
    with pseudonyms reversed for `evidence.write` members (unless `?pseudonyms=keep`),
    always kept for viewers."""

    observed: list[AiClaimOut]
    interpretation: list[AiClaimOut]
    hypotheses: list[AiHypothesisOut]
    overall_confidence: AiOverallConfidenceOut
    next_steps: list[AiNextStepOut]
    limitations: list[str]
    attack_techniques: list[AiAttackOut]
    timeline: list[AiTimelineOut]
    flags: list[OutputFlag]
    verification: AiVerificationOut
    pseudonyms: PseudonymMode
    created_at: datetime


class AiChildRunOut(BaseModel):
    id: uuid.UUID
    job_id: uuid.UUID | None
    status: AiRunStatus
    error_code: str | None
    refusal_category: str | None
    flags: list[OutputFlag]
    citation_accuracy: float | None
    usage: AiTokenUsage
    finished_at: datetime | None


class AiRunDetail(AiRunOut):
    context_stats: ContextStats | None
    metrics: RunMetrics | None
    flags: list[OutputFlag]
    child_runs: list[AiChildRunOut]
    output: AiOutputOut | None
    # True for a canary-leak run: its body is never returned.
    output_withheld: bool


# --- usage ---------------------------------------------------------------------------


class AiProviderUsageOut(BaseModel):
    provider: AiProviderName
    runs: int
    usage: AiTokenUsage
    cost_micros: int


class AiUsageOut(BaseModel):
    """Today's (UTC) usage from `ai_runs.usage`; cost is an estimate."""

    day: date
    providers: list[AiProviderUsageOut]
    total_tokens: int
    cost_micros: int
    daily_token_budget: int
    remaining_tokens: int
    run_token_cap: int
    incident_token_cap: int
    ceilings: AiCeilingsOut
