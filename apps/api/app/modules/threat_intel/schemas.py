"""HTTP models of the threat intel routes (M4 phase 5).

Write-only secrets: `api_key` is a `SecretStr` that appears in request models only; no
response model has a key, ciphertext or sealing column other than `key_last4`. Validators
never put a submitted value in their message (the error envelope echoes loc/msg/type only).

Provider summaries are the frozen per-provider models of `summaries.py`, exposed as a
discriminated union (`provider`), so the generated contracts carry per-provider types.
"""

import enum
import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    StringConstraints,
    field_validator,
)
from pydantic.config import JsonDict

from app.core.pagination import Page
from app.modules.threat_intel.models import MAX_EXCLUDED_SUFFIXES, MAX_VALUE_CHARS
from app.modules.threat_intel.normalize import normalize_suffix
from app.modules.threat_intel.providers.base import (
    Detections,
    IocType,
    ProviderName,
    ResultStatus,
    VerifyStatus,
)
from app.modules.threat_intel.seal import MAX_KEY_CHARS, MIN_KEY_CHARS
from app.modules.threat_intel.summaries import ProviderSummary

RunScope = Literal["manual", "job"]
RunStatus = Literal["queued", "running", "waiting", "completed", "partial", "failed"]
ItemState = Literal["pending", "done", "cached", "abandoned"]
ItemReason = Literal[
    "rate_limited", "quota_exhausted", "deadline", "auth_failed", "policy_blocked"
]
# The contract name of the provider-side `IocType` (the analysis results have their own
# `IocType`): a PEP 695 alias gives the OpenAPI component a stable, distinct name. Use it,
# never the bare enum, in request/response models.
type TiIocType = IocType

_KEY_RULE = f"api_key must be {MIN_KEY_CHARS}-{MAX_KEY_CHARS} printable ASCII characters"


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _api_key(value: SecretStr) -> SecretStr:
    """Strip, then 8-256 printable ASCII (the seal's own rule). Never echoes the value."""
    text = value.get_secret_value().strip()
    if not MIN_KEY_CHARS <= len(text) <= MAX_KEY_CHARS or not all(
        0x20 <= ord(c) <= 0x7E for c in text
    ):
        raise ValueError(_KEY_RULE)
    return SecretStr(text)


ApiKey = Annotated[SecretStr, AfterValidator(_api_key)]


def _no_default(schema: JsonDict) -> None:
    schema.pop("default", None)


# --- integrations --------------------------------------------------------------------


class LimitsOut(BaseModel):
    per_minute: int | None
    per_day: int | None


class LimitsIn(_In):
    """Self-imposed limits; an org may lower them, never raise them above the ceilings."""

    per_minute: int | None = Field(default=None, ge=1, le=1_000_000)
    per_day: int | None = Field(default=None, ge=1, le=100_000_000)


class IntegrationUpdate(_In):
    # Write-only: never part of any response, audit row or log line.
    api_key: ApiKey | None = None
    enabled: bool | None = None
    # Optional (false when omitted). No `default` in the JSON schema: openapi-typescript would
    # otherwise make it a required property of the generated request type.
    acknowledge_terms: bool = Field(default=False, json_schema_extra=_no_default)
    # MISP only: https, no userinfo/query/fragment (checked syntactically, no DNS).
    base_url: Annotated[str, StringConstraints(max_length=2048)] | None = None
    # Replaces the org's limits; `{}` resets them to the catalog defaults.
    limits: LimitsIn | None = None


class IntegrationOut(BaseModel):
    name: ProviderName
    label: str
    supported_types: list[TiIocType]
    tos_note: str
    privacy_note: str
    needs_base_url: bool
    default_limits: LimitsOut
    ceilings: LimitsOut
    # False for `mock` in prod, and for every provider when TI is disabled.
    available: bool
    # A sealed key is stored (shown only as its last four characters).
    configured: bool
    enabled: bool
    key_last4: str | None
    verify_status: VerifyStatus | None
    verified_at: datetime | None
    last_error_code: str | None
    terms_ack_at: datetime | None
    base_url: str | None
    # The org's own (lowered) limits, if any.
    limits: LimitsOut | None


class IntegrationSaved(IntegrationOut):
    """A PUT's answer: the read model plus whether a key check (`ti.verify`) was queued. It
    is not when nothing verifiable changed (no new key, no new base URL), when the
    per-provider verify limit (shared with POST .../verify) is spent, or when the broker is
    unreachable; the save itself stands in every case."""

    verify_queued: bool


class IntegrationPage(Page[IntegrationOut]):
    ti_enabled: bool


class VerifyQueued(BaseModel):
    provider: ProviderName
    status: Literal["queued"] = "queued"


def _suffixes(values: list[str]) -> list[str]:
    out: list[str] = []
    for index, value in enumerate(values):
        normalized = normalize_suffix(value)
        if normalized is None:
            raise ValueError(f"excluded_suffixes[{index}] is not a valid domain suffix")
        if normalized not in out:
            out.append(normalized)
    return out


class TiSettingsUpdate(_In):
    excluded_suffixes: Annotated[
        list[Annotated[str, StringConstraints(max_length=255)]],
        Field(max_length=MAX_EXCLUDED_SUFFIXES),
        AfterValidator(_suffixes),
    ]


class TiSettingsOut(BaseModel):
    # Domain suffixes never sent to any provider (domains, URL hosts, email domains).
    excluded_suffixes: list[str]
    updated_at: datetime | None


# --- results -------------------------------------------------------------------------


class ResultOut(BaseModel):
    """One provider answer (verdict-free, source-attributed)."""

    id: uuid.UUID
    run_id: uuid.UUID
    provider: ProviderName
    ioc_type: TiIocType
    value_norm: str
    ioc_key: str
    status: ResultStatus
    found: bool
    score: float | None
    score_scale: str | None
    detections: Detections | None
    tags: list[str]
    families: list[str]
    attack_ids: list[str]
    first_seen: datetime | None
    last_seen: datetime | None
    summary: ProviderSummary | None
    permalink: str | None
    error_code: str | None
    fetched_at: datetime
    expires_at: datetime | None
    # Past its cache lifetime (an older answer; a new lookup would ask the provider again).
    stale: bool


class ResultPage(Page[ResultOut]):
    pass


class HistoryOut(Page[ResultOut]):
    """Every stored answer for one normalized indicator (all providers, newest first)."""

    ioc_type: TiIocType | None
    value_norm: str | None
    ioc_key: str | None
    notes: list[str]
    # Why no provider would receive this value (results may still exist, e.g. for `mock`).
    skipped: str | None


class IocEnrichmentOut(BaseModel):
    """The latest answer of one provider for one IOC row (`include=enrichment`)."""

    provider: ProviderName
    status: ResultStatus
    found: bool
    score: float | None
    score_scale: str | None
    detections: Detections | None
    tags: list[str]
    families: list[str]
    attack_ids: list[str]
    fetched_at: datetime
    expires_at: datetime | None
    stale: bool
    permalink: str | None
    result_id: uuid.UUID


class IocInclude(enum.StrEnum):
    ENRICHMENT = "enrichment"


# --- runs ----------------------------------------------------------------------------


class LookupType(enum.StrEnum):
    IP = "ip"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class EnrichmentCreate(_In):
    # Defaults to every enabled (and available) provider.
    providers: Annotated[list[ProviderName], Field(min_length=1, max_length=16)] | None = None


class LookupValueIn(_In):
    value: Annotated[str, StringConstraints(min_length=1, max_length=MAX_VALUE_CHARS)]
    # Detected from the value when omitted.
    type: LookupType | None = None


class LookupCreate(_In):
    values: Annotated[list[LookupValueIn], Field(min_length=1, max_length=100)]
    providers: Annotated[list[ProviderName], Field(min_length=1, max_length=16)] | None = None

    @field_validator("providers")
    @classmethod
    def _distinct(cls, value: list[ProviderName] | None) -> list[ProviderName] | None:
        return None if value is None else list(dict.fromkeys(value))


class RunOut(BaseModel):
    id: uuid.UUID
    scope: RunScope
    job_id: uuid.UUID | None
    status: RunStatus
    providers: list[str]
    summary: dict[str, Any]
    deadline_at: datetime
    resume_at: datetime | None
    requested_by: uuid.UUID
    requested_by_name: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class RunPage(Page[RunOut]):
    pass


class RunItemOut(BaseModel):
    seq: int
    provider: ProviderName
    ioc_type: TiIocType
    value_norm: str
    ioc_key: str
    state: ItemState
    reason: ItemReason | None
    # This run's answer, or the cached answer of an earlier run (`from_cache`).
    result: ResultOut | None
    from_cache: bool


class RunItemPage(Page[RunItemOut]):
    pass


class RunDetailOut(RunOut):
    items: RunItemPage


class ValueReportOut(BaseModel):
    """How one manual lookup value was normalized, and who (if anyone) receives it."""

    index: int
    ioc_type: str | None
    value_norm: str | None
    ioc_key: str | None
    notes: list[str]
    # Set when no requested provider may receive the value (nothing is sent).
    skipped: str | None
    providers: list[str]
    provider_skips: dict[str, str]


class RunRequestOut(BaseModel):
    """202: a new run; 200: an active run of the same job (`deduplicated`) or nothing
    eligible (`run` is null, the report explains why)."""

    run: RunOut | None
    deduplicated: bool
    items: int
    summary: dict[str, Any]
    report: list[ValueReportOut]
