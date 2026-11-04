"""Strict, verdict-free per-provider summary models (frozen in M4 phase 1; RT14, RT19).

Adapters only fill these: they copy and coerce selected provider fields, never the raw body.
The API builds the OpenAPI union from `ProviderSummary`, and `ti_results.summary` stores
`model_dump(mode="json")`.

Provider text is untrusted (it may target M5's model as prompt injection): every string is
stripped of control, format (bidi, zero-width) and separator characters, then truncated to a
byte budget measured as JSON, so the worst case of every model is bounded. Lists are capped.
Each model refuses to serialize above `SUMMARY_MAX_BYTES` (the DB check uses the same limit),
and `tests/unit/test_ti_summaries.py` proves the worst case of every model fits.
"""

import json
import re
import unicodedata
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Self

from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field, model_validator

SUMMARY_MAX_BYTES = 16 * 1024

# Control, format (bidi overrides, zero-width), surrogate, private-use and unassigned
# characters are dropped; line and paragraph separators become spaces.
_DROP_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})
_SPACE_CATEGORIES = frozenset({"Zl", "Zp", "Zs"})
_ATTACK_ID = re.compile(r"T\d{4}(?:\.\d{3})?")


def clean_text(value: str) -> str:
    """Drop control/format characters, fold whitespace to single spaces, trim."""
    out: list[str] = []
    for char in value:
        category = unicodedata.category(char)
        if char in "\t\n\r\v\f" or category in _SPACE_CATEGORIES:
            out.append(" ")
        elif category not in _DROP_CATEGORIES:
            out.append(char)
    return " ".join("".join(out).split())


def _json_bytes(value: str) -> int:
    return len(json.dumps(value, ensure_ascii=False).encode()) - 2


def fit_bytes(value: str, max_bytes: int) -> str:
    """The longest prefix whose JSON-encoded UTF-8 form is at most `max_bytes` bytes."""
    value = value[:max_bytes]  # every character costs at least one byte
    if _json_bytes(value) <= max_bytes:
        return value
    low, high = 0, len(value)
    while low < high:
        mid = (low + high + 1) // 2
        if _json_bytes(value[:mid]) <= max_bytes:
            low = mid
        else:
            high = mid - 1
    return value[:low]


def _text(max_bytes: int) -> Callable[[Any], Any]:
    def validate(value: Any) -> Any:
        if not isinstance(value, str):
            return value  # pydantic's str validation then refuses it
        return fit_bytes(clean_text(value), max_bytes)

    return validate


def _cap(limit: int) -> Callable[[Any], Any]:
    def validate(value: Any) -> Any:
        if isinstance(value, list | tuple):
            return list(value[:limit])
        return value

    return validate


def _attack_ids(limit: int) -> Callable[[Any], Any]:
    """Keep only well-formed ATT&CK technique ids (upper-cased, de-duplicated, capped)."""

    def validate(value: Any) -> Any:
        if not isinstance(value, list | tuple):
            return value
        seen: list[str] = []
        for item in value:
            if isinstance(item, str):
                tid = item.strip().upper()
                if _ATTACK_ID.fullmatch(tid) and tid not in seen:
                    seen.append(tid)
        return seen[:limit]

    return validate


def _utc(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


Text8 = Annotated[str, BeforeValidator(_text(8))]
Text16 = Annotated[str, BeforeValidator(_text(16))]
Text32 = Annotated[str, BeforeValidator(_text(32))]
Text40 = Annotated[str, BeforeValidator(_text(40))]
Text48 = Annotated[str, BeforeValidator(_text(48))]
Text64 = Annotated[str, BeforeValidator(_text(64))]
Text80 = Annotated[str, BeforeValidator(_text(80))]
Text96 = Annotated[str, BeforeValidator(_text(96))]
Text128 = Annotated[str, BeforeValidator(_text(128))]
Text160 = Annotated[str, BeforeValidator(_text(160))]
Text256 = Annotated[str, BeforeValidator(_text(256))]

Count = Annotated[int, Field(ge=0, le=10**12)]
SignedInt = Annotated[int, Field(ge=-(10**12), le=10**12)]
Timestamp = Annotated[datetime | None, AfterValidator(_utc)]

Tags20 = Annotated[list[Text64], BeforeValidator(_cap(20))]
Tags8 = Annotated[list[Text48], BeforeValidator(_cap(8))]
AttackIds8 = Annotated[list[str], BeforeValidator(_attack_ids(8))]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _Summary(_Model):
    @model_validator(mode="after")
    def _bounded(self) -> Self:
        if summary_size(self) > SUMMARY_MAX_BYTES:
            raise ValueError("summary exceeds the size limit")
        return self


def summary_size(model: BaseModel) -> int:
    """Serialized size as Postgres renders the jsonb column (`summary::text`)."""
    return len(json.dumps(model.model_dump(mode="json"), ensure_ascii=False).encode())


# --- VirusTotal v3 -------------------------------------------------------------------


class VtAnalysisStats(_Model):
    malicious: Count = 0
    suspicious: Count = 0
    harmless: Count = 0
    undetected: Count = 0
    timeout: Count = 0


class VtVotes(_Model):
    harmless: Count = 0
    malicious: Count = 0


class VirusTotalSummary(_Summary):
    provider: Literal["virustotal"] = "virustotal"
    last_analysis_stats: VtAnalysisStats | None = None
    reputation: SignedInt | None = None
    total_votes: VtVotes | None = None
    tags: Tags20 = []
    last_analysis_date: Timestamp = None
    first_submission_date: Timestamp = None
    last_submission_date: Timestamp = None
    suggested_threat_label: Text128 | None = None
    meaningful_name: Text256 | None = None
    type_tag: Text32 | None = None
    as_owner: Text128 | None = None
    country: Text8 | None = None


# --- AbuseIPDB v2 --------------------------------------------------------------------


class AbuseIpdbSummary(_Summary):
    provider: Literal["abuseipdb"] = "abuseipdb"
    abuse_confidence_score: Annotated[int, Field(ge=0, le=100)] | None = None
    total_reports: Count | None = None
    num_distinct_users: Count | None = None
    last_reported_at: Timestamp = None
    is_whitelisted: bool | None = None
    is_tor: bool | None = None
    usage_type: Text64 | None = None
    isp: Text128 | None = None
    country_code: Text8 | None = None
    # AbuseIPDB report category ids (1-23 today), de-duplicated by the adapter.
    categories: Annotated[list[Annotated[int, Field(ge=0, le=255)]], BeforeValidator(_cap(30))] = []


# --- abuse.ch URLhaus ----------------------------------------------------------------


class UrlhausBlacklists(_Model):
    spamhaus_dbl: Text64 | None = None
    surbl: Text64 | None = None


class UrlhausSummary(_Summary):
    provider: Literal["urlhaus"] = "urlhaus"
    # Which URLhaus endpoint answered (`/v1/url/`, `/v1/host/` or `/v1/payload/`).
    lookup: Literal["url", "host", "payload"] | None = None
    url_status: Text16 | None = None
    threat: Text64 | None = None
    tags: Tags20 = []
    date_added: Timestamp = None
    last_online: Timestamp = None
    blacklists: UrlhausBlacklists | None = None
    url_count: Count | None = None
    first_seen: Timestamp = None
    last_seen: Timestamp = None
    signature: Text128 | None = None


# --- abuse.ch MalwareBazaar ----------------------------------------------------------


class MalwareBazaarSummary(_Summary):
    provider: Literal["malwarebazaar"] = "malwarebazaar"
    first_seen: Timestamp = None
    last_seen: Timestamp = None
    signature: Text128 | None = None
    tags: Tags20 = []
    file_type: Text32 | None = None
    imphash: Text64 | None = None
    ssdeep: Text160 | None = None
    tlsh: Text80 | None = None
    # Names of the vendors that hold intel on the sample (never their report text).
    vendor_intel: Annotated[list[Text48], BeforeValidator(_cap(30))] = []


# --- AlienVault OTX ------------------------------------------------------------------


class OtxPulse(_Model):
    name: Text160
    tags: Tags8 = []
    malware_families: Annotated[list[Text64], BeforeValidator(_cap(4))] = []
    attack_ids: AttackIds8 = []
    modified: Timestamp = None


class OtxValidation(_Model):
    source: Text48 | None = None
    name: Text128 | None = None
    message: Text160 | None = None


class OtxSummary(_Summary):
    provider: Literal["otx"] = "otx"
    pulse_count: Count | None = None
    pulses: Annotated[list[OtxPulse], BeforeValidator(_cap(10))] = []
    reputation: SignedInt | None = None
    validation: Annotated[list[OtxValidation], BeforeValidator(_cap(5))] = []


# --- MISP ----------------------------------------------------------------------------


class MispAttribute(_Model):
    type: Text32
    category: Text48 | None = None
    to_ids: bool = False
    first_seen: Timestamp = None
    last_seen: Timestamp = None
    timestamp: Timestamp = None
    event_id: Annotated[int, Field(ge=1, le=2**63 - 1)] | None = None
    event_info: Text96 | None = None
    event_uuid: uuid.UUID | None = None
    tags: Annotated[list[Text40], BeforeValidator(_cap(6))] = []


class MispSummary(_Summary):
    provider: Literal["misp"] = "misp"
    # Attributes MISP returned (the list below keeps at most 20 of them).
    attribute_count: Count = 0
    attributes: Annotated[list[MispAttribute], BeforeValidator(_cap(20))] = []
    # Distinct TLP tags over every returned attribute, so a cap never hides a TLP marking.
    tlp: Annotated[list[Text32], BeforeValidator(_cap(4))] = []


# --- mock (dev/test only) ------------------------------------------------------------


class MockSummary(_Summary):
    provider: Literal["mock"] = "mock"
    behaviour: Text32 | None = None
    label: Text64 | None = None
    hits: Count | None = None
    tags: Tags8 = []


ProviderSummary = Annotated[
    VirusTotalSummary
    | AbuseIpdbSummary
    | UrlhausSummary
    | MalwareBazaarSummary
    | OtxSummary
    | MispSummary
    | MockSummary,
    Field(discriminator="provider"),
]

SUMMARY_MODELS: dict[str, type[_Summary]] = {
    "virustotal": VirusTotalSummary,
    "abuseipdb": AbuseIpdbSummary,
    "urlhaus": UrlhausSummary,
    "malwarebazaar": MalwareBazaarSummary,
    "otx": OtxSummary,
    "misp": MispSummary,
    "mock": MockSummary,
}
