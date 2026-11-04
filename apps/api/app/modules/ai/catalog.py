"""AI provider metadata (M5 phase 1, FROZEN): read by the API and the worker alike.

Data only, no adapter imports. Model ids and prices are config and churn: catalog changes go
through the parent (phase 3 verifies ids through the Models APIs and reports back).
Prices are USD per million tokens; `cost_micros` = Σ tokens × USD/MTok (1 USD = 10^6 micros
and 1 MTok = 10^6 tokens, so the factors cancel). Cost is always labelled an estimate.
"""

import math
from dataclasses import dataclass
from types import MappingProxyType

from app.modules.ai.contracts import AiProviderName, ProviderUsage

PRICE_VERSION = "2026-11-05"


@dataclass(frozen=True)
class ModelPrice:
    input: float
    output: float
    cache_read: float
    cache_write: float


@dataclass(frozen=True)
class AiModel:
    id: str
    label: str
    price: ModelPrice
    # False until phase 3 lists the id through the provider's Models API.
    verified: bool = False


@dataclass(frozen=True)
class ProviderLimits:
    """Requests per minute per org (token bucket); an org can lower it, never raise it above
    `ceilings` (operator override: `AI_CEILINGS.per_minute`)."""

    per_minute: int


@dataclass(frozen=True)
class AiCatalogEntry:
    name: AiProviderName
    label: str
    models: tuple[AiModel, ...]
    default_model: str
    tos_note: str
    privacy_note: str
    default_limits: ProviderLimits
    ceilings: ProviderLimits
    # Available only when ENV is not prod and AI_MOCK_ENABLED=true.
    dev_only: bool = False
    # Refused unless GEMINI_BILLING_ENABLED=true and the org attested a paid-tier key (RT5).
    requires_billing_flag: bool = False

    @property
    def model_ids(self) -> tuple[str, ...]:
        return tuple(m.id for m in self.models)

    def model(self, model_id: str) -> AiModel | None:
        return next((m for m in self.models if m.id == model_id), None)


_EVIDENCE_LEAVES = (
    "Running an analysis sends evidence excerpts to {label}: IP addresses, hostnames, URLs, "
    "file facts and finding text from the selected job or investigation. Internal IPs, "
    "hostnames and usernames are pseudonymized by default; public indicators are sent as is."
)

_ENTRIES = (
    AiCatalogEntry(
        name=AiProviderName.ANTHROPIC,
        label="Anthropic Claude",
        models=(
            AiModel(
                "claude-sonnet-5",
                "Claude Sonnet 5",
                ModelPrice(input=2.0, output=10.0, cache_read=0.20, cache_write=2.50),
            ),
            AiModel(
                "claude-opus-5-5",
                "Claude Opus 5.5",
                ModelPrice(input=4.0, output=20.0, cache_read=0.20, cache_write=5.00),
            ),
        ),
        default_model="claude-sonnet-5",
        tos_note=(
            "Your organization's own Anthropic API key: your organization is bound by its own "
            "Anthropic Commercial Terms and Usage Policy. CyberLab uses it for defensive "
            "security analysis only, with no tools. Standard API retention applies unless "
            "your organization has a zero-data-retention agreement."
        ),
        privacy_note=_EVIDENCE_LEAVES.format(label="Anthropic"),
        default_limits=ProviderLimits(per_minute=20),
        ceilings=ProviderLimits(per_minute=200),
    ),
    AiCatalogEntry(
        name=AiProviderName.GEMINI,
        label="Google Gemini",
        models=(
            AiModel(
                "gemini-3.8-flash",
                "Gemini 3.8 Flash",
                ModelPrice(input=1.50, output=7.50, cache_read=0.375, cache_write=1.50),
            ),
        ),
        default_model="gemini-3.8-flash",
        tos_note=(
            "Your organization's own Gemini API key: your organization is bound by the Gemini "
            "API Additional Terms and Google's usage policies; CyberLab uses it for defensive "
            "security analysis only. Paid-tier keys only: requires GEMINI_BILLING_ENABLED on "
            "the platform and your attestation that the key belongs to a billing-enabled "
            "project."
        ),
        privacy_note=(
            _EVIDENCE_LEAVES.format(label="Google")
            + " On the unpaid tier Google may use prompts and responses to improve its "
            "products and human reviewers may read them, so free-tier keys are not allowed."
        ),
        default_limits=ProviderLimits(per_minute=20),
        ceilings=ProviderLimits(per_minute=200),
        requires_billing_flag=True,
    ),
    AiCatalogEntry(
        name=AiProviderName.MOCK,
        label="Test analyst (mock)",
        models=(
            AiModel(
                "mock-1",
                "Mock analyst",
                ModelPrice(input=0.0, output=0.0, cache_read=0.0, cache_write=0.0),
                verified=True,
            ),
        ),
        default_model="mock-1",
        tos_note="Development and test sink only; refused in production.",
        privacy_note="Analyses go to the local ai-mock container; nothing leaves the host.",
        default_limits=ProviderLimits(per_minute=600),
        ceilings=ProviderLimits(per_minute=6000),
        dev_only=True,
    ),
)

AI_CATALOG: MappingProxyType[AiProviderName, AiCatalogEntry] = MappingProxyType(
    {entry.name: entry for entry in _ENTRIES}
)
AI_PROVIDER_NAMES: tuple[str, ...] = tuple(name.value for name in AiProviderName)

if set(AI_CATALOG) != set(AiProviderName):
    raise RuntimeError("every AI provider needs a catalog entry")
for _entry in _ENTRIES:
    if _entry.default_model not in _entry.model_ids:
        raise RuntimeError(f"{_entry.name}: default model is not in its allowlist")


def find_model(model_id: str) -> AiModel | None:
    """A model by id across providers (for pricing the served model)."""
    for entry in _ENTRIES:
        found = entry.model(model_id)
        if found is not None:
            return found
    return None


def cost_micros(model_id: str, usage: ProviderUsage) -> int | None:
    """Estimated cost in USD micros, or None when the model has no price here."""
    model = find_model(model_id)
    if model is None:
        return None
    p = model.price
    total = (
        usage.input_tokens * p.input
        + usage.output_tokens * p.output
        + usage.cache_read_tokens * p.cache_read
        + usage.cache_write_tokens * p.cache_write
    )
    return math.ceil(total)
