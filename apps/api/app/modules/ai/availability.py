"""Whether an AI provider may be used in this deployment (shared by the API and the worker).

This is the operator-level gate only. Per-org conditions (AI enabled with the privacy
acknowledgement, provider enabled with its terms acknowledgement, Gemini paid-tier
attestation, a key) are checked by the routes and re-checked by the worker.
"""

from typing import Literal

from app.core.config import Settings
from app.modules.ai.catalog import AI_CATALOG
from app.modules.ai.contracts import AiProviderName

UnavailableReason = Literal["ai_disabled_platform", "prod_mock", "gemini_billing_required"]


def provider_available(
    settings: Settings, name: AiProviderName | str
) -> tuple[bool, UnavailableReason | None]:
    """(available, reason). Everything is unavailable with `AI_ENABLED=false`; a `dev_only`
    provider (the mock) only outside prod and with `AI_MOCK_ENABLED`; a provider that
    `requires_billing_flag` (Gemini) only with `GEMINI_BILLING_ENABLED=true` (RT5)."""
    provider = AiProviderName(name)
    if not settings.ai_enabled:
        return False, "ai_disabled_platform"
    entry = AI_CATALOG[provider]
    if entry.dev_only and (settings.env == "prod" or not settings.ai_mock_enabled):
        return False, "prod_mock"
    if entry.requires_billing_flag and not settings.gemini_billing_enabled:
        return False, "gemini_billing_required"
    return True, None
