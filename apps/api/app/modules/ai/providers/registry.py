"""Provider registry (signature FROZEN in phase 1; body: phase 3).

Builds the adapter for `name` (`anthropic`, `gemini`, `mock`) after re-checking, in this
order:
1. the name is a known provider (`fake` and the eval providers are never built here: tests
   and the eval harness inject those);
2. the operator-level availability (`ai.availability.provider_available`): AI on for the
   platform, the mock only outside prod and with `AI_MOCK_ENABLED`, Gemini only with
   `GEMINI_BILLING_ENABLED=true` (RT5);
3. `model` is in the catalog allowlist for that provider (RT10: no fallback model, ever).
Each refusal raises `errors.ProviderUnavailable(reason)` (worker:
`failed/provider_unavailable`). A missing or unusable key raises
`ProviderError(auth_failed)` without quoting it.

`org_options` is accepted for forward compatibility and currently unused: the per-org gates
(AI enabled + privacy ack, provider enabled + terms ack, Gemini paid-tier attestation) are
checked by the routes and the worker before a provider is built.
"""

from collections.abc import Mapping
from typing import Any

from pydantic import SecretStr

from app.core.config import Settings
from app.modules.ai.availability import provider_available
from app.modules.ai.catalog import AI_CATALOG
from app.modules.ai.contracts import AiProviderName, LlmProvider, ProviderErrorKind
from app.modules.ai.providers.errors import ProviderUnavailable, fail


def build_provider(
    name: AiProviderName | str,
    *,
    api_key: SecretStr | None,
    model: str,
    settings: Settings,
    org_options: Mapping[str, Any],
) -> LlmProvider:
    try:
        provider = AiProviderName(name)
    except ValueError:
        provider = None
    if provider is None:
        raise ProviderUnavailable("unknown_provider")
    available, reason = provider_available(settings, provider)
    if not available:
        raise ProviderUnavailable(reason or "ai_disabled_platform")
    if model not in AI_CATALOG[provider].model_ids:
        raise ProviderUnavailable("model_not_allowed")
    if api_key is None:
        raise fail(ProviderErrorKind.AUTH_FAILED)
    if provider is AiProviderName.ANTHROPIC:
        from app.modules.ai.providers.anthropic import AnthropicProvider

        return AnthropicProvider(api_key=api_key, model=model, settings=settings)
    if provider is AiProviderName.GEMINI:
        from app.modules.ai.providers.gemini import GeminiProvider

        return GeminiProvider(api_key=api_key, model=model, settings=settings)
    from app.modules.ai.providers.mock import MockProvider

    return MockProvider(api_key=api_key, model=model, settings=settings)


__all__ = ["build_provider"]
