"""`build_provider` (M5 phase 3): the model allowlist, the operator-level availability and the
prod refusals are re-checked on every build; `fake` and eval providers are never built here;
the key never shows in the built adapter's repr.
"""

from typing import Any

import pytest
from pydantic import SecretStr

from app.modules.ai.catalog import AI_CATALOG
from app.modules.ai.contracts import (
    AiErrorCode,
    AiProviderName,
    LlmProvider,
    ProviderError,
    ProviderErrorKind,
)
from app.modules.ai.providers.anthropic import AnthropicProvider
from app.modules.ai.providers.errors import ProviderUnavailable
from app.modules.ai.providers.gemini import GeminiProvider
from app.modules.ai.providers.mock import MockProvider
from app.modules.ai.providers.registry import build_provider
from tests.unit.test_ai_http import KEY, make_settings, prod

KINDS = {
    AiProviderName.ANTHROPIC: AnthropicProvider,
    AiProviderName.GEMINI: GeminiProvider,
    AiProviderName.MOCK: MockProvider,
}
OPEN = {"gemini_billing_enabled": True, "ai_mock_enabled": True}


def build(name: str, model: str, settings: Any = None, key: str | None = KEY) -> LlmProvider:
    return build_provider(
        name,
        api_key=SecretStr(key) if key is not None else None,
        model=model,
        settings=settings or make_settings(**OPEN),
        org_options={},
    )


@pytest.mark.parametrize(
    ("name", "model"),
    [(entry.name.value, model) for entry in AI_CATALOG.values() for model in entry.model_ids],
)
async def test_every_catalog_model_builds_its_adapter(name: str, model: str) -> None:
    provider = build(name, model)
    try:
        assert isinstance(provider, KINDS[AiProviderName(name)])
        assert isinstance(provider, LlmProvider)
        assert provider.name == name
        assert KEY not in repr(provider)
        assert model in repr(provider)
    finally:
        await provider.aclose()


@pytest.mark.parametrize(
    ("name", "model"),
    [
        ("anthropic", "claude-sonnet-5-5"),  # unverified researcher ids: not allowlisted
        ("anthropic", "claude-haiku-5-5"),
        ("anthropic", "claude-opus-4-8"),  # a server-side fallback target (RT10)
        ("anthropic", "gemini-3.8-flash"),
        ("gemini", "claude-sonnet-5"),
        ("mock", "claude-sonnet-5"),
        ("anthropic", ""),
    ],
)
def test_models_outside_the_allowlist_are_refused(name: str, model: str) -> None:
    with pytest.raises(ProviderUnavailable) as caught:
        build(name, model)
    assert caught.value.reason == "model_not_allowed"
    assert caught.value.error_code is AiErrorCode.PROVIDER_UNAVAILABLE


@pytest.mark.parametrize("name", ["fake", "hostile", "replay", "openai", ""])
def test_unknown_and_in_process_providers_are_never_built(name: str) -> None:
    with pytest.raises(ProviderUnavailable) as caught:
        build(name, "fake-1")
    assert caught.value.reason == "unknown_provider"


@pytest.mark.parametrize(
    ("name", "model", "overrides", "reason"),
    [
        ("anthropic", "claude-sonnet-5", {"ai_enabled": False}, "ai_disabled_platform"),
        (
            "gemini",
            "gemini-3.8-flash",
            {"gemini_billing_enabled": False},
            "gemini_billing_required",
        ),
        ("mock", "mock-1", {"ai_mock_enabled": False}, "prod_mock"),
    ],
)
def test_availability_is_rechecked(
    name: str, model: str, overrides: dict[str, Any], reason: str
) -> None:
    with pytest.raises(ProviderUnavailable) as caught:
        build(name, model, make_settings(**{**OPEN, **overrides}))
    assert caught.value.reason == reason


def test_the_mock_is_refused_in_prod() -> None:
    with pytest.raises(ProviderUnavailable) as caught:
        build("mock", "mock-1", prod(make_settings(**OPEN)))
    assert caught.value.reason == "prod_mock"


async def test_prod_builds_the_vendor_adapters() -> None:
    provider = build("anthropic", "claude-opus-5-5", prod(make_settings(**OPEN)))
    try:
        assert isinstance(provider, AnthropicProvider)
    finally:
        await provider.aclose()


@pytest.mark.parametrize("key", [None, "", "x", "tab\tin-key-0000", "line\nbreak-0000"])
def test_a_missing_or_unusable_key_is_auth_failed(key: str | None) -> None:
    with pytest.raises(ProviderError) as caught:
        build("anthropic", "claude-sonnet-5", key=key)
    assert caught.value.kind is ProviderErrorKind.AUTH_FAILED
    if key:
        assert key not in str(caught.value) and key not in repr(caught.value)


async def test_provider_names_are_accepted_as_enum_or_string() -> None:
    provider = build_provider(
        AiProviderName.MOCK,
        api_key=SecretStr(KEY),
        model="mock-1",
        settings=make_settings(**OPEN),
        org_options={"ignored": True},
    )
    try:
        assert isinstance(provider, MockProvider)
    finally:
        await provider.aclose()
