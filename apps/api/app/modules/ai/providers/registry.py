"""Provider registry (signature FROZEN in phase 1; phase 3 fills the body).

Builds the adapter for `name` (`anthropic`, `gemini`, `mock`) after re-checking the model
allowlist and availability; it never builds `fake` or eval providers (tests inject those).
"""

from collections.abc import Mapping
from typing import Any

from pydantic import SecretStr

from app.core.config import Settings
from app.modules.ai.contracts import AiProviderName, LlmProvider


def build_provider(
    name: AiProviderName | str,
    *,
    api_key: SecretStr | None,
    model: str,
    settings: Settings,
    org_options: Mapping[str, Any],
) -> LlmProvider:
    raise NotImplementedError("phase 3")
