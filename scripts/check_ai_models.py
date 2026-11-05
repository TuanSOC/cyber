#!/usr/bin/env python3
"""Check the AI catalog's model ids against the providers' Models APIs (M5 phase 3).

Lists the models through the official SDKs (Anthropic `client.models.list()`, Gemini
`client.aio.models.list()`), over the same hardened clients as the adapters (the models list
route is allowed for this script only), and prints for every catalog id whether the provider
serves it, with its context and output limits. Catalog changes are proposed to the parent,
never made here. Without a key a provider is reported `skipped` and its ids stay unverified.

Keys come from files (never from the command line or an env value). It needs the api image
and egress, e.g. from the repo root:

  docker run --rm -v "$PWD:/repo" -w /repo/apps/api \
    -v "$HOME/.keys:/keys:ro" cyberlab/api:dev \
    python ../../scripts/check_ai_models.py --anthropic-key-file /keys/anthropic \
      --gemini-key-file /keys/gemini

Exit status: 0 every checked catalog id exists, 1 some id is missing, 2 nothing was checked.
"""

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import SecretStr

API = Path(__file__).resolve().parents[1] / "apps" / "api"
if str(API) not in sys.path:
    sys.path.insert(0, str(API))

from app.core.config import Settings  # noqa: E402
from app.modules.ai.catalog import AI_CATALOG  # noqa: E402
from app.modules.ai.contracts import AiProviderName  # noqa: E402
from app.modules.ai.providers.anthropic import AnthropicProvider  # noqa: E402
from app.modules.ai.providers.gemini import GeminiProvider  # noqa: E402

# Ids the research mentioned but the catalog does not allow (reported, never added here).
EXTRA_IDS = {
    AiProviderName.ANTHROPIC: ("claude-sonnet-5-5", "claude-haiku-5-5"),
    AiProviderName.GEMINI: (),
}


def _settings() -> Settings:
    """Defaults only (vendor base URLs, default timeouts): no database or broker needed."""
    return Settings.model_construct()


def _key(path: str | None) -> SecretStr | None:
    if not path:
        return None
    return SecretStr(Path(path).read_text(encoding="utf-8").strip())


async def _anthropic(key: SecretStr) -> dict[str, dict[str, Any]]:
    entry = AI_CATALOG[AiProviderName.ANTHROPIC]
    provider = AnthropicProvider(
        api_key=key,
        model=entry.default_model,
        settings=_settings(),
        allow_list_models=True,
    )
    found: dict[str, dict[str, Any]] = {}
    try:
        async for model in provider.client.models.list(limit=100):
            found[model.id] = {
                "display_name": model.display_name,
                "lifecycle": model.lifecycle,
                "max_input_tokens": model.max_input_tokens,
                "max_output_tokens": model.max_tokens,
            }
    finally:
        await provider.aclose()
    return found


async def _gemini(key: SecretStr) -> dict[str, dict[str, Any]]:
    entry = AI_CATALOG[AiProviderName.GEMINI]
    provider = GeminiProvider(
        api_key=key,
        model=entry.default_model,
        settings=_settings(),
        allow_list_models=True,
    )
    found: dict[str, dict[str, Any]] = {}
    try:
        pager = await provider.client.aio.models.list(config={"page_size": 100})
        async for model in pager:
            name = (model.name or "").removeprefix("models/")
            found[name] = {
                "display_name": model.display_name,
                "max_input_tokens": model.input_token_limit,
                "max_output_tokens": model.output_token_limit,
                "actions": model.supported_actions,
            }
    finally:
        await provider.aclose()
    return found


def _report(provider: AiProviderName, found: dict[str, dict[str, Any]] | None) -> list[str]:
    entry = AI_CATALOG[provider]
    missing: list[str] = []
    print(f"\n== {provider.value} ==")
    if found is None:
        print("  skipped: no key file; catalog ids stay unverified")
        return missing
    for model_id in (*entry.model_ids, *EXTRA_IDS[provider]):
        info = found.get(model_id)
        tag = "catalog" if model_id in entry.model_ids else "not in allowlist"
        if info is None:
            print(f"  MISSING {model_id} ({tag})")
            if model_id in entry.model_ids:
                missing.append(model_id)
        else:
            print(f"  ok      {model_id} ({tag}) {json.dumps(info, default=str)}")
    return missing


async def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--anthropic-key-file")
    parser.add_argument("--gemini-key-file")
    args = parser.parse_args(argv)
    checked = False
    missing: list[str] = []
    for provider, path, lister in (
        (AiProviderName.ANTHROPIC, args.anthropic_key_file, _anthropic),
        (AiProviderName.GEMINI, args.gemini_key_file, _gemini),
    ):
        key = _key(path)
        found = await lister(key) if key is not None else None
        checked = checked or found is not None
        missing += _report(provider, found)
    if not checked:
        return 2
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
