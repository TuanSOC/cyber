"""Live recorder: answers queued cassette misses with a real provider (local only).

Runs inside `analyst-worker-test` (the only test container with egress), never in CI:
`scripts/ai_eval.py --provider anthropic ...` with `AI_EVAL_LIVE=1`. The api-test side
(`test_ai_eval_live.py`, stage `collect`) renders every case through the real pipeline with a
`ReplayProvider` whose misses are written to `pending.json`; this module sends each pending
prompt through the real adapter (`providers.registry.build_provider`, no tools), and writes the
sanitized answer into the cassette store as run `n`. The api-test side then replays and scores
(stage `score`), so live metrics and replay metrics come from the same code path.

The key is read from the file `AI_EVAL_KEY_FILE` (mounted read-only from `.secrets/`), never
from an environment variable, and never printed or stored.

    python -m tests.ai_eval.live_call /eval/<run>/pending.json /eval/<run>/cassettes
"""

import argparse
import asyncio
import datetime as dt
import json
import os
import sys
from pathlib import Path

from pydantic import SecretStr

from app.core.config import get_settings
from app.modules.ai.contracts import ProviderError, ProviderErrorKind, ProviderRequest
from app.modules.ai.providers.registry import build_provider
from tests.ai_eval.providers import (
    Cassette,
    CassetteStore,
    PendingRequest,
    sanitize_error,
    sanitize_result,
)

MAX_RATE_RETRIES = 3


def read_key() -> SecretStr:
    path = os.environ.get("AI_EVAL_KEY_FILE")
    if not path or not Path(path).is_file():
        raise SystemExit("live_call: AI_EVAL_KEY_FILE must name a mounted key file")
    key = Path(path).read_text(encoding="utf-8").strip()
    if not key:
        raise SystemExit("live_call: the key file is empty")
    return SecretStr(key)


async def fulfil(pending: list[PendingRequest], store: CassetteStore, provider_name: str) -> int:
    settings = get_settings()
    by_model: dict[str, list[PendingRequest]] = {}
    for item in pending:
        by_model.setdefault(item.key.model, []).append(item)
    done = 0
    key = read_key()
    for model, items in by_model.items():
        provider = build_provider(
            provider_name, api_key=key, model=model, settings=settings, org_options={}
        )
        try:
            for item in sorted(items, key=lambda p: (p.case, p.stage, p.run)):
                request = ProviderRequest(
                    model=model,
                    system=item.system,
                    user=item.user,
                    output_schema=item.output_schema,
                    max_output_tokens=item.max_output_tokens,
                    effort=item.effort or settings.ai_anthropic_effort,
                )
                entry = await _call(provider, request)
                cassette = store.get(item.key) or Cassette(
                    key=item.key, case=item.case, stage=item.stage, task=item.task
                )
                while len(cassette.runs) < item.run:
                    cassette.runs.append(sanitize_error(ProviderError(ProviderErrorKind.TIMEOUT)))
                if len(cassette.runs) == item.run:
                    cassette.runs.append(entry)
                cassette.recorded_at = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
                store.put(cassette)
                done += 1
                print(f"recorded {item.case} {item.stage} run {item.run}", flush=True)
        finally:
            await provider.aclose()
    return done


async def _call(provider: object, request: ProviderRequest) -> dict[str, object]:
    analyze = provider.analyze  # type: ignore[attr-defined]
    for attempt in range(MAX_RATE_RETRIES + 1):
        try:
            return sanitize_result(await analyze(request))
        except ProviderError as exc:
            retry = exc.kind in (ProviderErrorKind.RATE_LIMITED, ProviderErrorKind.OVERLOADED)
            if retry and attempt < MAX_RATE_RETRIES:
                await asyncio.sleep(min(exc.retry_after_s or 20.0 * (attempt + 1), 90.0))
                continue
            return sanitize_error(exc)
    raise AssertionError("unreachable")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tests.ai_eval.live_call")
    parser.add_argument("pending", type=Path)
    parser.add_argument("cassettes", type=Path)
    parser.add_argument("--provider", default=os.environ.get("AI_EVAL_PROVIDER", "anthropic"))
    args = parser.parse_args(argv)
    if os.environ.get("AI_EVAL_LIVE") != "1":
        print("live_call: AI_EVAL_LIVE=1 is required", file=sys.stderr)
        return 2
    data = json.loads(args.pending.read_text(encoding="utf-8"))
    pending = [PendingRequest.from_json(item) for item in data]
    done = asyncio.run(fulfil(pending, CassetteStore(args.cassettes), args.provider))
    print(f"live_call: {done} answers recorded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
