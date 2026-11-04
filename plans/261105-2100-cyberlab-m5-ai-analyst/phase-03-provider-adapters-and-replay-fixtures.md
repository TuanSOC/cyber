---
phase: 3
title: "Provider adapters and replay fixtures"
status: pending
priority: P1
effort: "6h"
dependencies: [1]
---

# Phase 3: Provider adapters and replay fixtures (group B, 2b)

## Overview
Three `LlmProvider` adapters behind the frozen protocol (Anthropic via the official SDK, Gemini via `google-genai`, mock via plain httpx to `ai-mock`), the provider registry, the typed error mapping, recorded replay fixtures for parsing and error paths, an opt-in live smoke test, and the verification of model ids through the Models APIs.

**Owns:**
- `app/modules/ai/providers/{anthropic,gemini,mock,registry,errors}.py`, `app/modules/ai/http.py`;
- `tests/fixtures/ai/{anthropic,gemini,mock}/`;
- `scripts/check_ai_models.py` (no separate fixture recorder: phase 6's `--record` is the only recorder, RT14);
- `tests/unit/test_ai_provider_{anthropic,gemini,mock}.py`, `test_ai_registry.py`, `test_ai_http.py`, `test_ai_provider_live.py`.

Catalog changes (model ids, prices) are proposed to the parent, never edited here.

## Requirements
- **Registry** `build_provider(name, *, api_key, model, settings, org_options)`:
  - `model` must be in the catalog allowlist for `name`;
  - availability rechecked: mock refused in prod or when disabled; gemini refused unless `GEMINI_BILLING_ENABLED=true`;
  - it never builds `fake` or eval providers (those are injected in tests).
- **Anthropic** (`AsyncAnthropic(api_key=…, max_retries=0, timeout=…, http_client=ai.http.anthropic_client())`; `base_url` only from `AI_ANTHROPIC_BASE_URL` in test):
  - **Transport (RT20):** `ai.http.anthropic_client()` builds an `httpx2.AsyncClient` (`trust_env=False`, no redirects) with a request event hook that allows only `POST /v1/messages`, `POST /v1/messages/count_tokens` and `GET /v1/models/{id}` on the configured host. Tests pass `httpx2.MockTransport` to the same factory, so fixtures replay at the transport and the request shape is asserted on the wire.
  - `analyze`: **streamed** (RT2): `client.messages.stream(...)` + `get_final_message()` with `output_config={"format": {"type": "json_schema", "schema": provider_json_schema("anthropic")}, "effort": settings.ai_anthropic_effort}`; `system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]`; one user message; `max_tokens=AI_MAX_OUTPUT_TOKENS`. An idle timer (`AI_CALL_IDLE_TIMEOUT_S`) reset on every stream event aborts a stalled stream; `ProviderError.request_sent` is true from the moment the request is sent.
    - **No `temperature` / `top_p`** (400 on these models).
    - No `thinking` parameter (adaptive is the default; Opus 5.5 rejects disabling it).
    - No tools; no native citations.
  - No `fallbacks` parameter and no beta namespace (RT10).
  - Check `stop_reason` before parsing:
    - `refusal` → `ProviderError(refused, category=stop_details.category)` (an open string; `stop_details` may be null: branch on `stop_reason` only, RT24);
    - `max_tokens` → `max_tokens`;
    - `model_context_window_exceeded` → `context_too_large`; `pause_turn` or any unknown value → `provider_error` (RT19);
    - otherwise take the JSON text block and `json.loads` it; the worker re-validates against `AnalysisOutput`.
  - `served_model = response.model`; `usage` from `input_tokens`, `output_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`.
  - `count_tokens`: `client.messages.count_tokens(...)` with the same system, messages and output config.
  - `verify`: `client.models.retrieve(model)` (cheap, proves the key and the model).
  - **Error mapping** by SDK exception class, never by message text:

    | SDK error | Mapped kind |
    |---|---|
    | `RateLimitError` | `rate_limited` with `retry-after`, or `spend_limit` when `error.details.error_code == "enforced_spend_limit_reached"` |
    | status 529 / `OverloadedError` | `overloaded` |
    | `AuthenticationError` / `PermissionDeniedError` | `auth_failed` |
    | `BadRequestError` | `bad_request` |
    | `APITimeoutError` | `timeout` |
    | `APIConnectionError` | `transport` |

    Exceptions are re-raised **without** the cause chain or body (`from None`), and the API key never appears in any repr.
- **Gemini** (`genai.Client(api_key=…, http_options=…)`, `client.aio.models.generate_content`):
  - `config`: `system_instruction`, `response_mime_type="application/json"`, `response_json_schema=provider_json_schema("gemini")`, `max_output_tokens`; safety settings left at their defaults.
  - Verify the API choice (`generate_content` vs Interactions) and the current model ids with `scripts/check_ai_models.py` and record it.
  - Mapping:
    - 429 `RESOURCE_EXHAUSTED` → `rate_limited` (no header → exponential backoff hint);
    - 400 with a safety / prohibited block reason or `finish_reason` SAFETY → `refused`;
    - `MAX_TOKENS` → `max_tokens`;
    - 401/403 → `auth_failed`.
  - `count_tokens` returns `None` (the estimator is used).
- **Mock** (httpx via `ai/http.py`):
  - `trust_env=False`, no redirects, 120 s total, 2 MiB body cap, strict JSON (depth, no NaN);
  - path allowlist `POST /v1/analyze`, `POST /v1/count_tokens`, `GET /v1/verify` on `AI_MOCK_BASE_URL` only;
  - `X-Mock-Key` attached per request through a redacted `httpx.Auth`;
  - the same error mapping by status.
- **`ai/http.py`:** the egress client factories: `httpx` for the mock (and Gemini if its SDK accepts an injected client), `httpx2` for Anthropic, cloned in spirit from `threat_intel/http.py` without editing it.
- **Replay fixtures** (`tests/fixtures/ai/<provider>/<case>.json`): sanitized recorded responses (no keys, no request ids that identify the account) for:
  - ok;
  - refusal (cyber);
  - max_tokens;
  - 429 with and without `retry-after`;
  - spend limit;
  - 529;
  - 401;
  - malformed and schema-invalid;
  - Gemini safety-400.

  The fixtures are hand-written from the documented response shapes (SSE event streams for Anthropic, JSON for Gemini) and replayed at the transport (`httpx2.MockTransport` for Anthropic, `httpx.MockTransport` or a stub client for Gemini); the adapter tests assert the typed results.
- **`scripts/check_ai_models.py`:** lists the Anthropic (`client.models.list()`) and Gemini models and prints which catalog ids exist, with context and output limits. The output goes into the phase notes. Verification proposals go to the parent: `claude-sonnet-5` and `claude-opus-5-5`, and the researcher's `claude-sonnet-5-5` / `claude-haiku-5-5` (unverified, not in the allowlist).
- **Live smoke test** `test_ai_provider_live.py` (marker `live`, needs `AI_LIVE=1` and a key file): one small analyze per provider; never in the gate.

## Implementation Steps
1. `errors.py` (ProviderError helpers), `http.py`, the mock adapter and tests (against the phase-2-independent in-test stdlib stub of the wire protocol).
2. The Anthropic adapter (streamed) with transport-level fixture replays: request shape, idle timeout, every stop reason.
3. The Gemini adapter with fixtures; the billing gate.
4. The registry and its tests (allowlist, availability, prod refusals).
5. Key-leak unit tests: the sentinel key is absent from `repr(provider)`, the client, every `ProviderError`, and logs captured during each error fixture.
6. The model check script; phase notes with the verified ids and prices and the resolved SDK versions.

## Success Criteria
- [ ] Every fixture maps to the specified `ProviderResult` / `ProviderError` kind (`test_ai_provider_*.py`).
- [ ] No request carries `temperature` or tools; the Anthropic request carries `output_config.format` and a cached system block (request-shape tests).
- [ ] The sentinel key never appears in reprs, errors or logs.
- [ ] Model ids are verified or explicitly marked unverified in the phase notes, and the parent is notified of catalog changes.

## Risk Assessment
- **SDK transport and API drift** (`httpx2`, the streaming helpers). The versions are pinned below the next major in phase 1; tests run at the transport, and the verified shapes are recorded.
- **Gemini ids and API surface are volatile.** The adapter is isolated and gated, so the feature can ship with Anthropic only if Gemini verification fails (documented).
- **A provider that silently ignores the JSON schema.** The worker always re-validates; `invalid_output` is the fallback.
