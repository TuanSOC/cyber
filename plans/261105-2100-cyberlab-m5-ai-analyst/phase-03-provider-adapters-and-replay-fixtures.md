---
phase: 3
title: "Provider adapters and replay fixtures"
status: completed
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
- [x] Every fixture maps to the specified `ProviderResult` / `ProviderError` kind (`test_ai_provider_*.py`). — `test_every_fixture_maps_to_its_typed_outcome` in `test_ai_provider_anthropic.py`, `test_ai_provider_gemini.py` and `test_ai_provider_mock.py`, over `tests/fixtures/ai/` (anthropic 21, gemini 21, mock 15 fixtures) (83f24a1).
- [x] No request carries `temperature` or tools; the Anthropic request carries `output_config.format` and a cached system block (request-shape tests). — `test_ai_provider_anthropic.py::test_the_request_shape_on_the_wire` (`FORBIDDEN_PARAMS`: `temperature`, `top_p`, `top_k`, `tools`, `tool_choice`, `thinking`, `fallbacks` … disjoint from the body; `output_config` format and effort; system block `cache_control: ephemeral`; no `beta`), `test_count_tokens_uses_the_same_shape_and_is_never_billed`; Gemini body keys are exactly `contents`, `systemInstruction`, `generationConfig` (`test_ai_provider_gemini.py::test_the_request_shape_on_the_wire`) (83f24a1).
- [x] The sentinel key never appears in reprs, errors or logs. — every `test_every_fixture_maps_to_its_typed_outcome` asserts the key is absent from DEBUG caplog (including each provider's `key_echo_400.json`); `test_the_adapter_is_an_llm_provider_with_a_redacted_repr` (×3); `test_ai_http.py::test_key_auth_is_redacted_and_never_a_client_header`, `test_unsafe_keys_are_refused_without_quoting_them` (83f24a1); `test_ai_key_leak.py::test_providers_and_errors_never_print_the_key` (6b52742).
- [x] Model ids are verified or explicitly marked unverified in the phase notes, and the parent is notified of catalog changes. — every vendor model is explicitly unverified (`verified=False` in `catalog.py`; only the local `mock-1` is verified): `scripts/check_ai_models.py` exists but has not been run, because no key was available. The catalog was not changed, so there was no change to notify (see the notes).

## Risk Assessment
- **SDK transport and API drift** (`httpx2`, the streaming helpers). The versions are pinned below the next major in phase 1; tests run at the transport, and the verified shapes are recorded.
- **Gemini ids and API surface are volatile.** The adapter is isolated and gated, so the feature can ship with Anthropic only if Gemini verification fails (documented).
- **A provider that silently ignores the JSON schema.** The worker always re-validates; `invalid_output` is the fallback.

## Implementation Notes (2026-11-06)
- **Commit:** 83f24a1 (lane run, see phase 2). It adds:
  - `providers/{anthropic,gemini,mock,errors}.py`, `http.py` and `registry.py`;
  - 57 handcrafted replay fixtures, replayed through `httpx2.MockTransport` / `httpx.MockTransport`;
  - `scripts/check_ai_models.py`.
- **Resolved SDKs:** `anthropic 2.5.0` on `httpx2 2.16.0` (pin `>=2.5,<3`); `google-genai 2.34.0` on `httpx 0.28.1` (pin `>=2.34,<3`). SDK retries are off in both (`max_retries=0`): the worker owns every retry.
- **Model ids and prices** (`PRICE_VERSION = "2026-11-05"`, USD per MTok for input / output / cache read / cache write). **All vendor ids are unverified.**
  - `claude-sonnet-5` (default): $2 / $10 / $0.20 / $2.50;
  - `claude-opus-5-5`: $4 / $20 / $0.20 / $5.00;
  - `gemini-3.8-flash`: $1.50 / $7.50 / $0.375 / $1.50.
  - The Anthropic ids match the claude-api reference (RT24). The Gemini id comes from the research report only. `claude-sonnet-5-5` and `claude-haiku-5-5` are not in the allowlist.
- **Anthropic call:**
  - `messages.stream` + `get_final_message`, `max_tokens` 16 000;
  - one cached system block;
  - `output_config {format: json_schema, effort}`, effort from `AI_ANTHROPIC_EFFORT` (medium); a per-request override is allowed (`test_a_request_effort_overrides_the_setting`).
- **Timeouts (RT2):** idle 60 s, reset by any chunk including SSE `ping`; total 300 s.
  - Tests: `test_the_idle_timer_aborts_a_stalled_stream`, `test_ping_keep_alives_reset_the_idle_timer`, `test_the_total_timeout_bounds_a_slow_but_alive_stream`.
- **Stop reasons (RT19, RT24):**
  - `refusal` → `refused`, with the open category kept as is (≤ 32 characters);
  - `max_tokens` → `max_tokens`;
  - `model_context_window_exceeded` → `context_too_large`;
  - `pause_turn` and unknown reasons → `provider_error`.
  - Errors are mapped by SDK exception class or the structured `error.type`, never by message text.
  - Fixtures: `refusal_cyber`, `refusal_no_details`, `pause_turn`, `context_window_exceeded`, `unknown_stop_reason`, `overloaded_in_stream`.
- **Review (phase 3):**
  - `ProviderError.usage` (an additive frozen change): an answer that ended in a refusal or `max_tokens` carries its billed usage to the settlement (phase 2).
  - `count_tokens` failures are never billed (`test_count_tokens_failures_are_never_billed`).
- **Gemini:**
  - not streamed; `count_tokens` is not used, the estimate applies (`test_count_tokens_is_not_used`);
  - `vertexai=False` with an explicit base URL, so no environment variable can redirect it (`test_environment_variables_cannot_redirect_the_client`);
  - errors are mapped by status plus `ErrorInfo.reason`; `SAFETY` / `PROHIBITED_CONTENT` / `RECITATION` and blocked prompts → `refused` (fixtures `finish_*`, `prompt_blocked`, `safety_400`).
  - The billing gate (`GEMINI_BILLING_ENABLED` plus the per-key attestation) is enforced in the registry and the API (phase 7).
- **HTTP clients** (`http.py`):
  - `trust_env=False` and no redirects;
  - a method + path allowlist on one origin per provider, checked before anything is sent (`test_anthropic_client_refuses_everything_else`, `test_a_request_outside_the_allowlist_never_leaves`, `test_every_client_ignores_the_environment_and_redirects`);
  - the models list is allowed for the check script only (`test_the_models_list_is_allowed_for_the_check_script_only`);
  - base-URL overrides are refused in prod (`test_base_url_overrides_apply_outside_prod_only`);
  - mock body cap 2 MiB with strict JSON (`test_read_capped_refuses_oversize_and_encoded_bodies`, `test_loads_strict_refuses`).
- **Registry:** `test_models_outside_the_allowlist_are_refused`, `test_the_mock_is_refused_in_prod`, `test_availability_is_rechecked`, `test_a_missing_or_unusable_key_is_auth_failed`, `test_unknown_and_in_process_providers_are_never_built`.
- **Live:** `unit/test_ai_provider_live.py::test_live_verify_and_analyze` is skipped unless `AI_EVAL_LIVE=1` and a key file are given. It was never run: no key.
- **Deviations:**
  - `scripts/record_ai_fixtures.py` was cut (RT14), so the fixtures are handcrafted from the documented shapes, not recorded.
  - The Gemini adapter is built and tested, but it stays behind the operator billing gate.
