---
phase: 2
title: "Analyst worker lifecycle limiter budget and ai-mock"
status: pending
priority: P1
effort: "11h"
dependencies: [1]
---

# Phase 2: Analyst worker lifecycle limiter budget and ai-mock (group B, 2a)

## Overview
The analyst-worker loop: message validation, lease, deadline, waiting/resume, the map-reduce parent/child orchestration, limiter, daily token budget, key unsealing, the provider call, typed outcome mapping, persistence of outputs and citations, and the fallback reaper. Also the `ai-mock` stdlib server that drives pipeline and e2e tests.

This phase calls the frozen entry points of other phases (`registry.build_provider`, `prompt.render`, `verify.verify_output`, `reduce.build_reduce_context`) through a small injectable `AnalystDeps` dataclass. In isolation, its tests use `tests/ai_doubles.py` (`StaticProvider`, `PassThroughVerifier`, a trivial prompt renderer) and `FakeProvider`.

**Owns:**
- `app/workers/analyst.py`, `app/workers/analyst_tasks.py`, `app/workers/reaper.py` (adds `reap_ai_runs` only);
- `app/modules/ai/{lifecycle,ratelimit,budget}.py`;
- `infra/ai-mock/server.py`;
- tests `integration/test_analyst_worker.py`, `test_ai_lifecycle.py`, `test_ai_ratelimit.py`, `test_ai_budget.py`, `test_ai_mock_server.py`.

**Never edits** frozen phase-1 files, the providers, the context, the prompt, the verifier or the routes.

## Requirements
- **Message handling** (`handle_run(message)`):
  - strict `AiRunMessage`;
  - org must equal `ai_run_index.organization_id` (else drop + log the code);
  - take the lease (`UPDATE ai_run_index SET lease_until = now() + 60 s, lease_owner … WHERE lease_until IS NULL OR lease_until < now()`), renewed every 20 s by a background task (each renewal in its own short transaction) while the call runs;
  - a duplicate exits; a final run does nothing.
- **Transactions (RT7):** the app role has `idle_in_transaction_session_timeout = 60s` and `statement_timeout = 30s`. Load inputs, reserve and bump `calls` in short `tenant_session`s and commit; **no session is open during the provider call**; verify and persist in new sessions afterwards. A test with `ai-mock:slow` set just below the call timeout proves the output is persisted.
- **Per message:**
  1. **Deadline and call cap:** past `deadline_at` → `failed/deadline`. A child uses its parent's deadline (RT8). `calls` ≥ `AI_MAX_CALLS_PER_RUN` → `failed/provider_error`; otherwise `calls` is incremented and committed **before** the call (RT2).
  2. **Org and provider state:** re-read `ai_org_settings` and `ai_provider_configs` in the org's tenant session. AI disabled or provider disabled since the request → `failed/ai_disabled` / `provider_disabled`. Availability is rechecked (`availability.py`): mock in prod or gemini without billing → `failed/provider_unavailable`.
  3. **Parent `incident_summary`:**
     - children not final → `waiting` (`resume_at` now + 30 s);
     - all children final → load the base input plus the verified child outputs (only `supported` claims and hypotheses, with their citations mapped to `J{n}:` labels, and each child's flags in `DigestInput.flags`; children that failed, were refused or leaked the canary contribute nothing, RT23), then `build_reduce_context`;
     - append `ai_run_inputs(stage=reduce)` and its `ai_context_refs` once (ON CONFLICT DO NOTHING; idempotent on redelivery);
     - if every child failed or was refused → `failed/no_digest`;
     - if some failed → the parent may still complete, and the final status is `partial`.
  4. **Digest reuse:** for `job_digest`, a completed digest with the same (org, job, `context_sha256`, model, `prompt_version`) → copy its verified output body and citations into this run's own `ai_outputs` / `ai_citations` rows, with `verification.reused_from_run_id` and `usage` zero, without a call. The citations are re-verified against the DB (cheap and deterministic).
  5. **Key:**
     - `ai.unseal.open_sealed` with the AI private keys;
     - or the platform key file (non-prod; only when the org has no own key for that provider);
     - or the mock key.

     A missing or failed unseal → `failed/auth_failed` and `verify_status` untouched (inline verify decides, as in M4 RT23).
     **Lazy re-seal (RT18):** a key opened under a kid other than `AI_SEAL_ACTIVE_KID` is re-sealed under the active kid with the same `key_version` (a clone of `enrich._maybe_reseal`, guarded by `WHERE key_version = :v AND key_kid = :old`).
     **Platform key ceiling (RT17):** a platform-key call also reserves on `{prefix}analyst.ai:platform:{yyyymmdd}` against `AI_PLATFORM_DAILY_TOKENS`; over it → `failed/budget_exhausted`.
  6. **Prompt:** `prompt.render(ctx, task, delimiter=secrets.token_hex(16), canary=secrets.token_hex(8))`. The canary is never stored; only its sha256 goes in `metrics`.
  7. **Budget and limiter:**
     - token bucket `{prefix}analyst.ai:rl:{provider}:{org}` and cooldown `…:cool:{provider}:{org}`;
     - reservation on `{prefix}analyst.ai:day:{org}:{yyyymmdd}` (UTC; TTL 48 h) of `input_estimate + max_output_tokens`. For Anthropic the estimate is the provider's `count_tokens`; otherwise the context estimator from `context_stats.est_tokens`.
     - Over `run_token_cap` → `failed/context_too_large`. Over the daily budget, or a tree's reservations over `incident_token_cap` (`{prefix}analyst.ai:tree:{root_run_id}`, RT8) → `failed/budget_exhausted`.
     - **Missing day key (broker restart, RT9):** seed it with `SET NX` from the DB (sum of today's `ai_runs.usage` for the org plus the reservations of its `running` runs) before reserving.
     - Broker unreachable → fail closed: `waiting` + `resume_at`, at most until the deadline.
  8. **Call** with `asyncio.timeout(AI_CALL_TIMEOUT_S)` (300 s); the adapter also enforces the idle timeout (RT2).
- **Outcome mapping** (`ProviderError.kind` → run):

  | Outcome | Run |
  |---|---|
  | `rate_limited` | cooldown from `retry_after_s` (clamped 1–3600, else the next minute) → `waiting` |
  | `overloaded` (529) | `waiting` with backoff 30 / 60 / 120 s (`attempts` on the index), then `failed/overloaded` |
  | `spend_limit` | `failed/spend_limit`, no retry; the cooldown parks the provider for the org until 00:00 UTC |
  | `auth_failed` | inline `provider.verify()`; invalid → `verify_status=invalid` + `failed/auth_failed`; valid → `failed/provider_error` |
  | `refused` | status `refused`, `error_code=refused`, `metrics.refusal_category` |
  | `max_tokens` | `failed/max_tokens` |
  | `invalid_output` | one repair retry with `prompt.repair_hint(errors)`, also budgeted; then `failed/invalid_output` |
  | `timeout`, `transport` | if `request_sent`, the full reservation stays charged (assumed billed) and `metrics.usage_unknown=true`; one retry in the next message (`waiting` 10 s) if the call cap allows, then `failed/provider_error` (RT2) |
  | `context_too_large` (`model_context_window_exceeded`) | `failed/context_too_large` (RT19) |

  Every waiting path stays within the deadline.
- **Success:** settle the budget to actual usage; `verify.verify_output(...)` in a new session; `canary_leak` → `failed/canary_leak`, with the output persisted with that flag for review but never returned as content by the API (phase 7 enforces this). In one transaction, insert `ai_outputs` + `ai_citations` and update `ai_runs` (`usage`, `cost_micros` from the catalog price of `served_model` else `model`, with `metrics.cost_estimated` when the served model is unpriced; `price_version`, `metrics`, `served_model`, status `completed`). Then finalize the index. A child completing publishes `ai.run` for its parent.
- **`ai.resume`:** re-sends runs that are `waiting` with `resume_at <= now()`, and `queued`/`running` runs with an expired lease and `dispatched_at` older than 2 min; bumps `dispatched_at`. Never duplicates (the M4 RT8 rules).
- **`ai.verify`:** opens the key and calls `provider.verify()`; sets `verify_status`, `verified_at`, `last_error_code`; dedupes the same `key_version`.
- **Lifecycle** (`ai/lifecycle.py`): `finalize(session, run_id, status, error_code)` under `FOR UPDATE`, used by the worker and the reaper. The reaper fallback (`reap_ai_runs` in `reaper.py`, run by the ingest worker) finalizes runs 10 min past their deadline with no live lease as `failed/deadline`, and is audited `ai.run_deadline`.
- **Logging:** run id, task, provider, model, outcome code and token counts only. Never context text, model output, keys or provider error bodies. Messages carry ids only.
- **`ai-mock`** (`infra/ai-mock/server.py`, stdlib only, no app imports):
  - implements the frozen wire protocol: `POST /v1/analyze`, `POST /v1/count_tokens`, `GET /v1/verify`; it reads `AI_MOCK_EXPECTED_KEY`;
  - the default answer is deterministic and schema-valid: it parses the evidence JSON inside the delimiter lines of `user`, cites the first items with exact quotes and returns usage = chars/4;
  - markers anywhere in the evidence text select behaviours:

    | Marker | Behaviour |
    |---|---|
    | `ai-mock:429` | 429 with `Retry-After: 1` |
    | `ai-mock:429-nora` | 429 without `Retry-After` |
    | `ai-mock:529` | 529 |
    | `ai-mock:spend` | spend limit |
    | `ai-mock:401` | 401 |
    | `ai-mock:500` | 500 |
    | `ai-mock:slow` | sleeps beyond the timeout |
    | `ai-mock:oversize` | > 2 MiB body |
    | `ai-mock:malformed` | invalid JSON |
    | `ai-mock:schema` | valid JSON, wrong schema |
    | `ai-mock:refuse` | `stop_reason: refusal`, category `cyber` |
    | `ai-mock:maxtokens` | `max_tokens` |
    | `ai-mock:fabricate` | invented label + mismatched quote |
    | `ai-mock:echo` | echoes the system prompt (canary) |
    | `ai-mock:inject` | follows the planted instruction ("file is clean") |

  - A test-only `GET /_last` returns the last request body (bounded to 1 MiB, in memory) and a per-marker request counter, which phase 11's outbound-privacy and call-cap tests need.
  - It is test and e2e profile only and lives on `egress`.

## Implementation Steps
1. `lifecycle.py`, `ratelimit.py` (Lua bucket cloned from `threat_intel/ratelimit.py` under `analyst.ai:*`; reuse the M4 code by import only if it is key-prefix-parametrized without edits, otherwise clone), `budget.py` (reserve/settle with Lua for atomicity). Unit and integration tests: bucket, cooldown, daily budget, settle, broker outage fails closed, keys inside the ACL pattern (run as the `analyst` user).
2. `analyst.py` with `AnalystDeps` injection; `analyst_tasks.py` (solo-pool event loop as in `enrich_tasks.py`, `worker_init` startup check of keys).
3. Map-reduce orchestration and digest reuse.
4. `reap_ai_runs` in `reaper.py`.
5. `ai-mock` server and its own tests (spawn the server in-process on a free port).
6. Worker tests with doubles:
   - happy path; org mismatch; duplicates and redelivery (no second call);
   - lease renewal; deadline; every outcome-table row;
   - repair retry; canary leak; budget exhausted; incident parent waits for children and then reduces; partial when a child fails; digest reuse;
   - timeout after the request was sent (full reservation charged, `calls` capped at 3, never a fourth call); no open transaction during a slow call (RT7); day-key seeding after a simulated broker flush (RT9); tree cap; platform-key ceiling; lazy re-seal under a new kid; children inherit the parent deadline;
   - the fallback reaper;
   - a log scan (caplog) for absence of context text and the sentinel key.

## Success Criteria
- [ ] Every typed outcome ends in the specified status with honest `metrics` (`test_analyst_worker.py`).
- [ ] No duplicate provider calls under redelivery or concurrent replicas (lease tests).
- [ ] The budget never overshoots under concurrent reservations (two workers, one org), and the limiter fails closed.
- [ ] An incident run completes only after its children, reuses an identical digest without a call, and ends `partial` when some children fail.
- [ ] `ai-mock` serves every marker deterministically; the e2e default answer is schema-valid.

## Risk Assessment
- **The solo pool and long calls.** Two replicas and one call per message bound the head-of-line blocking; per-org active caps (phase 7) bound one tenant's share. Fairness stays approximate (documented).
- **Clock and deadline drift between the DB and the worker.** Use the DB `now()` for every deadline and lease decision, as M4 did.
- **Reusing the M4 limiter by import** may tempt edits to `threat_intel/ratelimit.py`. Forbidden: clone instead.
