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
- [x] Every typed outcome ends in the specified status with honest `metrics` (`test_analyst_worker.py`). — `test_analyst_worker.py::test_terminal_outcomes`, `test_refusals_are_final_with_their_category`, `test_spend_limit_fails_and_parks_the_provider_until_midnight`, `test_auth_failed_verifies_inline`, `test_overloaded_backs_off_then_fails`, `test_rate_limited_waits_for_the_cooldown`, `test_invalid_output_twice_fails`, `test_a_canary_leak_fails_and_keeps_the_output_for_review`, `test_timeouts_after_the_request_was_sent_stay_charged_and_cap_at_three_calls`, `test_happy_path_persists_output_citations_usage_and_metrics` (83f24a1); end to end `test_ai_pipeline.py::test_failures_are_typed` (6b52742).
- [x] No duplicate provider calls under redelivery or concurrent replicas (lease tests). — `test_analyst_worker.py::test_redelivery_and_concurrent_replicas_make_one_call`, `test_a_live_lease_held_elsewhere_exits`, `test_a_worker_that_lost_its_lease_never_touches_the_run`; `test_ai_lifecycle.py::test_only_the_lease_holder_may_park_or_end_the_run` (83f24a1).
- [x] The budget never overshoots under concurrent reservations (two workers, one org), and the limiter fails closed. — `test_ai_budget.py::test_concurrent_reservations_never_overshoot`, `test_daily_budget_is_all_or_nothing_and_settles_to_actual`, `test_broker_errors_fail_closed`; `test_ai_ratelimit.py::test_broker_errors_fail_closed`; `test_analyst_worker.py::test_the_limiter_fails_closed` (83f24a1).
- [x] An incident run completes only after its children, reuses an identical digest without a call, and ends `partial` when some children fail. — `test_analyst_worker.py::test_an_incident_waits_for_its_children_then_reduces`, `test_an_identical_digest_is_reused_without_a_call`, `test_an_incident_is_partial_when_a_child_fails`, `test_an_incident_without_any_digest_fails` (83f24a1); through the real worker `test_ai_pipeline.py::test_an_incident_maps_its_jobs_and_reduces_their_digests` (6b52742).
- [x] `ai-mock` serves every marker deterministically; the e2e default answer is schema-valid. — `test_ai_mock_server.py::test_error_markers`, `test_body_markers`, `test_fabricate_echo_and_inject`, `test_rate_limited_once_per_marker`, `test_slow_markers_answer_late`, `test_the_first_known_marker_wins`, `test_default_answer_is_schema_valid_and_cites_exact_quotes` (83f24a1); the real-prompt fix `test_the_default_answer_reads_the_real_prompt` and `test_ai_pipeline.py::test_every_pcap_task_completes_with_verified_citations` (6b52742). The browser run of the default answer is in the dev e2e (pending gate).

## Risk Assessment
- **The solo pool and long calls.** Two replicas and one call per message bound the head-of-line blocking; per-org active caps (phase 7) bound one tenant's share. Fairness stays approximate (documented).
- **Clock and deadline drift between the DB and the worker.** Use the DB `now()` for every deadline and lease decision, as M4 did.
- **Reusing the M4 limiter by import** may tempt edits to `threat_intel/ratelimit.py`. Forbidden: clone instead.

## Implementation Notes (2026-11-06)
- **Commits:**
  - 83f24a1: phases 2–7, merged after the parallel lanes. Phase 2 is `workers/analyst.py` (+1654), `lifecycle.py`, `ratelimit.py`, `budget.py`, `reap_ai_runs` and `infra/ai-mock/server.py`.
  - 6b52742: phase-11 fixes: `_refund_call`, ai-mock prompt parsing, new markers.
- **Parallel execution (group B, phases 2–7):**
  - Six lanes, each with its own test DB (`cyberlab_b{n}_test`), app Redis db and broker db, all run through `scripts/lane-test.sh` (6edfa9b). A 3-slot semaphore limits the containers running at once (host RAM).
  - Each lane checked its own tests, ruff, format and mypy. The full suite ran after the merge (83f24a1 says "full API suite pending").
  - An API session-limit interruption stopped the agents mid-way. They were resumed from the working tree.
- **Lease** (`lifecycle.py`, `analyst.py`):
  - `lease_until = now() + 60 s`, renewed every 20 s, each renewal in its own transaction. Every decision uses the DB `now()`.
  - `ai.resume` runs every 30 s from ingest-beat (`test_resume_resends_due_runs_once`).
  - `test_a_waiting_run_is_not_due_before_resume_at`.
  - Deadlines 1200 s / 3600 s; children inherit the parent's deadline (`test_children_inherit_the_parent_deadline`, `test_past_the_deadline_fails_without_a_call`).
- **Review (Low), lease ownership:**
  - Every write checks `lease_owner`: the call counter and its refund, the renewals, `set_waiting`, `finalize`, and the output insert (which re-reads the owner `FOR UPDATE`).
  - A worker that lost the lease writes nothing and releases its reservation.
  - Tests: `test_a_worker_that_lost_its_lease_never_touches_the_run`, `test_only_the_lease_holder_may_park_or_end_the_run`.
- **Call cap (RT2):**
  - `ai_run_index.calls` is committed before each call (`_count_call`); the cap is `AI_MAX_CALLS_PER_RUN` = 3 (`test_the_call_cap_ends_the_run`).
  - **6b52742:** an unbilled 429 or 529 gives its call back (`_refund_call`). Tests: `test_an_unbilled_rate_limit_does_not_use_up_a_call`, `test_a_rate_limit_with_the_call_cap_used_still_waits`, `test_an_overload_at_the_call_cap_backs_off_instead_of_failing`.
- **Timeouts (RT2, RT7):**
  - After the request was sent, a timeout keeps the full reservation charged and sets `metrics.usage_unknown` (`test_timeouts_after_the_request_was_sent_stay_charged_and_cap_at_three_calls`).
  - A transport error before sending is not charged (`test_a_transport_error_before_sending_is_not_charged`).
  - No DB session is open during the call (`test_no_session_is_open_during_a_slow_call`, using `ai-mock:slow`); `test_the_hard_call_timeout`.
- **Typed outcomes:**
  - 429 → `waiting` until `Retry-After` (clamped 1–3600 s), else the next minute;
  - 529 / 503 back off 30 / 60 / 120 s, then the run fails `overloaded`;
  - a spend limit parks the provider until 00:00 UTC;
  - 401 / 403 run an inline verify;
  - one repair call with a hint that names paths only (`test_one_repair_retry_with_the_hint`);
  - refusals are final, with no fallback model (RT10).
- **Limiter** (`ratelimit.py`):
  - Cloned from M4 under `{prefix}analyst.ai:*`; `threat_intel/ratelimit.py` is untouched.
  - Token bucket per (provider, org); cooldowns can only be extended.
  - The per-minute limit lowers but never raises (`test_effective_per_minute_lowers_but_never_raises`). Keys outside the ACL pattern are refused (`test_keys_outside_the_acl_pattern_are_refused`).
  - Broker errors fail closed, and the run waits 30 s.
- **Budget** (`budget.py`):
  - One Lua reserve over the day, tree and platform keys (all or nothing), then a settle to the actual usage.
  - RT9: a missing day key is seeded from the DB with `SET NX` (`test_the_day_key_is_seeded_from_the_db_after_a_broker_flush`).
  - Tree cap: `test_the_incident_tree_cap`. Platform ceiling of 200 000 tokens per day: `test_the_platform_key_and_its_global_ceiling`.
- **Review (Low), tree and platform re-seed:**
  - The tree and platform keys are also re-seeded from the DB (`_seed_tree`, `_seed_platform`); the platform seed is approximate, over at most 1000 orgs without their own key. A key that cannot be seeded fails closed.
  - Tests: `test_a_lost_tree_key_is_reseeded_from_the_db`, `test_a_lost_platform_key_is_reseeded_from_the_db`, `test_ai_budget.py::test_missing_tree_and_platform_keys_are_seeded_from_the_db`, `test_missing_tree_or_platform_keys_without_a_seed_fail_closed`.
- **Review (Low), refusal settlement:**
  - A refusal that comes with usage (a 200 with `stop_reason: refusal`, or an error that carries `usage`) is settled to that usage, instead of releasing the reservation.
  - `NOT_BILLED` errors without usage release it.
  - Tests: `test_refusals_are_final_with_their_category`, `test_an_error_with_reported_usage_is_settled_to_it`, `test_errors_without_usage_settle_the_budget`.
- **Incident map-reduce:**
  - The parent polls every 30 s until every child is final, then freezes `ai_run_inputs(stage=reduce)`, so a redelivered parent reuses it (`test_a_redelivered_parent_reuses_its_frozen_reduce_input`).
  - It ends `partial` when some child did not complete, and `failed / no_digest` when none did.
- **Keys:**
  - the verify verdict is recorded once per key version (`test_verify_records_the_verdict_once_per_key_version`);
  - lazy re-seal under the active kid (RT18, `test_a_key_under_an_old_kid_is_resealed_under_the_active_one`);
  - an unseal failure is `auth_failed` and leaves `verify_status` untouched.
- **Reaper:** `reap_ai_runs` fails runs 10 minutes past their deadline that hold no live lease, and audits `ai.run_deadline` (`test_ai_lifecycle.py::test_reaper_fails_runs_long_past_their_deadline_without_a_lease`).
- **Secrets:** `test_logs_and_selects_carry_no_secrets_or_content` checks caplog, and that the worker never selects `pseudonym_map` (RT26).
- **ai-mock** (stdlib):
  - markers `429`, `429-nora`, `529`, `spend`, `401`, `500`, `slow`, `slow-<n>`, `oversize`, `malformed`, `schema`, `refuse`, `maxtokens`, `fabricate`, `echo`, `inject`; 6b52742 added `429-once-<label>` and `hostile`.
  - **Eval-found bug (fixed in 6b52742):** ai-mock never parsed the real prompt; it understood only the test doubles' context object. So every real run got the empty answer.
