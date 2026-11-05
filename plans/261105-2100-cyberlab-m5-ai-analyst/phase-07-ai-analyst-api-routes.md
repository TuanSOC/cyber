---
phase: 7
title: "AI analyst API routes"
status: completed
priority: P1
effort: "10h"
dependencies: [1]
---

# Phase 7: AI analyst API routes (group B, 2f)

## Overview
The org-scoped HTTP surface:
- **AI providers:** catalog, write-only keys, terms acknowledgement, verify.
- **AI settings:** enable with privacy acknowledgement, pseudonymization, inclusions, budgets.
- **Context preview.**
- **Runs:** creation with dedupe, caps and rate limits; list; detail with output, resolved citations and pseudonym display; the context viewer.
- **Usage.**
- **Audit.**

The API only builds and freezes the context, seals keys, records and publishes; it never contacts a provider.

**Owns:**
- `app/modules/ai/router_{runs,providers,settings}.py` (fills the stubs), `app/modules/ai/runs.py` (fills the stub);
- `app/modules/ai/service_{runs,providers,settings,outputs}.py`, `app/modules/ai/repository.py`, `app/modules/ai/schemas.py`;
- `tests/ai_api_helpers.py`, `tests/integration/test_ai_api_{providers,settings,runs,outputs,rbac}.py`;
- `tests/security/idor_cases_ai.py` (the AI cases and victim extenders; phase 1 created it empty and `test_idor_routes.py` merges it, RT11).

## Requirements
- **Providers** (`router_providers.py`):
  - `GET /orgs/{org}/ai/providers` (`org.read`): the catalog. Each entry has:
    - `name`, `label`, `models` (id, label, price per MTok, `verified`), `default_model`, `tos_note`, `privacy_note`;
    - `available` + `unavailable_reason` (`prod_mock`, `gemini_billing_required`, `ai_disabled_platform`);
    - `platform_key` (true when the dev platform key covers it: the API reads only a non-secret `AI_PLATFORM_PROVIDER`; it never sees the file);
    - and, when configured: `enabled`, `model`, `configured`, `key_last4`, `verify_status`, `verified_at`, `last_error_code`, `terms_ack_at`, `paid_tier_ack_at` (gemini).

    Never ciphertext columns.
  - `PUT /orgs/{org}/ai/providers/{provider}` (`integrations.manage`): `{api_key?: SecretStr, enabled?, acknowledge_terms?, acknowledge_paid_tier?, model?}`.
    - The first configuration requires a key, unless `platform_key`.
    - The first `enabled=true` requires `acknowledge_terms` → `422 terms_not_acknowledged`; for `gemini` also `acknowledge_paid_tier` → `422 paid_tier_not_acknowledged` (RT5).
    - A model outside the allowlist → `422 model_not_allowed`; unavailable → `422 provider_unavailable`.
    - A new key → `key_version + 1`, sealed with `ai/seal.py` under `AI_SEAL_ACTIVE_KID`, `verify_status=unverified`, `ai.verify` queued (10 per 10 min per org and provider).
    - The org row is locked `FOR NO KEY UPDATE`.
    - Audit `integration.ai_terms_acknowledged`, `integration.ai_key_set` / `ai_key_replaced` (provider, last4, kid, version) or `integration.ai_updated`.
  - `DELETE …/{provider}/key` → an UPDATE clearing the sealed columns and `enabled=false` (version floor kept), 204, audited.
  - `POST …/{provider}/verify` → 202, rate limited.
- **Settings** (`router_settings.py`): `GET` (`org.read`) and `PUT` (`integrations.manage`) `/orgs/{org}/ai/settings`:
  - fields: `ai_enabled`, `acknowledge_privacy`, `default_provider`, `pseudonymize_internal`, `internal_cidrs` (≤ 50 valid CIDRs), `internal_suffixes` (≤ 50 domain suffixes), `include_strings`, `include_ti`, `include_case_text`, `daily_token_budget`, `run_token_cap`, `incident_token_cap` (no `refusal_fallback`, RT10);
  - turning AI on requires `acknowledge_privacy` (`422 privacy_not_acknowledged`), and so does widening the disclosure later: `include_case_text` or `include_strings` turned on, or `pseudonymize_internal` turned off (RT22); budgets above `AI_CEILINGS` → `422 budget_above_ceiling`;
  - the response includes the ceilings and the privacy notice text;
  - audit `ai.settings_updated` (changed field names and booleans; CIDR and suffix counts, not values), `ai.enabled` / `ai.disabled`.
- **Preview** `POST /orgs/{org}/ai/context-preview` (`evidence.write`; 30 per user per 10 min): same body as a run.
  - It calls `builder.preview` and returns `context_stats`, the item list as it would be sent (pseudonyms shown), and the categories of data that would leave.
  - Nothing is persisted and nothing audited.
  - Refused when AI is disabled (`409 ai_disabled`), so preview never becomes a way around the opt-in.
- **Runs** (`router_runs.py`):
  - `POST /orgs/{org}/ai/runs` (`evidence.write`): `{task, job_id?, investigation_id?, target_id?, provider?, model?, regenerate?: bool}`.
  - **Checks:**
    - `ai_enabled` → else `409 ai_disabled`;
    - the provider is enabled with terms acknowledged, available and keyed (own key or platform) → else `409 no_provider_enabled` / `422 provider_unavailable`;
    - the job is succeeded → else `409 job_not_ready`; task / target validity → `422`;
    - per user `AI_RUNS_PER_USER_10MIN` → 429;
    - today's DB usage for the org (sum of `ai_runs.usage`) ≥ `daily_token_budget` → `409 budget_exhausted` (RT9);
    - non-final runs of the org (**children included**) + the runs this request creates (1, or 1 + children for an incident) > `AI_ACTIVE_RUNS_PER_ORG`, or the same globally > `AI_ACTIVE_RUNS_GLOBAL` → `409 ai_busy`, under the per-org then global advisory locks (the M4 pattern) (RT8).
  - Then `builder.build_run` → `runs.create_run`, in **one transaction**:
    - `ai_runs` (+ children for an incident, with `parent_run_id`, scope `job`, task `job_digest`, and the parent's `deadline_at`), `ai_run_index`, `ai_run_inputs` (stage `base`, context, sha256, pseudonym map), `ai_context_refs`;
    - audit `ai.run_requested`: task, target ids, provider, model, `prompt_version`, `context_sha256`, per-kind counts, pseudonymization counts, the inclusion toggles, truncation; **no content**.
  - Commit, then `runs.dispatch` (children first, then the parent). A publish failure still answers 202, because `ai.resume` recovers.
  - **Dedupe:** an identical (org, task, target, provider, model, `prompt_version`, `context_sha256`) run that is active or completed is returned with `deduplicated: true` (200), unless `regenerate`, which creates a new run with `supersedes_run_id`.
  - `GET /orgs/{org}/ai/runs?job_id&investigation_id&task&status&target_id&cursor` (`evidence.read`): top-level runs, newest first.
  - `GET /orgs/{org}/ai/runs/{run_id}` (`evidence.read`):
    - status, error code, `resume_at`, deadline, provider, model, served model, `prompt_version`, `context_stats`, usage, cost (`estimated` flag), metrics, flags, children summaries;
    - when completed, the output read model (`service_outputs.py`, from the stored body, `verification.claims` and `ai_citations` rows): sections with claim status; citations with status, reason, kind, `ref_id`, `job_id` and a server-built **internal** deep-link descriptor `{route: "pcap"|"malware"|"evidence"|"investigation", job_id, tab, ref}` for verified ones only; and the display text with pseudonyms reversed (from the run tree's map) unless `?pseudonyms=keep`;
    - `canary_leak` runs never return the body;
    - refused runs return the category.
  - `GET /orgs/{org}/ai/runs/{run_id}/context` (`evidence.read`): the exact frozen context(s) sent (base and reduce) plus `context_sha256`; `?reveal=true` adds the pseudonym map.
  - `GET /orgs/{org}/ai/usage` (`org.read`): today's tokens and cost per provider from `ai_runs.usage` (DB), alongside the budget and ceilings.
- **Schemas:**
  - `api_key` is write-only (excluded from every response model; validators never echo it);
  - the output read model has **no free-form URL field**;
  - error codes are stable strings;
  - typed OpenAPI for the output sections, citations and context items.
- **Contracts:** the parent regenerates `packages/contracts` after the group-B merge.

## Implementation Steps
1. Repository and service for providers (seal with the public key only; catalog from `catalog.py`; availability from `availability.py`) and settings; routes; tests:
   - RBAC (analyst or viewer PUT → 403; viewer GET without secrets);
   - terms and privacy acknowledgements;
   - the sentinel key absent from responses, audit and caplog (including 422 bodies);
   - replace bumps the version; remove keeps the floor; concurrent PUTs serialize;
   - mock unavailable in prod; gemini unavailable without billing; model allowlist;
   - budget ceilings.
2. `runs.py` (`create_run`, `dispatch`) and the run routes with tests:
   - creation and dedupe; regenerate; caps under concurrency (global lock test); rate limit; publish failure → 202;
   - incident creates children;
   - a disabled org → 409; preview refused when disabled;
   - the audit row has no context text (scan for seeded field values).
3. The output read model (`service_outputs.py`) with tests:
   - unsupported claims are marked; deep links only for verified citations;
   - pseudonyms reversed vs kept; a canary-leak body is never returned; refused category.
4. The context viewer and usage routes.
5. `idor_cases_ai.py`: the AI cases and a victim extender (provider config, settings, a run with context); `test_idor_routes.py` passes in this lane (the timeline case lives in phase 4's module and is checked at the merge); `test_ai_api_rbac.py` role matrix. Builder-dependent tests monkeypatch `fake_build_run` / `fake_preview` from `tests/ai_doubles.py` over the stub (RT12).

## Success Criteria
- [x] The IDOR and RLS enumerators cover every AI route and table, and they pass. — `security/test_idor_routes.py` with `idor_cases_ai.py` (all 12 `/ai/*` routes; the victim extender seeds a provider config, settings and a run with its context, and `{run_id}` is overridden per template), `integration/test_rls_coverage.py` (all 8 `ai_*` tables), `test_ai_api_rbac.py::test_ai_role_matrix` (83f24a1, 6b52742); full API suite 3441 passed / 42 skipped.
- [x] No response, audit detail, error envelope or log line contains the sentinel key, the pseudonym map (unless `reveal`), or context text in audit. — `test_ai_api_providers.py::test_sentinel_key_never_leaks` (responses, audit rows, DEBUG caplog, 422 bodies), `test_sealed_key_opens_only_with_the_ai_private_key`; `test_ai_api_runs.py::test_run_creation_commits_everything_and_dedupes` (scans the `ai.run_requested` audit row for every free-text context value), `test_revealing_the_pseudonym_map_is_audited` (83f24a1); `test_ai_key_leak.py::test_the_key_never_leaves_its_sealed_columns`, `test_providers_and_errors_never_print_the_key`, container-log scan `scripts/check-ai-key-leak.mjs` (6b52742).
- [x] A run request commits the run, index, inputs, refs and audit atomically; caps and dedupe hold under concurrency. — `test_ai_api_runs.py::test_run_creation_commits_everything_and_dedupes`, `test_incident_creates_children_in_one_transaction`, `test_concurrent_identical_requests_create_one_run`, `test_global_cap_holds_under_concurrent_creation`, `test_active_caps_count_children`, `test_failed_runs_are_not_deduplicated` (83f24a1).
- [x] The read model never exposes a link for an unverified or invalid citation, and never returns a canary-leak body. — `test_ai_api_outputs.py::test_claims_citations_and_deep_links`, `test_static_evidence_and_record_links`, `test_canary_leak_body_is_never_returned`, `test_refused_run_returns_its_category` (83f24a1).

## Risk Assessment
- **Preview as a data-exfil or DoS path.** It is behind the same opt-in, permission and per-user limit, with no persistence.
- **Pseudonym reversal leaks internal names to viewers.** Members can already read the same rows; reversal uses the run's own map only, never across orgs.
- **Building a large context inside the request** holds a DB session. The caps bound the work; measure p95 and, if it is too slow, note it for phase 11 (async build is out of scope).

## Implementation Notes (2026-11-06)
- **Commits:**
  - 83f24a1 (lane run, see phase 2): `router_{providers,settings,runs}.py`, `service_{providers,settings,runs,outputs}.py`, `schemas.py`, `repository.py`, `runs.py`; contracts regenerated (`packages/contracts/openapi.json`, `src/schema.d.ts`);
  - 6b52742: the reveal permission and the provider `limits`.
- **Routes (12):**
  - providers: `GET /ai/providers`, `PUT /ai/providers/{provider}`, `DELETE /ai/providers/{provider}/key` (204), `POST /ai/providers/{provider}/verify` (202);
  - settings and usage: `GET` / `PUT /ai/settings`, `GET /ai/usage`;
  - runs: `POST /ai/runs` (202 for a new run, 200 when deduplicated), `POST /ai/context-preview`, `GET /ai/runs`, `GET /ai/runs/{run_id}`, `GET /ai/runs/{run_id}/context`.
- **Providers:**
  - Keys are write-only: 8–256 printable ASCII characters, `422 invalid_api_key` without echo. The API seals with the public key only.
  - A replace bumps the version; a remove keeps the version floor (`test_replace_bumps_version_and_remove_keeps_it`). Concurrent PUTs serialize on the org row (`test_concurrent_puts_serialize`).
  - Verify is limited to 10 per provider per 10 minutes (`test_verify_is_queued_and_rate_limited`).
  - Error codes: `terms_not_acknowledged`, `paid_tier_not_acknowledged`, `model_not_allowed`, `provider_unavailable`, `limit_above_ceiling`.
- **Review (Low), Gemini attestation per key:**
  - A new Gemini key clears `paid_tier_ack_*`. If the provider stays enabled, the attestation must come in the same request.
  - Tests: `test_a_new_gemini_key_needs_a_new_paid_tier_attestation`, `test_gemini_needs_billing_and_a_paid_tier_attestation`.
- **Settings:**
  - off by default and readable by viewers;
  - turning AI on needs `acknowledge_privacy`;
  - budgets stay within the ceilings (`422 budget_above_ceiling`);
  - CIDR and suffix lists hold at most 50 entries each (`test_cidr_and_suffix_lists`).
- **Review (Low), re-consent:**
  - These changes widen the disclosure and need `acknowledge_privacy` again (`422 privacy_not_acknowledged`): turning `include_ti`, `include_strings` or `include_case_text` on; turning pseudonymization off; removing any CIDR or suffix entry.
  - Adding entries never does.
  - Tests: `test_widening_the_disclosure_needs_a_new_acknowledgement`, `test_re_ack_when_less_is_pseudonymized_or_ti_is_included`, `test_adding_internal_entries_needs_no_new_acknowledgement`.
- **Run creation:**
  - One transaction holds the run, index, inputs, refs and the audit row; the audit carries ids and counts only.
  - Locks: a per-org advisory lock, then the global one.
  - Caps: 12 active runs per org and 40 overall, children included (RT8; `409 ai_busy`).
  - Limits: 10 run requests per user per 10 minutes; the daily budget is pre-checked against the DB (RT9, `409 budget_exhausted`, `test_daily_budget_is_checked_against_the_db`).
  - A publish failure still answers 202 (`test_publish_failure_still_answers_202`).
- **Dedupe:** on (task, scope, target, provider, model, `context_sha256`); failed runs are never deduplicated; `regenerate` sets `supersedes_run_id`.
- **Preview:** 30 per user per 10 minutes; nothing is persisted or audited (`test_preview_persists_nothing`).
- **Read model** (`service_outputs.py`):
  - Every claim and citation carries its status and reason.
  - A deep-link descriptor `{route, job_id, tab, ref}` exists only for verified citations, built from the stored kind, ref and job.
  - Pseudonyms are reversed in whole tokens only (`test_reverser_replaces_whole_tokens_only`), or kept with `?pseudonyms=keep`.
  - The incident parent shows the child flags (RT23, `test_incident_parent_shows_child_flags`).
- **Review (Low), reveal audit:**
  - `GET …/context?reveal=true` adds the pseudonym map and writes `ai.context_revealed` (run, actor and stages, never a name).
  - 6b52742 restricted it to `evidence.write`, so viewers get 403.
- **Phase-11 addition (6b52742):** an org may set its own per-minute request limit within the ceiling (`test_an_org_sets_its_own_request_limit_within_the_ceiling`).
- **Not done:** no p95 was recorded for building the context inside the request (a plan risk item).
