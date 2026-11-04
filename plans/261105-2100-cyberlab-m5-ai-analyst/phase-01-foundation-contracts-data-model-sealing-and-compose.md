---
phase: 1
title: "Foundation contracts data model sealing and compose"
status: pending
priority: P1
effort: "18h"
dependencies: []
---

# Phase 1: Foundation contracts data model sealing and compose

## Overview
One agent lays the frozen foundations that every parallel phase builds on:
- migration 0011 and the models;
- the generalized sealing (M4 behaviour intact) with a new `ai` domain;
- the `analyst` process role and settings;
- the analyst-worker service, its broker ACL user and network placement;
- every shared contract (enums, context and provider models, the output schema, labels, the text sanitizer, the catalog);
- the rule-based `FakeProvider`, test doubles, cross-phase stubs and empty routers.

After this phase the stack runs as before. The analyst-worker starts and fails any `ai.run` with `not_implemented`, and nothing AI is user-visible yet. **Everything listed under "Frozen interfaces" in plan.md is frozen at the end of this phase.**

## Requirements
- **Dependencies (RT20):** `anthropic>=2.5,<3` (official SDK; it depends on the separate `httpx2` package, which coexists with the pinned `httpx 0.28.1`) and `google-genai>=2.34,<3` (not the deprecated `google-generativeai`; needs `httpx>=0.28.1`) as api runtime dependencies; `uv.lock` updated; `cyberlab/api:dev` rebuilt once (the image runs with `UV_OFFLINE`). Record the resolved versions in the phase notes. No other phase edits `pyproject.toml` / `uv.lock`.
- **Alembic head (RT25):** confirm that the head is still `0010` (M4 is in its gate); if M4 added a migration, number this one head + 1 and tell the parent.
- **Sealing refactor** (decision; keep M4 intact):
  - `app/core/sealbox.py`:
    - `SealDomain(scheme: str, providers: frozenset[str], url_bound: Callable[[str], bool])`;
    - `seal_in(domain, plaintext, org_id, provider, kid, key_version, base_url_norm, public_key) -> SealedKey`;
    - `aad(domain, org_id, provider, kid, key_version, base_url_norm)`;
    - `check_context(domain, …)`, `derive_key(domain, …)`, `load_public_key`, `last4`, `SealError`, `SealedKey`. Key rules unchanged: 8–256 printable ASCII, no surrounding whitespace.
  - `app/core/sealbox_open.py`: `open_in(domain, sealed, org_id, provider, base_url_norm, private_keys) -> SecretStr`, `load_private_keys(path)`, `UnsealError`.
  - `threat_intel/seal.py` and `threat_intel/unseal.py` become wrappers with `TI_DOMAIN = SealDomain("cyberlab.ti.v1", {ProviderName…}, url_bound=lambda p: p == "misp")`. **Every existing public name and signature is kept**, and every M4 test passes unchanged.
    - Add `tests/fixtures/seal/ti_prerefactor.json`: a ciphertext produced by the current code before the refactor, generated and committed first.
    - Add `test_ti_seal.py::test_prerefactor_ciphertext_still_opens`.
  - `app/modules/ai/seal.py`: `AI_DOMAIN = SealDomain("cyberlab.ai.v1", {"anthropic","gemini","mock"}, url_bound=lambda p: False)` and `seal(plaintext, org_id, provider, kid, key_version, public_key)` (`base_url_norm` always `""`). The analyst also imports it for the lazy re-seal (RT18).
  - `app/modules/ai/unseal.py`: `open_sealed(sealed, org_id, provider, private_keys)`, `load_private_keys`.
  - Cross-domain tests: an AI ciphertext does not open as TI (and vice versa) even under the same key pair, because the scheme sits in both the HKDF info and the AAD.
- **Settings** (`core/config.py`):
  - `ProcessRole` adds `analyst`; `ANALYST_FORBIDDEN = ENRICH_FORBIDDEN + ("ti_seal_private_keys_file",)`. `_role_guards` gains an `analyst` branch (today it returns early only for `enrich`; every other role is treated as api/ingest and requires JWT/MinIO/Redis).
  - New settings:
    - `AI_ENABLED` (true), `AI_SEAL_PUBLIC_KEYS`, `AI_SEAL_ACTIVE_KID`;
    - `AI_SEAL_PRIVATE_KEYS_FILE` (analyst only, every env);
    - `AI_PLATFORM_KEY_FILE` + `AI_PLATFORM_PROVIDER` (analyst only; refused in prod);
    - `AI_MOCK_ENABLED`, `AI_MOCK_BASE_URL`, `GEMINI_BILLING_ENABLED` (false);
    - `AI_DEFAULT_PROVIDER`, `AI_ANTHROPIC_EFFORT` (`medium`), `AI_ANTHROPIC_BASE_URL` / `AI_GEMINI_BASE_URL` (test only, refused in prod);
    - `AI_MAX_INPUT_TOKENS` (60 000), `AI_MAX_OUTPUT_TOKENS` (16 000), `AI_CALL_TIMEOUT_S` (300), `AI_CALL_IDLE_TIMEOUT_S` (60), `AI_MAX_CALLS_PER_RUN` (3), `AI_RUN_DEADLINE_S` (1200), `AI_INCIDENT_DEADLINE_S` (3600, inherited by the children), `AI_MAX_JOBS_PER_INCIDENT` (10) (RT2, RT8);
    - `AI_CEILINGS` (JSON: `daily_token_budget` 20 000 000, `run_token_cap` 200 000, `incident_token_cap` 2 000 000, `per_minute` per provider) and the org defaults 1 000 000 / 100 000 / 600 000 (RT9);
    - `AI_PLATFORM_DAILY_TOKENS` (200 000, analyst only, RT17);
    - `AI_RUNS_PER_USER_10MIN` (10), `AI_ACTIVE_RUNS_PER_ORG` (12) and `AI_ACTIVE_RUNS_GLOBAL` (40), both counting every non-final run including incident children (RT8).
  - `_prod_guards` refuses:
    - `AI_MOCK_ENABLED`, `AI_PLATFORM_KEY_FILE`, `AI_ANTHROPIC_BASE_URL`, `AI_GEMINI_BASE_URL`;
    - a missing public key for the active AI kid while `AI_ENABLED`;
    - `dev-` AI kids in any case, and the committed dev AI public key under any kid.

    The `COOKIE_SECURE` check stays api-only (the M4 H1 lesson).
  - **Role-scoped kid guards (RT6):** the existing TI kid checks (`TI_SEAL_ACTIVE_KID` in `TI_SEAL_PUBLIC_KEYS`, no `dev-` kid) run for `api` and `enrich` only; the AI kid checks run for `api` and `analyst` only. The dev-public-key refusals apply wherever the keys are present. Fixtures: the rendered prod env of every role (`api`, `ingest`, `enrich`, `analyst`) is accepted by `Settings`.
  - Every other role refuses `AI_SEAL_PRIVATE_KEYS_FILE` / `AI_PLATFORM_KEY_FILE`.
- **Keys:**
  - committed dev pair `infra/ai/dev-seal-private.json` (kid `dev-ai-1`) with its public key in `.env.example`;
  - `scripts/gen_ai_seal_keys.py` (clone of `gen_ti_seal_keys.py`: mode 0400, `chown 10001` hint, `--add --kid`);
  - the analyst refuses to start (exit 1) if the file is unreadable or lacks the active kid.
- **Migration `0011_ai_analyst.py`** (owner role), exactly the tables, constraints, triggers and grants in plan.md's data model:
  - `ai_provider_configs` (provider check; sealed all-or-none; `key_last4` length 4; `enabled` ⇒ `terms_ack_at`; `enabled` for `gemini` ⇒ `paid_tier_ack_at` (RT5); the sealed-key requirement is enforced in the app, because the dev platform key has no sealed row; monotonic `key_version` trigger copied from 0009; **no DELETE grant**; column UPDATE on the sealed columns for the analyst's lazy re-seal, RT18);
  - `ai_org_settings` (`ai_enabled` ⇒ `privacy_ack_at`; array length checks ≤ 50; budgets > 0; `incident_token_cap`; no `refusal_fallback`, RT10);
  - `ai_runs`:
    - checks on `task`, `scope` and `status`;
    - `job_id` NOT NULL iff `scope = 'job'`, `investigation_id` NOT NULL iff `scope = 'investigation'`;
    - `parent_run_id` only for `job_digest`;
    - `context_sha256 ~ '^[0-9a-f]{64}$'`; jsonb size checks;
    - the transition trigger cloned from `ti_run_transition` with `refused` as a final state;
    - column UPDATE grants as listed;
  - `ai_run_index` (the `ti_run_index` pattern: RLS `app_org_id() IS NULL OR …`, column UPDATE grants, composite FK to the run, index (status, resume_at); `calls` int ≥ 0, RT2);
  - `ai_run_inputs`, `ai_context_refs`, `ai_outputs`, `ai_citations` (append-only with `forbid_mutation`, composite FKs to their run/output of the same org, size and enum checks, index `ai_context_refs (organization_id, kind, ref_id)`).

  FORCE RLS everywhere. The app role cannot UPDATE `organization_id`, `provider`, `task` or `created_at`.
- **Models:** `app/modules/ai/models.py`, registered in `app/models.py`.
- **Contracts** (`app/modules/ai/`, frozen):
  - `contracts.py`, `output_schema.py`, `labels.py`, `text.py`, `catalog.py`, `availability.py`, `messages.py` as specified in plan.md "Frozen interfaces".
  - **Output schema:**
    - every object `extra="forbid"`;
    - caps: `observed` ≤ 40, `interpretation` ≤ 20, `hypotheses` ≤ 10, `next_steps` ≤ 10, `attack_techniques` ≤ 20, `timeline` ≤ 60, citations per claim ≤ 8, `text` ≤ 600, `quote` ≤ 256, `field` ≤ 64;
    - `provider_json_schema("anthropic")` removes the length/number keywords **and the array constraints (`minItems`/`maxItems`)** the API does not support and keeps `additionalProperties: false` (RT19); `"gemini"` keeps `minItems`/`maxItems`;
    - a lenient loader `coerce_caps(parsed) -> (parsed, truncation_counts)` truncates over-cap arrays and strings before strict validation (presentation caps are never a reason for a paid repair call, RT19);
    - a test proves the serialized worst case ≤ 64 KiB.
  - **Contracts added by the red team (RT12):** `RunScope`, `OutputVerification`, `RunMetrics`, `ValidationFailed(errors)`, `ContextBuildError(code)`, `ProviderError.request_sent` (true once the request left the process, so the worker knows a timeout may have been billed), `DigestInput.flags`; `ProviderRequest` has no `fallback` field (RT10). `AiErrorCode` includes `context_too_large`, `budget_exhausted`, `provider_error`, `deadline`, `canary_leak`, `no_digest`, `not_implemented` and the rest of plan.md's outcome table; `CitationReason` includes `quote_too_short`, `weak_anchor`, `digest_not_evidence`.
  - **Catalog:**
    - `anthropic`: models `claude-sonnet-5` ($2 / $10, cache read $0.20) default, and `claude-opus-5-5` ($4 / $20, cache read $0.20), `verified=false` until phase 3 checks the Models API;
    - `gemini`: default `gemini-3.8-flash`, price from the researcher report, `verified=false`, `requires_billing_flag=True`, privacy note on free-tier training;
    - `mock`: `mock-1`, `dev_only`;
    - plus `price_version`, ToS and privacy notes. The Anthropic and Gemini ToS notes say that a BYOK org is bound by its own provider terms and usage policy (defensive security analysis only) (RT24).
  - **`text.py`:**
    - strips C0/C1 except `\n\t`, U+200B–200F, U+202A–202E, U+2066–2069, U+FEFF and U+E0000–E007F, returning counts;
    - `defang` / `refang` (`hxxp`, `[.]`, `[:]`); canonical IP and hash.
- **`FakeProvider`** (`ai/providers/fake.py`):
  - deterministic and rule-based. It reads `ProviderRequest.context`, the in-process `FrozenContext` reference. Real adapters never serialize that field; they send only `system` and `user`. So it does not depend on the phase-5 prompt format.
  - It cites the top items by kind priority with an exact `field` + `quote`, adds `attack_techniques` from capability `attack_ids`, and emits one hypothesis, one next step and one limitation.
  - Usage = chars/4.
- **Stubs** (signatures frozen; bodies `raise NotImplementedError`, owned later): `ai/context/builder.py`, `ai/context/reduce.py`, `ai/prompt.py`, `ai/verify.py`, `ai/providers/registry.py`, `ai/runs.py`; plus `reaper.reap_ai_runs()` returning 0, already called from the `reap` task in `workers/tasks.py` (phase 2 fills it) (RT12).
- **Doubles (RT12):** `tests/ai_doubles.py` also provides `fake_build_run`, `fake_preview`, `trivial_render` and `passthrough_reduce`, so phases 2 and 7 test against stubs that would otherwise raise.
- **IDOR split (RT11):** `tests/security/test_idor_routes.py` merges `ROUTE_CASES` from the new, empty `tests/security/idor_cases_reads.py` (phase 4) and `tests/security/idor_cases_ai.py` (phase 7), and runs their `VICTIM_EXTENDERS` to fill `Victim.extra`. The existing cases and assertions stay unchanged.
- **Routers:** `ai/router.py` (frozen) includes empty `router_runs.py`, `router_providers.py` and `router_settings.py`, registered in `app/main.py`.
- **Jobs package:** `cyberlab_jobs.tasks` gains `AI_RUN = "ai.run"`, `AI_RESUME = "ai.resume"`, `AI_VERIFY = "ai.verify"` and `Queues.analyst`.
- **Celery:**
  - `app/workers/analyst_app.py` (clone of `enrich_app.py`: own unacked keys `{prefix}analyst.unacked*`, remote control and events off, `acks_late`, prefetch 1, visibility timeout ≥ 2× the call timeout);
  - `app/workers/analyst_tasks.py` with no-op tasks that mark a run `failed/not_implemented` (owned by phase 2 afterwards);
  - `celery_app.py` beat entry `ai.resume` every 30 s to the analyst queue.
- **Compose** (`docker-compose.yml`, `.prod.yml`, `.env.example`):
  - `x-analyst-env` (`ENV`, `PROCESS_ROLE: analyst`, `DATABASE_URL`, `BROKER_URL: redis://analyst:${BROKER_ANALYST_PASSWORD}@redis-broker:6379/0`, `QUEUE_PREFIX`, `AI_*` including `AI_SEAL_PUBLIC_KEYS` / `AI_SEAL_ACTIVE_KID` for the lazy re-seal), never merged with `*api-env` / `*enrich-env`;
  - `BROKER_ANALYST_PASSWORD` defaults to `change-me-broker-analyst` in the dev compose file, so an older `.env` does not crash `redis-broker`; the prod overlay requires it (`:?`) and the prod placeholder check refuses `change-me` (RT25);
  - **lane support (RT3):** the test-profile broker URLs (`api-test` `BROKER_URL` and `TEST_BROKER_*_URL`, `enrich-worker-test`, `analyst-worker-test`) use `/${TEST_BROKER_DB:-1}` instead of the literal `/1`;
  - `analyst-worker` (api image, `[enrich, egress]`, the hardening of the enrich-worker, secret `ai_seal_private` → `infra/ai/dev-seal-private.json`);
  - `analyst-worker-test` (test profile, `test.` prefix, test DB, `AI_MOCK_ENABLED=true`), on which `api-test` depends;
  - `ai-mock` skeleton (test + e2e profiles, `egress` only, `python:3.12-alpine`, uid 65534, `infra/ai-mock/server.py` returning 501; owned by phase 2 afterwards);
  - **prod override:** `analyst-worker` with the prod image, `ENV: prod`, `volumes: !reset []`, `.secrets/ai_seal_private.json`, `AI_MOCK_ENABLED: "false"`, `deploy.replicas: 2` (or two services if compose scale is unsupported in the gate);
  - `docker-compose.ai-platform.yml` (dev-only overlay mounting `.secrets/ai_platform_key` as a secret for the analyst, with `AI_PLATFORM_PROVIDER`), never in the gate.
- **Broker ACL** (`infra/redis-broker/entrypoint.sh`): user `analyst` with `resetkeys ~analyst* ~test.analyst*` plus `_kombu.binding.*` for `analyst` / `test.analyst`, and the same channel and command denies as `enrich`.
- **Guard and coverage tests:**
  - `test_tenant_session_guard.py` allowlists `app/workers/analyst.py` and the AI reaper path;
  - new `unit/test_ai_import_guard.py` covers every import form, as in M4 RT21:
    - `ai.unseal` only from `app/workers/analyst*.py`;
    - `core.sealbox_open` only from the two unseal wrappers;
    - `ai.providers.{anthropic,gemini,mock,registry}`, `ai.http`, `anthropic` and `google.genai` only from the analyst worker and the adapters;
    - `app/workers/analyst*.py` never imports `threat_intel.unseal`, and `app/workers/enrich*.py` never imports `ai.unseal`;
  - `test_ti_import_guard.py` is updated for the moved generic code;
  - `test_rls_coverage.py` registers the eight tables.

## Implementation Steps
1. Commit the pre-refactor TI ciphertext fixture. Refactor into `core/sealbox*.py`; TI wrappers; AI wrappers; seal tests (round trip, wrong org / provider / kid / version / domain, tampering, reprs).
2. Settings, role rules, prod guards, dev AI key pair, keygen script; `unit/test_config.py` additions:
   - the analyst refuses JWT / MinIO / Redis / TI private keys;
   - other roles refuse AI private and platform keys;
   - prod refuses mock, platform key, base URL overrides and `dev-` kids;
   - the rendered prod analyst env is accepted (fixture `tests/fixtures/compose/analyst-worker.prod.env.json`).
3. Migration 0011, the models and `integration/test_ai_schema.py`: RLS per table, cross-org FKs, append-only (also for the owner), transitions, finals immutable, the `key_version` trigger, no DELETE, the column grants, constraints, upgrade and downgrade.
4. Contracts, output schema, labels, text, catalog, availability, messages; `unit/test_ai_contracts.py` (schema export per provider, worst-case size, label grammar, sanitizer tables, catalog consistency).
5. `FakeProvider`, `tests/ai_doubles.py`, `tests/ai_helpers.py`, the stubs, the routers, the jobs package names.
6. Compose, ACL, `ai-mock` skeleton, the platform overlay and `TEST_BROKER_DB`. `integration/test_analyst_acl.py`:
   - `analyst` is confined;
   - `analyst` can `EVAL` on `test.analyst.ai:*`;
   - pcap / static / enrich cannot touch `analyst*`;
   - `api` and `ingest` can publish.

   `container/test_analyst_network.py`, run inside `analyst-worker-test`: default route present, not on `analysis`, cannot resolve `api`, `redis`, `minio` or `enrich-worker`, and no api secrets in the env.
7. Re-run the full API suite, `pnpm verify` and `docker compose -f … -f docker-compose.prod.yml config` (analyst with `ENV=prod`, no `JWT_SECRET` / `MINIO_*` / `REDIS_URL` / `TI_SEAL_PRIVATE_KEYS_FILE`). Write "Phase notes (frozen)" with the exact signatures.
8. **Lane setup for group B (parent, after the commit; plan.md "Parallel execution on this host"):** rebuild `cyberlab/api:dev`, create `cyberlab_b2_test` … `cyberlab_b7_test`, create the six worktrees with their edited `.env` copies, and run `tests/unit/test_ai_contracts.py` once in each lane as a smoke test.

## Success Criteria
- [ ] Every M4 seal test passes unchanged, and the pre-refactor ciphertext still opens. An AI ciphertext never opens under the TI domain, another org, provider, kid or version.
- [ ] The analyst env holds no JWT, MinIO, app Redis or TI private key (dev and prod configs). The enrich env holds no AI private or platform key.
- [ ] Broker ACL and network tests confine `analyst`; analyzers and `enrich` cannot reach `analyst*`.
- [ ] Migration 0011 is applied and tested. The contracts, output schema, catalog, stubs and doubles are committed and documented in the phase notes as frozen.
- [ ] `pnpm verify` green on a fresh clone (dev AI key pair, no platform key file needed).

## Risk Assessment
- **The seal refactor could change bytes and orphan stored TI keys.** The pre-refactor fixture test is the guard; the wrappers keep the AAD byte for byte.
- **Over-freezing.** Interfaces may need changes once group B starts. Change requests go to the parent, which changes the frozen file and notifies all group-B agents; no agent edits a frozen file.
- **Compose replicas in the prod overlay** may not be honored without swarm. If `deploy.replicas` is ignored, define `analyst-worker-2` explicitly.
- **SDK dependency weight.** Resolved by the red team (RT20): `anthropic` uses the separate `httpx2` package and does not conflict with `httpx 0.28.1`; `google-genai` adds `google-auth`, `requests` and `websockets` to the api image. If `uv lock` still reports a conflict, pin the newest compatible versions and tell the parent.

## Frozen interfaces (as built)

Phase 1 as implemented (2026-11-05). Everything below is frozen for group B; change requests go to the parent. Paths are relative to `apps/api` unless noted.

**Dependencies (resolved in `uv.lock`):** `anthropic 2.5.0` (+ `httpx2 2.16.0`, `httpcore2 2.16.0`, `httpx2-jsfetch`, `truststore`, `jiter`, `distro`, `docstring-parser`, `sniffio`) and `google-genai 2.34.0` (+ `google-auth 2.62.1`, `requests 2.34.2`, `tenacity 9.1.4`, `pyasn1*`, `charset-normalizer`); `httpx` stays `0.28.1`; `websockets` was already present (uvicorn). `cyberlab/api:dev` was rebuilt; both SDKs import and `httpx2.MockTransport` exists. The alembic head before 0011 was `0010` (confirmed).

**1. Migration and models.** `alembic/versions/0011_ai_analyst.py` (revises 0010) and `app/modules/ai/models.py` (registered in `app/models.py`): `AiProviderConfig`, `AiOrgSettings`, `AiRun`, `AiRunIndex`, `AiRunInput`, `AiContextRef`, `AiOutput`, `AiCitation`.
- Functions `ai_run_transition` and `ai_key_version_guard`; `forbid_mutation` on `ai_run_inputs`, `ai_context_refs`, `ai_outputs`, `ai_citations`; no DELETE grant on any `ai_*` table.
- Column UPDATE grants: `ai_provider_configs` (enabled, model, the sealed columns, verify_status, verified_at, last_error_code, limits, terms_ack_*, paid_tier_ack_*, updated_at); `ai_org_settings` (everything but organization_id); `ai_runs` (status, error_code, served_model, usage, cost_micros, price_version, metrics, started_at, finished_at); `ai_run_index` (status, resume_at, deadline_at, dispatched_at, lease_until, lease_owner, attempts, calls).
- Transitions: queued → running | failed; running → waiting | completed | partial | failed | refused; waiting → running | failed; finals are immutable. The identity columns (task, scope, job/investigation/target/parent ids, provider, model, prompt_version, output_schema, context_sha256, context_stats, requested_by, supersedes_run_id, deadline_at, created_at) are immutable even for the owner.
- Shapes worth knowing: `ai_runs.requested_by` is NOT NULL (children carry the parent's requester); `parent_run_id IS NOT NULL ⇔ task = 'job_digest'`; `target_kind ∈ {finding, alert}` together with `target_id`; `ai_run_inputs` PK (run_id, stage); `ai_context_refs` PK (run_id, label), so a reduce ref that reuses a base label is inserted ON CONFLICT DO NOTHING, with a composite FK (job_id, org) to `analysis_jobs`; `ai_outputs` unique run_id and `verification` ≤ 32 KiB; `ai_citations` has `claim_id`, a nullable `claim_status` (NULL for `next_steps` refs) and `stale`. The budget server defaults come from `core/config.py` `AI_DEFAULT_*` (1 000 000 / 100 000 / 600 000).

**2. Sealing.**
- `app/core/sealbox.py`: `SealDomain(scheme: str, providers: frozenset[str], url_bound: Callable[[str], bool])`, `SealedKey`, `SealError(code)`, `KID_PATTERN`, `KEY_BYTES`, `NONCE_BYTES`, `MIN_KEY_CHARS`, `MAX_KEY_CHARS`, `aad(domain, org_id, provider, kid, key_version, base_url_norm) -> bytes`, `derive_key(domain, shared, epk, recipient_pk) -> bytes`, `check_context(domain, provider, kid, key_version, base_url_norm)`, `seal_in(domain, plaintext, org_id, provider, kid, key_version, base_url_norm, public_key) -> SealedKey`, `load_public_key(b64)`, `raw_public(key)`, `key_text(value)`, `last4(value)`.
- `app/core/sealbox_open.py`: `UnsealError(code)`, `load_private_keys(path) -> dict[str, X25519PrivateKey]`, `open_in(domain, sealed, org_id, provider, base_url_norm, private_keys) -> SecretStr`.
- `threat_intel/seal.py` and `unseal.py`: every M4 name and signature kept (re-exported), plus `TI_DOMAIN`; `SCHEME = "cyberlab.ti.v1"`. `tests/fixtures/seal/ti_prerefactor.json` (written by the M4 code before the refactor) still opens.
- `ai/seal.py`: `AI_SCHEME = "cyberlab.ai.v1"`, `AI_DOMAIN` (anthropic / gemini / mock, never URL-bound), `seal(plaintext, org_id, provider, kid, key_version, public_key) -> SealedKey`; re-exports `SealedKey`, `SealError`, `last4`, `load_public_key`.
- `ai/unseal.py`: `open_sealed(sealed, org_id, provider, private_keys) -> SecretStr`, `load_private_keys`, `UnsealError`.
- Dev pair `infra/ai/dev-seal-private.json` (kid `dev-ai-1`; its public key is `config.DEV_AI_SEAL_PUBLIC_KEYS`). `scripts/gen_ai_seal_keys.py` (`--kid`, default `prod-ai-YYYYMMDD`; `--out`, default `.secrets/ai_seal_private.json`; `--add`).

**3. Settings (`core/config.py`).** `ProcessRole` adds `analyst`; `ANALYST_FORBIDDEN = (*ENRICH_FORBIDDEN, "ti_seal_private_keys_file")`; `AiCeilings{daily_token_budget = 20M, run_token_cap = 200k, incident_token_cap = 2M, per_minute: dict[AiProviderName, int]}` from the `AI_CEILINGS` JSON.
- Fields: `ai_enabled`, `ai_seal_public_keys`, `ai_seal_active_kid`, `ai_seal_private_keys_file` (analyst only), `ai_platform_key_file` (analyst only, refused in prod), `ai_platform_provider` (refused in prod), `ai_platform_daily_tokens` (200 000), `ai_mock_enabled`, `ai_mock_base_url`, `gemini_billing_enabled`, `ai_default_provider` (anthropic), `ai_anthropic_effort` (medium), `ai_anthropic_base_url` / `ai_gemini_base_url` (refused in prod), `ai_max_input_tokens` 60 000, `ai_max_output_tokens` 16 000, `ai_call_timeout_s` 300, `ai_call_idle_timeout_s` 60, `ai_max_calls_per_run` 3, `ai_run_deadline_s` 1200, `ai_incident_deadline_s` 3600, `ai_max_jobs_per_incident` 10, `ai_ceilings`, `ai_runs_per_user_10min` 10, `ai_active_runs_per_org` 12, `ai_active_runs_global` 40.
- Prod: the TI kid checks run for api and enrich only, the AI kid checks for api and analyst only (RT6); the committed dev public keys (TI and AI) are refused in any role; `broker_url` joins the `change-me` placeholder check (RT25).

**4. Contracts (`ai/contracts.py`).**
- Enums: `AiProviderName`; `AiTask` (+ `REQUESTABLE_TASKS`, `TARGETED_TASKS`, `JOB_ONLY_TASKS`, `INVESTIGATION_ONLY_TASKS`); `AiScope`; `AiRunStatus` (+ `RUN_ACTIVE`, `RUN_FINAL`); `AiErrorCode` (not_implemented, deadline, ai_disabled, provider_disabled, provider_unavailable, auth_failed, spend_limit, overloaded, max_tokens, invalid_output, context_too_large, budget_exhausted, provider_error, canary_leak, no_digest, refused); `RefKind` (`.prefix`, `RefKind.from_prefix()`); `Confidence`; `CitationStatus`; `ClaimStatus`; `CitationReason` (unknown_label, digest_not_evidence, field_not_allowed, out_of_scope, row_missing, quote_mismatch, quote_too_short, quote_required, weak_anchor, no_verified_citation, invalid_attack, no_timestamp); `OutputFlag` (canary_leak, verdict_language, command_like, external_url); `ProviderErrorKind` (rate_limited, overloaded, spend_limit, auth_failed, refused, max_tokens, invalid_output, context_too_large, bad_request, timeout, transport, provider_error); `VerifyStatus`. Type aliases `FieldValue = str | int | float | bool | None`, `ContextStage`, `ContextBuildCode`, `Section`.
- Request and context: `AiRunRequest{task, job_id?, investigation_id?, target_id?, provider?, model?, regenerate}` (+ `.scope`; validates the task / target / scope shape and rejects `job_digest`), `RunScope{scope, job_ids, investigation_id, evidence_ids}`, `ContextItem{label, kind, fields: dict[str, FieldValue]}`, `ContextRef{label, kind, ref_table, ref_id, job_id, fields_sha256, stage}`, `KindStats`, `ContextStats{per_kind, omitted, est_tokens, truncated, truncated_fields, dropped_keys, pseudonymized, neutralized, stripped, jobs_omitted}`, `FrozenContext{version = "ctx.v1", task, scope, items, refs, stats, pseudonym_map}` with `canonical_json()`, `.sha256` (over version, task and items only) and `item(label)`, `BuiltRun{root, children}`.
- Provider side: `PromptParts{system, user, delimiter, canary}`, `ProviderRequest{model, system, user, output_schema, max_output_tokens, effort, context}` (`context` is `exclude=True`), `ProviderUsage{input_tokens, output_tokens, cache_read_tokens, cache_write_tokens; .total}`, `ProviderResult{parsed, usage, served_model, stop_reason, refusal_category, request_id}`, `ProviderError(kind, *, http_status, retry_after_s, category, request_sent)` (an Exception whose message is the kind), `VerifyOutcome{status, error_code}`, the `LlmProvider` Protocol (`name`; async `analyze`, `count_tokens`, `verify`, `aclose`).
- Verification: `CitationResult{claim_path, section, claim_id, label, kind, ref_id, job_id, field, quote, status, reason, stale}`, `ClaimVerdict{status, reason}`, `OutputVerification{version = "v1", claims: dict[claim_id, ClaimVerdict] (attack entries keyed `attack:<tid>`, timeline entries `timeline:<i>`), citations: dict[status, int], dropped_refs, invalid_attack, truncation, reused_from_run_id}`, `RunMetrics{version, citations_total / verified / unverified / invalid, citation_accuracy, by_reason, claims_total, claims_unsupported, unsupported_claim_rate, weak_anchor, invalid_ref_rate, invalid_attack, truncation, strip_counts, flags, refusal_category, usage_unknown, cost_estimated, canary_sha256, repaired, replayed}`, `VerifiedOutput{body: AnalysisOutput, citations, verification, flags, metrics; .claims}`, `DigestInput{run_id, job_id, job_label "J{n}", context, body, claims, citations, flags}`.
- Exceptions: `ValidationFailed(errors: list[str])`, `ContextBuildError(code)`. The ai-mock wire protocol is in the module docstring.

**5. Output schema (`ai/output_schema.py`).** `OUTPUT_SCHEMA_VERSION = "ai.v1"`; `Citation{ref, field?, quote?}`, `Claim{id, text, confidence, citations}`, `Hypothesis{id, text, confidence, supporting: list[Citation], contradicting: list[Citation]}`, `OverallConfidence`, `NextStep{text, rationale, refs: list[str]}`, `AttackTechnique{technique_id, rationale, citations}`, `TimelineEntry{text, citations}`, `AnalysisOutput`. Caps `MAX_*` as specified, plus limitations ≤ 10, refs ≤ 8, label ≤ 16, id ≤ 16. Labels and technique ids are not pattern-checked in the schema: they are verifier findings, never a repair.
- `provider_json_schema(provider)`: references inlined; title, default and description dropped; every object `additionalProperties: false`. Anthropic also loses length, number and array bounds, `pattern` and `format`; Gemini loses string lengths, `pattern` and `format` but keeps `minItems` / `maxItems`.
- `coerce_caps(parsed) -> (parsed, {"lists", "strings", "size_trimmed"})`, `body_size(doc)`, `BODY_MAX_BYTES = 64 KiB`.

**6–8. Labels, text, catalog, availability, messages.**
- `ai/labels.py`: `LABEL_PATTERN`, `ParsedLabel{kind, index, job}`, `format_label(kind, index, job=None)`, `parse_label(label) -> ParsedLabel | None`, `qualify(label, job)`, `is_label`.
- `ai/text.py`: `sanitize(text) -> (clean, StripCounts{control, bidi, zero_width, tag; total, add(), as_dict()})`, `nfc`, `collapse_ws`, `defang`, `refang` (the exact inverse; case kept, e.g. `HTTPS://` → `HXXPS[:]//`), `canonical_ip`, `canonical_hash`, `truncate(text, n)` (n characters + `…[truncated k]`).
- `ai/catalog.py`: `AI_CATALOG`, `AI_PROVIDER_NAMES`, `AiCatalogEntry{name, label, models, default_model, tos_note, privacy_note, default_limits, ceilings, dev_only, requires_billing_flag; model_ids, model()}`, `AiModel{id, label, price: ModelPrice{input, output, cache_read, cache_write} (USD per MTok), verified}`, `ProviderLimits{per_minute}`, `PRICE_VERSION = "2026-11-05"`, `find_model(id)`, `cost_micros(model_id, usage) -> int | None`.
- `ai/availability.py`: `provider_available(settings, name) -> (bool, "ai_disabled_platform" | "prod_mock" | "gemini_billing_required" | None)`.
- `ai/messages.py`: `AiRunMessage{run_id, org_id}`, `AiVerifyMessage{org_id, provider: AiProviderName, key_version}`, `AiResumeMessage{}`. `cyberlab_jobs`: `AI_RUN`, `AI_RESUME`, `AI_VERIFY`, `Queues.analyst`.

**9. Stubs** (signatures frozen; the bodies raise `NotImplementedError`):
- `ai/context/builder.py`: `async build_run(session, org_id, user_id, req, settings_row: AiOrgSettings) -> BuiltRun`, `async preview(...) -> FrozenContext`;
- `ai/context/reduce.py`: `build_reduce_context(base, digests: list[DigestInput]) -> FrozenContext`;
- `ai/prompt.py`: `PROMPT_VERSION = "m5.1"`, `render(ctx, task, *, delimiter, canary) -> PromptParts`, `repair_hint(errors: list[str]) -> str`;
- `ai/verify.py`: `async verify_output(session, org_id, run_scope, ctx, refs: Sequence[ContextRef], parsed: dict, canary) -> VerifiedOutput`;
- `ai/providers/registry.py`: `build_provider(name, *, api_key: SecretStr | None, model: str, settings: Settings, org_options: Mapping[str, Any]) -> LlmProvider`;
- `ai/runs.py`: `async create_run(session, org_id, user_id, req, built) -> tuple[AiRun, bool]`, `async dispatch(run_ids: Sequence[uuid.UUID]) -> None`;
- `workers/reaper.py`: `async reap_ai_runs() -> int` (returns 0; already called by the `reap` task).

**10–11. FakeProvider and doubles.**
- `ai/providers/fake.py`: `FakeProvider(model="fake-1")` (`name = "fake"`, `.calls`) and `fake_output(ctx, task=None) -> dict`. Deterministic: observed claims quote at most 120 characters of the item's first string field of ≥ 8 characters and contain the quote; ATT&CK ids come from capability `attack_ids` / `attack` fields; a timeline for summarize_pcap, incident_summary and job_digest; `D` items are never cited.
- `tests/ai_doubles.py`: `make_context(*, task, job_id, items, scope, job_label, pseudonym_map)` (default items J1 F1 F2 A1 C1 I1 E1 N1 R1), `fields_sha256`, `ok_result`, `StaticProvider(script | [script, …], *, name, tokens, verify)` (`.requests`, `.calls`, `.closed`), `PassThroughVerifier()` (callable with the `verify_output` signature, `.calls`), `fake_build_run`, `fake_preview`, `trivial_render`, `passthrough_reduce`.
- `tests/ai_helpers.py`: `AI_SENTINEL_KEY`, `AiSealKeys`, `new_ai_seal_keys(kid)`, `seed_ai_settings(t, *, enabled, **fields)`, `seed_ai_config(t, keys=None, *, provider, key, enabled, version, model, sealed) -> config_id`, `seed_job(t, analyzer, *, status) -> job_id`, `seed_ai_run(t, *, job_id, ctx, task, status, provider, model, parent_run_id, deadline_s) -> run_id`.

**12–16. Routers, IDOR split, worker, compose.**
- `ai/router.py` includes the empty `router_providers`, `router_settings` and `router_runs` (each `APIRouter(prefix="/orgs/{org_id}", tags=["ai"])`), registered in `app/main.py`.
- IDOR split: the shared types moved to `tests/security/idor_types.py` (`Victim` gained `extra: dict[str, str]`; `RouteCases`, `VictimExtender`, `PathOverrides`, `StateHook`). `idor_cases_reads.py` (phase 4) and `idor_cases_ai.py` (phase 7) each export `ROUTE_CASES`, `VICTIM_EXTENDERS`, `PATH_OVERRIDES`, `RESOURCE_PARAMS` and `STATE_HOOKS`. The AI run routes reuse `{run_id}`, which the TI cases fill with the TI run: override it per template through `PATH_OVERRIDES`.
- Celery: `workers/analyst_app.py` (`celery_app`, `queues`; queue `{prefix}analyst`, unacked keys `{prefix}analyst.unacked*`, visibility timeout ≥ 2× the call timeout); `workers/analyst_tasks.py` (`ai.run`, `ai.resume`, `ai.verify`; `worker_init` key check, exit 1); `workers/analyst.py` (`check_startup(settings)` and the no-op `handle_run` / `handle_resume` / `handle_verify`). `celery_app.py` beat `resume-ai-runs` every 30 s to `queues.analyst`.
- Compose: `x-analyst-env`, `x-analyst-worker`, services `analyst-worker`, `analyst-worker-test` and `ai-mock` (test/e2e; `/health` 200, everything else 501), secret `ai_seal_private`. The prod overlay adds `x-prod-ai`, the `analyst-worker` override (prod image, `deploy.replicas: 2`, rendered as such by `docker compose config`) and requires `BROKER_ANALYST_PASSWORD` and `AI_PROD_SEAL_*`. Plus `docker-compose.ai-platform.yml`.
- Lanes: every test-profile broker URL uses `/${TEST_BROKER_DB:-1}`; `TEST_DATABASE_URL`, `TEST_MIGRATION_DATABASE_URL` and `TEST_REDIS_URL` come from `.env` (override them per lane). The api-test env adds `TEST_BROKER_ANALYST_URL` and `TEST_AI_MOCK_EXPECTED_KEY`. Broker ACL user `analyst`: `~analyst* ~test.analyst*` plus its kombu bindings.

**Deviations from the plan text.**
- `coerce_caps` also drops whole entries (timeline → attack_techniques → hypotheses → interpretation → limitations → next_steps → observed) until the body is ≤ 60 KiB. The per-item caps alone allow about 0.5 MB, so "worst case ≤ 64 KiB" holds after `coerce_caps` (tested), not for the raw caps.
- `app/workers/analyst.py` exists from phase 1 (no-op + `check_startup`), because the tenant-session allowlist test requires every allowlisted file to contain a call. Phase 2 owns it and deletes `tests/integration/test_analyst_noop.py`.
- The analyst can resolve `enrich-worker` (they share `enrich` and `egress`). The network test asserts that it is not on `analysis` and cannot resolve `api`, `redis` or `minio`, not that `enrich-worker` is unresolvable.
- The dev compose file has defaults for `AI_SEAL_ACTIVE_KID` / `AI_SEAL_PUBLIC_KEYS` (the dev pair) and `BROKER_ANALYST_PASSWORD`, so an older `.env` still starts (RT25).
- `AI_PLATFORM_PROVIDER` is refused in prod too; `broker_url` joined the prod `change-me` check.
- Prod env fixtures for every role: `tests/fixtures/compose/{api,ingest-worker,enrich-worker,analyst-worker}.prod.env.json` (secrets masked). There is no drift checker yet for the three new ones (phase 11 owns `scripts/check-analyst-env.mjs`).
- `infra/` is not mounted in `api-test`, so the dev AI pair's consistency is proven by the dev analyst-worker's startup check, not by a unit test.

**Verification (2026-11-05).** Full API gate in `api-test` (ruff, format, mypy strict, pytest): 2566 passed, 38 skipped. `analyst-worker-test` network suite: 19 passed. `node scripts/check-enrich-env.mjs` unchanged and green; `node scripts/gen-contracts.mjs` produced no diff (the AI routers are still empty). Dev stack `docker compose up -d --wait` healthy with `analyst-worker` (startup key check passed on the dev pair) and `ai-mock` (healthy). `pnpm e2e`: 6 passed, 1 skipped, 1 failed: `threat-intel.spec.ts` could not upload `.e2e-data/static/packed_like.bin` because host Windows Defender quarantines that generated sample (`Get-MpThreatDetection`), not because of this phase.
