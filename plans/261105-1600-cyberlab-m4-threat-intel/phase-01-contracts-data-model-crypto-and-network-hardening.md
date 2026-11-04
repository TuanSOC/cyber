---
phase: 1
title: "Contracts data model crypto and network hardening"
status: pending
priority: P1
effort: "14h"
dependencies: []
---

# Phase 1: Contracts data model crypto and network hardening

## Overview
Lay the frozen foundations: the TI tables, the sealed-key crypto, the new permission, wider
audit redaction, the provider interface, every per-provider summary model and the provider
catalog, the `enrich` queue and ACL user, the least-privilege enrich-worker, and the network
change (`backend` internal, new `egress` network). After this phase the stack runs as before
with no egress from `backend`; no TI feature is user-visible yet.

## Requirements
- **Dependencies:** `cryptography` added to the api runtime dependencies; `httpx` moved from dev to runtime.
- **Migration 0009** (owner role; FORCE RLS on every tenant table; grants as in the plan):
  - `ti_provider_configs`, `ti_org_settings`, `ti_enrichment_runs`, `ti_run_items`, `ti_run_index`, `ti_results`.
  - Constraints:
    - provider check (`virustotal`, `abuseipdb`, `urlhaus`, `malwarebazaar`, `otx`, `misp`, `mock`);
    - `base_url` NOT NULL iff misp;
    - the sealed columns are all NULL or all set;
    - `key_last4` is 4 characters;
    - `enabled = true` requires `terms_ack_at` set (RT16);
    - `scope` in (`manual`, `job`); `job_id` NOT NULL iff `scope = 'job'`;
    - `summary` ≤ 16 KiB (`octet_length`);
    - `ti_results.status` in (`ok`, `not_found`, `error`, `auth_failed`);
    - `ti_run_items.state` in (`pending`, `done`, `cached`, `abandoned`), `reason` NOT NULL iff `abandoned`.
  - `ti_provider_configs` trigger (RT18): when any sealed column changes, the new `key_version` must be higher, or equal with a different `key_kid` (re-seal); `key_version` never decreases.
  - Run status-transition trigger: queued → running ⇄ waiting → completed / partial / failed, plus queued / waiting → partial / failed (deadline and fallback reaper); final states are immutable.
  - `ti_results`: `forbid_mutation` trigger, unique (run_id, provider, ioc_key), lookup index (organization_id, ioc_key, provider, fetched_at DESC).
  - `ti_run_items`: PK (run_id, provider, ioc_key); index (run_id, state, seq); the app role may UPDATE only `state`, `result_id`, `reason`.
  - `ti_run_index` (RT25: the real `analysis_job_index` pattern from 0002/0003):
    - RLS `app_org_id() IS NULL OR organization_id = app_org_id()`; written by the API in the run-creating transaction; read by the trusted workers in a `tenant_session(None, None)` system session;
    - column-level UPDATE only on `status`, `resume_at`, `deadline_at`, `dispatched_at`, `lease_until`, `lease_owner`;
    - index on (status, resume_at).
  - Column grants: the app role cannot UPDATE `organization_id`, `provider` or `created_at` anywhere.
- **RBAC:** `Permission.INTEGRATIONS_MANAGE = "integrations.manage"` in `_ADMIN` only. `test_rbac.py` matrix updated.
- **Audit:** `_SENSITIVE_KEY` widened to `password|token|secret|api[_-]?key|authorization|auth[_-]?key|x-apikey|(^|_)key$`, with an explicit allowlist (`key_last4`, `key_kid`, `key_version`, `ioc_key`). Nested dicts and lists of dicts are sanitized too. Existing audit and auth-event details are re-checked (none currently uses a `_key` field).
- **Crypto, split by capability (RT21):**
  - `app/modules/threat_intel/seal.py`: `seal(plaintext, org_id, provider, kid, key_version, base_url_norm, public_key) -> SealedKey`; imported by the API;
  - `app/modules/threat_intel/unseal.py`: `open_sealed(sealed, org_id, provider, base_url_norm, private_keys)`; only the enrich worker may import it;
  - X25519 + HKDF-SHA256 + AES-256-GCM with a 96-bit random nonce;
  - AAD as in the plan, including `base_url_norm` for MISP (RT1);
  - `last4` is computed before sealing; plaintext only in `SecretStr` / local variables; `SealedKey` and errors never carry plaintext.
- **Settings** (`core/config.py`):
  - `PROCESS_ROLE` (`api` default, `ingest`, `enrich`). For `enrich`, `jwt_secret`, the MinIO fields and `redis_url` must be **absent** and become optional at type level; for every other role they stay required, as today (RT2);
  - `TI_ENABLED` (default true);
  - `TI_SEAL_PUBLIC_KEYS` (JSON kid → base64 key);
  - `TI_SEAL_ACTIVE_KID`;
  - `TI_SEAL_PRIVATE_KEYS_FILE` (accepted only when `PROCESS_ROLE=enrich`, in every env);
  - `TI_MOCK_ENABLED`, `TI_MOCK_BASE_URL`, `TI_MISP_ALLOW_PRIVATE`, `TI_MISP_INSECURE_TLS`, `TI_MISP_ALLOWED_PORTS`, `TI_MISP_CA_FILE`, `TI_MAX_IOCS_PER_RUN` (200), `TI_RUN_DEADLINE_S` (1800), `TI_SLICE_S` (20);
  - the per-provider ceilings.

  `_prod_guards` refuses:
  - `TI_MOCK_ENABLED`, `TI_MISP_ALLOW_PRIVATE` or `TI_MISP_INSECURE_TLS` set to true;
  - a missing public key for the active kid while `TI_ENABLED`;
  - an active kid starting with `dev-` (RT12).
- **Seal keys (RT12):**
  - a committed dev-only pair: `infra/ti/dev-seal-private.json` (kid `dev-1`) and its public key in `.env.example`, so `pnpm dev` and CI work on a fresh clone;
  - `scripts/gen_ti_seal_keys.py` writes `.secrets/ti_seal_private.json` (mode 0400; prints the `chown 10001:10001` needed for the prod image user) and prints the `.env` lines;
  - `.secrets/` added to `.gitignore` and the root `.dockerignore`;
  - the enrich worker refuses to start (exit 1, clear message) if the key file is unreadable or lacks the active kid.
- **Interface, frozen at the end of the phase** (only the parent changes it afterwards):
  - `threat_intel/providers/base.py`: `ProviderResult` (the normalized verdict-free model from the provider report plus `status`, `score_scale`), `Provider` protocol (`name`, `supported_types`, `allowed_paths`, `async lookup(client, ioc) -> ProviderResult`, `async verify(client) -> VerifyOutcome`), `IocType` enum, `ProviderError` kinds;
  - `threat_intel/summaries.py` (RT14): every strict per-provider summary model, with the field lists from phase 3 and phase 4 (VT, AbuseIPDB, URLhaus, MalwareBazaar, OTX, MISP, mock), capped strings and lists, control and bidi characters stripped (RT19), ≤ 16 KiB serialized. Adapters only fill them; phase 5 builds the OpenAPI union from them;
  - `threat_intel/catalog.py` (RT14): per provider `label`, `supported_types`, `tos_note`, `privacy_note`, `default_limits`, `ceilings`, `dev_only`. No adapter imports; adapters and the API both read it.
- **Routers:** empty `threat_intel` and `attack` routers registered in `app/main.py` now, so phases 4 and 5 never edit `main.py` (RT14).
- **`cyberlab_jobs`:** `Queues.enrich`; task names `ti.enrich`, `ti.resume`, `ti.verify`. They live in the shared package only so that the analyzer ACL tests can name the queue; analyzers never use them.
- **Network** (`docker-compose.yml`, `.prod.yml`):
  - `backend: internal: true`; new `egress` network (bridge, not internal);
  - `x-enrich-env` anchor (RT2): `ENV`, `PROCESS_ROLE: enrich`, `DATABASE_URL`, `BROKER_URL: redis://enrich:…@redis-broker:6379/0`, `QUEUE_PREFIX`, `TI_*`. Never merged with `*api-env`;
  - `enrich-worker` service (api image, `backend` + `egress`, `celery -A app.workers.enrich_app worker -Q enrich --pool solo --without-gossip --without-mingle --without-heartbeat --loglevel INFO`, read_only, cap_drop ALL, no-new-privileges, tmpfs `/tmp`, `restart: unless-stopped`, private key as a compose `secrets:` file pointing at `infra/ti/dev-seal-private.json`) (RT7);
  - **prod override (RT3):** `enrich-worker` in `docker-compose.prod.yml` with `image: cyberlab/api:prod`, `ENV: prod`, `volumes: !reset []`, and the secret file overridden to `.secrets/ti_seal_private.json`;
  - `enrich-worker-test` (test profile, `test.` prefix, broker db 1, test DB, `ENV=test`, `TI_MOCK_ENABLED=true`); `api-test` depends on it;
  - `ti-mock` (test + e2e profiles, `egress` only, stdlib `python:3.12-alpine`, server in `infra/ti-mock/server.py`; it reads its own `TI_MOCK_EXPECTED_KEY`);
  - dev `api` and `enrich-worker` get `TI_MOCK_ENABLED=${TI_MOCK_ENABLED:-true}` and `TI_MOCK_BASE_URL=http://ti-mock:8080` (the dev e2e uses them); the prod override sets `TI_MOCK_ENABLED: "false"` for both.

  In phase 1 the worker starts and consumes nothing but a no-op `ti.enrich` that fails the run with `not_implemented`.
- **Celery enrich app** (`app/workers/enrich_app.py`): `worker_enable_remote_control=False`, `worker_send_task_events=False`, `task_ignore_result=True`, `task_acks_late=True`, `worker_prefetch_multiplier=1`, unacked keys `{prefix}enrich.unacked*`, the same socket timeouts as `celery_app` (RT7).
- **Egress check (documented):** go through every service on `backend` and confirm that it needs no runtime internet. Fix what breaks:
  - drop the dev MinIO console port (unpublishable on internal networks), and document `docker compose exec minio …` / `mc` instead;
  - set `UV_NO_SYNC=1` and `UV_OFFLINE=1` for `migrate`, `api`, `api-test`, `ingest-*` and `enrich-*`;
  - confirm that `pnpm dev`, `pnpm test:api`, `pnpm test:workers`, `pnpm e2e` and `pnpm verify:prod` still pass.

  Record the per-service table in DEPLOYMENT.md (phase 7 finalizes the text).
- **Broker ACL** (`infra/redis-broker/entrypoint.sh`): `user enrich on >${BROKER_ENRICH_PASSWORD} resetkeys ~enrich* ~test.enrich*`, plus `~_kombu.binding.{q} ~_kombu.binding_permanent.{q}` for q in `enrich` and `test.enrich`, then `resetchannels +@all ${DENY} ${READ_DENY}`.
  - Read/write `enrich*` covers its queue, its unacked keys, its slice re-publish and its limiter keys (`{prefix}enrich.ti:*`); `EVAL` with declared keys works under the ACL.
  - It has no access to `ingest*` or `trusted.*`.
  - The pcap and static patterns cannot match `enrich*` (asserted).
- **Guard tests:**
  - `test_tenant_session_guard.py` allowlists `app/workers/enrich.py` and the TI reaper fallback;
  - a new AST test forbids importing the adapter modules and the registry under `app.modules.threat_intel.providers` (everything except `providers.base`, which the API and `normalize.py` share), `…threat_intel.http` and `…threat_intel.unseal` outside `app/workers/enrich*.py` and tests (any import form);
  - the RLS-coverage and IDOR route enumerators pick up the new tables automatically (they fail until phase 5 adds routes, so register the tables now).

## Implementation Steps
1. Dependencies, settings (`PROCESS_ROLE` rules), prod guards, the dev key pair and the keygen script, with unit tests for the guards (enrich role rejects `JWT_SECRET` / MinIO / `REDIS_URL`; api role rejects the private-key file; prod rejects `dev-` kids).
2. `seal.py` / `unseal.py` with unit tests:
   - a round trip;
   - a wrong org, provider, kid, key_version or MISP `base_url` fails;
   - a flipped byte in ct, nonce or epk fails;
   - an unknown kid fails;
   - plaintext is absent from `repr` and from exceptions.
3. Migration 0009 and the models. Tests: a fresh `upgrade head`, downgrade, RLS per table, append-only `ti_results`, the transition trigger, the `key_version` trigger, the column grants on `ti_run_items` and `ti_run_index`.
4. Permission, audit-sanitize widening and allowlist (unit tests over nested and list details), and the RBAC matrix.
5. `base.py`, `summaries.py`, `catalog.py`, the empty routers and `Queues.enrich`; freeze them.
6. Compose: networks, `x-enrich-env`, `enrich-worker` (dev + prod override), test services, `ti-mock` skeleton, broker ACL user and password in `.env.example`. Add a broker ACL test, `test_enrich_acl.py`:
   - `enrich` cannot read or write `ingest*`, `pcap*`, `static*` or `trusted.*`;
   - `enrich` can `EVAL` a script on `test.enrich.ti:*` keys;
   - `pcap` and `static` cannot touch `enrich*`;
   - `api` can publish to `enrich`.
7. Egress check: route-table assertions (no default route in `/proc/net/route`) for api-test; a fix list; the full test suites and e2e re-run; `docker compose -f … -f docker-compose.prod.yml config` shows `enrich-worker` with `ENV=prod` and no `JWT_SECRET`, `MINIO_*` or `REDIS_URL`.

## Success Criteria
- [ ] `pnpm verify` green with `backend` internal on a fresh clone (dev key pair); the api-test container has no default route. — **pending gate** (`pnpm verify:prod`, which includes `pnpm verify`); the no-route half already passes: `container/test_egress.py::test_no_default_route` (1f94ac2).
- [x] Sealed ciphertext cannot be opened under another org's, provider's, version's or MISP URL's AAD; the api process cannot load a private key (settings test). — `test_ti_seal.py::test_wrong_org_or_provider_fails`, `test_wrong_key_version_fails`, `test_misp_round_trip_is_bound_to_its_url`; `test_config.py::test_only_the_enrich_role_may_load_a_private_key`, `test_private_key_file_refused_even_in_prod_for_the_api` (1f94ac2).
- [x] The enrich-worker env holds no JWT secret, MinIO credentials or app Redis URL, in dev and prod configs. — `test_config.py::test_enrich_role_refuses_api_secrets`, `test_the_prod_enrich_worker_env_is_accepted` (rendered prod env fixture), `test_enrich_network.py::test_its_environment_holds_no_api_secrets`, `scripts/check-enrich-env.mjs` (5376596).
- [x] Broker ACL tests confine `enrich`; the analyzer users cannot reach `enrich*`. — `test_enrich_acl.py::test_enrich_user_is_confined`, `test_analyzers_cannot_touch_enrich` (1f94ac2).
- [x] `ProviderResult`, `Provider`, `summaries.py`, `catalog.py`, migration 0009 and the seal format are frozen and documented in the phase notes. — "Phase notes" below and `unit/test_ti_contracts.py` (1f94ac2); later schema changes went into 0010, never 0009.

## Phase notes (frozen at the end of phase 1)

- **Provider interface** `app/modules/threat_intel/providers/base.py`: `ProviderName`, `IocType` (`ipv4 ipv6 domain url md5 sha1 sha256 email`), `ResultStatus`, `VerifyStatus`, `ProviderErrorKind`, `ProviderError(kind, http_status, retry_after_s)` (no body ever), `IocRef(ioc_type, value_norm, ioc_key)`, `compute_ioc_key` = sha256(`type` NUL `value_norm`), `AllowedPath(method, host|None=MISP host, path regex)`, `VerifyOutcome(status, error_code)`, `Detections`, `ProviderResult` (provider, status, found, score/score_scale, detections, tags ≤ 32, families ≤ 16, attack_ids ≤ 32 T-ids, first/last_seen, summary, https-only permalink, error_code) and the `Provider` protocol (`name`, `supported_types`, `allowed_paths`, `lookup`, `verify`).
- **Summaries** `threat_intel/summaries.py`: one strict model per provider, discriminated by `provider`; strings cleaned (control/format/bidi dropped) and truncated to a JSON byte budget; lists capped; `summary_size()` ≤ 16 KiB proven for every model's worst case (`tests/unit/test_ti_contracts.py`). Additions beyond the phase-3/4 field lists: URLhaus `lookup` (which endpoint answered), MISP `attribute_count` and summary-level `tlp`, the `mock` model.
- **Catalog** `threat_intel/catalog.py`: label, supported types, ToS/privacy notes, `default_limits` = `ceilings` (free tiers), `dev_only` (mock), `needs_base_url` (MISP). Operators raise a ceiling with `TI_CEILINGS`; `Settings.ti_ceiling()` resolves it.
- **Seal format** `seal.py` / `unseal.py`: as in the plan (X25519 → HKDF-SHA256(salt = epk ‖ recipient pk, info `cyberlab.ti.v1`) → AES-256-GCM, 96-bit nonce; AAD `cyberlab.ti.v1|org|provider|kid|key_version|base_url_norm`). Keys are 8–256 printable ASCII characters (a 4-character `last4` needs a minimum length). `SealedKey` repr hides `last4`.
- **Migration 0009** as specified, plus: `ti_results.latency_ms` (for the run p50/p95 and the metric), `ti_results.error_code`, composite FKs so items and results only point at runs/results of their own org, `enabled` also requires a sealed key, `found` only on `ok`, `expires_at` NULL iff `error`/`auth_failed`. Residual: the app role may DELETE a `ti_provider_configs` row, which resets the `key_version` floor for that provider.
- **Broker message** `threat_intel/messages.py: TiRunMessage{run_id, org_id}` (task kwarg `message`); task names `ti.enrich` / `ti.resume` / `ti.verify`, queue `Queues.enrich`.
- **Prod seal keys**: the prod override reads `TI_PROD_SEAL_ACTIVE_KID` / `TI_PROD_SEAL_PUBLIC_KEYS` (fails fast when unset) so one `.env` can serve the dev stack (committed `dev-1`) and the prod-like stack.

## Implementation Notes (2026-11-05)
- **Commits:** 1f94ac2 (phase 1). The phase-1 review fixes landed with phase 2 in 5376596, and 0009 stayed frozen, so every later schema change is in migration **0010**.
- **Migration 0009** (`alembic/versions/0009_threat_intel.py`): the six tables as specified, with FORCE RLS, the run-transition and monotonic `key_version` triggers, and `forbid_mutation` on `ti_results`. The additions are listed in the phase notes above (`latency_ms`, `error_code`, composite FKs).
  - `integration/test_ti_schema.py` covers tenant isolation, cross-org writes, append-only results (also for the owner), legal and illegal transitions, immutable final states, the key-version trigger (`test_a_new_key_needs_a_higher_version`, `test_reseal_under_another_kid_keeps_the_version`), the column grants and the constraints.
- **Migration 0010** (`0010_ti_hardening.py`, review L7/L8):
  - `REVOKE DELETE ON ti_provider_configs` from the app role. A deleted row used to reset the `key_version` floor, which was the residual noted in the phase notes; removing a key is now an UPDATE that clears the sealed columns.
  - `ti_run_index.run_id` now references `(id, organization_id)`.
  - Tests: `test_app_role_cannot_delete_provider_configs`, `test_run_index_cannot_name_another_org`, `test_removing_a_key_keeps_the_version_floor`.
- **Seal / unseal** (`seal.py`, `unseal.py`): `unit/test_ti_seal.py` covers:
  - the round trip and the MISP URL binding;
  - a wrong org, provider, kid, version or private key; a flipped byte in ct, nonce or epk; truncated parts;
  - no plaintext in reprs or errors; loading the private key file; `check_startup`.
  - **Deviation:** keys must be 8–256 printable ASCII characters (the plan said 1–256), because `last4` needs a minimum length. Surrounding whitespace and non-printable characters are refused at seal time (7abb484).
- **Settings** (`core/config.py`):
  - `PROCESS_ROLE` is `api`, `ingest` or `enrich`. `ENRICH_FORBIDDEN` (`jwt_secret`, `minio_*`, `redis_url`) is refused for `enrich`, and `TI_SEAL_PRIVATE_KEYS_FILE` is refused for every other role in every env. Kids must match `[A-Za-z0-9._-]{1,64}`.
  - `_prod_guards` refuses the mock, allow-private and insecure-TLS flags, a missing public key for the active kid, `dev-` kids in any letter case, and the committed dev public key under any kid (review L6, `DEV_SEAL_PUBLIC_KEYS`).
  - Tests in `unit/test_config.py`: `test_enrich_role_refuses_api_secrets`, `test_only_the_enrich_role_may_load_a_private_key`, `test_prod_refuses_dev_kids_in_any_case`, `test_prod_refuses_the_committed_dev_public_key_under_any_kid`.
- **Review H1 (prod crash):** the prod enrich-worker crash-looped because `_prod_guards` required `COOKIE_SECURE`, which only the API receives.
  - The check now applies only when `process_role == "api"`.
  - `test_the_prod_enrich_worker_env_is_accepted` replays the rendered prod env (`tests/fixtures/compose/enrich-worker.prod.env.json`).
  - The gate requires the prod enrich-worker to be `running 0` (no restart) after 15 s (`verify.mjs` `workerProblems`).
- **Review M2 (network, deviation):** the worker no longer joins `backend`, from which it could reach the app Redis, MinIO and the API.
  - A new internal `enrich` network holds only Postgres and redis-broker. The worker sits on `enrich` + `egress`.
  - `container/test_enrich_network.py` runs inside `enrich-worker-test` from the gate.
- **Audit redaction** (`audit/service.py`, review):
  - Keys are normalized before matching: camelCase becomes snake_case, `-`, space and `.` become `_`, and everything is lowercased. So `privateKey`, `X-Mock-Key` and `X-OTX-API-KEY` are caught.
  - The pattern also covers `passphrase`, `credentials` and `cookie`. The allowlist is `key_last4`, `key_kid`, `key_version`, `ioc_key`.
  - Nested dicts and lists of dicts are sanitized too (`unit/test_audit_sanitize.py`).
- **Import guard** (`unit/test_ti_import_guard.py`, RT21, review L5):
  - `unseal` may only be imported from `app/workers/enrich*.py`, not even from the adapters or the registry.
  - `http`, the registry and the adapters may also be imported from the adapter modules. `providers/base.py` and `providers/__init__.py` get no exemption.
  - Every import form counts, including `importlib.import_module` and `__import__` with a constant name.
- **Compose / egress:**
  - `backend` is `internal: true`, plus a new `egress` bridge. The `x-enrich-env` anchor is never merged with `*api-env`.
  - `UV_NO_SYNC=1` / `UV_OFFLINE=1` are set; the dev MinIO console port is dropped.
  - The enrich-worker runs `--pool solo --without-gossip --without-mingle --without-heartbeat` with `read_only`, `cap_drop: [ALL]`, `/tmp` tmpfs (16m) and the compose secret `ti_seal_private`.
  - Evidence: `container/test_egress.py::test_no_default_route` and `test_no_internet_connection`; the per-service check table is in DEPLOYMENT.md.
- **Broker ACL** (`infra/redis-broker/entrypoint.sh`): user `enrich` gets `resetkeys ~enrich* ~test.enrich*` plus its own kombu bindings. `integration/test_enrich_acl.py`:
  - `test_enrich_user_is_confined`;
  - `test_enrich_user_has_what_it_needs` (`EVAL` on `test.enrich.ti:*`);
  - `test_analyzers_cannot_touch_enrich`;
  - `test_api_user_can_publish_to_enrich`.
- **RBAC:** `integrations.manage` is in `_ADMIN` (owner/admin). The matrix is in `test_rbac.py`; phase 5 adds `test_ti_api_rbac.py::test_ti_role_matrix`.
- **Keygen** `scripts/gen_ti_seal_keys.py`: writes mode 0400, chowns to 10001 when it can (otherwise prints the `chown`), and takes `--add --kid` for rotation (used by the THREAT_INTEL.md runbook). `ti.enrich` was a `not_implemented` no-op until phase 2, as planned.
- **Accepted residuals:** the enrich-worker uses the full app DB role (RT17) and has unrestricted egress (THREAT_MODEL.md, M4).
- **Tests:** the full API suite gives 2221 passed / 19 skipped at d3a93e1.
