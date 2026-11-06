---
phase: 1
title: "Foundation contracts migration 0014 and ops services"
status: completed
priority: P1
effort: "22h"
dependencies: []
---

# Phase 1: Foundation contracts migration 0014 and ops services (group A)

## Overview
One agent lays the frozen foundations for eight parallel lanes:
- migration 0014 and the models;
- the role bootstrap (`cyberlab_retention`) for fresh and existing volumes;
- every new route as a **501 stub** with its frozen request and response schemas, then one `pnpm gen:contracts` run;
- the new services and their least-privilege wiring: `db-bootstrap`, `retention-worker(-test)`, the broker user `retention`, the MinIO purge user and policy (with the S3 legal-hold actions; the api policy is unchanged, RT5), SSE-S3 on every bucket, the metrics token secret, and the `MINIO_IMAGE` / `MC_IMAGE` / `MINIO_DATA_DIR` variables;
- the beat entries and task registrations, with stubs behind them;
- two small implemented pieces shared by other phases: `ops/error_classes.py` and `core/audit_dedupe.py`;
- test helpers, the IDOR module split, the web shared files and slot mounts (RT16), the `lane-test.sh` lane rewrite (RT15) and the root script stubs.

After this phase the stack runs as before:
- the new routes answer `501 not_implemented`;
- `correlation.index_pending` returns 0;
- `retention.sweep` finds no policy and does nothing;
- `/internal/metrics` is off without a token;
- SSE-S3 applies to new objects.

**Everything listed under "Frozen interfaces" in plan.md is frozen at the end of this phase.**

## Requirements
- **Pre-flight:**
  - Confirm that M6 is merged and its `pnpm verify:prod` is green.
  - Confirm the alembic head is `0013`; otherwise number the migration head + 1 and tell the parent.
  - Create `feat/m7-platform-ops` from the M6 merge.
  - Re-read the M6 versions of `workers/{celery_app,tasks}.py`, `evidence/{models,schemas}.py`, `reports/models.py` (the render status check and transition trigger), `infra/minio/init.sh` and the compose files.
- **Role bootstrap:**
  - `infra/postgres/init/02-m7-roles.sh` (fresh volumes).
  - `infra/postgres/bootstrap.sh`, run by a one-shot `db-bootstrap` service (`postgres:17.11-alpine`, superuser `POSTGRES_PASSWORD`, `backend` network, `depends_on: postgres healthy`, and `migrate` depends on it). It is idempotent and creates or alters `cyberlab_retention` with `LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE`, the password from `POSTGRES_RETENTION_PASSWORD` (psql variable quoting as in `01-init.sh`), `statement_timeout 30s`, `idle_in_transaction_session_timeout 60s`, and `CONNECT` on `cyberlab` and `cyberlab_test` plus every `cyberlab_b*_test` that exists.
  - Prod requires the password (no default).
- **Migration `0014_m7_platform_ops.py`** (the 0011 / 0012 conventions; the table list and grants are in plan.md "Data model"):
  - **Guard:** fail with "run db-bootstrap" when `cyberlab_retention` does not exist.
  - **Tables:** `org_retention_policies` (with `pending_enforce` / `enforce_effective_at`, RT1), `retention_policy_index` (system lookup, RT3), `legal_holds`, `retention_runs`, `retention_run_items`, `evidence_purges`, `correlation_keys`, `correlation_job_state`, `job_outcomes`.
    - FORCE RLS and the `tenant_isolation` policy on every tenant table; `job_outcomes` is system; `retention_policy_index` gets the `analysis_job_index` policy (`app_org_id() IS NULL OR organization_id = app_org_id()`).
    - Composite same-org FKs, as in 0013.
    - Named checks: the floors as constants (30; the `EVIDENCE_LOCK_DAYS` floor is enforced by the API because it is configuration), `octet_length` caps, and the enum checks.
  - **Triggers:**
    - `legal_holds` releases once;
    - `retention_run_items` and `evidence_purges` are append-only with plain `forbid_mutation()`;
    - `org_retention_policies` writes `updated_at`.
  - **`forbid_mutation_except_retention()`** (`IF TG_OP = 'DELETE' AND current_user = 'cyberlab_retention' THEN RETURN OLD`, else raise). It replaces the trigger on `ti_results`, `ai_run_inputs`, `ai_context_refs`, `ai_outputs` and `ai_citations`. The downgrade restores the strict trigger.
  - **`evidence`:** add `declared_type` (text ≤ 32) and `type_mismatch` (bool), both NULL. Extend `evidence_immutable()` so both columns are write-once: NULL may become a value only in the inserting transaction, so in practice they are set at INSERT and never updated.
  - **Enum and check extensions:** `ALTER TYPE custody_action ADD VALUE IF NOT EXISTS 'purged'` and `'sent_to_sandbox'` (the custody column is `action`, an enum, RT12; the values are usable only after the migration commits, and the downgrade leaves them, documented). `report_renders` gains status `purged`, the transition trigger allows `succeeded → purged` only for `current_user = 'cyberlab_retention'`, and `ux_report_renders_version_id_format_renderer` is recreated with `WHERE status NOT IN ('failed', 'purged')` (RT11).
  - **System user (RT12):** insert `retention@system.invalid` with the fixed id `RETENTION_SYSTEM_USER_ID`, `is_active = false` and an unusable password hash (not a valid argon2 string); it is the custody actor of purges. A test proves login and `current_user` refuse it.
  - **`job_outcomes` triggers:** `AFTER UPDATE OF status` on `analysis_jobs`, `ti_enrichment_runs`, `ai_runs` and `report_renders`, `WHEN` the new status is terminal and the old one was not. Each calls a `SECURITY DEFINER` function owned by `cyberlab_owner`, with `SET search_path = pg_catalog, public`.
    - The function inserts `kind`, `subkind`, `status`, `error_code`, `queue_ms = started - created`, `run_ms = finished - started` and `finished_at`. Phase 1 reads the exact column names of each table.
    - It never copies an org id, user, value or text.
    - `REVOKE ALL ON FUNCTION … FROM PUBLIC`.
  - **Search:** `CREATE EXTENSION IF NOT EXISTS pg_trgm`, then the indexes in plan.md (FTS `simple` expression GIN with `coalesce` on nullable columns, trigram GIN), as plain `CREATE INDEX` inside the migration transaction (RT20: `migrate` runs before any writer; `CONCURRENTLY` would break atomicity). Record the exact expressions in the phase notes for phase 4.
  - **Grants:**
    - app: S/I (+ the per-column UPDATEs) on the tenant tables, SELECT on `job_outcomes`;
    - `cyberlab_retention`: SELECT on what the selector reads (including `retention_policy_index`, `report_citations`, `ti_run_items`); DELETE on the purgeable tables (plan.md list: the bulk derived tables, `ti_results` + `ti_run_items` (RT10), `ai_runs` + the four children + `ai_run_index`, `job_outcomes`; **not** `correlation_*`, RT9); INSERT on `retention_run_items`, `evidence_purges`, `evidence_custody_events` and `audit_logs`; UPDATE (`status`, `counts`, `finished_at`, `error`) on `retention_runs`; UPDATE (`status`) on `report_renders`; UPDATE (`s3_synced_at`) on `legal_holds`.
    - app: S/I/U on `retention_policy_index` (the policy PUT writes it in the same transaction).
  - **Upgrade and downgrade** pass `test_migrations.py`.
- **Models:** `retention/models.py`, `correlation/models.py`, `ops/models.py`, the evidence columns and custody event, and the `reports` render status. Register them in `app/models.py`.
- **Settings** (`core/config.py`, plan.md "Settings"), with the process-role refusals:
  - `retention` refuses `JWT_SECRET`, the app Redis URL, the api MinIO keys, every seal or signing private key file and the AI platform key;
  - every other role refuses the purge MinIO credentials and the retention DB URL.

  `tests/unit/test_config.py` gains the matrix.
- **Compose (dev, test, prod overlay):**
  - **`db-bootstrap`** as above.
  - **`retention-worker`:**
    - api image, `celery -A app.workers.retention_app worker -Q retention --pool solo --without-gossip --without-mingle --without-heartbeat`;
    - uid 10001, read-only rootfs, tmpfs `/tmp` 16m, `cap_drop: ALL`, no-new-privileges, 384m;
    - `backend` network only;
    - env `x-retention-env`: `PROCESS_ROLE=retention`, `DATABASE_URL` of the retention role, broker user `retention`, the purge MinIO keys and the `RETENTION_*` settings.
  - **`retention-worker-test`** (test profile; `QUEUE_PREFIX=test.`, the test DB and buckets).
  - **`api-test` env:** `RETENTION_TEST_DATABASE_URL`, `TEST_MINIO_PURGE_ACCESS_KEY` / `_SECRET_KEY`, `TEST_BROKER_RETENTION_URL`, `RATE_LIMIT_USER_PER_MIN=100000`; also on `e2e`. No anonymous limit setting (RT14).
  - **`scripts/lane-test.sh` (RT15, RT25):** also rewrite `RETENTION_TEST_DATABASE_URL` to `cyberlab_b<N>_test`, and resolve the slot lock root through `LANE_LOCK_ROOT` (default unchanged) so `restore-drill.mjs` takes exactly the same slots.
  - **The `metrics_token` secret** on api (`METRICS_TOKEN_FILE`); `.secrets/metrics_token` is generated by the dev bootstrap note in `.env.example`.
  - **The `minio_kms_key` secret** on minio (`MINIO_KMS_SECRET_KEY_FILE`, `<name>:<base64 32 bytes>`). Verify that the bitnami image honours `MINIO_KMS_SECRET_KEY_FILE`; if it does not, an entrypoint wrapper exports `MINIO_KMS_SECRET_KEY` from the file. A committed dev key name `cyberlab-dev-kms` is refused in prod by the env check.
  - **KMS on an existing volume (RT7):** the key also encrypts MinIO's IAM and config. Before switching the shared dev stack, copy the `miniodata` volume into a throwaway project, enable the key there, restart twice, and check that the users, policies and an old object still work. Record the result in the notes.
  - **`image: ${MINIO_IMAGE:-bitnamilegacy/minio:2025.5.24}`**, `${MC_IMAGE:-…}` and the volume path `${MINIO_DATA_DIR:-/bitnami/minio/data}`.
  - **Prod overlay:** requires `POSTGRES_RETENTION_PASSWORD`, `BROKER_RETENTION_PASSWORD`, `MINIO_PURGE_SECRET_KEY` and the KMS secret.
- **Broker:** user `retention` (`~retention* ~test.retention*`, the same command set as `enrich`). The `ingest` user may publish to `retention` (beat) and so may `api` (manual runs). Add `tests/integration/test_retention_acl.py`, cloned from `test_report_acl.py`.
- **MinIO (`init.sh`):**
  - `mc encrypt set sse-s3` on every bucket (idempotent).
  - `purge-policy.template.json`:
    - `s3:DeleteObjectVersion`, `s3:GetObjectRetention`, `s3:GetObjectLegalHold`, `s3:PutObjectLegalHold` (the hold sync, RT5), `s3:ListBucketVersions` and `s3:GetObjectVersion` on `evidence`, `results` and `reports` (+ test twins);
    - an explicit `Deny` `s3:DeleteObjectVersion` / `s3:DeleteObject` on `arn:aws:s3:::<reports>/*/snapshot.json`;
    - no `PutObject`, no `BypassGovernanceRetention`.
  - User `cyberlab-purge` with that policy.
  - The api policy is **unchanged** (RT5: no legal-hold action for the API).
- **Workers:**
  - `workers/retention_app.py` (Celery app, queue `retention`) and `workers/retention_tasks.py` (`retention.sweep`, `retention.run_org`, `retention.sync_holds`, RT5) calling the stubs in `workers/retention.py`.
  - In `workers/tasks.py`, register `correlation.index_pending` → `correlation/indexer.index_pending(limit)` (stub returns 0).
  - Beat entries in `celery_app.py`: `correlation.index_pending` every 60 s on the ingest queue (≤ 5 jobs, `CORRELATION_INDEX_BUDGET_S` 10 s, RT19), and `retention.sweep` daily at 02:30 UTC on the retention queue (`crontab`).
- **Implemented here:**
  - **`ops/error_classes.py`:** enumerate every `error_code` literal emitted by `analysis` (pcap and static analyzers and the reaper), `threat_intel`, `ai` and `reports` render paths (grep the contracts and the lifecycle modules), and map each to `parse | infra | policy | provider | input | other`. A unit test fails on any code found in the contracts that is missing from the map.
  - **`core/audit_dedupe.py`** (`once_per`, Redis `SET NX EX` under the `ad:` prefix), with a unit test.
- **Schemas and stubs:** every route in the plan.md table, with its permission dependency, frozen request and response models and `501 not_implemented`. Search is `POST /search` with a `SearchIn{q, types, cursor}` body (RT13). The policy schemas carry `pending_enforce` / `enforce_effective_at` (RT1); hold responses carry `s3_sync`.
  - The `/internal/metrics` route is mounted on the root app, not the `/api/v1` router, and answers 404 while the token is unset.
  - `EvidenceOut` and the investigation read schema gain their fields (defaults: `purged_at=None`, `legal_hold=False`, `type_mismatch=None`, `declared_type=None`).
  - The new error codes are added to `core/errors.py`.
  - Run `pnpm gen:contracts` once.
- **Cross-phase stubs:** the signatures in plan.md "Cross-phase entry points".
- **Root scripts:**
  - `scripts/{backup,restore,restore-drill}.mjs`, `scripts/ops_metrics.py` and `scripts/live_run.mjs` as stubs (exit 2, "not implemented in phase 1"), plus the `package.json` entries.
  - `.gitignore` gains `backups/`.
  - `scripts/check-retention-worker-env.mjs` is created as a stub that phase 11 fills.
- **Test helpers:**
  - `tests/ops_helpers.py`: `seed_retention_policy` (with helpers that backdate `effective_at` / `enforce_effective_at`), `seed_hold` (and `seed_released_hold(released_days_ago)`), `seed_aged_closed_case(...)` (a pcap and a static job with bulk rows, results objects, a render, a status event backdated, TI results reused by a later `cached` run item, and an AI run tree), `seed_correlated_jobs(...)` (two cases and two orgs sharing an IP, a domain, a sha256 and a JA3, all as `iocs` rows, RT8), `seed_job_outcomes`, `retention_session()`;
  - the empty `tests/fixtures/dynamic/`;
  - the IDOR modules with `PENDING_ROUTES`.
- **Frozen test updates:**
  - RLS coverage for the new tenant tables;
  - `test_append_only.py`: the strict tables still refuse DELETE for the owner **and** for `cyberlab_retention`; the exception tables refuse UPDATE for everyone and DELETE for the app and the owner;
  - the tenant-session guard (the retention worker opens tenant sessions only through `tenant_session`).
- **Web shared:**
  - `lib/audit-actions.ts`: `retention.*`, `legal_hold.*`, `evidence.purged`, `evidence.viewed`, `evidence.custody_viewed`, `evidence.type_mismatch`;
  - `lib/nav.ts`: Search; Settings → Retention and Operations;
  - `lib/http-errors.ts`: messages for the new codes;
  - `components/search/search-box.tsx`: an empty stub mounted in the shell header;
  - **slot components (RT16)**, each an empty component mounted once: `components/correlation/ioc-seen-in.tsx` in `components/analysis/iocs-tab.tsx`; `components/correlation/related-cases-card.tsx` and `components/legal-holds/case-hold-card.tsx` in `components/investigations/overview-tab.tsx`; `components/investigations/legal-hold-badge.tsx` in `case-workspace.tsx` and the investigations list; `components/evidence/evidence-integrity-strip.tsx` in the evidence page. `components/evidence/evidence-actions.tsx` disables download and verify when `purged_at` is set. Phases 8 and 9 then edit only their components.

## Implementation Steps
1. Pre-flight, the branch, the role bootstrap and the `db-bootstrap` service. Check on the dev volume, the test DB and one lane DB.
2. Migration 0014 and the models. Run `test_migrations.py`, RLS coverage and append-only (extended).
3. The settings matrix, the compose services, the prod overlay, the broker user and the MinIO policies, SSE and the KMS secret. Then `docker compose up` on infra: minio-init is idempotent twice, and `mc encrypt info` shows SSE on every bucket.
4. The worker app, the tasks, the beat entries and the stubs.
5. `error_classes.py` and `audit_dedupe.py` with their tests.
6. The schemas, the 501 stubs, the error codes, the internal mount and `pnpm gen:contracts`.
7. The test helpers, the IDOR split, the web shared files and the script stubs.
8. Smoke check:
   - the existing API suite is green (in a lane, one run);
   - the M6 report pipeline test and one pcap and one static pipeline test still pass with SSE-S3 buckets (presigned POST unchanged);
   - the analyzers and renderer still upload.
9. Rebuild `cyberlab/api:dev`, then commit.

## Success Criteria
- [x] 0014 upgrades and downgrades cleanly (enum values excepted). The system user exists and cannot log in; a purged render no longer blocks its re-render index slot. Every new tenant table is FORCE RLS and covered. The strict append-only tables refuse DELETE even for `cyberlab_retention`, and the exception tables allow it only for that role. — `integration/test_migrations.py::test_downgrade_0006_then_fresh_upgrade_head` (0014 down / up); `test_m7_schema.py::test_the_system_user_exists_and_cannot_log_in`, `test_only_retention_purges_a_render_and_it_frees_the_slot`, `test_tenant_tables_are_isolated`; `test_rls_coverage.py::test_every_tenant_table_has_forced_rls`, `test_system_visible_retention_policy_index_holds_no_tenant_data`, `test_job_outcomes_is_a_system_table_without_tenant_data`; `test_append_only.py::test_retention_role_cannot_mutate_strict_append_only_tables`, `test_exception_tables_allow_delete_for_the_retention_role_only`, `test_exception_tables_refuse_update_for_everyone` (980386a).
- [x] `db-bootstrap` creates the role idempotently on fresh and existing volumes, and 0014 fails clearly without it. — Existing volumes done: the dev volume, `cyberlab_test` and a lane DB were bootstrapped and migrated to 0014, and `test_m7_schema.py::test_the_migration_refuses_to_run_without_the_role` covers the clear failure (980386a). Fresh volumes: every restore drill starts a fresh `cyberlab-drill` project, where `init/02-m7-roles.sh` runs first, and all passed with 0 mismatches (`infra/backup/last-drill.json`, `plans/reports/m7-heavy-steps-261106.md`).
- [x] The retention worker starts with least-privilege env (the settings matrix passes), and its broker ACL is confined. — `unit/test_config.py::test_retention_role_runs_with_its_least_privilege_env`, `test_retention_role_refuses_every_other_secret`, `test_retention_role_needs_the_retention_db_role`, `test_other_roles_refuse_the_purge_user`, `test_other_roles_refuse_the_retention_db_role`, `test_no_role_holds_the_minio_kms_key`; `test_retention_acl.py::test_retention_user_is_confined`, `test_other_workers_cannot_touch_retention`, `test_api_and_ingest_users_can_publish_to_retention`. On the dev stack the worker connected as broker user `retention` and handled a published `retention.sweep` (0 runs) (980386a).
- [x] SSE-S3 is on for every bucket, and the existing presigned upload paths (pcap, static, report) still pass. — `test_m7_foundation.py::test_every_bucket_has_sse_s3`; `test_analysis_pipeline` (4), `test_analysis_static_pipeline` (2) and `REPORT_E2E=1 test_report_pipeline` (1) against SSE buckets (980386a); phase 6 `test_storage_sse.py` re-proves every presigned path (9316433).
- [x] Every new route exists as a 501 stub with frozen schemas, the contracts are regenerated, and the IDOR enumerator lists the new routes as pending. — At 980386a: 14 org routes + `/internal/metrics` as stubs, `PENDING_ROUTES` 9 + 4 + 1, contracts regenerated (30 new schemas, 12 new paths, nothing removed). By 9316433 every stub is implemented: `test_m7_foundation.py::test_every_m7_route_exists_and_none_is_pending`, `test_no_route_still_raises_the_501_stub`.
- [x] `error_classes` covers every emitted error code (test). — `unit/test_error_classes.py::test_every_contract_code_is_classified`, `test_every_literal_code_of_the_api_is_classified`, `test_analyzer_codes_match_the_worker_sources` (980386a).
- [x] The full existing API suite and the worker suites are green. — Met in gate run vp8 (2026-11-06, the pre-fix gate): API 4915 passed / 53 skipped / 1 xfailed, and `test:workers` passed. After the review fix d9e409c (migration 0015) and the gate fixes 7d2a8e8: the targeted lane suites 109 passed; full API run 1 had 4915 passed and 1 teardown deadlock error in the test reset, fixed in `conftest.py` with a retry (7d2a8e8). No later full run is recorded. The phase-1 run (lane 2) had only `test_idor_routes.py::test_owner_request_succeeds[route60]` / `[route63]` failing, which fail the same way on 1692756 (an M6 fixture bug). 9316433 fixes them (see the notes). `test:workers` was not run in phase 1.

## Risk Assessment
- **SSE-S3 on the frozen bitnami MinIO** could reject presigned POSTs or need extra env. Test the three upload paths in step 8 before committing. If SSE breaks a path, keep the SSE code behind `MINIO_SSE_ENABLED` (default off) and tell the parent.
- **The `job_outcomes` triggers vs the existing transition triggers:** use AFTER triggers only, so they never change a row and never raise on bad data. An exception inside them would fail the status change, so phase 5 owns the full test, but step 8 runs the reaper tests.
- **Enum values cannot be removed** by the downgrade (`custody_action`): the downgrade leaves them, and `test_migrations.py` tolerates it (RT12).
- **The KMS switch on a live volume** (RT7): rehearsed on a copy first (step 3).
- **Scope creep:** this phase is large (about 20 h). Anything beyond the frozen list goes to the owning phase.

## Frozen interfaces (as built)

Built on `feat/m7-platform-ops` from 1692756 (M6 code-complete; alembic head was `0013`, so the migration is `0014`). Not committed (the parent commits). Deviations from plan.md are marked **(deviation)**.

**Migration `0014_m7_platform_ops.py`** (down_revision `0013`):
- Guard: a `DO` block raises `role cyberlab_retention does not exist: run db-bootstrap first` (run before and after the enum autocommit block). The `custody_action` values `purged` / `sent_to_sandbox` are added in an `autocommit_block` (0006's rule); the downgrade leaves them.
- `CREATE EXTENSION IF NOT EXISTS pg_trgm` (dropped by the downgrade).
- Tables (text + CHECK, no new enums; composite same-org FKs; FORCE RLS + `tenant_isolation` on the seven tenant tables):
  - `org_retention_policies` (PK `organization_id`; `ti_results_days`, `ai_runs_days`, `closed_case_days`, `pending_*` of each, `effective_at`, `enforce`, `pending_enforce`, `enforce_effective_at`, `updated_by`, `created_at`, `updated_at`). Checks: every value `NULL OR BETWEEN 30 AND 36500`; `pending_pair` (`effective_at` set iff a pending value is); `enforce_pair` (`pending_enforce = (enforce_effective_at IS NOT NULL)`); `enforce_pending_only_when_off`. Trigger `org_retention_policy_touch` (identity immutable, sets `updated_at`).
  - `retention_policy_index` (PK `organization_id`, `updated_at`; policy `retention_policy_index_scope` = `app_org_id() IS NULL OR organization_id = app_org_id()`).
  - `legal_holds` (`id`, `scope` org/investigation, `investigation_id`, `reason` 1..500, `placed_by/at`, `released_by/at`, `release_reason` 1..500, `s3_synced_at`; checks `scope_target`, `released_pair`, `release_reason_when_released`; indexes `(organization_id, released_at)`, `(investigation_id)`). Trigger `legal_hold_guard`: released once, identity immutable.
  - `retention_runs` (`mode` dry_run/enforce, `trigger` schedule/manual, `status` queued/running/completed/partial/failed, `requested_by` (set iff manual), `policy` jsonb ≤ 4 KiB, `counts` ≤ 8 KiB, `sample` (array) ≤ 64 KiB, `error` code, `created_at`, `started_at`, `finished_at`). Trigger `retention_run_guard`: final statuses and identity immutable.
  - `retention_run_items` (append-only: `run_id`, `category` ti_results/ai_runs/closed_case, `ref_table`, `ref_id`, `job_id`, `rows`, `bytes`, `object_key` + `object_version_id` (pair), `outcome` purged/skipped_hold/skipped_locked/object_delete_failed/kept_cited, `created_at`).
  - `evidence_purges` (append-only tombstone: PK `evidence_id`, `run_id`, `object_version_id`, `sha256`, `purged_at`).
  - `correlation_keys` (`investigation_id`, `evidence_id`, `job_id` NOT NULL, `kind` ∈ the 11 kinds, `key` sha256 hex, `value_norm` 1..2048, `source_table` iocs/malware_samples/evidence_hashes, `source_id` text ≤ 64, `first_seen`, `last_seen`, `created_at`; unique `(job_id, kind, key)`; indexes `(organization_id, kind, key)`, `(investigation_id)`, trigram `ix_correlation_keys_value_norm_trgm`).
  - `correlation_job_state` (PK `job_id`, `indexed_at`, `keys`, `truncated`).
  - `job_outcomes` (system, no RLS: `id`, `kind` pcap/static/ti/ai/report, `subkind`, `status`, `error_code`, `queue_ms`, `run_ms`, `finished_at`; indexes `(finished_at)`, `(kind, finished_at)`).
- `record_job_outcome()` (SECURITY DEFINER, `SET search_path = pg_catalog, public`, EXECUTE revoked from PUBLIC) behind `AFTER UPDATE OF status ... WHEN (NEW.status::text IN <terminal> AND OLD.status::text NOT IN <terminal>)` triggers `<table>_job_outcome` on `analysis_jobs` (kind = analyzer, subkind = profile), `ti_enrichment_runs` (kind ti, subkind = the single provider or `multi`, error NULL: TI runs store no code), `ai_runs` (subkind = provider) and `report_renders` (subkind = format). `queue_ms = started - created`, `run_ms = finished - started` (NULL when never started). Codes failing `^[a-z][a-z0-9_]{0,63}$` become `other`; any error inside is a WARNING (the status change never fails).
- `forbid_mutation_except_retention()` (DELETE allowed iff `current_user = 'cyberlab_retention'`, UPDATE never) replaces the `<table>_append_only` trigger of `ti_results`, `ai_run_inputs`, `ai_context_refs`, `ai_outputs`, `ai_citations`. `retention_run_items` / `evidence_purges` use `forbid_mutation()`.
- `evidence` + `declared_type varchar(32)` (`ck_evidence_declared_type_length`) and `type_mismatch bool`, both NULL; `evidence_immutable()` makes them write-once: a change is allowed only from (NULL, NULL) while `OLD.xmin` is the current transaction (so set in the inserting transaction; rows inserted inside a SAVEPOINT are not covered).
- `report_renders`: status check gains `purged`; `report_render_transition()` allows `succeeded -> purged` only for `cyberlab_retention` and only the status (else `a render purge changes the status only`); `purged` is final. `ux_report_renders_version_id_format_renderer` now `WHERE status NOT IN ('failed', 'purged')` (RT11).
- System user (RT12): `00000000-0000-4000-8000-00000000a7e0`, `retention@system.invalid`, `is_active = false`, hash `!unusable:retention-system-user`. **(deviation)** The downgrade leaves it (custody rows may reference it, like the enum values). Login refuses the address at validation (422, `.invalid` is a reserved name) and `current_user` refuses a forged token (401).
- Search indexes (phase 4 must use these exact expressions):
  - `ix_investigations_search_fts`: `to_tsvector('simple'::regconfig, coalesce(title, '') || ' ' || coalesce(description, ''))`;
  - `ix_investigations_case_number_trgm`: `(case_number::text) gin_trgm_ops` **(deviation: the number, not `CASE-00012`)**;
  - `ix_analysis_findings_search_fts`: same expression as cases over `analysis_findings`;
  - `ix_network_alerts_search_fts`: `to_tsvector('simple'::regconfig, coalesce(signature, ''))`;
  - `ix_analyst_note_versions_search_fts`: `to_tsvector('simple'::regconfig, coalesce(body, ''))`;
  - `ix_evidence_original_filename_trgm`: `original_filename gin_trgm_ops`; `ix_correlation_keys_value_norm_trgm`: `value_norm gin_trgm_ops`.
- Grants. App: S/I on the policies, index, holds, runs, correlation tables; SELECT on run items, purges, `job_outcomes`; UPDATE on the policy columns, `retention_policy_index.updated_at`, `legal_holds (released_by, released_at, release_reason)`. `cyberlab_retention`: USAGE on `public`, EXECUTE on `app_org_id()/app_user_id()`; SELECT on the 36 tables the selector reads (`RETENTION_SELECT`: not `organizations`, `users`, `refresh_tokens`, provider configs, `correlation_*`); DELETE on `RETENTION_DELETE` (the 8 bulk tables, `ti_results`, `ti_run_items`, `ai_runs`, `ai_run_index`, the 4 `ai_*` children, `job_outcomes`); INSERT on runs, run items, purges, custody, audit; UPDATE `retention_runs (status, counts, sample, started_at, finished_at, error)` **(deviation: + `sample`, `started_at`)**, `report_renders (status)`, `legal_holds (s3_synced_at)`.

**Models** (registered in `app/models.py`): `retention/models.py` (`OrgRetentionPolicy`, `RetentionPolicyIndex`, `LegalHold`, `RetentionRun`, `RetentionRunItem`, `EvidencePurge`; constants `FLOOR_DAYS`, `HOLD_SCOPES`, `RUN_*`, `CATEGORIES`, `ITEM_OUTCOMES`), `correlation/models.py` (`CorrelationKey`, `CorrelationJobState`, `CORRELATION_KINDS`, `SOURCE_TABLES`), `ops/models.py` (`JobOutcome`, `KINDS`), `Evidence.declared_type/type_mismatch`, `CustodyAction.PURGED/SENT_TO_SANDBOX`, `reports.models.RENDER_STATUSES` + `purged` (`RENDER_INDEX_STATUSES` keeps the index's four). `reports/schemas.RenderStatus` + `purged`; `reports/dispatch.create_render` dedupe skips purged renders (matches the index, RT11).

**Settings** (`core/config.py`): `ProcessRole` + `retention`; constants `RETENTION_ROLE`, `RETENTION_FORBIDDEN`, `RETENTION_FLOOR_DAYS = 30`, `RETENTION_SYSTEM_USER_ID/EMAIL`, `DEV_KMS_KEY_NAME`. Fields: `retention_policy_delay_days` 7, `retention_batch_rows` 5000, `retention_batch_objects` 200, `retention_run_slice_s` 120, `retention_sample_limit` 50, `retention_job_outcomes_days` 90, `retention_system_user_id`, `minio_purge_access_key/secret_key`, `correlation_common_key_jobs` 50, `correlation_max_keys_per_job` 20000, `correlation_index_budget_s` 10, `correlation_index_batch_jobs` 5, `search_min_query_chars` 2, `search_max_query_chars` 256, `search_hits_per_type` 20, `search_statement_timeout_s` 3, `search_per_user_per_min` 30, `metrics_token_file`, `rate_limit_user_per_min` 600, `evidence_view_audit_dedupe_s` 900, `minio_kms_secret_key_file` (refused for every role). Guards (`_ops_role_guards`): `retention` refuses `RETENTION_FORBIDDEN` (JWT, app Redis, api MinIO keys, TI / AI / report key files, AI platform key, metrics token), needs `DATABASE_URL` of `cyberlab_retention` plus `MINIO_ENDPOINT` and the purge keys; every other role refuses the purge keys and a `cyberlab_retention` DATABASE_URL; only `api` takes `METRICS_TOKEN_FILE`; prod refuses a change-me `MINIO_PURGE_SECRET_KEY`. **(deviation)** There is no separate `RETENTION_DATABASE_URL` setting: the worker's `DATABASE_URL` is the retention role's (so `tenant_session` works unchanged); tests use `RETENTION_TEST_DATABASE_URL` (a TEST_ name Settings never reads).

**Errors** (`core/errors.py`): `Gone` (410 `gone`), `EvidencePurged` (410 `evidence_purged`), `LegalHoldActive` (409), `PolicyFloor` (422), `RetentionAcknowledgementRequired` (422), `SearchQueryInvalid` (422). `core/clients.get_purge_minio()` (retention role only).

**Schemas and 501 stubs** (14 org routes + 1 root route; permission dependency first, bodies validated):
- `retention/schemas.py`: `RetentionValues`, `RetentionPolicyIn{ti_results_days, ai_runs_days, closed_case_days (required, nullable, 1..36500), enforce, acknowledge_destruction?}`, `RetentionPolicyOut` (+ `pending_*`, `effective_at`, `pending_enforce`, `enforce_effective_at`, `delay_days`, `floors`, `updated_by/at`), `RetentionPreviewIn` (optional values), `RetentionCategoryCount`, `RetentionCandidateOut`, `RetentionPreviewOut{generated_at, policy, counts, sample, truncated, holds_active}`, `RetentionRunCreate{dry_run?}` **(deviation: mode never in the body, `dry_run: true` may only downgrade)**, `RetentionRunOut`, `RetentionRunPage`, `RetentionRunItemOut`, `RetentionRunDetail` (+ `sample`, `items`, `items_total`), `LegalHoldCreate{scope, investigation_id?, reason}`, `LegalHoldRelease{reason}`, `LegalHoldOut` (+ `case_ref`, `placed_by_name`, `protects_until`, `active`, `s3_sync` pending/synced, `s3_synced_at`), `LegalHoldPage`.
- Routes `retention/router.py`: `GET|PUT /retention/policy` (org.read / org.update), `POST /retention/preview` (org.update), `GET /retention/runs` + `GET /retention/runs/{retention_run_id}` (audit.read), `POST /retention/runs` (org.update, 202), `GET /legal-holds?investigation_id=&active_only=` (investigation.read), `POST /legal-holds` (201), `POST /legal-holds/{hold_id}/release` (org.update). **(deviation)** path params are `{retention_run_id}` and `{hold_id}` (`{run_id}` is the TI run's in the IDOR enumerator).
- `correlation/schemas.py` (`CorrelationKind`, `CaseRefOut`, `SeenInOut`, `JobCorrelationsOut`, `OccurrenceOut`, `CorrelationLookupOut`, `RelatedCaseOut`, `RelatedCasesOut`); routes `GET /analyses/{job_id}/correlations`, `GET /correlations?kind=&value=`, `GET /investigations/{investigation_id}/related` (investigation.read).
- `search/schemas.py` (`SearchType`, `SEARCH_TYPES`, `MatchKind`, `SearchIn{q 1..1024, types?, cursor?}`, `SearchHit`, `SearchGroup`, `SearchOut{groups, partial}`); `POST /search` (investigation.read).
- `ops/schemas.py` (`Window` 1h/24h/7d, `OutcomeKind`, `KindMetricsOut`, `OrgOpsMetricsOut{window, generated_at, items, active}`); `GET /ops/metrics?window=` (audit.read).
- `ops/internal.py`: `GET /internal/metrics` on the root app: 404 while `METRICS_TOKEN_FILE` is unset or empty or when `X-Forwarded-For` is present, 401 without the bearer token (constant-time), then 501 (phase 5). `metrics_token()` is `lru_cache`d.
- `EvidenceOut` + `purged_at=None`, `legal_hold=False`, `declared_type=None`, `type_mismatch=None`; `InvestigationOut` + `legal_hold=False`.

**Cross-phase entry points:** `retention/select.py` (`EffectivePolicy{ti_results_days, ai_runs_days, closed_case_days, enforce, .empty}`, `Candidate`, `CategoryCount`, `CandidateSet{candidates, counts, truncated}`, `async candidates(session, org_id, policy, *, now, limit)` raises), `retention/holds.py` (`HoldSet{org_wide, investigation_ids}.covers(investigation_id)` implemented, `async active_holds(session, org_id, *, now)` raises), `workers/retention.py` (`RunOutcome`, `async sweep() -> int` returns 0, `async run_org(org_id, run_id)` raises, `async sync_holds(org_id) -> int` returns 0), `correlation/normalize.correlation_key(ioc_type, raw)` raises, `correlation/indexer.index_pending(limit)` returns 0, `ops/metrics.py` (`PlatformMetrics`, `platform_metrics`, `render_prometheus` raise), `ops/error_classes.py` (**implemented**: `ErrorClass` parse/infra/policy/provider/input/other, `ANALYZER_CODES`, `ERROR_CLASS` (read-only mapping), `classify(code)`), `core/audit_dedupe.once_per(key, ttl_s)` (**implemented**: `SET NX EX` under `ad:`, keys 1..256 chars, Redis errors propagate).

**Workers:** py-jobs `RETENTION_SWEEP`, `RETENTION_RUN_ORG`, `RETENTION_SYNC_HOLDS`, `CORRELATION_INDEX_PENDING`, `Queues.retention`. `workers/retention_app.py` (queue `{prefix}retention`, unacked keys under it, remote control and events off), `workers/retention_tasks.py` (tasks take `message`: `{}`, `{org_id, run_id}`, `{org_id}` **(deviation: the repo's one-`message` convention instead of `sync_holds(org_id)`)**). `workers/tasks.py` registers `correlation.index_pending` (batch = `CORRELATION_INDEX_BATCH_JOBS`). Beat: `index-correlation-keys` every 60 s on ingest (expires 55), `retention-sweep` `crontab(02:30 UTC)` on retention (expires 23 h).

**Infra:** `infra/postgres/bootstrap.sh` (idempotent; `\gexec` creates the role, `ALTER ROLE ... PASSWORD :'retention_pw'`, timeouts, CONNECT on `cyberlab`, `cyberlab_test` and every `cyberlab_b*_test`), `init/02-m7-roles.sh` runs it (mounted at `/opt/cyberlab/bootstrap.sh` in postgres). Compose: `db-bootstrap` (migrate depends on it), `x-retention-env`, `x-retention-worker`, `retention-worker` (384m, backend only, uid 10001, read-only, cap_drop ALL), `retention-worker-test` (profile test, `test.retention`, test DB / buckets, not an api-test dependency), api-test `RETENTION_TEST_DATABASE_URL`, `TEST_MINIO_PURGE_ACCESS_KEY/_SECRET_KEY`, `TEST_BROKER_RETENTION_URL`, `RATE_LIMIT_USER_PER_MIN=100000`; `x-api-env` + `RATE_LIMIT_USER_PER_MIN` (default 600, the e2e can raise it) and `RETENTION_POLICY_DELAY_DAYS`; api secret `metrics_token` (`METRICS_TOKEN_FILE`; dev file `infra/ops/dev-metrics-token` is empty = off, `METRICS_TOKEN_SECRET_FILE` overrides); minio `${MINIO_IMAGE}`, `${MINIO_DATA_DIR}`, secret `minio_kms_key` + `MINIO_KMS_SECRET_KEY_FILE` (dev: committed `infra/minio/dev-kms-key`, name `cyberlab-dev-kms`); minio-init `${MC_IMAGE}`, `ENV`, `MINIO_SSE_ENABLED` (default true), purge keys, the KMS secret (name check only). Prod overlay: requires `POSTGRES_RETENTION_PASSWORD`, `BROKER_RETENTION_PASSWORD`, `MINIO_PURGE_SECRET_KEY`; secrets from `.secrets/minio_kms_key` and `.secrets/metrics_token`; minio-init refuses the dev key name when `ENV=prod`. Broker user `retention` (`~retention* ~test.retention*` + its kombu bindings, enrich's command set). MinIO: `mc encrypt set sse-s3` on all six buckets; `purge-policy.template.json` + user `cyberlab-purge`: list / versions / lock config on the buckets; `GetObjectVersion`, `DeleteObject`, `DeleteObjectVersion`, `GetObjectRetention`, `Get/PutObjectLegalHold` on objects; `Deny DeleteObject/DeleteObjectVersion` on `<reports>/*/snapshot.json`; no PutObject, PutObjectRetention or bypass. **(deviation)** `s3:DeleteObject` is required: this MinIO build authorizes a version delete with it too (without it every delete was AccessDenied); a delete without a version id only adds a delete marker. The api policy is unchanged. `init.sh` refuses purge keys starting with `-` (mc parsed one as a flag and echoed it).
- `scripts/lane-test.sh`: rewrites `RETENTION_TEST_DATABASE_URL` to the lane DB (built from `POSTGRES_RETENTION_PASSWORD`, RT15), exports the slot root as `LANE_LOCK_ROOT` (override honoured) and prints it with `--print-lock-root` (RT25).
- Root scripts: `backup`, `restore`, `restore:drill`, `live:run` (Node stubs, exit 2), `ops:metrics` (`scripts/ops_metrics.py` in api-test, exit 2), `scripts/check-retention-worker-env.mjs` (stub). `.gitignore` + `backups/`. `.env.example` M7 block.

**SSE-S3 / KMS rehearsal (RT7, 2026-11-06):** the 2.3 GB `cyberlab_miniodata` volume was copied into a throwaway volume and network. On the copy, the bitnami image honoured `MINIO_KMS_SECRET_KEY_FILE` natively (no wrapper; `mc admin kms key status`: `cyberlab-dev-kms` encrypt / decrypt OK). Users (`cyberlab-api`), policies and a pre-KMS evidence object (69 059 B) stayed readable; `mc encrypt set sse-s3` worked and a new object reported `SSE-S3`; the api user read it. Two restarts: same results. `init.sh` ran twice (idempotent), and `ENV=prod` with the dev key name exited 1. The rehearsal resources were removed, then the dev stack was switched (minio recreated with the key, minio-init twice: SSE on all six buckets, purge user created). Objects written before stay plaintext until rewritten.

**Web:** `lib/audit-actions.ts` (+9 M7 actions), `lib/nav.ts` (`Search` item; `SETTINGS_TABS` / `settingsTabs(can)` with Retention (org.read) and Operations (audit.read), used by `settings/layout.tsx`), `lib/http-errors.ts` (`HTTP_ERROR_TEXT`, `httpErrorText`, `apiErrorText`, + test). Slots rendering nothing, each mounted once: `components/search/search-box.tsx` (shell header), `components/correlation/ioc-seen-in.tsx` (`iocs-tab.tsx`), `components/correlation/related-cases-card.tsx` and `components/legal-holds/case-hold-card.tsx` (`overview-tab.tsx`), `components/investigations/legal-hold-badge.tsx` (`case-workspace.tsx` above the tab list, and the investigations list), `components/evidence/evidence-integrity-strip.tsx` (evidence page). `evidence-actions.tsx` disables Download and Verify when `purged_at` is set. Required by the contract: `lib/reports.ts` (`purged` render label, final) and `custody-timeline.tsx` (`purged`, `sent_to_sandbox` labels).

**Tests and helpers:** `tests/ops_helpers.py` (`retention_session`, `retention_sessionmaker`, `purge_minio`, `seed_retention_policy`, `backdate_policy`, `seed_hold`, `seed_released_hold`, `AgedCase` + `seed_aged_closed_case` (real evidence objects, pcap + static ingest, a succeeded render with its object, a backdated closing event, an old TI result reused by a `cached` item, an AI parent + `job_digest` child finished `aged_days` ago), `SHARED_IOCS`, `CorrelatedSeed` + `seed_correlated_jobs`, `seed_job_outcomes(owner_engine, rows)`); `tests/fixtures/dynamic/.gitkeep`; IDOR `idor_cases_{retention,correlation,ops}.py` with `PENDING_ROUTES` (9 + 4 + 1), merged by `test_idor_routes.py` (`M7_CASE_MODULES`, `PENDING_MODULES`). `tests/conftest.py` re-seeds the system user after every truncation. `test_tenant_session_guard`: `ALLOWED` + `workers/retention.py`, `modules/correlation/indexer.py`, both in `PENDING_ALLOWED` (phase 11 empties it). `test_ti_key_leak.GLOBAL_GETS` + `/internal/metrics`. New: `unit/test_error_classes.py`, `unit/test_audit_dedupe.py`, `integration/test_m7_schema.py`, `integration/test_m7_foundation.py`, `integration/test_retention_acl.py`; extended `unit/test_config.py` (the matrix), `test_migrations.py` (0014 down/up), `test_rls_coverage.py`, `test_append_only.py`.

**Verification (2026-11-06, lane 2):** ruff / format clean, `mypy app` clean; unit M7 + config + guard 134 passed / 1 skipped; `test_m7_schema`, `test_rls_coverage`, `test_retention_acl`, `test_append_only`, `test_m7_foundation` all passed; `test_migrations`, `test_m6_schema`, `test_m6_foundation`, `test_report_renders`, `test_evidence`, `test_ti_key_leak`, `test_storage_minio` and the IDOR enumeration tests 108 passed / 1 skipped; SSE upload paths: `test_analysis_pipeline` 4, `test_analysis_static_pipeline` 2, `REPORT_E2E=1 test_report_pipeline` 1 (each with its test worker alone). Web: typecheck, eslint, vitest 449. Contracts regenerated (30 new schemas, 12 new paths, `CustodyAction` / `EvidenceOut` / `InvestigationOut` / `RenderOut` changed, nothing removed). Dev DB migrated to 0014; the retention worker started, connected as `retention` and handled a published `retention.sweep` (0 runs). Full API suite (lane 2, enrich / analyst test workers and the mocks on lane 2, the pcap / static pipelines deselected because they ran above): 1643 passed / 58 skipped up to the first failure, then `tests/security tests/smoke tests/ti tests/unit` 2787 passed / 10 skipped. The only failures are `test_idor_routes.py::test_owner_request_succeeds[route60]` and `[route63]` (the report version `content` / `snapshot` routes answer `409 integrity_failed`: the IDOR victim's version is signed with `new_signing_keys()` but `verify_stored` checks `REPORT_SIGNING_PUBLIC_KEYS`). **They fail identically on unmodified HEAD 1692756** (checked in a temporary worktree, lane 3, 2 failed / 384 passed): an M6 test-fixture issue, not M7. Worker suites (`test:workers`) not run (instructions).

**Local state (git-ignored):** `.env` gained `POSTGRES_RETENTION_PASSWORD`, `BROKER_RETENTION_PASSWORD`, `MINIO_PURGE_ACCESS_KEY/SECRET_KEY`; `.secrets/minio_kms_key` (`cyberlab-kms-1`) and `.secrets/metrics_token` were created for the prod overlay.

**Open for the parent:**
- `pnpm verify:prod` on the shared dev volumes would start MinIO with `.secrets/minio_kms_key`, a different key from the dev key that now encrypts that volume's IAM, and MinIO could not read its users (RT7). Run the prod gate on a fresh project (`COMPOSE_PROJECT_NAME=cyberlab-clean`) or decide how the gate shares keys (phase 11).
- `scripts/check-retention-worker-env.mjs` (phase 11) must allow `minio-init`, which holds the purge keys to create the user.
- Not run here: `verify:prod`, `test:workers`, e2e (instructions), and the worktree / lane setup (parent).

## Implementation Notes (2026-11-07)
- **Commits:**
  - 980386a: phase 1 (102 files, +16 032 / −6 230; most of the churn is the regenerated `openapi.json`).
  - 9316433: phases 2–10, the group-B review fixes and the contract gap fields (160 files, +25 890). It also touched these phase-1 files: `ops/internal.py`, `retention/{holds,select,router,schemas}.py`, the IDOR modules and `lane-test.sh`.
- **As built:** the signatures and deviations are under "Frozen interfaces (as built)". The main deviations:
  - no `RETENTION_DATABASE_URL`: the worker's `DATABASE_URL` is the retention role's;
  - the path params are `{retention_run_id}` and `{hold_id}`;
  - `RetentionRunCreate{dry_run?}`: the mode is never in the body;
  - the tasks take one `message`;
  - `retention_runs` UPDATE also covers `sample` and `started_at`;
  - the downgrade keeps the system user;
  - the case-number trigram index is on the number.
- **The purge policy needs `s3:DeleteObject`:** this bitnami MinIO build also uses it to authorize a versioned delete. Without it, every purge delete was `AccessDenied`. A delete without a version id only adds a delete marker. The `snapshot.json` Deny covers both actions (`test_m7_foundation.py::test_purge_user_policy`, `test_purge_user_cannot_delete_a_report_snapshot`; phase 6 `test_snapshot_json_explicit_deny_applies_to_versioned_deletes`).
- **SSE-S3 / KMS rehearsal on a volume copy (RT7):**
  - The 2.3 GB `miniodata` volume was copied into a throwaway project.
  - The bitnami image reads `MINIO_KMS_SECRET_KEY_FILE` natively, so no entrypoint wrapper is needed.
  - Users, policies and a pre-KMS object survived two restarts, and new objects report SSE-S3.
  - `ENV=prod` with the dev key name exits 1.
  - The dev stack was switched only after that.
  - Old objects stay plaintext until they are rewritten.
- **KMS shared-volume caveat for `verify:prod`:**
  - Dev and prod-like runs share one compose project, so they share one MinIO volume.
  - That volume's IAM is encrypted with the dev key, and the prod overlay's `.secrets/minio_kms_key` cannot read it.
  - Until phase 11 settles how the gate shares keys, run the gate on a fresh project (`COMPOSE_PROJECT_NAME=cyberlab-clean`). This is recorded in TESTING.md and DEPLOYMENT (SSE-S3 and the KMS key).
- **Contract gap fields** (9316433; the frozen schemas only grew, nothing was removed):
  - search: TLP, snippet ranges and the per-type `error`;
  - correlation: `source_ids`, sample keys and TI counts;
  - ops: recent failures;
  - retention: run-item paging and `purged_by_run_id`.

  Contracts were regenerated (`openapi.json` +504, `schema.d.ts` +187).
- **Search indexes:** the exact expressions are listed above for phase 4. Under RLS the planner does not use them (phase-4 notes).
- **Verification (phase 1, lane 2):**
  - ruff, format and `mypy app` clean;
  - the M7 unit, config and guard tests: 134 passed, 1 skipped;
  - the schema, RLS, ACL, append-only, foundation, migration and IDOR enumeration tests passed;
  - the SSE upload paths passed (pcap 4, static 2, report 1);
  - web: typecheck, eslint and vitest 449 passed.
- **The M6 IDOR fixture fix:**
  - `route60` and `route63` failed the same way on unmodified 1692756. The victim's report version was signed with `new_signing_keys()`, but `verify_stored` checks `REPORT_SIGNING_PUBLIC_KEYS`.
  - 9316433 adds `idor_cases_reports._publish_seed_key`, which publishes the test key's public half and fixes `route60`, `route63` and `route65`.
  - The re-run is in the full suite (pending gate).
- **Parallel lanes:**
  - group B ran in lanes through `scripts/lane-test.sh`;
  - lane 8 is new: 9316433 widened the range from 2..7 to 2..8;
  - each lane has its own `cyberlab_b<N>_test`, Redis and broker db N, and the rewritten `RETENTION_TEST_DATABASE_URL`;
  - the slots are shared through `LANE_LOCK_ROOT`, with `LANE_SLOTS=3`.
- **Lane MinIO bucket flake:** the lanes share the MinIO test buckets, and a flake was seen there. Phase 11 is fixing it.
- **Still pending for phase 11:**
  - `test_tenant_session_guard.PENDING_ALLOWED` still lists `workers/retention.py` and `correlation/indexer.py`;
  - `scripts/check-retention-worker-env.mjs` is still the exit-2 stub, and it must allow `minio-init`, which holds the purge keys.
- **Not done here:** `verify:prod`, `test:workers`, the e2e and the full API suite on the final tree. All are pending gate.
- **Closure (2026-11-06):** `test:workers`, the e2e and the full API suite passed in gate run vp8, and the prod phase passed with the fixed gate; the gate passed in segments, not in one `pnpm verify:prod` run (see the plan's Closure).
