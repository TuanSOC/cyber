---
phase: 1
title: "Foundation contracts migration 0014 and ops services"
status: pending
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
- [ ] 0014 upgrades and downgrades cleanly (enum values excepted). The system user exists and cannot log in; a purged render no longer blocks its re-render index slot. Every new tenant table is FORCE RLS and covered. The strict append-only tables refuse DELETE even for `cyberlab_retention`, and the exception tables allow it only for that role.
- [ ] `db-bootstrap` creates the role idempotently on fresh and existing volumes, and 0014 fails clearly without it.
- [ ] The retention worker starts with least-privilege env (the settings matrix passes), and its broker ACL is confined.
- [ ] SSE-S3 is on for every bucket, and the existing presigned upload paths (pcap, static, report) still pass.
- [ ] Every new route exists as a 501 stub with frozen schemas, the contracts are regenerated, and the IDOR enumerator lists the new routes as pending.
- [ ] `error_classes` covers every emitted error code (test).
- [ ] The full existing API suite and the worker suites are green.

## Risk Assessment
- **SSE-S3 on the frozen bitnami MinIO** could reject presigned POSTs or need extra env. Test the three upload paths in step 8 before committing. If SSE breaks a path, keep the SSE code behind `MINIO_SSE_ENABLED` (default off) and tell the parent.
- **The `job_outcomes` triggers vs the existing transition triggers:** use AFTER triggers only, so they never change a row and never raise on bad data. An exception inside them would fail the status change, so phase 5 owns the full test, but step 8 runs the reaper tests.
- **Enum values cannot be removed** by the downgrade (`custody_action`): the downgrade leaves them, and `test_migrations.py` tolerates it (RT12).
- **The KMS switch on a live volume** (RT7): rehearsed on a copy first (step 3).
- **Scope creep:** this phase is large (about 20 h). Anything beyond the frozen list goes to the owning phase.
