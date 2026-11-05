---
title: "CyberLab M7 Platform Operations and Correlation"
description: >-
  Make the platform operable and pivotable. Quiesced backup and restore of Postgres
  (including RLS roles and grants) and the MinIO volume (version ids, object lock and legal
  holds kept), with an automated restore drill in the gate. Per-org data retention with
  dry-run, legal hold, object-lock-aware purge by a least-privilege retention worker, and
  an audit of every purge. docs/SANDBOX_SECURITY.md and a frozen `dynamic.v1` contract
  (dynamic analysis stays disabled). Deterministic cross-job and cross-case correlation
  inside an org, plus org-wide search on Postgres FTS and trigram (OpenSearch deferred, with
  criteria). Runtime job metrics from DB triggers (failure rate, latency, parse success),
  served on a Prometheus endpoint and an org page. Cheap security hardening: a global
  per-user rate limit, an audit of evidence views, a type-mismatch flag, SSE-S3 at rest
  and a tested object-store image path. Plus the docs fixes from the coverage audit.
  Red-teamed 2026-11-06 (RT1–RT38).
status: pending
priority: P1
effort: 153h
branch: "feat/m7-platform-ops"
tags:
  - feature
  - operations
  - backup
  - retention
  - correlation
  - search
  - security
blockedBy: [261106-0900-cyberlab-m6-reports]
blocks: []
created: "2026-11-06T18:00:00.000Z"
createdBy: "ck:plan"
source: skill
---

# CyberLab M7 Platform Operations and Correlation

## Overview

**Requirements this milestone covers** (`requirement.txt`):
- §4: a `correlation` module, and `dynamic_analysis` with a clear interface (contract only).
- §3 and §12: "OpenSearch for searchable analysis results" and frontend "search". M7 builds Postgres search and records when OpenSearch would be needed.
- §7: the dynamic analysis architecture as a design: disposable VMs, isolation, snapshot rollback, controlled egress, limits, integrity and audit. Not enabled.
- §10: "auditable access logs". Evidence metadata and custody views become audited.
- §13: data retention, backup and restore, rate limiting, secure object storage and file type verification (the Partials in the audit).
- §14: worker failure rate, analysis latency and parsing success over real runs, and the live TI / AI measurement procedure.
- §15: `docs/SANDBOX_SECURITY.md`.

**Input:** `plans/reports/requirements-coverage-261106.md`: its prioritized gaps 1–8, the quick wins and the overclaims. Gap 9 (memory forensics) is its own milestone, M8.

**What exists today (scout, 2026-11-06, branch `feat/m6-reports`):**
- **Alembic head:** `0013_m6_same_org_fks`. M7 adds **0014**.
- **Roles:** `cyberlab_owner` and `cyberlab_app` (NOBYPASSRLS, `statement_timeout 30s`, `idle_in_transaction 60s`). Both are created by `infra/postgres/init/01-init.sh`, which runs **only on an empty volume**. The owner is bound by FORCE RLS, so `reconcile_orphans.py` already needs the `postgres` superuser.
- **Append-only:** `forbid_mutation()` refuses UPDATE and DELETE even for the owner on `audit_logs`, `evidence_hashes`, custody, `ti_results`, `ai_run_inputs`, `ai_context_refs`, `ai_outputs`, `ai_citations`, the M6 version and event tables. `evidence_immutable` guards the evidence identity and storage columns.
- **MinIO:** `bitnamilegacy/minio:2025.5.24`. Upstream archived the community repository in February 2026 and has shipped source only since October 2025, so no maintained official image exists. Buckets:
  - `evidence` and `reports` (+ test twins): object lock, versioned, per-object GOVERNANCE retention, no default retention;
  - `results`: versioned, not locked.

  The api user can delete evidence versions (cleanup when an upload fails before commit), but has no delete on `reports`. There is no SSE.
- **Pins:** DB rows pin exact object versions (`evidence.storage_version_id`, `report_versions.object_version_id`, `report_renders.object_version_id`, `analysis_jobs.result_version_id`).
- **Correlation:** `iocs` has **no `ioc_key`**. Its indexes are per job (`uq_iocs_job_id_type_value` on `md5(value)`). `compute_ioc_key(type, value_norm)` lives in `threat_intel/providers/base.py`, with the normalizer next to it. `ti_results` and `ioc_collection_items` carry `ioc_key`.
- **Jobs:** `analysis_jobs` has `created_at`, `started_at`, `finished_at`, `status` and `error_code`. The `*_index` system tables hold no tenant data. Beat schedules the reaper every 60 s and two 30 s resumes.
- **Rate limiting:** `core/rate_limit.hit(key, limit, window_s)` (Redis fixed window), used only by specific routes.
- **Evidence uploads:** `evidence/uploads.py:_sniff` runs libmagic on the head and records it as metadata; it never rejects.
- **RBAC:** org-wide. Permissions: `org.read/update`, `members.*`, `investigation.read/write`, `evidence.read/write`, `audit.read`, `integrations.manage`. No new permission is needed.
- **Docs:** `docs/SANDBOX_SECURITY.md` does not exist. The audit's doc quick wins are all still open (checked: TESTING.md rows 72 and 85, PRD "Milestone 1", DATABASE §11 mapping, ROADMAP "Later"), except M5 `plan.md`, which is already `completed`.

- **Verified by the red team (2026-11-06):** the RLS policies apply to every role (no `TO` clause), so a new role is bound like the app; `organizations` is visible only to members or the current org (RT3). `evidence_custody_events.action` is the enum `custody_action` and `actor_id` is a NOT NULL FK to `users` (RT12). The api MinIO user already holds `s3:DeleteObject` / `s3:DeleteObjectVersion` on the evidence buckets (RT5). `iocs.type` already carries `ja3`, `ja3s`, `cert_sha256` and `file_*` (py-jobs `IocType`), and M6's `ioc_collections/normalize.normalize_item` already keeps private values and keys the pcap-only types (RT8). `ti_run_items.result_id` and `ai_runs.parent_run_id` / `supersedes_run_id` reference purge candidates (RT10). `ux_report_renders_version_id_format_renderer` is unique `WHERE status <> 'failed'` (RT11). The ingest worker is a solo pool (RT19). Caddy forwards only `/api/*` and writes no access log; uvicorn trusts `X-Forwarded-For` from any peer (RT27). The e2e samples already live in a named volume because host AV quarantines them (RT6).

Decisions taken by the planner are marked **(decision)**. The red-team pass ran on 2026-11-06 (table below); changed passages cite their RT id.

## Architecture (decided)

    operator: pnpm backup  ->  drain jobs -> quiesce writers -> pg_dump -Fc (superuser) + globals
                              + security fingerprint + row counts -> objects.json (versions, retention,
                              legal holds) -> stop minio -> tar of the MinIO data volume
                              -> manifest.json (sha256 per file, alembic head, images, KMS key
                                 fingerprint) -> restart
              pnpm restore ->  empty volumes only -> postgres init + db-bootstrap (roles)
                              -> pg_restore (single transaction) -> restore_verify --db (fingerprint,
                                 row counts; before anything writes, RT4) -> untar the MinIO volume
                              -> minio-init (idempotent) -> restore_verify --objects (hashes,
                                 retention, legal holds, report signatures) -> migrate -> revoke
                                 refresh tokens -> start -> restore_verify --rls (RLS probe)
              pnpm restore:drill -> the same, end to end, in project `cyberlab-drill` (gate step, alone;
                                 backups kept in a drill volume, never on the host disk, RT6)

    ingest-beat --daily retention.sweep--> redis-broker --queue retention--> retention-worker
      (api image, PROCESS_ROLE=retention, DB role cyberlab_retention: DELETE on purgeable tables
       only, NOBYPASSRLS, per-org tenant_session; MinIO user cyberlab-purge: DeleteObjectVersion,
       Get/PutObjectLegalHold (hold sync, RT5), no PutObject, no governance bypass, Deny on
       reports/*/snapshot.json)
      -> orgs from the system lookup retention_policy_index (RT3) -> per org: effective policy
         (values and enforce after the delay, RT1) + legal holds (released holds protect for the
         delay) -> S3 legal-hold sync -> candidates (shared selector, also used by the API's dry-run
         preview) -> dry-run report | enforce: tombstone + custody + audit (commit) -> delete the
         object version -> run items -> retention.run_completed audit

    ingest-beat --60 s correlation.index_pending--> ingest-worker (trusted, app role, 10 s budget)
      -> succeeded jobs without correlation_job_state -> correlation_keys (kind, key, value_norm)
         from iocs, malware_samples and evidence_hashes through the M6 normalize_item (RT8)
    API (RLS): job pivots "also seen in", key lookup, related cases, org search (POST, RT13)
      (correlation_keys trigram + FTS 'simple' expression indexes on cases, findings, alerts,
       notes, evidence filenames)

    terminal status UPDATE on analysis_jobs / ti_enrichment_runs / ai_runs / report_renders
      -> AFTER trigger (SECURITY DEFINER) -> job_outcomes (system table, no tenant data)
      -> GET /internal/metrics (API, outside /api, bearer token, backend network only)
      -> GET /api/v1/orgs/{org}/ops/metrics (RLS, the org's own jobs)

**Backup and restore** (decision)
- **Offline, quiesced, single node.**
  - `pnpm backup` (`scripts/backup.mjs`) first **drains** (RT21): it waits until the `*_index` tables show no queued or running job, run or render (timeout 10 min, then `--force`), so a backup does not turn in-flight jobs into reaper failures. It refuses while any test-profile or `compose run` container of the project is up (they share MinIO and Postgres).
  - It then stops every writer: gateway, web, api, ingest-worker, ingest-beat, enrich, analyst, the analyzers, report-worker and retention-worker.
  - **Postgres:** with the writers stopped, it runs `pg_dump -Fc` **as the `postgres` superuser**. FORCE RLS binds the owner, and pg_dump runs with `row_security=off`, so an owner dump errors out. It also writes `pg_dumpall --globals-only --no-role-passwords` for reference.
  - **Objects:** while MinIO is still up, `objects.json` lists every version of the evidence, reports and results buckets with its size, etag, retention mode, retain-until and legal hold (an `mc` helper with the root credentials, RT4).
  - **MinIO:** it stops MinIO and tars the data volume with a helper container (read-only mount, `--numeric-owner`, paths relative to `MINIO_DATA_DIR` so the tar extracts into another image's data dir, RT25).
  - It then writes `manifest.json` and restarts the stack.
  - Downtime is minutes at this scale. The backup is documented as a maintenance window.
- **Why a volume-level MinIO copy:** DB rows pin object **version ids**. Every S3-level copy (`mc mirror`, `mc cp`) creates new version ids, which would break every pin, and the pinned `evidence` columns are immutable by trigger. A volume copy keeps:
  - the version ids;
  - the per-object retention and legal holds;
  - the SSE metadata;
  - MinIO users and policies (`.minio.sys`).

  The online path (MinIO site or bucket replication, which preserves version ids, plus Postgres PITR with WAL archiving) needs a second site. It is deferred and documented.
- **Contents of `backups/<UTC ts>/`:**
  - `postgres.dump`, `globals.sql`;
  - `security.json`: the catalog fingerprint (see below);
  - `tables.json`: the exact row count per table, computed as superuser. **No content digests** (RT4): `pg_restore --exit-on-error --single-transaction` is all-or-nothing, and an ordered `string_agg` digest hits the 1 GB text limit on `network_records` and depends on `TimeZone` and float settings;
  - `objects.json` (above);
  - `minio-data.tar`;
  - `manifest.json`: sha256 of every file, alembic head, image ids and tags, `MINIO_IMAGE`, `MINIO_DATA_DIR`, `EVIDENCE_LOCK_DAYS`, the KMS key **name** and the sha256 **fingerprint** of the key (never the key; a restore refuses a different key, RT7), created_at.

  The catalog fingerprint in `security.json` covers:
  - `relrowsecurity` and `relforcerowsecurity` per table;
  - `pg_policies`;
  - table and column privileges;
  - non-internal triggers;
  - role attributes and `pg_db_role_setting`.

  `BACKUP_DIR` defaults to `./backups/`, which is gitignored. The script refuses a target inside the repository that git would track.
- **What a backup is (RT6):** the complete platform in one place: every org's evidence (malware samples included; objects written before SSE are plaintext in the tar), notes, reports, the argon2 password hashes, the refresh-token hashes, the sealed provider keys and MinIO's IAM store. It holds **no plaintext secret**, but it is a TLP:RED asset and the prime exfiltration target. The script prints this, recommends a target excluded from host antivirus (AV quarantines evidence bytes, as it does the e2e samples) and offline encryption with age; DEPLOYMENT and THREAT_MODEL say the same.
- **Not in the backup:**
  - **Secrets:** `.env` and `.secrets/`, which hold the seal private keys, the report signing keys, the MinIO KMS key, the JWT secret and the DB passwords. They are backed up separately, encrypted (age or gpg), and the script prints the checklist. Without the seal keys the sealed TI and AI provider keys are unrecoverable. Without the KMS key MinIO cannot read its own IAM and config, nor any SSE object (RT7).
  - **Redis and the broker:** ephemeral (denylist, rate limits, queues). The reapers fail in-flight jobs past their deadline. Logged-out access tokens are valid again until they expire (≤ the access TTL): the DR runbook rotates `JWT_SECRET` on a restore after an incident (RT26).
- **Restore** (`pnpm restore -- --from <dir> --replace-empty-stack`):
  1. Refuse unless the volumes are empty (no `alembic_version` row and no `.minio.sys`). The operator runs `docker compose down -v` deliberately.
  2. Check every manifest hash, and that the configured KMS key's fingerprint equals the manifest's (RT7).
  3. Refuse a backup whose alembic head is newer than the image's.
  4. Start postgres (the init script creates the DBs and roles), then `db-bootstrap` (M7 roles).
  5. `pg_restore --exit-on-error --single-transaction` as the superuser into the init-created `cyberlab`. Owners and ACLs restore because the roles exist.
  6. **`restore_verify --db`** at once, before anything writes (RT4): the fingerprint and the row counts equal the backup's.
  7. Untar the MinIO volume, start minio and `minio-init` (idempotent), then **`restore_verify --objects`**.
  8. `migrate` (it upgrades an older backup; the fingerprint was already checked against the old head).
  9. **Revoke every refresh token** (default; `--keep-sessions` opts out). Tokens revoked after the backup point would otherwise become valid again.
  10. Start the stack and run **`restore_verify --rls`**.
- **`restore_verify`** (`apps/api/app/scripts/restore_verify.py`, api image, superuser DB URL; exit 1 on any mismatch, JSON report; three phases, RT4):
  - `--db`: the security fingerprint and the row counts equal the manifest's;
  - `--objects`: every version in `objects.json` exists with the same size, etag, retention mode, retain-until and legal hold; every evidence version re-hashes to `evidence_hashes` (tombstoned evidence is absent, or present and reported as the warning `purged_pending_delete`, RT22); every `report_versions` snapshot re-hashes and its Ed25519 signature verifies with `REPORT_SIGNING_PUBLIC_KEYS`; every succeeded render and job result object re-hashes;
  - `--rls`: an RLS probe as `cyberlab_app`: org A sees zero rows of org B, and UPDATE on `audit_logs` is refused.
- **Restore drill** (`pnpm restore:drill`, `scripts/restore-drill.mjs`):
  - It runs in its own compose project `-p cyberlab-drill` (own volumes and networks, no published ports) with postgres, redis, redis-broker, minio, minio-init, db-bootstrap, migrate and api: about 1.2 GB.
  - **`down -v` guard (RT2):** `stack.mjs` refuses `down -v` unless the project is the literal `cyberlab-drill`, it strips `COMPOSE_PROJECT_NAME` / `COMPOSE_FILE` from the child env, and it checks that every volume it would remove carries the label `com.docker.compose.project=cyberlab-drill`. `pnpm restore` never removes volumes.
  - **Backups stay in Docker (RT6):** the drill writes its backup into the named volume `cyberlab-drill_backups`, never to the host disk.
  - **Steps:**
    1. Seed through the real HTTP API from inside the network (`app/scripts/drill_seed.py`): two orgs, locked evidence uploads, notes, a collection, a legal hold, a retention policy, a finalized signed report, an evidence purge tombstone, and synthetic TI / AI rows inserted as the owner (labelled `drill`). The seeder is a one-off `compose run` container; for the tombstoned object only it uses the drill MinIO root with governance bypass, because the purge user cannot delete a locked version (RT17).
    2. Back up.
    3. `down -v`.
    4. Restore **into the target MinIO image** (proving an image switch keeps the format).
    5. Run `restore_verify`, then log in as a seeded user, download an evidence item and compare its sha256.
    6. `down -v`.
  - **Exclusive:** the drill takes every lane slot (RAM; the same lock root as `lane-test.sh`, RT25) and is the last gate step, after the main stack is stopped.

**Retention, purge and legal hold** (decision)
- **Policy per org** (`org_retention_policies`; every value NULL = keep forever, the default). Three knobs:
  - `ti_results_days`: TI history by age. A result goes only together with its `ti_run_items`, and only when every item that references it (later runs reuse results as `cached`) belongs to a run finished before the cutoff (RT10);
  - `ai_runs_days`: completed AI runs (with inputs, refs, outputs, citations) by age, as whole run trees: a run goes only when every run linked to it by `parent_run_id` / `supersedes_run_id` is eligible and uncited (RT10);
  - `closed_case_days`: for cases closed or archived at least N days ago (from `investigation_status_events`; a case with no status event, i.e. closed before M6, is never selected, and a case with a queued or running job is skipped, RT24): evidence **bytes**, the bulk derived rows (`network_flows`, `network_records`, `analysis_timeline`, `malware_strings`, `malware_sections`, `malware_imports`, `malware_exports`, `malware_resources`), their `results` objects and report **renditions** (re-renderable from the signed snapshot).
- **Never purged by policy:**
  - case, evidence and job metadata;
  - hashes, custody, audit logs;
  - notes and their versions, IOC collections, status events;
  - findings, alerts, `iocs`, `malware_samples`, signatures and capabilities (small and citable, so citations and collections keep resolving);
  - `correlation_keys` and `correlation_job_state` (RT9): they derive only from kept rows, so a closed case keeps correlating ("seen in a case closed last year"); deleting them would also make the indexer rebuild them on the next tick;
  - signed report snapshots, versions and citations.

  AI runs, TI rows and bulk rows **cited by a report version** (`report_citations.ref_table` / `ref_id`, or `ai_citation_id`) are kept as `kept_cited` (RT23).
- **Floors and delay:**
  - Floors: TI ≥ 30 days, AI ≥ 30 days, closed case ≥ max(30, `EVIDENCE_LOCK_DAYS`). So the purge never needs governance bypass: it only deletes versions whose retention has expired, and it refuses any locked or legal-held version.
  - A **lowered** value takes effect after `RETENTION_POLICY_DELAY_DAYS` (7; the `pending_*` columns with `effective_at`). A raised value takes effect at once.
  - **Every loosening waits for the delay (RT1):** turning `enforce` on is stored as `pending_enforce` with `enforce_effective_at` (turning it off applies at once), and a **released** legal hold keeps protecting its data until `released_at + RETENTION_POLICY_DELAY_DAYS`. A hijacked admin session therefore cannot destroy data instantly, whether through an old effective policy plus a fresh `enforce`, a manual run, or a hold release followed by a run. The worker reads mode and values from the DB only, never from the task message.
  - Every change is audited (`retention.policy_changed`).
- **Dry-run first:**
  - `enforce` defaults to false, so scheduled runs write dry-run reports (counts, bytes, a bounded sample of candidates).
  - `POST …/retention/preview` computes the same candidates read-only in the API, through the shared selector `retention/select.py`.
  - Turning `enforce` on needs `org.update` and `acknowledge_destruction`, is audited, and takes effect after the delay.
- **Legal hold** (`legal_holds`: scope `org` or `investigation`; `org.update` to place or release; reason ≤ 500; released once):
  - Any active hold covering the data (including one released less than the delay ago) excludes it from every category, and an org hold skips the org.
  - A case hold is mirrored as **S3 legal hold ON** on that case's evidence versions and report snapshots **by the retention worker** (RT5): the API commits the hold and publishes `retention.sync_holds(org_id)`, and every run syncs again. The API answers `s3_sync: pending`. The api MinIO user gains **no** legal-hold action, so an API compromise cannot clear S3 holds. Releasing turns S3 hold OFF (after the delay) unless another hold still covers the object.
  - The purge refuses any version whose S3 legal hold is ON, whatever the DB says.
- **Executor:** a new `retention-worker` (api image, `PROCESS_ROLE=retention`, solo pool, queue `retention`, broker user `retention`).
  - DB role `cyberlab_retention`: LOGIN, NOBYPASSRLS. It has SELECT, plus DELETE only on the purgeable tables, plus INSERT on the run, tombstone, custody and audit tables. It works in per-org `tenant_session`s.
  - **Org list (RT3):** RLS binds the role, and `organizations` shows only member or current orgs, so the sweep cannot list orgs. 0014 adds the system lookup `retention_policy_index` (org id, `updated_at`; policy `app_org_id() IS NULL OR organization_id = app_org_id()`, the `analysis_job_index` pattern), written by the API in the same transaction as every policy PUT. The sweep reads it in a system session.
  - **Actor:** 0014 inserts the fixed system user `retention@system.invalid` (`RETENTION_SYSTEM_USER_ID`, `is_active = false`, unusable password hash), because custody `actor_id` is a NOT NULL FK to `users` (RT12). Login and `current_user` already refuse inactive users; a test proves it.
  - MinIO user `cyberlab-purge`:
    - it has `DeleteObjectVersion`, `GetObjectRetention`, `GetObjectLegalHold`, `PutObjectLegalHold` (the hold sync) and list on `evidence`, `results` and `reports`;
    - an explicit **Deny** on `reports/*/snapshot.json` (delete actions);
    - no `PutObject` and no `BypassGovernanceRetention`.
  - It holds no JWT secret, seal keys or signing key.
  - **What an API compromise can do (RT5, corrected):** the API never purges through retention, and lowering a policy or arming `enforce` waits for the delay and is audited. But the api MinIO user keeps its M1 `DeleteObject` / `DeleteObjectVersion` on the evidence buckets (cleanup of a failed upload), so once a version's GOVERNANCE lock expires (`EVIDENCE_LOCK_DAYS`, 30) a compromised API can delete it without a tombstone. Residual, recorded in THREAT_MODEL; `restore_verify` and `reconcile_orphans` report a pinned version that is missing without a tombstone. A compromised retention worker can clear an S3 hold and then delete (also recorded).
- **Append-only exception** (0014): `ti_results` and the four append-only `ai_*` tables switch to `forbid_mutation_except_retention()`. It allows **DELETE only when `current_user = 'cyberlab_retention'`**, and UPDATE never. Every other append-only table keeps `forbid_mutation()`. Referential actions run as the table owner, so a cascade can never delete from an exception table; the purge deletes children explicitly in FK order (RT10).
- **Order per evidence:**
  1. One transaction: the `evidence_purges` tombstone (append-only: version id, sha256, run) + a custody event `purged` (actor: the retention system user) + audit `evidence.purged`, then commit.
  2. Delete the object version.
  3. A failed delete is recorded in the run items (`object_delete_failed`) and retried by the next run. A crash between 1 and 2 leaves a tombstoned version without an item; the next run finds it the same way (tombstone present, version present) and `reconcile_orphans` reports it as `purged_pending_delete` (RT22).

  The evidence row itself is never changed. Download and verify answer `410 evidence_purged`, and the case shows "bytes purged on …, hashes and custody retained".
- **Batches:** ≤ 5 000 rows or 200 objects per batch, under `statement_timeout`. One run per org under an advisory lock. The run is time-sliced and resumed by the next sweep.
- **Backups and purge:** a purge is not retroactive in old backups. Backup retention is the operator's policy (documented). After restoring an older backup, run the retention sweep again (it is idempotent).

**Correlation and search** (decision; deterministic, no AI)
- **`correlation_keys`** (tenant): `kind` ∈ `ipv4, ipv6, domain, url, email, md5, sha1, sha256, ja3, ja3s, cert_sha256` (the M4 `IocType` values plus the pcap-only types, RT8); `key` = the `ioc_key` that M6 `ioc_collections/normalize.normalize_item(type, raw)` returns; `value_norm` ≤ 2 048; plus `investigation_id`, `evidence_id`, `job_id`, `source_table`, `source_id`, `first_seen` and `last_seen`.
  - **One normalizer (RT8):** `normalize_item` already runs the M4 TI normalizer, keeps private IPs and internal names (`ti_eligible=false`), and keys the pcap-only types with `opaque_key`. So `key` is byte-identical to `ti_results.ioc_key` and `ioc_collection_items.ioc_key`, and correlation joins both for free. A plain `sha256("ip\0" …)` or a lowercased JA3 would not match.
  - Sources: `iocs` (every type `normalize_item` accepts, JA3 / JA3S / cert included: they are already IOC rows), `malware_samples` hashes and `evidence_hashes` sha256. `network_records` is not read. `registry_key` and `file_path` are not indexed (noisy, host-specific).
  - Unique (job_id, kind, key); index (org, kind, key); trigram GIN on `value_norm`.
- **Indexer:** the trusted beat task `correlation.index_pending` (ingest-worker, app role, every 60 s) takes a bounded batch of succeeded jobs without a `correlation_job_state` row: at most 5 jobs and `CORRELATION_INDEX_BUDGET_S` (10 s) per tick, because the ingest worker is a solo pool shared with result ingest and the reaper (RT19). It needs no ingest code change, and the same task backfills the history; `app/scripts/backfill_correlation.py` does it for large installs as a one-off container, outside the worker.
- **Reads** (`investigation.read`):
  - the job pivot "also seen in": per key, the other jobs and cases, first / last seen and the top 5 cases;
  - the key lookup (the server normalizes the value);
  - related cases: cases sharing ≥ 1 key, ranked by the number of shared keys.

  A key seen in more than `CORRELATION_COMMON_KEY_JOBS` (50) jobs is flagged `common` and left out of the related-case ranking. Counts only; no scores.
- **Search** (`POST /orgs/{org}/search` with a JSON body `{q, types, cursor}`, RT13: a `GET ?q=` lands in the uvicorn access log, the Next.js request log of `/o/{org}/search?q=` and the browser history; the web page keeps `q` in the URL fragment only):
  - **Types:**
    - `observable`: an exact normalized match first, then trigram on `value_norm`;
    - `case`: FTS `simple` over title and description, plus trigram on the case number;
    - `evidence`: filename trigram;
    - `finding`: title and description FTS;
    - `alert`: signature FTS;
    - `note`: FTS over the current version, deleted notes excluded.
  - **Limits:** `q` 2–256 characters; 20 hits per type; `SET LOCAL statement_timeout = '3s'`; 30 / min per user.
  - **Not audited, and the query text is never logged** (recorded decision: IOC queries can be sensitive). It never appears in a URL, so no log filter is needed.
  - `malware_strings` and `network_records` are not searched. Their observables are already in `correlation_keys`, and per-job filters exist.
- **OpenSearch: not adopted in M7.** It would be revisited when an org passes about 50 M searchable rows, when the M7 search benchmark p95 exceeds 1 s, or when payload or strings full text is required. Recorded in ARCHITECTURE.

**Runtime metrics** (decision)
- **`job_outcomes`** (a system table without org id or tenant data: `kind` pcap / static / ti / ai / report, `subkind` (profile, provider or format), `status`, `error_code`, `queue_ms`, `run_ms`, `finished_at`) is written by `AFTER UPDATE` triggers (`SECURITY DEFINER`, owner) on the terminal transitions of `analysis_jobs`, `ti_enrichment_runs`, `ai_runs` and `report_renders`. No application call sites are needed, and reaper failures are counted too. The app role has SELECT only. The retention worker deletes rows older than 90 days.
- **Error classes:** `ops/error_classes.py` (frozen) maps every `error_code` the code can emit to `parse | infra | policy | provider | input | other`. Parse success = succeeded / (succeeded + failed `parse`).
- **`GET /internal/metrics`:**
  - It is outside `/api`, so the gateway never forwards it (Caddy sends everything else to `web`). The bearer `METRICS_TOKEN` (compose secret, constant-time compare) is the control; it is disabled when the token is unset. The `X-Forwarded-For` refusal is defence in depth only: uvicorn trusts that header from any peer, and a backend-network caller can simply omit it (RT27).
  - Exposed:
    - window gauges `cyberlab_jobs{kind,subkind,status,window}` for 1h, 24h and 7d;
    - `cyberlab_job_failure_ratio`;
    - the summary `cyberlab_job_duration_seconds{quantile}` (p50 / p95 / p99, run and queue);
    - `cyberlab_parse_success_ratio{analyzer}`;
    - active queue gauges from the `*_index` tables.

  No Prometheus server is added to compose (RAM); DEPLOYMENT gets a scrape config.
- **`GET /orgs/{org}/ops/metrics?window=`** (`audit.read`, RLS on the tenant tables): the org's own failure rate, latency and parse success per analyzer.
- **Recorded runs:** `scripts/ops_metrics.py` (a heavy step, run alone) replays the M2 dataset and the M3 sample set through the real workers three times through the API, then reads `job_outcomes` into `plans/reports/ops-metric-YYMMDD.md`. The gate's own e2e jobs are recorded as well.
- **Live TI / AI runs:** `scripts/live_run.mjs` refuses to run without `CYBERLAB_LIVE=1`, `.secrets/live.env` and `--max-calls` / `--max-usd`. It runs the existing `test_ai_provider_live.py`, `test_ti_provider_live.py` and `test_ai_eval_live.py` and fills `plans/reports/live-run-YYMMDD.md`. It is never part of the gate. Running it needs the user's keys and budget (a user decision); without them the report says "not run".

**Security hardening** (decision; cheap, high-value items only)
- **Global per-user rate limit** in `current_user`: `RATE_LIMIT_USER_PER_MIN` (600), keyed by user id. The answer is 429 with `Retry-After`. Redis failure fails closed, like the denylist. Test and e2e environments raise the limits.
  - **No anonymous per-IP middleware (RT14, cut):** a request carrying any bogus access cookie would skip it and then get a cheap 401 before the per-user limit, it needs a `main.py` change outside its phase, and the unauthenticated surface (login, register, refresh, signing keys) already has its own limits. Residual: no gateway-level flood limit (Caddy has none without a plugin), recorded in THREAT_MODEL.
- **Evidence view audit:** `evidence.viewed` (detail) and `evidence.custody_viewed` (custody list), deduplicated per (user, evidence, action) for 15 minutes through Redis `SET NX EX`. They go to `audit_logs`, not custody: custody is handling, the M1 split.
- **Declared type vs detected type:** at insert, `evidence.declared_type` (the extension family) and `type_mismatch` (vs libmagic and the magic routing) are set. 0014 adds them as nullable columns, write-once through `evidence_immutable`.
  - **Uploads are never rejected** (decision): an evidence platform must accept whatever an analyst collects, and rejecting disguised malware would break custody.
  - A mismatch writes the audit `evidence.type_mismatch` and shows a UI badge.
  - An org-level reject list is deferred.
- **SSE-S3 at rest:**
  - MinIO's built-in KMS key (`MINIO_KMS_SECRET_KEY_FILE`, a compose secret; format `<key-name>:<base64 32 bytes>`) and `mc encrypt set sse-s3` on every bucket in minio-init.
  - New objects only; existing objects stay plaintext until rewritten (documented).
  - **The key also encrypts MinIO's IAM and config (RT7):** losing or changing it leaves MinIO unable to read its users and policies, not only the SSE objects. Phase 1 first enables it on a copy of an existing volume and proves MinIO restarts and keeps its users. The manifest records the key fingerprint and a restore refuses a different key.
  - Presigned POST and GET are unaffected (phase 6 tests the analyzer paths).
  - Residual: the key sits on the same host, so this protects against loss of the volume or disk only.
- **Object-store image path:**
  - Upstream is archived. Phase 6 builds an **object-store conformance suite**: object lock at creation, per-object GOVERNANCE retention (extend, refuse to shorten), delete of a locked version refused without bypass, legal hold, exact-version GET, presigned POST with `content-length-range`, a presigned version GET, SSE-S3 and `ListObjectVersions`.
  - Candidates:
    - **(a)** a maintained, on-disk-compatible MinIO community fork image. Known on 2026-11-06 (RT28): `pgsty/minio` ("SILO", AGPLv3, Docker Hub images), which states the upstream env vars, `server` command and `/data` on-disk format; it also restores the web console, which must stay unpublished (MinIO sits on internal networks only). Phase 6 re-verifies cadence, CVE fixes and signatures;
    - **(b)** our own build of the last upstream release (`infra/minio/image/Dockerfile`; no future patches);
    - **(c)** RustFS, SeaweedFS or Ceph RGW.
  - Only (a) and (b) keep the on-disk format, and so the version-id pins. Bitnami's data dir is `/bitnami/minio/data`, upstream's `/data`: hence `MINIO_DATA_DIR` and the dir-relative tar. They are the only drop-in path; (c) would need a re-architecture and is recorded as such.
  - Phase 6 writes `plans/reports/researcher-YYMMDD-m7-object-store.md`. **The parent (or user) picks.** The switch is the parametrized `MINIO_IMAGE` / `MC_IMAGE` / `MINIO_DATA_DIR`, proven by the conformance suite and by a drill that restores a bitnami volume into the new image.

**Sandbox design** (decision; design and contract only; dynamic analysis stays disabled)
- **`docs/SANDBOX_SECURITY.md`:**
  - **Placement:** CAPE v2 on a **dedicated KVM host**, never Docker Desktop / WSL2, the app host or a shared API container.
  - **VMs:** guests are reverted to a golden snapshot before each job and destroyed after it.
  - **Network:** a per-VM host-only bridge with nftables default-drop. Routing is `none` (default) or `sinkhole` (INetSim / FakeNet on the sandbox host). `internet`, Tor and VPN routing are forbidden.
  - **Guest isolation:** no shared folders, no clipboard, no drag-and-drop, guest additions removed, no USB passthrough.
  - **Limits:** vCPU, RAM and disk caps; run ≤ 300 s with a hard kill.
  - **Interfaces:**
    - a one-way `sandbox-bridge` takes the sample with a presigned GET and verifies its sha256 before submission (and the guest agent verifies it again);
    - results leave as a `dynamic.v1` stream through a presigned POST and are ingested by the trusted ingest exactly like `static.v1`;
    - the management network is separate.
  - **Audit:** custody event `sent_to_sandbox`, the job audit, and the retained CAPE logs.
  - **Gating:** a gating checklist with the isolation acceptance tests (escape assumptions, egress, snapshot revert proof, management-network separation, kill switch).
- **`packages/py-jobs/src/cyberlab_jobs/dynamic.py`:** `DYNAMIC_SCHEMA = "dynamic.v1"`, `DynamicJobV1`, the `DynamicRecordLine` union (process, file, registry, network (sinkholed, with the route mode), signature, dropped file as hashes only), `DynamicSummaryV1` and `DYNAMIC_ENABLED = False`.
- **Gate tests:** `Analyzer` has no `dynamic` value; no queue, broker user, compose service or route exists; the contract round-trips its fixtures.

**Docs** (the audit's quick wins and overclaims, re-checked by phase 10 before editing):
- the §11 name mapping in DATABASE;
- the OpenSearch and correlation paragraph in ARCHITECTURE;
- the stale TESTING rows (72, 85) and the HostileProvider ASR 0.290;
- the PRD title and non-goals;
- ROADMAP "Later" additions: Autopsy, platform API keys, TCP stream reassembly and file carving;
- the TShark scope in PCAP_ANALYSIS and README;
- the README AI live-run and PDF/A-3a caveats;
- the precision / recall caveat in README and ROADMAP;
- the stray `scripts;C/` directory.

### Data model (migration **0014**; the M4–M6 conventions: FORCE RLS on every tenant table, composite tenant FKs, S/I grants plus per-column UPDATE, named checks with `octet_length` caps, no DELETE grant to the app role)

| Table / change | Scope / grants | Notes |
|---|---|---|
| `org_retention_policies` | tenant; app S/I + UPDATE (values, `pending_*`, `effective_at`, `enforce`, `pending_enforce`, `enforce_effective_at`, `updated_by/at`) | PK org; three `*_days` int NULL plus checks on the floors; `pending_*` and `effective_at` for lowered values; `pending_enforce` / `enforce_effective_at` (RT1) |
| `retention_policy_index` | system lookup like `analysis_job_index` (policy `app_org_id() IS NULL OR organization_id = app_org_id()`); app S/I/U; retention SELECT | PK org, `updated_at`; written with every policy PUT; the sweep's org list (RT3) |
| `users` (seed row) | existing | the fixed system user `retention@system.invalid` (`RETENTION_SYSTEM_USER_ID`), inactive, unusable hash: the custody actor (RT12) |
| `legal_holds` | tenant; app S/I + UPDATE (`released_by/at`, `release_reason`); retention UPDATE (`s3_synced_at`) | `scope` `org/investigation`, `investigation_id` (composite FK, NULL for org scope), reason ≤ 500, `placed_by/at`; trigger: release once; index on holds active or released within the delay (RT1) |
| `retention_runs` | tenant; app SELECT + INSERT (a dry-run requested through the API); retention S/I/U (`status`, `counts`, `finished_at`, `error`) | `mode` `dry_run/enforce`, `trigger` `schedule/manual`, `counts` jsonb ≤ 8 KiB, `sample` jsonb ≤ 64 KiB |
| `retention_run_items` | tenant, append-only (retention INSERT) | run FK, `category`, `ref_table`, `ref_id`, `job_id`, `rows`, `bytes`, `object_key`, `object_version_id`, `outcome` (`purged/skipped_hold/skipped_locked/object_delete_failed/kept_cited`) |
| `evidence_purges` | tenant, append-only (retention INSERT) | PK `evidence_id` (composite FK), `run_id`, `object_version_id`, `sha256`, `purged_at` |
| `evidence_custody_events` | existing | the enum `custody_action` gains `purged` (and `sent_to_sandbox`, reserved) through `ALTER TYPE … ADD VALUE` (RT12; usable only after the migration commits; the downgrade cannot drop enum values and leaves them, documented and allowed by `test_migrations.py`) |
| `evidence` (+cols) | existing; write-once through `evidence_immutable` | `declared_type` text NULL ≤ 32, `type_mismatch` bool NULL |
| `correlation_keys` | tenant; app S/I (no DELETE for anyone, RT9) | see Correlation; unique (job_id, kind, key); index (org, kind, key); GIN `gin_trgm_ops` on `value_norm` |
| `correlation_job_state` | tenant; app S/I | PK `job_id`, `indexed_at`, `keys` int, `truncated` bool |
| `job_outcomes` | system (no RLS, no tenant data); app SELECT; trigger INSERT; retention DELETE | see Runtime metrics; index (`finished_at`), (`kind`, `finished_at`) |
| `pg_trgm` + search indexes | — | `CREATE EXTENSION IF NOT EXISTS pg_trgm` (a trusted extension; the owner may create it); expression GIN FTS indexes on investigations (title, description), `analysis_findings` (title, description), `network_alerts` (signature), `analyst_note_versions` (body); trigram on the evidence filename and the case number; plain `CREATE INDEX` inside the migration transaction (RT20: `migrate` runs before any writer, and `CONCURRENTLY` in an `autocommit_block` would make a failed upgrade half-applied with invalid indexes). FTS expressions wrap nullable columns in `coalesce(…, '')`, and the search queries use the identical expressions |
| `forbid_mutation_except_retention()` | — | replaces the trigger on `ti_results`, `ai_run_inputs`, `ai_context_refs`, `ai_outputs`, `ai_citations` |
| DELETE grants to `cyberlab_retention` | — | the bulk derived tables, `ti_results` + `ti_run_items` (RT10), `ai_*` run tables, `report_renders` artifacts (a `purged` status; the transition trigger allows `succeeded → purged` only for that role), `job_outcomes`. Not `correlation_*` (RT9) |
| `report_renders` | existing | status check gains `purged` (re-render allowed); `ux_report_renders_version_id_format_renderer` is recreated with `WHERE status NOT IN ('failed', 'purged')`, otherwise the purged row blocks the re-render (RT11) |

Role bootstrap: `cyberlab_retention` is created by the new `infra/postgres/init/02-m7-roles.sh` (fresh volumes) **and** by the idempotent one-shot `db-bootstrap` service (postgres image, superuser, `depends_on` before `migrate`) for existing volumes, lanes and restores. 0014 fails with a clear message when the role is missing.

## Red-team changes (2026-11-06)

**Reviewers and sources.** Four hostile reviewers (security, reliability / restore, product / legal, scope / parallelism) checked this plan and the coverage audit against the code:
- API core: `core/{config,deps,rbac,tenancy,rate_limit,client_ip}.py`;
- modules: `evidence/{router,service,uploads}.py`, `ioc_collections/normalize.py`, `threat_intel/{normalize,providers/base}.py`;
- migrations 0001, 0003, 0004, 0009, 0011, 0012 (FKs, enums, RLS policies, append-only triggers, the render unique index);
- py-jobs `results.py` (`IocType`);
- infra: `docker-compose.yml`, `infra/postgres/init/01-init.sh`, `infra/minio/{init.sh,api-policy.template.json}`, `infra/caddy/{Caddyfile,common.caddy}`, the api Dockerfile;
- scripts and web: `scripts/{lane-test.sh,verify.mjs}`, the web page and component tree.

They also checked the MinIO fork status (`pgsty/minio`), the MinIO KMS / static-key docs (IAM and config encryption) and the MinIO versioned-delete permission docs. No container was run (a test sequence was in progress).

**Result:** 38 findings: 2 High, 18 Medium, 18 Low. 28 were accepted and applied, and 10 rejected. The seed questions are answered by RT1 (Q3), RT2 / RT6 / RT25 (Q5), RT4 / RT22 (Q4), RT7 / RT28 (Q1), RT10 (Q2), RT13 (Q7), RT14 (Q8), RT18 and RT29–RT32 (Q10); Q6 and Q9 stay as phase 5 and phase 1 measurements (no finding).

| ID | Finding (failure scenario) | Severity | Disposition |
|---|---|---|---|
| RT1 | **The delay covers values only.** A hijacked admin finds a short policy that has been effective in dry-run for months, turns `enforce` on and starts a manual run: instant destruction. Or releases a case hold and runs at once. | High | Accepted → turning `enforce` on and releasing a hold both take effect after `RETENTION_POLICY_DELAY_DAYS` (`pending_enforce`, `enforce_effective_at`; a released hold protects until `released_at + delay`); the worker reads mode and values from the DB only (plan Retention; phases 1, 3, 9, 11). |
| RT2 | **The drill's `down -v` can wipe the main stack.** `docker-compose.yml` declares `name: cyberlab`; an inherited `COMPOSE_PROJECT_NAME` or a mis-passed `--project` makes the drill's `finally: down -v` remove `pgdata` and `miniodata` of the dev stack, i.e. all evidence. | High | Accepted → `stack.mjs` refuses `down -v` unless the project is the literal `cyberlab-drill`, strips `COMPOSE_*` from the child env and checks the project label of every volume; restore never removes volumes; a unit test (plan Restore drill; phase 2). |
| RT3 | **The sweep sees no org.** RLS policies have no `TO` clause, so they bind `cyberlab_retention`, and `orgs_select` shows only member or current orgs. A system session of the retention role reads zero organizations, and retention silently never runs. | Medium | Accepted → system lookup `retention_policy_index` (the `analysis_job_index` policy pattern) written with every policy PUT; the sweep reads it (plan Retention, Data model; phases 1, 3). |
| RT4 | **`restore_verify` compares a mutated DB.** Digests are checked after `migrate`, the refresh-token revocation, api startup and the drill's login, so `refresh_tokens` (and everything after an upgrade) always differs. An ordered `string_agg` also hits the 1 GB text limit on `network_records`, and its text form depends on `TimeZone` and float settings. Retention and legal hold had no captured baseline. | Medium | Accepted → three verify phases: `--db` right after `pg_restore` (fingerprint, exact row counts; content digests dropped), `--objects` against an `objects.json` captured at backup time (version, size, etag, retention, legal hold), `--rls` after start (plan Backup and restore; phases 2, 11). |
| RT5 | **"An API compromise cannot purge" is false, and the api would get S3 hold control.** The api MinIO user already has `DeleteObject` / `DeleteObjectVersion` on the evidence buckets (failed-upload cleanup), effective once the 30-day GOVERNANCE lock expires. Giving it `PutObjectLegalHold` would also let it clear S3 holds first. | Medium | Accepted → the retention worker owns S3 hold sync (`retention.sync_holds`, published after the hold commit and run every sweep); the api gains no legal-hold action; the purge user gains Put/GetObjectLegalHold; the API-compromise and worker-compromise residuals are stated and recorded in THREAT_MODEL; `reconcile_orphans` and `restore_verify` report a pinned version missing without a tombstone (plan Retention; phases 1, 3, 6, 10). |
| RT6 | **Backups as an exfiltration and AV target.** A backup holds every org's evidence (pre-SSE objects in clear, malware samples included), argon2 hashes, refresh-token hashes, sealed keys and MinIO IAM, at `./backups/` on the host NTFS disk. The repo already keeps the e2e samples in a named volume because host AV quarantines them, so AV can also lock or quarantine `minio-data.tar` mid-drill. "No secrets in it" understates it. | Medium | Accepted → the drill keeps its backup in the volume `cyberlab-drill_backups`; `pnpm backup` prints what a backup contains (TLP:RED, no plaintext secret), recommends an AV-excluded target and age encryption; DEPLOYMENT / THREAT_MODEL updated (plan Backup and restore; phases 2, 10). |
| RT7 | **The KMS key protects more than SSE objects.** With a static KMS key MinIO also encrypts its IAM and config. A lost or changed key leaves MinIO unable to read its users and policies; enabling it on the existing bitnami volume migrates that config. A restore with a different key fails at boot, far from the cause. | Medium | Accepted → phase 1 enables KMS on a copy of an existing volume first; the manifest records the key fingerprint and restore refuses a mismatch; DEPLOYMENT states the full impact (plan SSE-S3, Restore; phases 1, 2, 10). |
| RT8 | **Correlation keys would not join TI or collections.** `compute_ioc_key` uses the `IocType` value (`ipv4` / `ipv6`), not `ip`; M6 keys JA3 trimmed, not lowercased. The plan reinvented a normalizer that M6 already has (`normalize_item`: TI normalize, private values kept, `opaque_key` for pcap-only types). JA3 / JA3S / cert are already `iocs` rows, and `network_records` has `details`, not `attributes`. | Medium | Accepted → `correlation_key` delegates to `normalize_item`; kinds are its output types (+ `cert_sha256`); sources are `iocs`, samples and evidence hashes; no `network_records` parsing (plan Correlation; phases 1, 4). |
| RT9 | **Purging correlation keys churns and loses the pivot.** The keys derive only from kept rows, so deleting them (and `correlation_job_state`) makes the indexer rebuild them on the next tick, and closed cases stop correlating, which is the main value. | Medium | Accepted → `correlation_*` are never purged; no DELETE grant (plan Retention, Data model; phases 1, 3, 11). |
| RT10 | **FKs make the TI and AI purge fail.** `ti_run_items.result_id` references `ti_results` (with a check that done / cached items keep it), and later runs reuse old results as `cached`. `ai_runs.parent_run_id` / `supersedes_run_id` link run trees. Deleting by age alone raises FK errors or deletes recent history. | Medium | Accepted → a TI result goes with its items only when every referencing item's run predates the cutoff (DELETE on `ti_run_items`); AI runs go as whole eligible, uncited trees; explicit FK order; cascades into append-only tables are refused by design (plan Retention, Data model; phases 1, 3). |
| RT11 | **A purged render blocks its re-render.** `ux_report_renders_version_id_format_renderer` is unique `WHERE status <> 'failed'`, so a `purged` row keeps the slot and the re-render insert fails. | Medium | Accepted → 0014 recreates the index with `status NOT IN ('failed', 'purged')`; phase 3 tests the re-render (plan Data model; phases 1, 3, 11). |
| RT12 | **No custody actor and no `event` check.** Custody `actor_id` is a NOT NULL FK to `users`, and the column is `action`, an enum `custody_action`. The plan's "retention system user from settings" does not exist. | Medium | Accepted → 0014 seeds the inactive system user `retention@system.invalid` (fixed id, unusable hash) and runs `ALTER TYPE custody_action ADD VALUE`; the downgrade leaves the values (documented); a test proves the user cannot log in (plan Retention, Data model; phases 1, 3). |
| RT13 | **The search query leaks through URLs.** `GET /search?q=` is in uvicorn's access log (the filter needs logging config that phase 4 does not own), in the Next.js request log of `/o/{org}/search?q=` and in browser history. | Medium | Accepted → `POST /search` with a JSON body (CSRF as usual); the page keeps `q` in the URL fragment; no log filter (plan Search; phases 1, 4, 8, 11). |
| RT14 | **The anonymous limiter is bypassable and out of place.** "Requests without an access cookie" skips any request with a bogus cookie, which then gets a cheap 401 before the per-user limit. It also needs `main.py`, frozen to phase 1. The unauthenticated routes already have their own limits. | Medium | Accepted → cut (YAGNI); per-user limit only; no gateway flood limit recorded as a residual (plan Security hardening; phases 1, 6, 11). |
| RT15 | **Lane retention tests would hit the wrong database.** `lane-test.sh` rewrites only `DATABASE_URL`, the migration URL and `REDIS_URL` per lane. `RETENTION_TEST_DATABASE_URL` would still point at the default `cyberlab_test` while the seed is in `cyberlab_b3_test`. | Medium | Accepted → phase 1 extends `lane-test.sh` to rewrite `RETENTION_TEST_DATABASE_URL` too (plan Parallel execution; phases 1, 3). |
| RT16 | **The web mount points are not file-disjoint and partly fictional.** `components/analysis/ioc-*` and `components/evidence/evidence-integrity*.tsx` do not exist (`iocs-tab.tsx`, `evidence-actions.tsx`). Phase 8 (Related cases) and phase 9 (hold card, badge) would both edit the case overview and workspace. | Medium | Accepted → phase 1 creates and mounts empty slot components (`correlation/ioc-seen-in.tsx`, `correlation/related-cases-card.tsx`, `legal-holds/case-hold-card.tsx`, `investigations/legal-hold-badge.tsx`, `evidence/evidence-integrity-strip.tsx`) and disables download / verify in `evidence-actions.tsx` on `purged_at`; phases 8 and 9 fill their components only (plan Frozen interfaces 9, ownership; phases 1, 8, 9, 11). |
| RT17 | **The drill cannot seed its tombstone.** The drill sets `EVIDENCE_LOCK_DAYS=1` and the purge user has no governance bypass, so deleting the tombstoned version fails; giving the api service the purge keys for the seeder also contradicts the env check. | Medium | Accepted → the seeder is a one-off `compose run` container in the drill project that uses the drill MinIO root with bypass for that one object (plan Restore drill; phase 2). |
| RT18 | **150 h is optimistic.** Phase 1 gains the system user, the policy index, the slot components and `lane-test.sh`; phase 3 the hold-sync task and the run trees; phase 11 the drill integration. | Medium | Accepted → 22 + 17 + 23 + 16 + 10 + 13 + 10 + 9 + 9 + 8 + 16 = 153 h, with RT4 (digests), RT8 (normalizer reuse), RT13 and RT14 cutting work; critical path about 69 h (Phases). |
| RT19 | **The indexer competes with ingest.** The ingest worker is a solo pool that also runs result ingest and the reaper tasks; 20 jobs × 20 000 keys per 60 s tick can delay real results during a backfill. | Low | Accepted → ≤ 5 jobs and a 10 s budget per tick (`CORRELATION_INDEX_BUDGET_S`); the backfill script runs as a one-off container (plan Correlation; phases 1, 4). |
| RT20 | **`CONCURRENTLY` in 0014 is risk without benefit.** It breaks migration atomicity (a failure leaves a half-applied upgrade and invalid indexes), while `migrate` runs before any writer. | Low | Accepted → plain `CREATE INDEX` in the transaction; `coalesce` in the FTS expressions (plan Data model; phase 1). |
| RT21 | **Quiesce kills jobs and lanes.** Stopping analyzers mid-job turns in-flight jobs into reaper failures (polluting `job_outcomes`); lane and test-profile containers share MinIO, so stopping it breaks them. | Low | Accepted → drain first (timeout, `--force`), refuse while test or `run` containers are up (plan Backup; phase 2). |
| RT22 | **A crash between tombstone and delete fails the verifier.** It leaves the version present with no `object_delete_failed` item. | Low | Accepted → reported as the warning `purged_pending_delete` by `restore_verify` and `reconcile_orphans`, retried by the next run (plan Retention, Restore; phases 2, 3). |
| RT23 | **Bulk rows are citable too.** `report_citations` reference rows by `ref_table` / `ref_id` (flows, records, timeline), so purging them breaks citation deep links. | Low | Accepted → cited bulk rows are `kept_cited`, like TI and AI (plan Retention; phase 3). |
| RT24 | **Closure detection gaps.** Cases closed before M6 have no status event; closed (not archived) cases still accept analyses, so a job can be queued on a case being purged. | Low | Accepted → no status event → never selected; a case with a queued or running job is skipped (plan Retention; phase 3). |
| RT25 | **Drill portability.** A tar rooted at `/bitnami/minio/data` cannot extract into an image using `/data`; the drill's slot lock must use exactly the lock root of `lane-test.sh` (`$TMPDIR` in Git Bash vs Node's `os.tmpdir()`). | Low | Accepted → dir-relative tar; one shared lock-root resolution (`LANE_LOCK_ROOT`, defaulting as `lane-test.sh` does) (plan Backup, Restore drill; phases 1, 2). |
| RT26 | **Access tokens survive a restore.** Redis is not restored, so logged-out access tokens are valid again until expiry; revoking refresh tokens does not cover them. | Low | Accepted → the DR runbook rotates `JWT_SECRET` when restoring after an incident (plan Backup; phase 10). |
| RT27 | **Check scopes and the metrics header claim.** `api-test` / `e2e` legitimately hold the retention test URL and purge test keys, so "no other service holds them" must exclude the test profile. The `X-Forwarded-For` refusal on `/internal/metrics` is not a control, since uvicorn trusts the header from any peer. | Low | Accepted → the env check covers runtime services; the bearer token is the stated control (plan Runtime metrics; phases 5, 11). |
| RT28 | **Object-store facts are stale.** A maintained fork image exists: `pgsty/minio` (SILO), stated drop-in with the same env, command and `/data` format; it re-enables the console. | Low | Accepted → named as candidate (a), console kept unpublished, re-verified by phase 6 (plan Object-store; phase 6). |
| RT29 | Cut the S3 legal-hold mirroring (YAGNI). | Low | Rejected → with RT5 it is the only hold control independent of the DB selector, and it protects held evidence from the api's cleanup-delete grant; the cost is one task. |
| RT30 | Cut the policy delay (YAGNI). | Low | Rejected → it is the only control against a hijacked admin session (RT1 extends it). |
| RT31 | Cut the related-cases ranking. | Low | Rejected → one SQL query over the same index; it is the analyst's main cross-case pivot. |
| RT32 | Cut the org operations page and route. | Low | Rejected → without a Prometheus server it is the only UI for the §14 numbers, and it is about 4 h. |
| RT33 | Encrypt backups inside the script (age). | Medium | Rejected for M7 → needs a pinned age binary or image and key management; operator encryption is documented, and the drill never writes to the host (RT6). |
| RT34 | Audit search queries, hashed, for §10. | Low | Rejected → a hashed IOC is dictionary-reversible; results are RLS-bound and evidence views are audited. Decision recorded. |
| RT35 | Remove the api's evidence delete grant (stage uploads under a prefix). | Medium | Rejected for M7 → it changes the M1 upload path and the version pins; residual recorded (RT5). |
| RT36 | Make `enforce` per category. | Low | Rejected → each category is already off while NULL. |
| RT37 | Make `job_outcomes` a tenant table so the org page reads it. | Low | Rejected → `/internal/metrics` would then need a definer aggregate across orgs; the tenant tables already answer per org. |
| RT38 | Let the drill run a real retention purge (retention-worker in the drill). | Low | Rejected → +384 MB and time in the exclusive gate step; the purge is proven by phase 11's pipeline test. |

Seed questions given to the reviewers (kept for traceability):
1. Does the quiesced volume tar of `bitnamilegacy/minio` (`/bitnami/minio/data`) restore into the candidate image with identical version ids, retention, legal holds and SSE metadata? Is `xl.meta` stable across that version gap?
2. Can `cyberlab_retention` delete anything outside its categories through FK cascades (`ondelete="CASCADE"` on the `*_index` tables) or RLS gaps? Does `forbid_mutation_except_retention` keep `audit_logs` absolutely immutable?
3. Can a hijacked admin destroy data before `RETENTION_POLICY_DELAY_DAYS`, for example through `enforce` plus an existing short policy, a manual run, or a hold release followed by a run?
4. Is the purge order (tombstone commit, then object delete) safe under crashes, and does `reconcile_orphans` understand tombstones?
5. Is the restore drill reliable on Windows Docker Desktop (tar ownership, volume mount paths, `MSYS_NO_PATHCONV`), and does it fit next to nothing else in 4–8 GB?
6. Do the `job_outcomes` triggers leak tenant data or break the terminal-state triggers already on those tables? What do they cost under the reaper's bulk fails?
7. Do the search queries stay under 3 s on the seeded volume? Can trigram `%` on short `q` scan everything? Is not logging query text acceptable for §10?
8. Does the global per-user limit break the e2e, the upload slots or the polling UIs (AI runs, renders)?
9. Do SSE-S3 buckets still accept the analyzers' and the renderer's presigned POST (policy conditions, `Content-MD5`)?
10. Scope: is anything here YAGNI for a learning-grade, single-node platform? Candidates: the S3 legal-hold mirroring, the policy delay, the related-cases ranking, the org metrics page.

## Phases

| Phase | Name | Group | Depends on | Status |
|-------|------|-------|------------|--------|
| 1 | [Foundation contracts migration 0014 and ops services](./phase-01-foundation-contracts-migration-0014-and-ops-services.md) | A | — | Pending |
| 2 | [Backup restore and restore drill](./phase-02-backup-restore-and-restore-drill.md) | B (2a, lane 2; the drill is a heavy step, alone) | 1 | Pending |
| 3 | [Data retention purge and legal hold](./phase-03-data-retention-purge-and-legal-hold.md) | B (2b, lane 3) | 1 | Pending |
| 4 | [Deterministic correlation and org search API](./phase-04-deterministic-correlation-and-org-search-api.md) | B (2c, lane 4) | 1 | Pending |
| 5 | [Runtime job metrics and live run procedures](./phase-05-runtime-job-metrics-and-live-run-procedures.md) | B (2d, lane 5; the replay is a heavy step) | 1 | Pending |
| 6 | [Security hardening rate limit view audit type mismatch and object storage](./phase-06-security-hardening-rate-limit-view-audit-type-mismatch-and-object-storage.md) | B (2e, lane 6; an image build is a heavy step) | 1 | Pending |
| 7 | [Sandbox security design and dynamic v1 contract](./phase-07-sandbox-security-design-and-dynamic-v1-contract.md) | B (2f, lane 7, unit only) | 1 | Pending |
| 8 | [Search and correlation frontend](./phase-08-search-and-correlation-frontend.md) | B (2g, web only) | 1 (frozen contracts) | Pending |
| 9 | [Retention legal hold and operations frontend](./phase-09-retention-legal-hold-and-operations-frontend.md) | B (2h, web only) | 1 (frozen contracts) | Pending |
| 10 | [Docs threat model and audit quick wins](./phase-10-docs-threat-model-and-audit-quick-wins.md) | C | B merged | Pending |
| 11 | [Hardening e2e restore drill metric and gate](./phase-11-hardening-e2e-restore-drill-metric-and-gate.md) | D | all | Pending |

Effort (RT18): 22 + 17 + 23 + 16 + 10 + 13 + 10 + 9 + 9 + 8 + 16 = **153 h**. Critical path: 1 → max(B) (phase 3, 23 h) → 10 → 11, about 22 + 23 + 8 + 16 = **69 h** of wall time with eight group-B agents. At most three API lanes run at once.

## Dependencies and parallelism

**Cross-plan:** blocked by `261106-0900-cyberlab-m6-reports`. Its gate (`pnpm verify:prod`) must be green and merged first. Phase 1 confirms that the alembic head is `0013` and that the M6 files it edits are final. The M6 files in question: `workers/{celery_app,tasks}.py`, `evidence/{schemas,models}.py`, compose, `infra/minio/*`, `scripts/{verify,e2e}.mjs`, `lib/{nav,audit-actions}.ts`. It then creates `feat/m7-platform-ops` from the M6 merge.

**Group A: phase 1, one agent; frozen when committed.** Only the parent changes frozen files afterwards. A change request goes to the parent, which decides and broadcasts it.

**Frozen interfaces** (phase 1 notes record the exact signatures):
1. **Migration `0014_m7_platform_ops.py`** and the models:
   - `retention/models.py` (`OrgRetentionPolicy`, `LegalHold`, `RetentionRun`, `RetentionRunItem`, `EvidencePurge`);
   - `correlation/models.py` (`CorrelationKey`, `CorrelationJobState`);
   - `ops/models.py` (`JobOutcome`);
   - `evidence/models.py` (`declared_type`, `type_mismatch`) and the custody `purged` event;
   - `reports/models.py` (`purged` render status).

   Later schema needs go into **0015**, assigned by the parent.
2. **Schemas and 501 stubs for every new route**, then one `pnpm gen:contracts` run:
   - `retention/schemas.py`;
   - `correlation/schemas.py`;
   - `search/schemas.py`;
   - `ops/schemas.py`;
   - the additions to `evidence/schemas.py`: `EvidenceOut.purged_at`, `type_mismatch`, `declared_type`, `legal_hold`;
   - the additions to `investigations/schemas.py`: `legal_hold`;
   - the error codes `evidence_purged` (410), `legal_hold_active`, `policy_floor`, `retention_acknowledgement_required`, `search_query_invalid`.

   Routes (all under `/api/v1/orgs/{org_id}` unless noted):

   | Method and path | Permission | Phase |
   |---|---|---|
   | `GET /retention/policy`, `PUT /retention/policy` | `org.read` / `org.update` | 3 |
   | `POST /retention/preview` | `org.update` | 3 |
   | `GET /retention/runs`, `GET /retention/runs/{run}`, `POST /retention/runs` (manual run) | `audit.read` / `org.update` | 3 |
   | `GET /legal-holds`, `POST /legal-holds`, `POST /legal-holds/{hold}/release` | `investigation.read` / `org.update` | 3 |
   | `GET /analyses/{job}/correlations` | `investigation.read` | 4 |
   | `GET /correlations?kind=&value=` | `investigation.read` | 4 |
   | `GET /investigations/{inv}/related` | `investigation.read` | 4 |
   | `POST /search` (body `{q, types, cursor}`; RT13) | `investigation.read` | 4 |
   | `GET /ops/metrics?window=` | `audit.read` | 5 |
   | `GET /internal/metrics` (root app, not `/api`) | bearer `METRICS_TOKEN` | 5 |
3. **Cross-phase entry points** (stubs raising `NotImplementedError` or returning 0; ownership moves to the named phase, which never changes the signature):
   - `retention/select.py`: `async candidates(session, org_id, policy: EffectivePolicy, *, now, limit) -> CandidateSet` (phase 3; the API preview and the worker both call it);
   - `retention/holds.py`: `async active_holds(session, org_id, *, now) -> HoldSet` (active, or released less than the delay ago, RT1) and `HoldSet.covers(investigation_id) -> bool` (phase 3; phases 4–6 never call it);
   - `workers/retention_tasks.py`: the task `retention.sync_holds(org_id)` (RT5), published by the hold routes after the commit;
   - `workers/retention.py`: `async sweep() -> int` and `async run_org(org_id, run_id) -> RunOutcome` (phase 3);
   - `correlation/normalize.py`: `correlation_key(ioc_type, raw) -> tuple[str, str, str] | None` (`(kind, key, value_norm)`, delegating to `ioc_collections.normalize.normalize_item`, RT8; phase 4);
   - `correlation/indexer.py`: `async index_pending(limit) -> int`, called by the `correlation.index_pending` task that phase 1 registers (phase 4);
   - `ops/error_classes.py`: `ERROR_CLASS: Mapping[str, ErrorClass]` and `classify(code) -> ErrorClass` (**implemented** in phase 1, frozen; phase 1 enumerates every code from the analyzers, TI, AI and renders);
   - `ops/metrics.py`: `async platform_metrics(session, *, now) -> PlatformMetrics` and `render_prometheus(m) -> str` (phase 5);
   - `core/audit_dedupe.py`: `async once_per(key, ttl_s) -> bool` (**implemented** in phase 1: Redis `SET NX EX`; used by phase 6).
4. **Settings** (`core/config.py`, all added by phase 1):
   - the `RETENTION_*` settings: floors, `POLICY_DELAY_DAYS`, batch sizes, `DATABASE_URL` for the retention role, purge MinIO credentials (role `retention` only);
   - `CORRELATION_COMMON_KEY_JOBS`, `CORRELATION_MAX_KEYS_PER_JOB`, `CORRELATION_INDEX_BUDGET_S` (RT19);
   - `SEARCH_*`;
   - `METRICS_TOKEN_FILE`;
   - `RATE_LIMIT_USER_PER_MIN` (no anonymous setting, RT14);
   - `RETENTION_SYSTEM_USER_ID` (the fixed id seeded by 0014, RT12);
   - `MINIO_KMS_SECRET_KEY_FILE` (minio only; the scripts read only its fingerprint, RT7);
   - `PROCESS_ROLE=retention` with its refusals: no JWT secret, seal or signing keys, app Redis or api MinIO user.
5. **Services** (compose; dev, test and prod):
   - `db-bootstrap`;
   - `retention-worker` and `retention-worker-test` (test profile, own broker db prefix);
   - the broker ACL user `retention` (`~retention* ~test.retention*`);
   - MinIO: the `cyberlab-purge` user and policy (with Put/GetObjectLegalHold, RT5), the api policy **unchanged**, SSE-S3 on every bucket, the KMS secret;
   - `MINIO_IMAGE` / `MC_IMAGE` / `MINIO_DATA_DIR` variables (defaults unchanged: bitnami);
   - the `metrics_token` secret on the api;
   - beat entries: `correlation.index_pending` every 60 s, `retention.sweep` daily at 02:30 UTC;
   - api-test env: `RETENTION_TEST_DATABASE_URL`, purge MinIO credentials, high rate limits;
   - `scripts/lane-test.sh`: also rewrites `RETENTION_TEST_DATABASE_URL` per lane (RT15), and exposes its lock-root resolution as `LANE_LOCK_ROOT` for the drill (RT25).
6. **Root scripts:** `package.json` entries `backup`, `restore`, `restore:drill`, `ops:metrics`, `live:run`, pointing to phase-1 stubs that exit 2 with "not implemented"; phases 2 and 5 replace the stub bodies. `.gitignore` gains `backups/`.
7. **Test helpers:**
   - `tests/ops_helpers.py`: seed a policy, holds, aged closed cases with purgeable rows and objects (evidence-test bucket, lock 0), correlation keys across two cases and two orgs, and `job_outcomes` rows;
   - `retention_session()` (the retention-role engine);
   - the fixture `tests/fixtures/dynamic/*.jsonl`, created **empty** and owned by phase 7.
8. **IDOR modules:** `tests/security/idor_cases_retention.py` (phase 3), `idor_cases_correlation.py` (phase 4) and `idor_cases_ops.py` (phase 5), merged by `test_idor_routes.py`, each with `PENDING_ROUTES` filled by phase 1. Phase 11 asserts they are empty.
9. **Web shared:**
   - `lib/audit-actions.ts` (the M7 actions);
   - `lib/nav.ts` (Search; Settings → Retention, Operations);
   - `lib/http-errors.ts` (the `evidence_purged` / `legal_hold_active` messages);
   - the empty `components/search/search-box.tsx` slot mounted in the shell header;
   - **every other web mount, as empty slot components mounted once (RT16):** `components/correlation/ioc-seen-in.tsx` (in `components/analysis/iocs-tab.tsx`, used by the pcap and static job pages), `components/correlation/related-cases-card.tsx` and `components/legal-holds/case-hold-card.tsx` (in `components/investigations/overview-tab.tsx`), `components/investigations/legal-hold-badge.tsx` (in `case-workspace.tsx` and the investigations list), `components/evidence/evidence-integrity-strip.tsx` (in the evidence page); `components/evidence/evidence-actions.tsx` disables download and verify when `purged_at` is set.
10. **`tests/conftest.py`, `test_rls_coverage.py`, `test_append_only.py`, `test_tenant_session_guard.py`** and the import guards are frozen in group B.

**Group B: phases 2–9, in parallel** (one subagent each, own worktree from the phase-1 commit, file-disjoint). Each phase's tests pass in isolation against the phase-1 stubs, helpers and frozen schemas. Cross-phase behaviour is tested after the merge (phase 11). Lanes run only their own test files plus `ruff` / `mypy` (API) or `pnpm --filter web lint typecheck test` on their own files (web). Nobody runs `pnpm verify` or the full suite in a lane.

| Phase | Owns (creates or edits; nobody else touches these in group B) |
|---|---|
| 2 (2a) | `scripts/{backup,restore,restore-drill}.mjs` (+ `scripts/lib/stack.mjs` for shared compose helpers and the `down -v` guard, + `stack.test.mjs`), `infra/backup/**` (drill overlay `docker-compose.drill.yml`, fingerprint SQL `security.sql`, `tables.sql` with row counts only), `apps/api/app/scripts/{restore_verify,drill_seed}.py`, `tests/unit/test_restore_verify.py`, `tests/integration/test_restore_verify_db.py`, `tests/unit/test_backup_manifest.py` |
| 3 (2b) | `app/modules/retention/**` (after the stubs), `app/workers/{retention_app,retention_tasks,retention}.py`, `evidence/{service,repository,transfer}.py` (`purged_at` / `legal_hold` on reads, `410` on download and verify), `analysis/service.py` (the `410` refusal of an analysis on purged evidence, one guard), `investigations/{service,repository}.py` (`legal_hold` on case reads), `app/scripts/reconcile_orphans.py` (tombstone awareness), `tests/security/idor_cases_retention.py`, `tests/integration/test_retention_{policy,holds,preview,purge,objects,append_only_exception,runs}.py`, `tests/unit/test_retention_select.py` |
| 4 (2c) | `app/modules/correlation/**` and `app/modules/search/**` (after the stubs; `normalize.py` imports, never edits, `ioc_collections/normalize.py`), `app/scripts/backfill_correlation.py`, `tests/security/idor_cases_correlation.py`, `tests/integration/test_correlation_{indexer,reads,related}.py`, `test_search.py`, `test_search_perf.py` (seeded volume, marked heavy-lite), `tests/unit/test_correlation_normalize.py` |
| 5 (2d) | `app/modules/ops/{metrics,router,internal}.py` (not `error_classes.py`), `scripts/{ops_metrics.py,live_run.mjs}`, `tests/security/idor_cases_ops.py`, `tests/integration/test_job_outcomes_triggers.py`, `test_ops_metrics.py`, `test_internal_metrics.py`, `tests/unit/test_prometheus_render.py` |
| 6 (2e) | `core/deps.py` (global limit in `current_user`), `evidence/router.py` (view audit), `evidence/uploads.py` + `core/filetypes.py` (declared type, mismatch), `infra/minio/image/**`, `tests/integration/test_object_store_conformance.py`, `test_storage_sse.py`, `test_global_rate_limit.py`, `test_evidence_view_audit.py`, `test_type_mismatch.py`, `tests/unit/test_filetypes.py`, `plans/reports/researcher-YYMMDD-m7-object-store.md` |
| 7 (2f) | `docs/SANDBOX_SECURITY.md`, `packages/py-jobs/src/cyberlab_jobs/dynamic.py` (the only py-jobs file outside phase 1), `tests/fixtures/dynamic/**`, `tests/unit/test_dynamic_contract.py`, `tests/unit/test_dynamic_gate.py` |
| 8 (2g) | `apps/web/lib/{search,correlation}.ts` (+ tests), `lib/use-search.ts`, `components/search/**` (after the stub), `components/correlation/**`, `app/(app)/o/[orgId]/search/**`; including the phase-1 slots `ioc-seen-in.tsx` and `related-cases-card.tsx`; no mount edits (RT16) |
| 9 (2h) | `apps/web/lib/{retention,legal-holds,ops-metrics}.ts` (+ tests), `components/retention/**`, `components/legal-holds/**`, `components/ops/**`, `app/(app)/o/[orgId]/settings/{retention,operations}/**`, the phase-1 slots `components/evidence/evidence-integrity-strip.tsx` (purged and mismatch states), `components/legal-holds/case-hold-card.tsx` and `components/investigations/legal-hold-badge.tsx`; no mount edits (RT16) |

- **Shared files touched only by phase 1:**
  - `core/config.py`, `app/main.py`, `app/models.py`;
  - `workers/{celery_app,tasks}.py`;
  - `evidence/{models,schemas}.py`, `investigations/schemas.py`, `reports/models.py`;
  - compose files, `.env.example`, `.gitignore`, `package.json`;
  - `infra/postgres/init/02-m7-roles.sh`, `infra/postgres/bootstrap.sh`, `infra/minio/{init.sh,api-policy.template.json,purge-policy.template.json}`, `infra/redis-broker/entrypoint.sh`;
  - `packages/py-jobs/**` (except phase 7's `dynamic.py`), `packages/contracts/**` (generated after phase 1, then after the group-B merge);
  - `scripts/lane-test.sh` (RT15, RT25);
  - `apps/web/lib/{audit-actions,nav,http-errors}.ts`, `components/search/search-box.tsx` (stub), the shell header mount;
  - the slot mounts (RT16): `components/analysis/iocs-tab.tsx`, `components/investigations/{overview-tab,case-workspace}.tsx`, the investigations list page, the evidence page and `components/evidence/evidence-actions.tsx`;
  - the frozen test files above.
- **Group B merge (parent):**
  1. Merge the eight worktrees. Any conflict is a plan bug.
  2. Run the full API suite on the main stack.
  3. Run `pnpm gen:contracts` and check for no drift.
  4. Run `pnpm --filter web test typecheck`.
  5. Pick the object-store image from phase 6's report and flip the `MINIO_IMAGE` default (parent decision).
  6. Run the restore drill once, alone.
  7. Fix seams in the owning files, one commit per phase.
- **Group C: phase 10** (docs) after the merge.
- **Group D: phase 11 last.** It is the only phase allowed to touch other phases' files, and only for gate fixes.
- **One commit per phase.** The stack stays deployable after each:
  - new routes answer 501 until their phase lands;
  - the retention worker runs dry-run only (and with no policy set, nothing is a candidate);
  - the correlation indexer returns 0;
  - the metrics endpoint is off without a token.

### Parallel execution on this host (the M5/M6 lane scheme, `scripts/lane-test.sh`; 4–8 GB free)

1. **One shared infra stack**, started by the parent after the M6 gate: `postgres`, `redis`, `redis-broker`, `minio` (+ init, `db-bootstrap`). Everything else is stopped during group B: web, gateway, analyzers, report, enrich, analyst and retention workers.
2. **Worktrees** `..\cyber-wt\m7-b{n}` (`-b m7/b{n}` from the phase-1 commit), with `.env` copied in.
3. **API lanes:** phase 2 → lane 2, phase 3 → lane 3, phase 4 → lane 4, phase 5 → lane 5, phase 6 → lane 6, phase 7 → lane 7.
   - Run with `scripts/lane-test.sh <lane> uv run pytest -q -p no:cacheprovider <own paths>`. The lane DBs `cyberlab_b{2..7}_test` exist from M5/M6; the conftest migrates them to 0014. `db-bootstrap` created the role cluster-wide, so lanes need no superuser.
   - Phase 3 runs its purge tests in-process in `api-test` with the retention-role URL (no worker container); `lane-test.sh` points that URL at the lane DB (RT15).
   - At most three lane containers at once (`LANE_SLOTS=3`).
   - Lanes never `up`, `down`, `build`, `restart` or `stop`.
4. **Heavy steps (the parent runs each alone, after the lanes, with only the infra stack up):**
   - phase 2's `pnpm restore:drill` (its own project, about 1.2 GB; it takes every lane slot);
   - phase 5's `scripts/ops_metrics.py` replay (pcap-worker 2 GiB and static-worker 3 GiB, one at a time);
   - phase 6's candidate image build (`infra/minio/image`, a Go build of about 2 GB) and its conformance run against the candidate in a throwaway project;
   - phase 4's `test_search_perf.py`, when the seeded volume exceeds 200 k rows.
5. **Web lanes (phases 8, 9):** host `pnpm --filter web test -- <own paths>`, `typecheck` and `lint`, against the phase-1 contracts and mocked fetch. No containers and no lane slot.
6. **Fallback** when worktrees misbehave on Windows: the M5 fallback (main tree, lane variables in the shell, `python -m compileall` before each run).

## Definition of done

- **Backup and restore:**
  - `pnpm backup` drains, then produces a hashed, manifest-described backup with no plaintext secret in it (RT6).
  - `pnpm restore` rebuilds an empty stack from it.
  - `pnpm restore:drill` passes in the gate. It shows equal security fingerprints and row counts (checked before anything writes, RT4), every object version of `objects.json` present with an equal sha256 and its retention and legal hold intact, every report signature valid, the RLS probe clean, and a seeded user able to log in and download.
  - Refresh tokens are revoked after a restore.
- **Retention:**
  - With no policy, nothing is purged.
  - A dry-run lists exactly what enforce later deletes, on the same seed.
  - Enforce deletes only expired, unheld, uncited candidates. It writes tombstones, custody events, audit rows and run items, and evidence answers 410 while hashes and custody stay.
  - A held case or a held org is untouched, at the DB and the S3 level.
  - A lowered policy, turning `enforce` on and a hold release all wait for the delay (RT1).
  - `audit_logs` and the other strict append-only tables refuse DELETE even for `cyberlab_retention`.
  - The purge user cannot delete a report snapshot or a locked version.
  - The sweep finds every org with a policy through `retention_policy_index` (RT3), and a purged render re-renders (RT11).
- **Correlation and search:**
  - An IOC, a hash or a JA3 shared by two jobs in two cases shows in "also seen in" and in related cases, and never across orgs. Keys equal `ti_results.ioc_key` and `ioc_collection_items.ioc_key` (RT8), and they survive a closed-case purge (RT9).
  - Common keys are flagged.
  - Search finds cases, evidence, findings, alerts, notes and observables with deep links, within 3 s on the seeded volume, and never across orgs.
  - The OpenSearch decision is recorded.
- **Metrics:**
  - Every terminal job, run and render lands in `job_outcomes`, reaper failures included.
  - `/internal/metrics` serves Prometheus text only with the token, and never through the gateway.
  - The org page shows the org's own numbers.
  - `plans/reports/ops-metric-YYMMDD.md` records the failure rate, p50 / p95 latency and parse success over the replayed real runs.
  - The live-run procedure exists and is recorded as run or "not run".
- **Hardening:**
  - The global per-user limit answers 429 (RT14: no anonymous limiter).
  - Evidence detail and custody views are audited and deduplicated.
  - Type mismatches are flagged and audited, and never rejected.
  - New objects are SSE-S3 encrypted and every presigned path still works.
  - The object-store conformance suite passes on the current image and on the chosen candidate. The image choice is recorded.
- **Sandbox:** `docs/SANDBOX_SECURITY.md` covers every §7 item and the enabling checklist. `dynamic.v1` is frozen with fixtures. The gate test proves dynamic analysis is not wired anywhere.
- **Security:** every new route is in the IDOR enumerator and every new tenant table in RLS coverage. The retention role and the purge user are least-privilege, and the env checks prove it (`scripts/check-retention-worker-env.mjs`).
- **Gate:** `pnpm verify:prod` is green, including the restore drill as its last exclusive step. The e2e covers search, the "also seen in" pivot, a retention preview, a legal hold and the purged-evidence state on a seeded aged case.
- **Docs:** SANDBOX_SECURITY (new); ARCHITECTURE, DATABASE (with the §11 mapping), API, DEPLOYMENT (backup / restore runbook, retention operations, secrets, SSE, image path, metrics scrape), THREAT_MODEL (M7, closed gaps), TESTING, ROADMAP, PRD, README and PCAP_ANALYSIS are updated, and the audit's overclaims are fixed.

## Out of scope

- **Online backup:** PITR / WAL archiving (pgBackRest), MinIO site replication, off-site upload automation, backup encryption inside the script (documented with age / gpg), and backup retention scheduling.
- **Retention extras:** purging notes, collections, findings, alerts, IOCs, samples, signed snapshots, audit logs or custody. Also: per-case retention overrides, org deletion, GDPR subject requests, and automatic S3 lifecycle rules on the production buckets.
- **Dynamic analysis itself:** CAPE deployment, the sandbox-bridge, VM images, INetSim and any execution. Design and contract only.
- **Search extras:** OpenSearch, semantic or vector search, fuzzy ranking beyond trigram, searching `malware_strings`, `network_records` or payloads, saved searches and alerts / watchlists.
- **Correlation extras:** cross-org or community correlation, graph views, AI-assisted correlation, scoring.
- **Metrics extras:** a Prometheus or Grafana service in compose, OpenTelemetry tracing, alerting rules, per-org SLOs.
- **Other:** platform API keys / service accounts (recorded in ROADMAP "Later"), MFA / SSO, an org upload reject list, memory forensics (M8).

## Open risks

- **Restoring across MinIO versions:** a volume restore into a newer or forked MinIO relies on on-disk compatibility. The drill restoring a bitnami volume into the candidate is the proof. Without a compatible candidate, the image stays frozen, and the residual is recorded in THREAT_MODEL.
- **Downtime of the offline backup** grows with the volume size: a tar of a 20 GiB volume takes minutes. It is acceptable for single node; the online path is documented.
- **Destructive code paths:** the purge is the first code that deletes evidence bytes. Bounded by dry-run by default, the delay, the floors, the DB and S3 holds, the least-privilege role and user, the tombstone-first order and the run items. Residual: a selector bug deletes eligible-looking data. The e2e and the dry-run/enforce equality test cover it.
- **`job_outcomes` triggers** add work to every terminal transition. The reaper bulk-fail path is measured in phase 5.
- **Search cost:** trigram on short queries. Bounded by the minimum length, per-type limits, the 3 s statement timeout and the rate limit.
- **SSE key loss** makes every encrypted object and MinIO's own IAM and config unreadable (RT7). The secrets backup checklist, the manifest key fingerprint and the drill using the real key path cover it.
- **Lane memory:** three API lanes fit the M5/M6 budget only if the heavy steps run alone.
- **Contract drift:** the frontend builds against stubs. Any schema change after phase 1 is a parent broadcast, and the merge checks for drift.
