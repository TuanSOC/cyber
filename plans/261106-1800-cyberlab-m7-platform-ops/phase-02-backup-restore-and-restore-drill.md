---
phase: 2
title: "Backup restore and restore drill"
status: pending
priority: P1
effort: "17h"
dependencies: [1]
---

# Phase 2: Backup restore and restore drill (group B, 2a, lane 2; the drill is a heavy step)

## Overview
The §13 backup and restore with a tested restore:
- `pnpm backup`: quiesced, offline, single node;
- `pnpm restore`: onto empty volumes only;
- `restore_verify`: the integrity and security proof after a restore;
- `pnpm restore:drill`: seed → backup → destroy → restore → verify → download, in its own compose project, run alone in the gate.

The design is in plan.md "Backup and restore".

**Owns:**
- `scripts/{backup,restore,restore-drill}.mjs`, `scripts/lib/stack.mjs` and `scripts/lib/stack.test.mjs`;
- `infra/backup/**`: `docker-compose.drill.yml`, `security.sql` (the catalog fingerprint), `tables.sql` (exact per-table row counts; no content digests, RT4), `README` comments inline;
- `apps/api/app/scripts/{restore_verify,drill_seed}.py`;
- `tests/unit/test_backup_manifest.py`, `tests/unit/test_restore_verify.py` and `tests/integration/test_restore_verify_db.py`.

## Requirements
- **`scripts/lib/stack.mjs`:**
  - a compose runner (project name, files, profile; `MSYS_NO_PATHCONV=1` on Windows Git Bash);
  - `stopWriters()` and `startAll()`;
  - `volumeName(project, name)`;
  - **`downVolumes(project)` (RT2):** refuses unless `project === "cyberlab-drill"` (a literal, never derived), runs with `COMPOSE_PROJECT_NAME` / `COMPOSE_FILE` / `COMPOSE_PROFILES` removed from the child env, and first lists the volumes it would remove (`docker volume ls --filter label=com.docker.compose.project=cyberlab-drill`), refusing if any lacks that label. A unit test feeds it `cyberlab` and an env with `COMPOSE_PROJECT_NAME=cyberlab` and expects refusals;
  - `lockAllSlots()`: takes every slot under `LANE_LOCK_ROOT`, resolved exactly as `lane-test.sh` does (RT25);
  - `runHelper(image, mounts, cmd)` for tar, with a pinned `alpine` image already used in the repo, or `busybox`;
  - `sha256File`.

  No shell-string interpolation of paths: use argument arrays.
- **`pnpm backup [-- --out <dir>] [--prod]`:**
  1. Preconditions:
     - the stack is up and healthy;
     - no test-profile or `compose run` container of the project is running (they share MinIO and Postgres, RT21);
     - the output dir is not tracked by git (`git check-ignore`) and not inside `.secrets`;
     - there is free disk ≥ 1.2 × (the pgdata size + the MinIO volume size); otherwise warn and require `--force`.
  2. **Drain** (RT21): poll the `*_index` tables (as superuser) until no job, TI run, AI run or render is queued or running; timeout 10 min, then refuse unless `--force`. Then stop the writers (plan.md list), in order: gateway, web, api, workers, beat.
  3. As `postgres`, via `docker compose exec postgres`:
     - `pg_dump -Fc -d cyberlab` (the superuser, not the owner: FORCE RLS);
     - `pg_dumpall --globals-only --no-role-passwords`;
     - `psql -At -f infra/backup/security.sql` → `security.json`;
     - `tables.sql` → `tables.json`: the exact `count(*)` per table of `public` (no content digests, RT4).
  4. **`objects.json`** (RT4), with MinIO still up: an `mc` helper container with the root credentials lists every version of the evidence, reports and results buckets (`mc ls --versions --json`) and reads each version's retention and legal hold; it records bucket, key, version id, size, etag, mode, retain-until and legal hold.
  5. Stop minio, then tar the data volume (`MINIO_DATA_DIR`) with `--numeric-owner` from a read-only mount into `minio-data.tar`, **relative to the data dir** (`-C <dir> .`), so it extracts into another image's dir (RT25).
  6. Write `manifest.json`: per-file sha256 and bytes, `alembic_head`, the images (`docker image inspect` ids for api, minio and postgres), `MINIO_IMAGE`, `MINIO_DATA_DIR`, `EVIDENCE_LOCK_DAYS`, the KMS key **name** and the sha256 **fingerprint** of the key file (never the key, RT7), `created_at`, the source project, and `tool_version: 1`.
  7. Restart everything (`up -d --wait`, the same profiles).
  8. Print the duration, the sizes, **what the backup contains** (RT6: every org's evidence, pre-SSE objects in clear, password and refresh-token hashes, sealed keys, MinIO IAM; TLP:RED; keep it on an AV-excluded, encrypted target) and the **secrets checklist**: `.env` and `.secrets/*` (seal private keys, signing keys, KMS key, metrics token), stored separately and encrypted, with the age command example.
  9. A failure at any step still restarts the stack (finally) and exits non-zero.
- **`pnpm restore -- --from <dir> --replace-empty-stack [--keep-sessions] [--prod]`:**
  1. Verify `manifest.json` and every file hash, and that the fingerprint of the configured KMS key equals the manifest's (RT7).
  2. Refuse when the image's alembic head is older than the backup's.
  3. Require **empty** volumes:
     - Postgres: `pgdata` missing, or no `alembic_version` table in `cyberlab`;
     - MinIO: no `.minio.sys` in the volume.

     Otherwise print the exact `docker compose down -v` command and exit 3. The script never runs `down -v` itself outside the drill project.
  4. Start postgres alone (the init creates the DBs and roles), then run `db-bootstrap`.
  5. `pg_restore --exit-on-error --single-transaction --no-password -U postgres -d cyberlab`.
  6. **`restore_verify --db`** immediately, before anything writes (RT4).
  7. Untar into the MinIO volume as root with `--numeric-owner` (into `MINIO_DATA_DIR` of the target image), start minio, run `minio-init`, then **`restore_verify --objects`**.
  8. Run `migrate`.
  9. Unless `--keep-sessions`, revoke every refresh token as the owner (`refresh_tokens` is not a tenant table: no RLS, checked in 0001). `auth_event_type` is an enum without a restore value, so log the count instead of writing `auth_events`.
  10. `up -d --wait`, then **`restore_verify --rls`**.
  11. Print the DR note: when restoring after an incident, rotate `JWT_SECRET` (logged-out access tokens are valid again until expiry, because Redis is not restored, RT26).
- **`app/scripts/restore_verify.py`** (runs in the api image; env: the superuser DB URL, MinIO credentials able to read retention and legal holds (the root in the restore and drill helper container), the public signing keys; output: JSON + exit code). Three phases (RT4), each runnable alone:
  - **`--db` (catalog):** recompute `security.json` and `tables.json` and compare them with the backup's. Any difference is a failure, listed per table or policy. It runs before `migrate` and before any service writes.
  - **`--objects`:** every version in `objects.json` exists with the same size, etag, retention mode, retain-until and legal hold. For every evidence row without an `evidence_purges` tombstone, stream the exact version and re-hash its sha256 against `evidence_hashes`. A pinned version missing **without** a tombstone is a failure (it also catches an out-of-band delete, RT5). Tombstoned evidence is absent, or present and reported as the warning `purged_pending_delete` (RT22).
  - **Reports:** for every `report_versions` row, the snapshot version re-hashes to `snapshot_sha256` and the manifest signature verifies (`app/core/signing.verify`). For every `succeeded` render, its artifact re-hashes.
  - **Job results:** for every succeeded job with a `result_version_id`, the object version exists.
  - **`--rls` (RLS probe):** connect as `cyberlab_app`:
    - set org A, then `count(*)` on one table per module where `organization_id = B` returns 0;
    - `UPDATE audit_logs` raises;
    - `DELETE FROM ti_results` raises for the app role.
  - **Bounds:** `--sample N` hashes a random sample instead of every object for big installs (the default in the drill is all).
- **`app/scripts/drill_seed.py`** (`httpx` against `http://api:8000` inside the drill network; owner SQL only where no API exists):
  - two orgs, three users (owner, analyst, viewer), two cases;
  - three evidence uploads per org with lock days > 0 (drill env `EVIDENCE_LOCK_DAYS=1`);
  - a note, a collection with a manual item, TLP set;
  - a case legal hold;
  - a retention policy, dry-run only;
  - a report finalized (no render-worker: one `queued` render row);
  - synthetic `ti_results` and `ai_runs` / `ai_outputs` rows labelled `drill`, inserted as the owner with `app.org_id` set;
  - a seeded `evidence_purges` tombstone with its object version deleted. The purge user cannot delete a version under the drill's 1-day lock, so the seeder (a one-off `compose run --rm` container of the drill project, never the `api` service) uses the drill MinIO root with `x-amz-bypass-governance-retention` for that one object (RT17).

  It prints the seeded ids to a JSON file consumed by the drill.
- **`pnpm restore:drill [-- --prod] [--target-minio-image <img>]`:**
  - Project `cyberlab-drill` with `docker-compose.yml` + `infra/backup/docker-compose.drill.yml`. The overlay drops published ports, sets `EVIDENCE_LOCK_DAYS=1` and the dev keys, and starts only postgres, redis, redis-broker, minio, minio-init, db-bootstrap, migrate and api.
  - **Exclusive:** take all `LANE_SLOTS` lock dirs (`lockAllSlots()`, the same `LANE_LOCK_ROOT` as `lane-test.sh`, RT25) before starting, and refuse when the main project's heavy services (analyzers, report-worker) are running.
  - **Backups stay in Docker (RT6):** the backup goes to the named volume `cyberlab-drill_backups` (mounted into the helper containers), never to the host disk, so host AV never sees evidence bytes and no path conversion is involved. It is removed with the project.
  - **Steps:**
    1. `up --wait`.
    2. Seed.
    3. `backup --project cyberlab-drill`.
    4. `down -v`.
    5. If `--target-minio-image` is given, switch `MINIO_IMAGE` (and `MINIO_DATA_DIR`) for the restore.
    6. `restore --project cyberlab-drill`.
    7. `restore_verify` (the three phases run inside `restore`; the drill asserts each report).
    8. **Functional checks over HTTP:** the seeded analyst logs in (the old session is revoked, so a new login is required). It downloads one evidence item and checks its sha256, gets the report version content, sees the signature valid, and gets `410 evidence_purged` on the tombstoned evidence. The viewer gets 403 on a write.
    9. `downVolumes("cyberlab-drill")`, always (finally; RT2).
  - It records the timings (backup, restore, verify) into `infra/backup/last-drill.json` (gitignored) for phase 11's metric.
- **Tests (lane 2, no drill):**
  - `test_backup_manifest.py`: manifest building and verification, a tampered file detected, a newer-head refusal, a KMS fingerprint mismatch refused;
  - `test_stack_guard` (node, in `scripts/lib/stack.test.mjs`): `downVolumes` refuses any other project and a polluted env (RT2);
  - `test_restore_verify.py`: the comparison logic on fixture JSON (policy missing, a grant changed, a row count changed, an object's retain-until shortened, a legal hold lost);
  - `test_restore_verify_db.py` (lane DB and test buckets): run the verifier's `--db`, `--objects` and `--rls` checks against seeded data. They pass; a flipped object version (a test writes a new version under the key), a pinned version deleted without a tombstone, or a dropped policy (in a transaction rolled back after) fails; a tombstoned version still present is a warning only.

## Implementation Steps
1. `stack.mjs` and the manifest helpers, plus `test_backup_manifest.py`.
2. `security.sql` and `tables.sql`; check that they run on the dev DB as superuser.
3. `restore_verify.py` and its tests in lane 2.
4. `backup.mjs`, run once on the dev stack (heavy: the parent's slot, the main stack only).
5. `restore.mjs`.
6. `drill_seed.py` and `restore-drill.mjs`, then the full drill **alone** (heavy step), twice: the second run proves idempotence and cleanup.
7. If phase 6 has produced a candidate image tag by then, run the drill with `--target-minio-image` and record the result for the parent.

## Success Criteria
- [ ] A backup drains first and contains the dump, the globals, the fingerprint, the row counts, `objects.json`, the MinIO tar and a hashed manifest, and no plaintext secret. The stack always restarts, even on failure.
- [ ] A restore refuses non-empty volumes, tampered files and newer backups, and rebuilds an empty stack whose `restore_verify` is clean.
- [ ] The drill passes end to end in `cyberlab-drill`:
  - fingerprints and row counts are equal before anything writes;
  - every version of `objects.json` is present with equal size, etag, retention and legal hold, and every evidence version re-hashes;
  - report signatures are valid;
  - the RLS probe is clean;
  - login after the session revocation, the download and the 410 for purged evidence work;
  - `down -v` cleans up, and only the drill project's volumes (the guard test passes).
- [ ] The drill's peak memory and duration are recorded, and it never runs alongside lanes.

## Risk Assessment
- **Windows paths and tar ownership:** use named volumes only (no bind-mounted data; the drill's backups too), helper containers for tar, and `--numeric-owner`. Test on Docker Desktop / WSL2 first. A real `pnpm backup` to `./backups/` writes through Docker Desktop file sharing: slow for large volumes, and host AV may scan it (RT6).
- **pg_restore and object ownership:** the init script creates `cyberlab` owned by `cyberlab_owner`. Restore with the default owner handling (the roles exist), and check `\dp` equality through the fingerprint.
- **Restoring the MinIO internal config (`.minio.sys`)** restores users and policies with the old secrets, encrypted with the KMS key (RT7). `minio-init` re-applies the current `.env` keys idempotently (`mc admin user add` updates the secret). With a different KMS key MinIO cannot read them at all: the fingerprint check refuses that restore up front. Document it.
- **Drill time and RAM:** seed small (a few MiB of evidence). The drill must finish in under 5 minutes on the host.
