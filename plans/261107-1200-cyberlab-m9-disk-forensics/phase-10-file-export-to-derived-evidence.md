---
phase: 10
title: "File export to derived evidence"
status: pending
priority: P2
effort: "14h"
dependencies: [1]
---

# Phase 10: File export to derived evidence (group B, 2h, lane 9)

## Overview
The bridge from disk triage to the M3 Malware Lab:
1. An analyst selects up to 20 allocated regular files (or NTFS named streams) of a finished disk job.
2. A disk job with profile `extract` downloads and re-verifies the segments again (there is no image cache, RT1), re-opens the image in the worker and copies each file out through phase 2's sandboxed `probe extract`.
3. The trusted side **re-hashes** the bytes and promotes each file, on request, to **derived evidence** in the same investigation, through the existing evidence upload pipeline.

Derived evidence inherits the restriction and gets its normal automatic static job. The API never parses the bytes. The worker's own sha256 is shown only as "reported by the worker" until promotion.

Cut candidate if the red team trims scope (the analyst can still download the image and extract locally); kept by default because it is the main triage-to-analysis workflow.

**Owns:**
- `app/modules/disk_forensics/{export_router,export_service,ingest_export}.py` (after the phase-1 stubs);
- `apps/workers/disk/disk_worker/export.py`;
- `tests/security/idor_cases_disk_exports.py`;
- `tests/integration/test_disk_export_{request,ingest,promote,ttl,custody}.py`;
- the worker test `apps/workers/disk/tests/unit/test_export.py`.

## Requirements
- **Request** (`POST /analyses/{job}/disk/file-exports`, body `{file_ids: [...]}`, 1..`DISK_EXPORT_MAX_FILES`; `evidence.write`; RT29):
  - **Source job:** a succeeded disk `triage` / `full` job of the org.
  - **Each file:**
    - allocated (`flags` without deleted / orphan), `type = reg` (or a stream of one);
    - `size ≤ DISK_EXPORT_MAX_BYTES` (64 MiB);
    - not on the never-collected list under **any** of its names (`cyberlab_jobs.disk.never_collect()` over every `disk_files` row with the same (`partition_index`, `meta_addr`), and over the parent file of a named stream; the constant phase 3's catalog also uses: a SAM hive, a hard link to it, `Login Data`, `key4.db` or a `.pfx` cannot be exported either; `409 disk_export_not_allowed` with reason `never_collect`; RT7);
    - the source evidence not purged.
  - **The quota** is checked against the sum of sizes (`507 insufficient_storage`).
  - **One transaction:**
    - an `analysis_jobs` row (`analyzer disk`, `profile extract`, `os_hint auto`, evidence = segment 0);
    - `analysis_job_segments` copied from the source job;
    - one `disk_exports` row per file (`pending`, the path snapshot);
    - audit `disk.export_requested`;
    - custody `export_requested` on every segment.
  - **Limits:** `DISK_MAX_ACTIVE_*` apply.
- **Dispatch** (`build_export_message`): the segment GETs, one presigned POST per file into the results bucket under `exports/<export_job>/<export_id>` with `content-length-range` ≤ the file's size, plus the result stream POST.
- **Worker** (`export.py: handle_export(msg)`):
  - the phase-2 download path (no cache) and magic check, within the export job's deadline budget;
  - `probe layout`, then `probe extract` per file (a natural key + `meta_seq` re-check; a reallocated or changed entry → per-file `failed` with the error code);
  - root uploads each `out/export/<n>` through its presigned POST, then the `disk-export.v1` stream (header with per-file status, size and worker sha256) → `finished`.
- **Ingest** (`ingest_export.ingest_disk_export`, on the `disk-ingest-worker` like every disk schema): validates the stream; sets each `disk_exports` row `ready` (with size, `worker_sha256`, the object key and its `object_version_id`) or `failed` (error code). The job succeeds if at least one file is ready.
- **Promote** (`POST /disk-exports/{id}/promote`, `evidence.write`; `409 disk_export_not_ready` / `disk_export_already_promoted` / `disk_export_expired`):
  - The API streams the exact object version (≤ 64 MiB) from the results bucket (the api user has Get there; red team read `infra/minio/api-policy.template.json`) through the **existing evidence-ingest code path**, refactored so `spool()` takes the object's chunk iterator instead of a request body (no copy of the code): sha256 / sha1 / md5 computed by the trusted side, type sniff, quota, the evidence bucket with object lock, custody.
  - The trusted sha256 must equal `worker_sha256`, else `failed` / `export_hash_mismatch` (integrity class) and nothing is promoted.
  - **In the evidence transaction:**
    - the new evidence (name = the original file name, sanitized; description "Exported from disk job …, partition i, path …");
    - `disk_exports.evidence_id`, `state = promoted`;
    - `apply_restricted_default(source="derived")` when any source segment is restricted, plus the source share-policy flags (never loosening);
    - custody `derived_from` on the new item (source job, segment ids, partition, path, `meta_addr`) and `export_promoted` on each segment;
    - audit `disk.export_promoted`.
  - **After commit:** the normal `auto_request` (PE → static `full`, else `av`). Static analysis is local (no egress); its TI / AI use is blocked by the inherited flags.
- **Expiry:** `ready` exports not promoted within `DISK_EXPORT_TTL_S` (7 days) become `expired` through the beat task `disk.expire_exports` (registered by phase 1 in `workers/tasks.py` on the ingest beat; its body `expire_exports()` lives in `export_service.py`; DB only). The api user cannot delete in the results bucket, so the object version is deleted by the retention worker's export arm with the purge user (phase 9; RT19); `exports/` has no object lock.
- **Read:** `GET /disk-exports/{id}` (`evidence.read`): state, size, `worker_sha256` labelled untrusted, the trusted hashes and evidence link after promotion.
- **IDOR:** `idor_cases_disk_exports.py` (a cross-org job / file / export id; a file of another job; promoting another org's export).

## Implementation Steps
1. Read phase 7's dispatch and ingest, `evidence/uploads.py`'s core function (reused, not copied), the M7 retention worker's object deletion, and the custody model.
2. Request validation and the transaction; the never-collected check uses the frozen `cyberlab_jobs.disk.never_collect()` over every name of the inode (the same function as phase 3's catalog).
3. Worker `export.py` with phase 2's `probe extract` (lane 9 with `--service disk-worker-test --heavy`, after the API tests, never concurrently).
4. Export ingest; promote through the evidence pipeline; the inheritance and custody; expiry.
5. IDOR and integration tests (lane 9), `ruff`, `mypy`.

## Success Criteria
- [ ] Only allocated regular files / streams ≤ 64 MiB none of whose names is on the never-collected list can be exported (a hard link to `SAM` is refused); each refusal has a reason code.
- [ ] Promotion re-hashes on the trusted side, refuses a worker-hash mismatch, creates evidence through the normal pipeline, inherits restriction and flags, records custody on both sides and triggers the normal static job.
- [ ] Unpromoted exports expire (`expired`, promote refused); their object versions are deleted by the retention worker (phase 9's test).
- [ ] `idor_cases_disk_exports.py` has no pending route.

## Risk Assessment
- **The API reads worker-produced bytes:** only to hash and store them, exactly as an upload. It never parses them, so the "never execute untrusted files" rule holds; the sniff is the existing magic read.
- **Every export re-downloads the image** (no cache, RT1): stated in the UI ("re-downloads and re-verifies the image: about as long as the analysis download"); batching up to 20 files per export amortizes it.
- **Storage roles:** the api user reads (not deletes) the results bucket; deletion is the retention worker's (RT19).

## As built (untested in Docker)

Code-only commit `feat(disk): file export to derived evidence (M9 phase 10, untested in Docker)`. Host-only checks: ruff (check + format) on every changed file, mypy strict (`--platform linux`, follow-imports silent) on the export / ingest / dispatch / uploads / repository / retention modules and the worker's `export.py` / `pipeline.py`, an app import + OpenAPI smoke (stubbed celery / magic / asyncpg / jwt, locked SQLAlchemy 2.1.7), pure checks of `ingest_export.validate` / `outcome` / `job_failure_code` and `export_service.file_refusal` / `derived_filename`. No integration or worker test ran.

**Seams:** `export_service.{request_exports, list_exports, get_export, promote, expire_exports, fail_pending_exports, send_export, inherit_restriction, file_refusal, inode_names, Planned, Promotable, DiskExportHashMismatch}`; `dispatch.export_key(job, export)` = `exports/<job>/<export_id>`; `evidence.uploads.store_spooled(request, …, spooled, on_insert=)` (the upload core, shared by upload and promote; `upload()` = checks + `spool()` + `store_spooled`); `EvidenceRow.derived_from` / `EvidenceOut.derived_from` (segment 0 of the source job); `retention.export_purge_orgs()`; worker `export.handle_export(msg, dirs, config) -> Path`, `read_back`, `write_stream`. Test helpers `tests/disk_export_helpers.py` (`exports` fixture, `source_job`, `ready_export`, `deliver_export`).

**Deviations (parent to confirm):**
- Routes: `GET /analyses/{job}/disk/file-exports` added (the job's exports, newest first, ≤ 500; phase 11's request) with its IDOR case; the request and promote routes take `CurrentUserDep` (own short sessions: commit before dispatch / before streaming); the request is rate limited (10 / user / 10 min).
- Phase 8's dirs route: `?parent=` is a decimal-text u64 (`^[0-9]{1,20}$`, > 2**64-1 → 422), so the OpenAPI type is string (phase 11's request).
- Migration 0017 (M9's own, not deployed) adjusted: `custody_action` += `export_requested`, `export_promoted`, `derived_from`; the export trigger allows `ready -> failed` (a promote whose trusted re-hash differs); a read-only `system_read` policy (`FOR SELECT USING (app_org_id() IS NULL)`) on `disk_exports`, so the expiry beat (app role) and the retention sweep find rows of every org; writes stay per-org tenant sessions.
- Retention fix (phase 9 gap): the sweep's export purge now visits every org with a purgeable export (`export_purge_orgs()`, system session), not only orgs in `retention_policy_index`; it also deletes the object of a `failed` export that kept one (refused promote).
- Expiry counts the TTL from `created_at` (no `ready_at` column).
- Ingest: the object version is found by listing the API-derived key (exactly one version, no delete marker, the reported size ≤ the listed size); otherwise that file is `failed` / `invalid_result`. A job with no ready file fails with the files' common disk code, else `analyzer_failed`. `workers/ingest._fail` (and the reaper, the lost publish) fail an `extract` job's `pending` exports with the job's code.
- Promote: quota over-run is `413 storage_quota_exceeded` (upload semantics); the request's quota check answers `507 insufficient_storage` as planned. A mismatch answers `409 export_hash_mismatch` (new API error) and audits `disk.export_rejected` (new audit action: web labels to add). The derived evidence's custody is `uploaded` + `derived_from`; segments get `export_promoted`.
- Worker: `handle_export` gained `dirs, config` (the skeleton test updated); root re-hashes the sealed `export/<n>` itself and reports that sha256; per-file codes `disk_export_not_allowed`, `stage_timeout`, `disk_parse_failed`, `result_upload_failed`.

**Remains to run (Docker):** ruff / mypy in the images; `pnpm gen:contracts` (new route, `CustodyAction` values, `parent` type) then web typecheck (`custody-timeline.tsx` needs labels for the three custody actions); lane 9 `tests/integration/test_disk_export_{request,ingest,promote,ttl,custody}.py`, `test_disk_export_purge.py`, `test_m9_foundation.py`, `test_m9_schema.py`, `test_migrations.py`, `tests/security/test_idor_routes.py`, `test_error_classes.py`; the worker's `tests/unit/test_export.py` and `test_skeleton.py` in `disk-worker-test` (`--heavy`, after the API tests); a real extract against phase 4's images.
