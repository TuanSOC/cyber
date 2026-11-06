---
phase: 6
title: "Security hardening rate limit view audit type mismatch and object storage"
status: completed
priority: P1
effort: "13h"
dependencies: [1]
---

# Phase 6: Security hardening: rate limit, view audit, type mismatch and object storage (group B, 2e, lane 6; an image build is a heavy step)

## Overview
The cheap, high-value §13 Partials from the audit:
- a global per-user API rate limit (the anonymous per-IP middleware is cut, RT14);
- an audit of evidence metadata and custody views (§10 "auditable access logs");
- a declared-type vs detected-type mismatch flag (flag, never reject);
- SSE-S3 verification on every presigned path (configured in phase 1);
- an object-store conformance suite plus a researched, tested image path off the frozen `bitnamilegacy/minio`.

The design is in plan.md "Security hardening".

**Owns:**
- `core/deps.py` (the limit inside `current_user`);
- `evidence/router.py` (the view audit) and `evidence/uploads.py` + `core/filetypes.py` (declared type, mismatch);
- `infra/minio/image/**`;
- `tests/integration/test_object_store_conformance.py`, `test_storage_sse.py`, `test_global_rate_limit.py`, `test_evidence_view_audit.py` and `test_type_mismatch.py`;
- `tests/unit/test_filetypes.py`;
- `plans/reports/researcher-YYMMDD-m7-object-store.md`.

## Requirements
- **Global per-user limit:**
  - In `current_user`, after the token is validated: `rate_limit.hit(f"u:{user_id}", RATE_LIMIT_USER_PER_MIN, 60)`.
  - Exempt: `GET /auth/me` (shell polling), the health routes and `report-signing-keys` (it has its own limit). The upload and download bodies count once per request.
  - 429 with `Retry-After` and the JSON error envelope.
- **No anonymous limiter (RT14, cut):** a "no access cookie" rule is skipped by any bogus cookie, it would need `main.py` (frozen to phase 1), and login, register, refresh and the signing-keys route already have their own limits. Residual recorded for phase 10.
- **Tests** (`test_global_rate_limit.py`, with the lane env lowered through monkeypatched settings):
  - the 601st request in a window → 429;
  - another user is unaffected;
  - `/auth/me` is exempt;
  - the existing suites keep passing with the test env defaults (100 000).
  - Check the M5 / M6 polling hooks (AI runs, renders) at 600 / min: at most about 1 request per 2 s per view, documented.
- **Evidence view audit** (`evidence/router.py`):
  - `GET /evidence/{id}` → `evidence.viewed`, and `GET /evidence/{id}/custody` → `evidence.custody_viewed`;
  - only when `core/audit_dedupe.once_per(f"{user}:{evidence}:{action}", 900)` is true;
  - written in the request's tenant session and committed. These read routes currently do not commit: add an explicit commit after the audit insert, keeping the "audit in the same transaction" rule.
  - Details: none beyond the ids; no IP (the audit row already has the actor).
  - The list routes are not audited (documented).
  - **Tests:** one row per 15 min per user, evidence and action; another user gets their own row; a 404 for another org writes no row; a viewer's view is audited.
- **Declared type and mismatch** (`core/filetypes.py`, `evidence/uploads.py`):
  - **`declared_family(filename) -> str | None`** from the extension: `pcap` (`.pcap`, `.pcapng`, `.cap`), `pe` (`.exe`, `.dll`, `.sys`, `.scr`, `.cpl`, `.ocx`), `elf` (no extension → None; `.so`, `.elf`), `pdf`, `zip` (`.zip`, `.jar`, `.apk`, `.docx`, `.xlsx`, `.pptx`), `office_legacy` (`.doc`, `.xls`, `.ppt`), `image`, `text` (`.txt`, `.log`, `.csv`, `.json`), `archive` (`.7z`, `.rar`, `.gz`, `.tar`).
  - **`detected_family(mime, magic_route)`** from libmagic's mime and the existing magic routing (`auto_choice`).
  - **`type_mismatch`** = both are known and differ (an allow-list of benign pairs, for example `zip` ↔ office OOXML and `text` ↔ `json`).
  - Set both columns at INSERT. On a mismatch, add the audit `evidence.type_mismatch` (declared and detected families) in the same transaction.
  - **Never reject** (decision). Routing to analyzers is unchanged.
  - **Tests:** an `.exe` named `invoice.pdf` → mismatch and audit; a pcapng named `.pcap` → no mismatch; no extension → None; a hostile filename (the `test_malicious_filenames` set) never crashes; the columns are write-once (an UPDATE raises from the trigger).
- **SSE-S3 verification** (`test_storage_sse.py`, test buckets):
  - `stat` of a new evidence upload, of a results object uploaded through a presigned POST (the pcap path) and of a report snapshot shows SSE-S3;
  - the analyzers' presigned GET of an encrypted version works;
  - `Content-MD5` is not required.
  - If phase 1 had to put SSE behind a flag, this phase proves the flag works on all three paths.
- **Object-store conformance suite** (`test_object_store_conformance.py`):
  - Runs against `MINIO_ENDPOINT` with the test buckets, and is parametrized to run against a throwaway candidate endpoint (`OBJECT_STORE_CANDIDATE_URL` plus root keys, a test-only env) in a separate compose project.
  - **Asserts, on a fresh locked bucket:**
    - versioning;
    - per-object GOVERNANCE retention: set, extend allowed, shorten refused without bypass;
    - delete of a locked version refused for the api and purge users, and allowed only with bypass for root;
    - a versioned delete by a user holding only `s3:DeleteObjectVersion` (the purge policy) works on an unlocked version, and the `snapshot.json` Deny applies to it;
    - legal hold ON / OFF by the purge user, refused for the api user (RT5), and the delete refused while ON;
    - exact-version GET;
    - a presigned POST with the `content-length-range` and key conditions the analyzers use;
    - a presigned GET by version;
    - `ListObjectVersions`;
    - SSE-S3 default encryption, and MinIO restarting with its users and policies intact under the KMS key (RT7);
    - the bucket policy explicit Deny (the `snapshot.json` rule);
    - `mc admin`-free operation for the app paths.
- **Image path research and candidate** (`plans/reports/researcher-YYMMDD-m7-object-store.md`):
  - **Facts:** upstream MinIO community distribution has been source-only since October 2025 and the repository has been archived since February 2026, so bitnamilegacy receives no patches. A community fork, `pgsty/minio` ("SILO", AGPLv3, Docker Hub images), states the upstream env vars, `server` command and `/data` on-disk format and re-enables the web console (RT28). Re-verify the current state on the web when this phase runs.
  - **Evaluate:**
    - (a) maintained community fork images that keep the MinIO on-disk format, `pgsty/minio` first (project health, release cadence, CVE fixes, license, signed images; the console must stay unpublished, and a matching `mc` image);
    - (b) a pinned source build of the last upstream release in `infra/minio/image/Dockerfile` (multi-stage `golang` → distroless or alpine, `govulncheck` report; no future patches);
    - (c) RustFS, SeaweedFS and Ceph RGW (object lock, presigned POST, versioning, RAM): incompatible on disk, so a re-architecture.
  - **Recommend one;** the parent or user decides.
  - **For the recommended candidate:**
    - build or pull it, and run the conformance suite against it in a throwaway project (a heavy step, alone);
    - hand the tag to phase 2's drill (`--target-minio-image`), which restores a bitnami volume into it;
    - record the data path (`MINIO_DATA_DIR`), the env differences (bitnami `MINIO_ROOT_*` vs upstream) and the `mc` image.
  - The flip of the `MINIO_IMAGE` default is done by the parent at the group-B merge, not in this phase.

## Implementation Steps
1. The global and anonymous limits, with their tests.
2. The view audit, with its tests.
3. `filetypes.py`, the upload changes, and the tests.
4. The SSE verification tests (lane, test buckets).
5. The conformance suite against the current MinIO (lane).
6. Research and write the report. Build or pull the candidate and run the conformance suite against it in a throwaway project (heavy, alone). Hand the tag to the parent and phase 2.

## Success Criteria
- [x] Authenticated users are limited per user, with exemptions documented and the existing suites green (no anonymous limiter, RT14). — The limit and the docs are done: `test_global_rate_limit.py::test_the_601st_request_in_a_window_is_refused`, `test_the_limit_is_per_user`, `test_auth_me_and_health_are_exempt`, `test_concurrent_requests_cannot_exceed_the_limit`, `test_redis_outage_fails_closed`, `test_test_env_default_is_high`; the exemptions are in API.md and the RT14 residual is in THREAT_MODEL (9316433). Existing suites green in gate run vp8 (2026-11-06, the pre-fix gate) (API 4915 passed / 53 skipped / 1 xfailed, workers, web). Its dev e2e ran at the compose dev default `RATE_LIMIT_USER_PER_MIN=600` (no `.env` override) and passed.
- [x] Evidence detail and custody views are audited, deduplicated per 15 min, and never for other orgs. — `test_evidence_view_audit.py::test_detail_and_custody_views_are_audited_once_per_window`, `test_window_expiry_writes_a_new_row`, `test_each_user_gets_their_own_row_and_a_viewer_is_audited`, `test_another_orgs_404_writes_no_row`, `test_list_routes_are_not_audited`, `test_failed_commit_gives_the_dedupe_slot_back` (9316433).
- [x] Declared-type mismatches are flagged and audited at upload, never rejected, and the columns are write-once. — `test_type_mismatch.py::test_exe_named_pdf_is_flagged_and_audited_not_rejected`, `test_matching_types_are_not_flagged`, `test_no_extension_declares_nothing`, `test_hostile_filenames_never_crash_the_classification`, `test_type_columns_are_write_once_after_upload`; `unit/test_filetypes.py` (8) (9316433).
- [x] Every presigned path works against SSE-S3 buckets, and new objects are encrypted. — `test_storage_sse.py::test_new_evidence_upload_is_encrypted_and_presigned_get_works`, `test_analyzer_result_presigned_post_is_encrypted_without_content_md5`, `test_render_presigned_post_into_locked_reports_bucket_is_encrypted`, `test_report_snapshot_is_encrypted_and_readable`, `test_plain_put_without_sse_headers_is_encrypted_by_the_bucket_default` (9316433).
- [x] The conformance suite passes on the current MinIO and on the recommended candidate. The research report records the options and a recommendation. — Done: the suite (14 tests) against the current MinIO in lane 6, and `plans/reports/researcher-261106-m7-object-store.md` with options (a)–(c) and the recommendation `pgsty/silo` (9316433). The candidate: after a backup, the conformance suite on `pgsty/silo` and a restore drill into it, the store was switched to `pgsty/silo` (6884ddd). The first activation could not create buckets (the bitnami volume root is gid 0); the wrapper now runs as `1001:0`, and then the live-store conformance passed (13 passed, 1 skipped, RT7 passed separately). The gate's prod-phase drill on the folded model then passed with `bucket_create` (`plans/reports/minio-switch-runbook-261107.md` Result, `infra/backup/last-drill.json`).

## Risk Assessment
- **The limit breaks the e2e or the polling UIs:** high test and e2e values, and `/auth/me` exempt. Phase 11 runs the e2e at the real dev default once.
- **A candidate image changes env names or the data dir:** both are parametrized in phase 1. The drill is the proof, and a failure keeps bitnami with the residual recorded.
- **The Go build exhausts RAM:** run it alone, or pull a fork image instead.

## Implementation Notes (2026-11-07)
- **Commit:** 9316433 (phases 2–10 together).
- **Lane 6:** `scripts/lane-test.sh 6 …` on its own files, plus ruff, format and mypy. The candidate pull and its run were not done (heavy, deferred).
- **Global per-user limit** (`core/deps.py`):
  - inside `current_user`, after the token check and before the DB lookup: `rate_limit.hit("u:{user}", RATE_LIMIT_USER_PER_MIN)`, 600 per minute;
  - `USER_LIMIT_EXEMPT = {GET /api/v1/auth/me}`; health and `report-signing-keys` never reach `current_user`;
  - a request counts once however many dependencies resolve it;
  - a Redis failure answers 503 (fail closed);
  - the test env default is 100 000.
- **No anonymous limiter (RT14, cut):** the residual is recorded in THREAT_MODEL ("Known gaps" and the M7 section).
- **Evidence view audit** (`evidence/router.py`):
  - `evidence.viewed` and `evidence.custody_viewed`, only when `once_per("{user}:{evidence}:{action}", 900)` is true;
  - an explicit commit after the audit insert;
  - a failed commit gives the dedupe slot back;
  - details hold ids only, and the list routes are not audited.
- **Declared vs detected type** (`core/filetypes.py` +127, `evidence/uploads.py`):
  - `declared_family(filename)`, `detected_family(mime, magic_route)` and `type_mismatch` with a symmetric `BENIGN_PAIRS` allow-list;
  - both columns are set at INSERT, plus the audit `evidence.type_mismatch` in the same transaction;
  - an upload is never rejected, and routing is unchanged;
  - the 0014 trigger makes the columns write-once.
- **SSE-S3:** verified on every presigned path (`test_storage_sse.py`, 6). Phase 1 did not need the `MINIO_SSE_ENABLED` fallback (it defaults to true).
- **Object-store conformance suite** (`test_object_store_conformance.py`, 14 tests), on a fresh locked bucket:
  - versioning, exact-version GET and `ListObjectVersions`;
  - GOVERNANCE retention: set, extend, and shortening refused;
  - a locked delete is refused except for root with bypass;
  - the purge user's versioned delete works on an unlocked version, and the `snapshot.json` Deny applies to it;
  - legal hold is set only by the purge user, and it blocks every delete;
  - presigned POST conditions, with no `Content-MD5` needed;
  - SSE-S3 defaults and the KMS key;
  - the app users hold no admin rights;
  - a restart keeps users, policies and encrypted objects (RT7).

  It passed against the current MinIO in lane 6.
- **The purge user needs `s3:DeleteObject`** for a versioned delete on this build (phase-1 deviation). `test_purge_user_deletes_an_unlocked_version_for_real` and `test_snapshot_json_explicit_deny_applies_to_versioned_deletes` pin the behaviour.
- **Object-store research** (`plans/reports/researcher-261106-m7-object-store.md`):
  - upstream MinIO was **archived on 2026-04-25** (the plan said February: corrected), and `pgsty/minio` was renamed `pgsty/silo`;
  - the bitnami build carries CVE-2025-62506 and SN-2026-015/016 (a GOVERNANCE retention bypass);
  - **recommended: `pgsty/silo:RELEASE.2026-10-26T00-00-00Z`, pinned by digest after `cosign verify`**, with `MINIO_DATA_DIR=/data` and an explicit `server` command;
  - `MC_IMAGE` stays bitnami until `init.sh` accepts `mcli`;
  - (b) a source build `infra/minio/image/Dockerfile` (with a `govulncheck` stage) is the fallback; (c) RustFS, SeaweedFS and Ceph RGW are not on-disk compatible.

  **Pending the user's decision.** The `MINIO_IMAGE` default is unchanged.
- **Group-B review, Medium (fixed in 9316433):**
  - The candidate object store had been attached to the main `cyberlab_backend` network.
  - `infra/minio/image/docker-compose.candidate.yml` now runs it on its own internal network `cyberlab-objstore_conformance` (no egress, nothing published). Only the `conformance` test container joins both networks.
  - The image is pinned by digest structurally: `${CANDIDATE_MINIO_IMAGE}@${CANDIDATE_MINIO_DIGEST}`, both required. It runs with a read-only rootfs, `cap_drop: ALL`, 512 MB and `pids_limit` 256.
- **Not done:**
  - the conformance run against the candidate;
  - the drill with `--target-minio-image`;
  - the option (b) build.

  All wait for the image decision (heavy, alone).
- **Pending gate:** the full suite at the test default, and the e2e at the real 600-per-minute dev limit (phase 11).
- **Closure (2026-11-06):** The full suite passed in gate run vp8, and its dev e2e ran at the dev default of 600 per minute; MinIO now runs `pgsty/silo` (6884ddd); the gate passed in segments, not in one `pnpm verify:prod` run (see the plan's Closure).
