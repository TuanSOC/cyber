---
phase: 6
title: "Security hardening rate limit view audit type mismatch and object storage"
status: pending
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
- [ ] Authenticated users are limited per user, with exemptions documented and the existing suites green (no anonymous limiter, RT14).
- [ ] Evidence detail and custody views are audited, deduplicated per 15 min, and never for other orgs.
- [ ] Declared-type mismatches are flagged and audited at upload, never rejected, and the columns are write-once.
- [ ] Every presigned path works against SSE-S3 buckets, and new objects are encrypted.
- [ ] The conformance suite passes on the current MinIO and on the recommended candidate. The research report records the options and a recommendation.

## Risk Assessment
- **The limit breaks the e2e or the polling UIs:** high test and e2e values, and `/auth/me` exempt. Phase 11 runs the e2e at the real dev default once.
- **A candidate image changes env names or the data dir:** both are parametrized in phase 1. The drill is the proof, and a failure keeps bitnami with the residual recorded.
- **The Go build exhausts RAM:** run it alone, or pull a fork image instead.
