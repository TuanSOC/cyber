---
phase: 6
title: "Memory dispatch and trusted ingest"
status: pending
priority: P2
effort: "19h"
dependencies: [1]
---

# Phase 6: Memory dispatch and trusted ingest (group B, 2e, lane 6)

## Overview
The trusted half of the memory pipeline, on the M2 / M3 pattern:
- **intake:** a memory upload (`?kind=memory`) gets its own size limit, the `memory` declared type, the TLP:RED default in the upload transaction, and no automatic analysis (RT3);
- **request:** `POST …/evidence/{id}/analyses` with `analyzer: memory`, the caps, the sensitivity default (through the phase-8 entry point) and the custody event;
- **dispatch:** the `MemoryJobV1` message (presigned GET for the exact version, presigned POST for the result) on queue `memory`;
- **ingest:** the whole `memory.v1` stream is validated (header, caps, trailer hash, image identity), then written in one transaction into the `memory_*` tables and the shared `analysis_findings`, `iocs` and `analysis_timeline`;
- **diagnostic results:** a failed `symbols_missing` job carries a small result whose header names the symbols it needs; the ingest stores that requirement only (plan "Symbols").

**Owns:**
- `app/modules/memory_analysis/{dispatch,ingest,stream}.py` (after the phase-1 stubs);
- the memory branches of `analysis/{service,dispatch,analyzers}.py`, `workers/ingest.py` and `workers/reaper.py` (phase 1 adds only the enum value and the stub calls);
- `evidence/uploads.py` and `core/filetypes.py` (the `kind=memory` limit and the `memory` declared type);
- `tests/integration/test_memory_{request,dispatch,ingest,results,diagnostic}.py`, `tests/unit/test_memory_stream.py`, `tests/unit/test_memory_filetypes.py`.

## Requirements
- **Intake** (`evidence/uploads.py`):
  - `POST …/investigations/{inv}/evidence?kind=memory` uses `MEMORY_MAX_BYTES` (default 8 GiB, ≤ 16 GiB, RT14) instead of `MAX_EVIDENCE_BYTES` (2 GiB), in `_check_request` on the declared `Content-Length` (early 413 `memory_image_too_large`) and as the `spool()` limit while streaming. Without `kind=memory` nothing changes.
  - **Sensitivity at upload** (RT3): `_insert_records` calls `memory_analysis.sensitivity.apply_memory_default(ctx.session, org_id, evidence.id, actor_id)` (the frozen phase-8 entry point) after the evidence flush, in the same transaction, when `kind=memory`.
  - The org storage quota check is unchanged (a memory image counts like any evidence; the quota check under the org row lock already covers it).
  - `declared_type` gains the family `memory`: set when `kind=memory`, or from the extensions `.raw .mem .vmem .lime .dmp .core` (`core/filetypes.py`). `type_mismatch` stays the M7 rule: libmagic and the magic routing; a raw image has no magic, so `memory` + `data` is **not** a mismatch.
  - The upload spools to `upload_tmp` as today. Free space is checked first (`statvfs` ≥ size + 1 GiB, else `507 insufficient_storage`).
  - **No auto-run for memory** (decision, plan): `auto_choice` never returns `memory`, even for LiME or crash-dump magic. A memory run takes minutes and gigabytes; it is always an explicit analyst action.
  - **No auto-run of any analyzer on a memory upload** (RT3): `upload()` skips `auto_request` when `kind=memory` (otherwise an image ≤ 64 MiB gets an automatic static `av` job). A test uploads a 1 MiB `kind=memory` file and asserts no job and the restricted state.
- **Request** (`analysis/service.py`):
  - `analyzer: memory` with `profile` ∈ `triage | full` (default `triage`) and `os_hint` ∈ `auto | windows | linux` (default `auto`); `profile` for pcap stays NULL (the 00NN check, plan Data model).
  - Refusals: evidence above `MEMORY_MAX_BYTES` → `413 memory_image_too_large`; empty evidence → `422 memory_image_empty`; purged evidence → `410 evidence_purged` (M7 guard); per-org active memory jobs ≥ `MEMORY_MAX_ACTIVE_PER_ORG` (1) or global ≥ `MEMORY_MAX_ACTIVE_TOTAL` (2) → `429 analysis_queue_full` (the existing per-analyzer cap code path).
  - In the same transaction as the job row: `await memory_analysis.sensitivity.apply_memory_default(session, org_id, evidence_id, actor_id)` (phase-1 stub, phase 8 implements; this phase only calls it; idempotent, so it covers images uploaded without `kind=memory`) and the custody event `analysis_requested` (existing).
  - Audit `analysis.requested` with `analyzer`, `profile`, `os_hint`.
- **Dispatch** (`memory_analysis/dispatch.py`, called from `analysis/dispatch.py`):
  - `MemoryJobV1` (frozen in phase 1) with `MemoryLimits` from settings; the presigned GET pins the exact version and expires with the queue TTL plus the job timeout (a large download starts late).
  - The result key is the M2 `results/{org}/{job}.ndjson.gz`; the POST policy caps it at `MEMORY_MAX_RESULT_BYTES` (256 MiB).
  - Task `memory.analyze` on queue `memory` (prefixed `test.` in the test profile).
- **Ingest** (`memory_analysis/ingest.py`, `stream.py`; dispatched by schema version in `workers/ingest.py`):
  - Validate the whole stream before any write, with the M3 `static_stream` structure: header names this job, schema and profile; per-kind caps (`MemoryLimits`), duplicates, trailer line count and sha256, gzip ratio and size bounds. `check_framing` gets the memory bounds (`MEMORY_MAX_RESULT_DECOMPRESSED_BYTES`, lines = the sum of the `MemoryLimits` caps + 3), not the shared 1 GiB / 400 000 defaults; `test_memory_stream.py` builds a stream at every cap and proves it fits the 256 MiB upload cap and these bounds (RT9).
  - **Identity:** the `image` line must carry the evidence record's size and sha256 (the worker hashes during download; a mismatch is `invalid_result`). The UI shows the trusted hashes.
  - **Consistency:** every `process.pid` referenced by a connection, injection or artifact exists in the process records or is recorded as `orphan_ref` in the summary counts (a hostile stream cannot invent links silently); `os` in the header matches the record kinds (no `bash` artifact on Windows, no `service` on Linux).
  - One transaction: `memory_images`, `memory_processes`, `memory_connections`, `memory_injections`, `memory_artifacts`, then `analysis_findings`, `iocs` and `analysis_timeline` through the existing M3 writers, the job summary (`memory_summary` jsonb ≤ 32 KiB), `succeeded`, custody `analyzed`, audit.
  - Batching follows `_limit_transaction` (statement timeout raised for the ingest transaction only, as M3 does); a result at every cap (about 160 k rows) must ingest within it (measured in phase 11).
- **Diagnostic result** (frozen in phase 1; plan "Symbols"):
  - A `finished` message with `outcome: failed`, `error_code: symbols_missing` **and** a `result_version_id` is accepted for memory jobs only (`IngestMessageV1` already allows it; the ingest refuses it for other analyzers).
  - The stream holds `header` (with `symbols.status = missing` and `symbols.required`), at most the `image` line, and the trailer. Anything else → the job fails `invalid_result` instead.
  - The ingest writes `memory_images` (facts and the requirement) and fails the job `symbols_missing`, in one transaction. The requirement is validated strictly (Windows: PDB name in the allowlist, 32-hex GUID, age ≤ 2^16; Linux: banner ≤ 512 printable characters).
- **Reaper:** memory jobs use `ANALYSIS_MEMORY_TIMEOUT_S` (5 400 s) plus the M2 grace; `never_started` after the queue TTL as usual.
- **Error codes:** every code from the worker and the ingest is in `ops/error_classes.py` (phase 1 adds them; this phase only emits them).

## Implementation Steps
1. Read the M3 `static_analysis/{ingest,stream}.py`, `workers/ingest.py` and the phase-1 `memory.py` contract.
2. Intake: `kind=memory`, limits, declared type, free-space check; unit and integration tests.
3. Request and caps; the sensitivity call; the custody and audit rows.
4. Dispatch: message, presigned URLs, task; test the message validates and pins the version.
5. Stream validation (`stream.py`) with hostile fixtures: wrong job, wrong hash, caps exceeded, duplicate pids, orphan refs, OS mismatch, trailer mismatch, extra fields, NUL, NaN, oversize gzip.
6. Writers and the single transaction; the diagnostic path.
7. Run lane 6: `scripts/lane-test.sh 6 uv run pytest -q -p no:cacheprovider <own paths>`, plus `ruff` / `mypy` on own files.

## Success Criteria
- [ ] A 4 GiB `kind=memory` upload is accepted under the memory limit and a 4 GiB upload without it is refused (tested with a declared `Content-Length`, no real bytes).
- [ ] A `kind=memory` upload is restricted with AI / TI excluded in its own transaction and gets no automatic job.
- [ ] A memory request creates a queued job, calls the sensitivity entry point once, writes custody and audit, and respects the per-org and global caps.
- [ ] The dispatched `MemoryJobV1` validates against the frozen contract and pins the evidence version.
- [ ] A valid `memory.v1` fixture ingests into every `memory_*` table plus findings, IOCs and timeline in one transaction; every hostile fixture fails `invalid_result` with no row written.
- [ ] A `symbols_missing` diagnostic result stores the requirement and fails the job; the same shape on a static job is refused.

## Risk Assessment
- **Large uploads through one HTTP request:** no resume; a dropped 8 GiB upload restarts. Accepted for M8 (single node, LAN); direct multipart upload to MinIO with a server-side re-hash is recorded in ROADMAP "Later".
- **Ingest size:** about 160 k rows at every cap in one transaction. Mitigated by per-kind caps (artifacts 50 000 after RT9) and `executemany` batches; phase 11 measures it.
- **Contract drift with phase 2:** both sides build against the phase-1 fixtures in `tests/fixtures/memory/`; any change is a parent broadcast.
