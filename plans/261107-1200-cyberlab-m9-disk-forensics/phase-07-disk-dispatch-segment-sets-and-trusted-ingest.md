---
phase: 7
title: "Disk dispatch segment sets and trusted ingest"
status: pending
priority: P2
effort: "21h"
dependencies: [1]
---

# Phase 7: Disk dispatch, segment sets and trusted ingest (group B, 2e, lane 6)

## Overview
The trusted API and ingest side of a disk job:
- the `kind=disk` upload (per-kind limit, the restricted default in the upload transaction, no automatic analysis);
- the job request with an ordered **segment set**;
- dispatch on the `disk` queue with presigned GETs per segment;
- the reaper's disk timeouts;
- the **hand-off** of a disk result from the shared ingest queue to the dedicated `disk-ingest-worker` (RT9);
- the **ingest** of a whole `disk.v1` stream in one transaction on that worker, including the in-org known-hash join and the diagnostic stream.

**Owns:**
- `app/modules/disk_forensics/{dispatch,handoff,ingest,stream,segments}.py` (after the phase-1 stubs);
- the disk branches of `analysis/{service,dispatch,analyzers}.py`;
- the bodies of the disk branches in `workers/ingest.py` (the hand-off), of the `disk.ingest` task and of `workers/reaper.py`;
- `evidence/uploads.py` (the `kind=disk` path);
- `core/filetypes.py` (EWF / raw detection labels);
- `tests/integration/test_disk_{upload,request,segments,dispatch,handoff,ingest,ingest_caps,known_hash_join,diagnostic,reaper}.py`, `tests/unit/test_disk_{stream,segments}.py`.

## Requirements
- **Upload** (`POST /investigations/{inv}/evidence?kind=disk`, the M8 `kind=memory` path):
  - the per-kind limit `DISK_MAX_UPLOAD_BYTES` on the declared length and while streaming (`413 disk_image_too_large`); empty → `422 disk_image_empty`;
  - in the upload transaction: `apply_restricted_default(…, source="disk")` (phase 1's service over M8's table, RT2) and **no** `auto_request` call (no static `av`; the M8 RT3 rule);
  - `detected_description` labels `EWF (E01) segment` / `raw disk image (unrecognised)` from magic (`core/filetypes.py`, label only; the worker decides).
- **Request** (`POST /evidence/{id}/analyses`, `analyzer: disk`, `profile: triage|full`, `os_hint`, `segments: [uuid, …]`):
  - **Segment set rules** (`segments.py`):
    - `segments[0]` must equal the path `{id}`;
    - 1..`DISK_MAX_SEGMENTS` unique ids;
    - every id is active (not purged, not tombstoned) evidence of the **same investigation** in the org;
    - the sum of sizes ≤ `DISK_MAX_IMAGE_BYTES` (`413 disk_image_set_too_large`);
    - otherwise `422 disk_segments_invalid` with a reason code (`duplicate`, `other_investigation`, `not_found`, `purged`, `empty`). An id of another org is `not_found` (no oracle).
  - **In one transaction:**
    - the job row (`profile`, `os_hint`);
    - `analysis_job_segments` (the trigger re-checks the investigation);
    - `apply_restricted_default(source="disk")` on **every** segment (idempotent);
    - a custody entry per segment (`analysis_requested`, with the job id and ordinal);
    - the audit.
  - `profile: extract` is refused here (phase 10 creates extract jobs).
  - Concurrency: `DISK_MAX_ACTIVE_PER_ORG` / `DISK_MAX_ACTIVE_TOTAL` (`429 analysis_busy`, the M8 pattern).
- **Dispatch** (`dispatch.build_disk_message`):
  - one presigned GET per segment for the exact version id, expiring after the queue TTL (12 h) + the job timeout;
  - the result POST (fixed key, `DISK_MAX_RESULT_BYTES`);
  - the ingest token;
  - `DiskLimits` from settings;
  - `deadline_at` (the job deadline the worker budgets against; RT5); no cache key (RT1);
  - published to `Queues.disk` as `disk.analyze`.
- **Reaper:** `ANALYSIS_DISK_TIMEOUT_S` + the M2 grace; the queue TTL for queued disk jobs. A handed-off job's deadline is the hand-off time + `DISK_INGEST_TIMEOUT_S`; a disk ingest that outlives it is reaped `timed_out` (its transaction then rolls back on the guarded transition).
- **Hand-off** (`handoff.hand_off`, RT9): the shared ingest worker (solo; also runs the reaper and the M7 correlation tick) only validates the `finished` event (token, org, version id), moves the job deadline by `DISK_INGEST_TIMEOUT_S` (1 800 s) under the job lock, and sends `disk.ingest` to `Queues.ingest_disk`; it never reads the stream. The `disk-ingest-worker` consumes that queue alone, so a multi-minute disk ingest never delays other analyzers' results, the reaper or correlation. Redelivery is safe (the guarded transition makes a second ingest a no-op).
- **Ingest** (`ingest.ingest_disk`, run by the `disk.ingest` task on the `disk-ingest-worker`, dispatched by schema version; the M3 / M8 pattern):
  - **Validation (pass 1):** framing with the disk bounds (`DISK_MAX_RESULT_DECOMPRESSED_BYTES`, lines = the sum of the caps + 3); the token and org from the job index; the whole stream validated against the frozen models before any write, streaming (only the natural-key set and the cited refs are kept in memory, never the records); the header's job id and segment count must match the job.
  - **Writes (pass 2):** `body_lines()` re-reads the validated file (the M2 two-pass framing).
  - **One transaction:**
    - `disk_images` (from the header);
    - `disk_partitions`;
    - `disk_files` via `COPY` in batches of 10 000 (`parent_addr` from the record, RT13; `ext` normalised);
    - `disk_events` via `COPY`, resolving `file_id` by natural key through a temp table;
    - findings (evidence refs resolved from natural keys / event ordinals to row ids; unresolved refs dropped and counted), IOCs, `analysis_timeline` rows, the job summary;
    - custody (`analysis_completed` on each segment).
  - **Known-hash join** (trusted, in the same transaction, `correlation:disk_known_org_hash@1`):
    - for the job's hashed files, join `sha256` / `sha1` / `md5` against the org's `iocs` hash values and `correlation_keys` hash kinds from **other** jobs;
    - one finding per matched file (`low`; capped at 500 findings, then one summary finding with the count), with evidence refs to the file and the matched source;
    - the join runs under the tenant session (RLS) with `SET LOCAL statement_timeout` = 120 s; a timeout skips the join and records `known_hash_join: skipped_timeout` in the summary (never fails the ingest).
- **Diagnostic** (`ingest_disk_diagnostic`, `no_supported_filesystem` / `unsupported_disk_format`): stores `disk_images` + `disk_partitions` only; the job fails with the worker's code.
- **Measurements:** the ingest test at every cap (500 000 files + 250 000 events + 5 000 findings) records the ingest time, the peak RSS of the ingest process (≤ 1 GiB, the `disk-ingest-worker` limit) and the Postgres size per job into the test output; phase 13 copies them to the metric report. A target of ≤ 10 min on the dev host (under `DISK_INGEST_TIMEOUT_S`); above it, the parent decides. A test proves a pcap result ingests on the shared worker while a disk ingest runs.

## Implementation Steps
1. Read the M8 dispatch / ingest (phase 6 of M8), `evidence/uploads.py`, `analysis/service.py`, `workers/ingest.py`, `reaper.py`, the M2 `COPY` ingest helpers.
2. The upload path and `filetypes.py` labels; tests (no auto job, restricted default in the same transaction, the limits).
3. `segments.py` and the request branch; tests for every refusal reason, cross-investigation and cross-org.
4. Dispatch, the hand-off and the reaper branch; tests with a fake broker.
5. Stream validation, `COPY` ingest, natural-key resolution, the known-hash join, the diagnostic ingest; the cap test with measurements; the concurrency test (shared ingest not blocked).
6. Lane 6: `scripts/lane-test.sh 6 uv run pytest -q -p no:cacheprovider <own paths>`, `ruff`, `mypy`.

## Success Criteria
- [ ] A `kind=disk` upload is restricted and AI / TI excluded in the same transaction and gets no job.
- [ ] Segment sets are validated (same investigation, order, unique, size), and every segment is restricted when a job is created.
- [ ] The fixture streams ingest in one transaction; a hostile stream writes nothing; unresolved refs are dropped and counted.
- [ ] The known-hash join finds a seeded IOC sha256 from another case and never reads another org's rows.
- [ ] A stream at every cap ingests within the framing bounds and the 1 GiB worker limit on the `disk-ingest-worker`; the shared ingest queue keeps serving while it runs; the time, RSS and size are recorded.

## Risk Assessment
- **Ingest duration:** isolated on the `disk-ingest-worker` (RT9); staged ingest was rejected (RT36: partial state, no app DELETE grant, redelivery duplicates). Two disk results ingest one after the other (one job at a time anyway).
- **The known-hash join on large org IOC tables:** indexed on (org, type, value); bounded by the statement timeout; skippable without failing.
- **Segment order mistakes by analysts:** for EWF, libewf validates the set itself (wrong order or a foreign segment → `unsupported_disk_format` with its reason); for split raw, order is the analyst's responsibility, stated in the run dialog (phase 11), and the media sha256 lets them compare against their acquisition notes.

## As built (untested in Docker)

Code-only commit `feat(disk): request, segment sets, dispatch and trusted ingest (M9 phase 7, untested in Docker)`. Host-only checks: py_compile of every changed module, the pure unit tests (`test_disk_stream.py`, `test_disk_segments.py`, `test_disk_settings.py`) through a throwaway shim (stubbed `minio`; host SQLAlchemy lacks `distinct_on`), an unused-import / line-length scan. Not run: ruff, mypy, any integration test.

**Seams:** `segments.check_shape` / `check_rows` (pure) / `load` / `of_job`, `Segment`; `DispatchInput.segments`; `dispatch.disk_limits(settings, profile)`; `handoff.publish` / `move_deadline` / `HandOffBusy` (a ConnectionError: `ingest.event` retries it); `stream.Caps` / `diagnostic_caps` / `JobFacts` / `file_ref` / `event_ordinal` / `finding_id`; `ingest.Resolver`, `known_hash_join`, `KNOWN_HASH_*`. Stored refs: `file:<disk_files.id>`, `event:<disk_events.id>`, `finding:<uuid>`; timeline refs the same (a bare finding uuid kept); known-hash findings cite `file:`, `ioc:<id>` / `correlation_key:<id>` and `job:<id>`. Test helper `tests/disk_results.py` (fixtures `sent`, `handoffs`; `deliver` runs hand-off + disk ingest in-process).

**Deviations (parent to confirm):**
- No `COPY`: Postgres refuses COPY into RLS tables (the M2 note), so rows go in as batched INSERTs of 10 000 lines / 16 MiB; file and event ids are generated in Python, so `file_id` and finding refs resolve from the cited refs pass 1 kept (no temp table).
- The job row is locked only at the end of the write (its rows' FKs hold KEY SHARE meanwhile). The hand-off and the reaper take disk job rows with `SKIP LOCKED` (the shared solo worker never waits on a disk ingest); the ingest itself rolls back and fails `timed_out` when it finishes past its deadline.
- `deadline_at` = message time + `ANALYSIS_DISK_TIMEOUT_S` (never past the reaper's started deadline).
- Extra refusal reason `archived`; `ordinal` beside `reason` in the error body; analysis-busy code stays M8's `analysis_queue_full`.
- `kind=disk` uploads also get M8's spool free-space check; `.e01` / `.ex01` declare the `disk` family; `UploadKind` gains `disk` (OpenAPI change: `pnpm gen:contracts` must be re-run).
- `volume_system` is stored NULL (not in the frozen header).

**Remains to run (Docker):** ruff / mypy; lane 6 `tests/unit/test_disk_{stream,segments}.py`, `tests/integration/test_disk_{upload,request,segments,dispatch,handoff,ingest,known_hash_join,diagnostic,reaper}.py`, `test_m9_foundation.py`; `DISK_INGEST_CAPS=1 … test_disk_ingest_caps.py` alone (time, RSS, Postgres size); `pnpm gen:contracts`.
