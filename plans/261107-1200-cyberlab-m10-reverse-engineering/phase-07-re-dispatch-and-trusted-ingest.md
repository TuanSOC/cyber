---
phase: 7
title: "Re dispatch and trusted ingest"
status: pending
priority: P2
effort: "16h"
dependencies: [1]
---

# Phase 7: RE dispatch and trusted ingest (group B, 2f, lane 6)

## Overview
The trusted side of the pipeline: request validation and job creation, the `ReJobV1` message, the reaper deadlines, and the ingest that validates a `re.v1` stream as a whole, joins capa locations to functions and writes everything in one transaction.

**Owns:** `apps/api/app/modules/reverse_engineering/{dispatch,ingest,stream,join}.py` (bodies of the frozen `build_re_message`, `ingest_re`, `ingest_re_diagnostic`), the `reverse` branches of `analysis/{service,dispatch,analyzers}.py`, `workers/{ingest,reaper}.py`, `tests/integration/test_analysis_reverse.py`, `test_re_ingest.py`, `test_re_join.py`, `tests/unit/test_re_stream.py`.

## Requirements
- **Request** (`POST /evidence/{id}/analyses`, `analyzer: reverse`, `evidence.write`):
  - `source_job_id` optional: default = the evidence's latest succeeded static job with profile `full` and `file_format ∈ {pe, elf}`; given explicitly, it must be such a job of the same evidence; otherwise `409 static_analysis_required`.
  - The source job's facts must say x86 / x86-64 (`PeInfo.machine` / `ElfInfo.machine`), else `422 unsupported_architecture` (refused before queueing; the worker re-checks). A PE whose source-job imports include `mscoree.dll!_CorExeMain` / `_CorDllMain` → `422 unsupported_managed_code`; `PeInfo` has no CLR field, so the worker's CLR-directory check is the authoritative one (diagnostic result).
  - Size ≤ `RE_MAX_BYTES` → else `413 re_sample_too_large`.
  - `profile`: `full` (default; optional `decompile_addresses`, 0–64 unique addresses, decimal strings ≤ 2^64 − 1, decompiled first: RT10, no `targeted` profile), `quick` (`422 profile_unavailable` unless `RE_QUICK_ENABLED`; `decompile_addresses` refused).
  - Active caps `RE_MAX_ACTIVE_PER_ORG` and the platform-wide `ANALYSIS_HEAVY_MAX_ACTIVE` over memory / disk / reverse (the shared check from phase 1, RT2; `429 too_many_active_jobs`, `reason: heavy_analysis_busy`, never naming another org's job); queue TTL 6 h; never auto-run (`auto_choice` unchanged, a test proves no upload creates a `reverse` job).
  - Custody and audit as for other manual analyses (`analysis.requested`, `analyzer: reverse`, profile, source job id; never addresses beyond their count).
- **Message** (`build_re_message`): the presigned GET of the exact evidence version, the presigned POST with the fixed result key and the `RE_MAX_RESULT_BYTES` cap, the ingest token, `limits` from settings, `capa_file_vas` computed from the source job's `malware_capabilities.locations` normalized to file virtual addresses (`loc − (capa_base_address − preferred_base)`, the preferred base from the source job's `pe.image_base` / the ELF lowest `PT_LOAD` recorded by phase 6; RT8) (ints, deduplicated, sorted, ≤ 512; none when the base is NULL), `file_format` from the source job.
- **Reaper:** run deadline `ANALYSIS_RE_TIMEOUT_S` + the M2 grace; queue deadline from the TTL.
- **Stream validation** (`stream.py`), before any write:
  - framing through `check_framing` with the RE bounds (`RE_MAX_RESULT_DECOMPRESSED_BYTES`, lines = sum of caps + 3); a unit test builds a stream at every cap and proves it fits both the 256 MiB upload cap and these bounds (M8 RT9);
  - header names this job, schema `re.v1`, the requested profile; `engine: replay` refused unless the api runs with `TEST_PROFILE=1`;
  - the shared `validate_stream()` cross-record rules from py-jobs; trailer hash; per-kind caps; duplicates refused;
  - `program.format` equals the source job's `file_format`.
- **Join** (`join.py`, pure, unit-tested; RT8): both sides normalized to **file virtual addresses**: capa `file_va = loc − (capa_base − preferred_base)`, Ghidra `file_va = va − (image_base − preferred_base)` with `preferred_base` from the file (PE `ImageBase`; ELF lowest `PT_LOAD` vaddr, page-aligned) and stored in `re_programs`; find the function whose body ranges contain it (interval search over sorted ranges); write `re_function_capabilities` rows (capability id, function entry, `file_va`); unmatched locations are counted in `re_programs.counts.capa_unlocated`. Unit tests cover PE, ELF non-PIE and ELF PIE with the base conventions phase 6 recorded; the real-engine proof is phase 12's (PE `injector`, ELF `elf_net` PIE and non-PIE).
- **Stream validation memory:** `validate_stream()` keeps only key sets (function entries, edge pairs, ref keys: ≈ 300 000 ints at the caps), never the records, so the single ingest worker stays bounded.
- **Ingest** (`ingest_re`, one transaction): `re_programs` (with `preferred_base` and `peak_memory_bytes`), the bulk tables (COPY-style batched inserts as in the M3 ingest), the join rows, `analysis_findings`, `iocs`, custody `analysis.completed`, job summary (counts, stage statuses, truncation flags, `capa_linked` / `capa_unlocated`) ≤ 32 KiB. `ingest_re_diagnostic`: header + program only, job `failed` with the diagnostic code (`unsupported_architecture`, `unsupported_managed_code`, `unsupported_format`).
- **Failure modes:** an invalid stream fails the job `invalid_result` with nothing written; a stream for a job whose source static job was purged (M7 retention) still ingests, without join rows (`capa_unlocated` = all).

## Implementation Steps
1. Read the M3 static request path, dispatch, ingest and the M8 memory variants (the most recent analyzer pattern).
2. Request validation and dispatch; integration tests for every refusal.
3. `stream.py` with the at-every-cap test; `join.py` with interval tests.
4. `ingest_re` / `ingest_re_diagnostic` wired by schema version in `workers/ingest.py`; reaper branch.
5. Lane 6 tests (seeded through `seed_static_source_job()` and the phase-1 fixtures), `ruff`, `mypy`.

## Success Criteria
- [ ] Every refusal path answers its code; no upload ever creates a `reverse` job.
- [ ] A fixture stream ingests completely in one transaction; every hostile fixture is refused with nothing written.
- [ ] The join links capabilities to the right functions for PE, ELF non-PIE and ELF PIE cases and counts the rest.

## Risk Assessment
- **Large transactions:** up to ≈ 300 000 rows plus 32 MiB of code in one transaction; batched inserts and `statement_timeout` sized for it (measured in phase 12 at every cap).
- **Source job semantics:** the RE job pins its source job id, so later static re-runs do not change an RE result's links (stated in the UI).
