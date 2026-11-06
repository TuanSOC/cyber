---
phase: 7
title: "Re dispatch and trusted ingest"
status: code-complete (untested in Docker)
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

## Notes (as built, untested in Docker)

Code-only (no container ran). Host checks: `tests/unit/test_re_stream.py` (38) and `tests/unit/test_re_join.py` (12) pass on the host (`--noconftest`, the API's missing third-party deps stubbed); the whole app imports and the integration modules collect.

- **Request** (`reverse_engineering/dispatch.load_source`, called by `analysis/service._create` after the per-org cap and the heavy cap, phase 1): the requested (else the latest) succeeded static `full` job of the same evidence whose `malware_samples.file_format` is `pe` / `elf` (a purged result has no sample row: it does not qualify) -> `409 static_analysis_required`; machine (case-insensitive) `i386` / `amd64` / `EM_386` / `EM_X86_64` else `422 unsupported_architecture` (missing facts too); a PE importing `mscoree.dll!_CorExeMain|_CorDllMain` -> `422 unsupported_managed_code`. Size (`413 re_sample_too_large`), `quick` gate, schema rules, custody and audit (`source_job_id`, the count of `decompile_addresses`, never the addresses) were already in phase 1's `_create` / `request_analysis`. No `analysis/service.py` change was needed.
- **Preferred base at dispatch:** PE `pe.image_base`; ELF the lowest allocated (`alloc` flag) section address > 0, page-aligned down (`ElfInfo` has no PT_LOAD field; phase 6 notes). `capa_file_vas` = `join.capa_file_vas(locations, capa_base, preferred)` (none without a capa base; <= 512, the lowest kept).
- **Message:** `build_re_message` unchanged from phase 1.
- **Reaper:** no change: the run deadline is `analyzers.timeout_s(REVERSE)` (`ANALYSIS_RE_TIMEOUT_S`) + the M2 grace (set on `started` by the shared ingest), the queue deadline the shared TTL; the RE ingest runs in the shared ingest worker (no hand-off like disk).
- **Stream** (`stream.py`): `check_framing` with `RE_MAX_RESULT_DECOMPRESSED_BYTES` / `Settings.re_max_result_lines()`; header job / profile; `engine: replay` only when `ingest.replay_allowed()` (`ENV=test`, the api-test service: there is no `TEST_PROFILE` setting in the API); header blocks sized against their `re_programs` jsonb checks (`header_too_large`) and the engine version <= 32; the shared `StreamChecker` (refusals -> reason `stream_rule`); program sha256 / size = the evidence (`program_mismatch`), format = the source job's when its sample row exists (`format_mismatch`); duplicate finding ids / IOCs. Kept in memory besides the checker's key sets: decompile statuses (<= max_decompiled) and, only when the source has capa locations, the body ranges for the join. The every-cap test is an estimate with every character escaped six-fold (≈ 680 MB < 768 MiB) plus the exact line bound.
- **Join** (`join.py`, pure): `capa file_va = loc - (capa_base - preferred_base)` with **`preferred_base` = the RE program record's** (`re_programs.preferred_base`), body RVA r -> file VA `preferred_base + r`; interval search over sorted ranges with a running max end; one link per (capability, function) at the lowest file VA; overlapping bodies link to every container. Counts: `capa_linked` / `capa_unlocated` (locations), `capabilities_linked`.
- **Ingest** (`ingest.py`): validation + join in a worker thread, then the shared `_persist`: `re_programs` (counts incl. `capa_linked` / `capa_unlocated`, peak memory = max stage peak, engine version), bulk rows in batches (`RowBuilder` gives imports / strings their uuid when read and maps the refs; a function's `decompile_status` from its decompiled line, else `not_selected`), links in batches of 1000, findings / IOCs in the shared tables. Summary (<= 32 KiB): header run facts, stages, trusted sample identity, program facts, counts, decompile budget, peak memory, `source_job_id`. `ingest_re_diagnostic`: header + program only, `re_programs` row then `_fail(code)` (the memory pattern).
- **Purged source:** no format check, no links, `capa_linked = capa_unlocated = 0` (the rows are gone, so "all" is 0).
- **Tests:** `tests/reverse_results.py` (static source through the real static ingest, request helper, retargeted fixtures), `tests/integration/test_analysis_reverse.py` (every accept / refusal path, ELF base, message, never automatic), `tests/integration/test_re_ingest.py` (success incl. join and redelivery, ELF, quick, purged source, diagnostic, hostile streams), `tests/unit/test_re_{stream,join}.py`. `test_m10_foundation.py`: the request now answers `409 static_analysis_required` (only that hunk is mine; phase 9 edits the same file).

**Remains (Docker):** `scripts/lane-test.sh 6 uv run pytest -q -p no:cacheprovider tests/unit/test_re_stream.py tests/unit/test_re_join.py tests/integration/test_analysis_reverse.py tests/integration/test_re_ingest.py tests/integration/test_m10_foundation.py`; `ruff format`, `ruff check`, `mypy` (not run: no ruff / mypy on the host); the ingest at every cap (time, RSS, statement timeout) in phase 12; the real capa + Ghidra base check (phases 6 / 12).
