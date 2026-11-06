---
phase: 1
title: "Foundation contracts migration and memory worker skeleton"
status: pending
priority: P2
effort: "27h"
dependencies: []
---

# Phase 1: Foundation contracts, migration 0015 and memory worker skeleton (group A)

## Overview
One agent lays the frozen foundations for eight parallel lanes:
- the `memory.v1` contract with fixtures;
- migration 0015 and the models;
- every new route as a **501 stub** with frozen schemas, then one `pnpm gen:contracts` run;
- the memory worker image and skeleton, the trusted symbol tool service, the broker user, volumes and compose wiring;
- the cross-phase entry points as stubs;
- implemented shared pieces: the memory error classes, the lifted IOC extractor (`cyberlab_worker.iocs`), the **analyzer sweep** (a memory arm in every two-analyzer branch, RT1) and the additive report snapshot field `omissions` (parent decision, RT10);
- the lane script extensions (`--service memory-worker-test`, `--heavy`, lane 8), test helpers, IDOR module, web shared files and slots.

After this phase the stack runs as before:
- the new routes answer `501 not_implemented`;
- a manual memory request is accepted by schema but the worker fails it `not_implemented`;
- nothing is automatic;
- the static worker behaves identically (IOC shim).

**Everything listed under "Frozen interfaces" in plan.md is frozen at the end of this phase.**

## Requirements
- **Pre-flight:**
  - M7 merged and its `pnpm verify:prod` (with the restore drill) green.
  - Alembic head is `0014`; otherwise number head + 1 and tell the parent.
  - Create `feat/m8-memory-forensics` from the M7 merge.
  - Re-read `analysis/{models,analyzers,service,dispatch}.py`, `workers/{celery_app,tasks,ingest,reaper}.py`, `ops/error_classes.py`, the 0006 profile checks, the 0014 `job_outcomes` checks and trigger, `infra/redis-broker/entrypoint.sh`, the static worker Dockerfile and compose anchors.
- **Contract** (`packages/py-jobs/src/cyberlab_jobs/memory.py`, the `static.py` style on the `Strict` base; plan "Frozen interfaces" 1):
  - `MemoryPlugin` holds exactly the plan's allow-list, with the **2.28.2 names**: `windows.malware.malfind`, `windows.malware.ldrmodules`, `linux.malware.*`, `windows.registry.*`, never the deprecated shims; no `windows.handles` and no YARA plugin (RT8, RT9). `PLUGINS_BY_PROFILE[(os, profile)]` gives the fixed run order.
  - `MemoryLimits`: processes 20 000, connections 50 000, injections 5 000, artifacts 50 000, findings 5 000, IOCs 20 000, timeline 5 000, `max_result_bytes` 256 MiB; `MemoryArtifactRecord.type` ∈ `module/service/hive/userassist/ldr_unlinked/bash/open_file/syscall_hook/hidden_module`.
  - `MemoryLimits` caps and bounds; `MemoryJobV1`; the header with `engine`, `symbols`, `plugins[]`.
  - The record models with bounded text (`cmdline` ≤ 4 096, names ≤ 64, paths ≤ 1 024, `head_hex` `^[0-9a-f]{0,128}$`, `disasm` ≤ 1 024, NUL-free), addresses `0 ≤ x < 2^64`, timestamps aware within 1970..2100, ports 0..65 535. `MemoryArtifactRecord.attributes` takes at most 32 scalar values (str ≤ 1 024, int, bool, null).
  - `WindowsPdb{name ∈ kernel PDB allow-list, guid ^[0-9A-F]{32}$, age 0..65 535}` and `LinuxBanner{banner: printable, ≤ 512}`.
  - `SymbolManifestV1{version: 1, volatility_version, files: [{path (relative, no `..`, ≤ 255), sha256, os, identity, source (`msdl` | `zip:<sha256>` | `operator`), imported_at, tool_version}]}`.
- **Report snapshot field** (`packages/py-jobs/src/cyberlab_jobs/report.py`; parent decision, RT10): `Omissions(Strict){memory_restricted: int ≥ 0}` and `ReportSnapshot.omissions: Omissions | None = None`. `canonical_json` leaves the key out when it is `None`. `test_report_canonical_golden.py`: every M6 snapshot fixture re-validates and re-serializes to the same bytes and sha256; a snapshot with `omissions` round-trips. Phase 8 fills it and renders it.
  - The diagnostic-stream rule.
  - `tasks.py`: `MEMORY_ANALYZE`, `Queues.memory`; exports in `__init__.py`.
- **Fixtures** `packages/py-jobs/tests/fixtures/memory/`, all hand-written and labelled synthetic in their header:
  - `windows_triage.ndjson` (about 40 processes with a hidden one, connections, an injection, artifacts of every Windows type, findings, IOCs, timeline);
  - `linux_triage.ndjson`;
  - `symbols_missing.ndjson`;
  - `hostile/` (wrong job, NaN, NUL, oversize cmdline, 33 attributes, a nested attribute, an extra field, a bad GUID, a path with `..` in a manifest, a stream after the trailer).

  `test_memory_contract.py` round-trips the valid ones and refuses every hostile one.
- **Migration `0015_m8_memory_forensics.py`** (plan "Data model"):
  - `ALTER TYPE analyzer ADD VALUE IF NOT EXISTS 'memory'` in an autocommit block (as 0006).
  - Every bulk memory table has `id` (uuid PK), `organization_id` and `job_id` (`retention/select.py` counts by them; citations reference `id`; RT23).
  - Replace the two profile checks; add `os_hint` with its iff check; extend the job guard that keeps the profile write-once to cover `os_hint`.
  - The `job_outcomes` kind check gains `memory`.
  - The five tenant tables with FORCE RLS, `tenant_isolation`, composite FKs, named checks (`octet_length`, `jsonb` size via `octet_length(x::text)`, scalar-only `attributes` through a `jsonb_typeof` check function).
  - The `memory_sensitivity` transition trigger (release once; no other UPDATE; no DELETE).
  - Grants: app S/I (+ the sensitivity columns); retention DELETE on the four bulk tables.
  - Downgrade drops the tables and restores the checks. The enum value stays (documented and allowed by `test_migrations.py`).
- **Models** `app/modules/memory_analysis/models.py`, registered in `app/models.py`; `Analyzer.MEMORY`.
- **Schemas and stubs:**
  - `memory_analysis/schemas.py` (`MemorySummaryOut`, `ProcessPage`, `ProcessDetailOut`, `ConnectionPage`, `InjectionPage`, `ArtifactPage`, `MemorySensitivityOut`, `ReleaseIn`);
  - the analysis request body (`analyzer`, `profile`, `os_hint`) and `EvidenceOut.memory_sensitivity`;
  - stub routers mounted in `main.py`: `memory_analysis/router.py` (phase 7) and `router_sensitivity.py` (phase 8);
  - the error codes;
  - `pnpm gen:contracts`.
- **Entry-point stubs:** plan "Frozen interfaces" 5, with exact signatures. The calls from `analysis/service.py`, `analysis/dispatch.py`, `workers/ingest.py` and `workers/reaper.py` are added as `if analyzer == MEMORY: <stub>` branches. Their bodies belong to phase 6.
- **Error classes:** every memory code mapped in `ops/error_classes.py` (`symbols_missing` → `input`, RT25), with a test that every code in `memory.py`'s `MemoryErrorCode` literal is classified; `test_error_classes.py` also scans `apps/workers/memory`.
- **Analyzer sweep** (RT1): add a memory arm to every two-analyzer branch:
  - api: `search/service.py:_job_href` (`/memory/{job}`), `case_attack/sources.py` (route), `investigations/timeline.py:_ANALYZER_TITLE` ("Memory analysis"), `ops/metrics.py:ANALYZER_KINDS` and the running states, `ops/models.py:KINDS` and its check (matching 0015), `ops/schemas.py` (`OutcomeKind`, the failed-job `kind` Literal), `reports/citations.py` (memory tabs), `reports/redact.py`, `ai/service_outputs.py` (memory route and tabs), `analysis/schemas.py` and `analysis/service.py` (profile rules, the too-large error map);
  - `ai/context/builder.py:_digest_selections`: a memory branch that calls a stub raising `NotImplementedError` (phase 8 implements it);
  - web: `lib/analysis.ts` (`analysisSegment` → `memory/{id}`, `analysisKindLabel` → "Memory (triage)" / "Memory (full)", profile labels), `lib/correlation.ts` (route), `lib/ai.ts` (`JOB_TASKS.memory = []`: no memory-specific AI task);
  - tests: `tests/unit/test_analyzer_exhaustive.py` (every analyzer-keyed map and Literal covers every `Analyzer` member) and `lib/analysis.test.ts`.
- **IOC extractor:** move `static_worker/detections/iocs.py`'s pure functions into `packages/py-worker-kit/src/cyberlab_worker/iocs.py`. The static module becomes a re-export. Run the static unit tests once in the static image (heavy, alone) to prove no behaviour change.
- **Settings:** plan "Frozen interfaces" 7, with validators (`MEMORY_MAX_BYTES ≤ 16 GiB` (RT14), `ANALYSIS_MEMORY_PLUGIN_TIMEOUT_S < ANALYSIS_MEMORY_TIMEOUT_S ≤ 21 600`, `MEMORY_MAX_RESULT_DECOMPRESSED_BYTES` 1 GiB, RT9).
- **Memory worker image** (`apps/workers/memory/Dockerfile`, the static Dockerfile structure):
  - `python:3.12-slim-trixie`; `tool` uid **10006** (`ENV CYBERLAB_TOOL_UID=10006 CYBERLAB_TOOL_GID=10006`, the renderer precedent: RLIMIT_NPROC is per host uid, RT18) and `symbols` uid 10005; `libmagic1`, `libseccomp2`, `xz-utils`, `ca-certificates` (`libsnappy1v5` for AVML).
  - The venv from `uv.lock` with `volatility3==2.28.2`, `pefile`, `capstone`, `jsonschema`, `celery`, `httpx`, and the path packages `cyberlab_jobs` / `cyberlab_worker`. No YARA engine (RT8).
  - **`finalize_image.py`:**
    - asserts that `leechcorepyc`, `pycryptodome`, `pillow`, `smb`, `yara` and `yara_x` are **not** importable;
    - asserts `volatility3.__version__ == "2.28.2"`;
    - makes `site-packages` root-owned, not writable;
    - removes nothing from volatility3 (no modification, VSL);
    - copies the wheel's `LICENSE.txt` to `/usr/share/doc/volatility3/`;
    - writes `versions.json`.
  - `ENV HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent`, so no `vol.json` default can apply.
  - dev and prod targets; the dev target adds `tests/` and `samples/`.
- **Skeleton:**
  - `memory_worker/celery_app.py` (task `memory.analyze`, the queue from the env, `--concurrency 1 --max-tasks-per-child 1`) and `config.py`;
  - `analyzer.py` sends `started` then `failed / not_implemented`;
  - empty packages for phases 2–5;
  - `tests/conftest.py`;
  - the py-worker-kit isolation tests wired into the memory image's test command.
- **Compose** (dev, test, prod; plan "Frozen interfaces" 8):
  - `x-memory-worker` anchor: `init: true`, `read_only`, `cap_drop: ALL` plus the six M3 caps, `no-new-privileges`, `pids_limit: 256`, `mem_limit: 3g`, `cpus: 2`, tmpfs `/tmp` 64m, `analysis` network only, volumes `memory_work:/work` and `memory_symbols:/symbols:ro`, the broker URL with user `memory`, `restart: unless-stopped`.
  - `memory-worker-test`: test profile, `test.` queue prefix, **`/work` a per-container tmpfs (512m)** instead of the volume, so concurrent lanes never share or reset each other's work dir (RT6); `memory_symbols_test:/symbols:ro` (used only by phase 11's pipeline run; unit and engine tests build temp stores and point `MEMORY_SYMBOLS_DIR` at them); bind mounts of `apps/workers/memory/{memory_worker,tests,samples,dataset}` and the two packages (the `report-worker-test` pattern).
  - `memory-symbols`: profile `tools`, the same image, `user: 10005`, `read_only`, `cap_drop: ALL`, `mem_limit: 2g`, network **`symbols_egress`** only (a new non-internal bridge used by nothing else; not the shared `egress`, RT17), volume `memory_symbols:/symbols` rw and an operator import dir `./.memory-import:/import:ro`, no secrets, `entrypoint: python -I -m memory_worker.symbols`. A second service `memory-symbols-test` (profile `tools`) is identical but mounts `memory_symbols_test` at `/symbols`, so `reindex` always records `file:///symbols/…` locations (RT5).
  - Volumes `memory_work`, `memory_symbols`, `memory_symbols_test`; an init step makes the symbol volumes owned by 10005 and world-readable. No corpus volume (parent decision).
  - `CADDY_EVIDENCE_MAX` = max(`MAX_EVIDENCE_BYTES`, `MEMORY_MAX_BYTES`) + 1 MiB in `.env.example` with a comment.
  - The api gets the memory settings; `api-test` gets high test caps and `MEMORY_MAX_BYTES` small (64 MiB) for the intake tests.
- **Broker:** `analyzer_user memory` in `infra/redis-broker/entrypoint.sh` (own queue keys, write-only ingest), `BROKER_MEMORY_PASSWORD`; the api user publishes to `memory`.
- **Lanes:** `scripts/lane-test.sh` accepts `memory-worker-test` (broker db only, like `report-worker-test`) and `--heavy` (two slots, taken atomically: both or wait). The phase checks whether `cyberlab_b8_test` exists and creates it if not (a parent-approved one-off `createdb` as superuser, then `db-bootstrap` for the grants), and records the command in TESTING.
- **Root scripts:** `memory:symbols` → `docker compose --profile tools run --rm memory-symbols "$@"` (with `MSYS_NO_PATHCONV=1`; `--store test` selects `memory-symbols-test`), implemented; `memory:metrics` → stub, exit 2.
- **Test helpers and frozen tests:** `tests/memory_helpers.py`; `idor_cases_memory.py` with `PENDING_ROUTES` = the six phase-7 routes and `idor_cases_memory_sensitivity.py` with the two phase-8 routes (RT24). `test_rls_coverage.py` and `test_append_only.py` list the new tables. `test_dynamic_gate.py` still passes: `memory` is not `dynamic`, and the gate's `sandbox` name pattern must not match `memory-symbols`.
- **Web shared:**
  - `nav.ts` drops `plannedFor` for memory;
  - `audit-actions.ts` gains `memory.sensitivity_defaulted`, `memory.sensitivity_released`;
  - `http-errors.ts` gains the codes;
  - the analyzer badge gains `memory`;
  - the three empty slots are mounted;
  - `components/analysis/iocs-tab.tsx` gains an optional `enrichDisabledReason?: string` prop that hides the Enrich button and shows the reason (RT16).

## Implementation Steps
1. Pre-flight and branch.
2. `memory.py`, fixtures and the contract test (py-jobs unit tests on the host).
3. Migration 0015, models, `test_migrations` up/down, RLS and append-only coverage.
4. Schemas, stub routers, error codes, settings, entry-point stubs and branches; `gen:contracts`.
5. Lift the IOC extractor; the analyzer sweep with its exhaustiveness tests; the report `omissions` field with the golden test.
6. Worker image, skeleton, compose, broker user, volumes, networks, Caddy limit; build the memory image (heavy, alone); run the py-worker-kit isolation tests in it. Then rebuild, one at a time, every image that copies py-jobs / py-worker-kit (api, pcap, static, report: the kit is copied before `uv sync`, so each venv layer rebuilds) and run the static unit tests once in the new static image (heavy).
7. Lane script, lane 8 DB, root scripts, test helpers, IDOR module.
8. Web shared files and slots; `pnpm --filter web test typecheck lint`.
9. Full API suite once (the frozen state), then commit; record the frozen signatures below.

## Success Criteria
- [ ] The contract round-trips every valid fixture and refuses every hostile one.
- [ ] 0015 upgrades and downgrades; every new tenant table has FORCE RLS and is in the coverage tests.
- [ ] The memory image builds, the forbidden dependencies are absent, Volatility is 2.28.2, and the py-worker-kit isolation tests pass inside it.
- [ ] Every new route answers 501. A memory job request reaches the worker and fails `not_implemented`. The static worker's tests are unchanged.
- [ ] `lane-test.sh 8` and `--service memory-worker-test --heavy` work.
- [ ] `pnpm gen:contracts` shows no drift after the commit, and the web shared changes pass typecheck.
- [ ] `test_analyzer_exhaustive.py`, `lib/analysis.test.ts` and `test_report_canonical_golden.py` pass; a failed memory job does not break the org operations page.

## Risk Assessment
- **Wide shared surface:** many shared files change at once. Mitigated by the M7 pattern (stubs, one commit, full suite before freezing).
- **Enum value in a transaction:** `ALTER TYPE … ADD VALUE` needs its autocommit block; tested by a fresh-DB upgrade and an upgrade of a seeded M7 DB.
- **Report snapshot field:** an additive field can change the canonical bytes of signed snapshots; the `None`-omission rule and the golden test guard it, and the api and report-worker images are rebuilt together (RT10).
- **Analyzer sweep breadth:** the exhaustiveness tests catch a branch missed by the grep (RT1).

## Frozen interfaces (as built)
<!-- Filled by the phase-1 agent at commit time: exact signatures, settings names, fixture list. -->
See "Frozen interfaces (as built, untested)" below.

## Frozen interfaces (as built, untested)

Code-only commit `wip(m8): phase 1 foundation (untested; Docker steps pending)` on `feat/m8-memory-forensics`, based on the M7 review fix `d9e409c` (it brings `0015_m7_hold_sync`). Nothing below ran in a container yet; host-only checks that passed: `test_memory_contract.py`, `test_report_canonical_golden.py`, the worker's `tests/unit/test_config.py`, the static `test_iocs.py` (pure Python), byte-compilation of every changed file, an import smoke of the API models / schemas / mappers.

**Deviations from the plan text (parent to confirm):**
- Migration is **`0016_m8_memory_forensics`** (down_revision `0015`, the M7 hold-sync revision; parent instruction). Later M8 schema needs go into **0017**.
- One job-profile column type for both analyzers: API enum **`JobProfile`** (`full`, `av`, `triage`) replaces `cyberlab_jobs.static.Profile` on `AnalysisJob.profile`, `AnalysisCreate`, `AnalysisJobOut` and the list filter (the OpenAPI component `Profile` becomes `JobProfile`; web `StaticProfile` / `MemoryProfile` are `Extract<JobProfile, …>`).
- `build_memory_message` is **implemented** (not a stub), so a phase-1 memory request reaches the worker; the GET expires with queue TTL + job timeout. `analysis/service.py` already applies the memory caps (`MEMORY_MAX_ACTIVE_*`), `413 memory_image_too_large`, `422 memory_image_empty` and calls `apply_memory_default` (a phase-1 no-op returning False). Phase 6 owns and may refine these.
- RT3 in phase 1: `POST …/evidence?kind=memory` is accepted (`UploadKind = Literal["memory"]`) and **skips `auto_request`**; the memory size limit, declared type, free-space check and the upload-time sensitivity default stay phase 6.
- Contract additions not spelled out in the plan: `MemoryLimits.identify_timeout_s`, `MemoryResultHeader.audit_events` (PEP 578 counts), `MemoryImageRecord.pdb` (`WindowsPdb | None`), `MemoryTimelineEvent` (memory has its own timeline kinds: `system_time`, `process_start`, `process_exit`, `connection`, `finding`; event ≤ 16 chars for `analysis_timeline.event`), `MemoryArtifactRecord` attributes capped at 4 KiB serialized (`MAX_ATTRIBUTES_BYTES`, so the RT9 framing proof holds: 50 000 × 32 KiB would not), `memory_images.engine` column.
- Sweep extras beyond the listed files (same RT1 defect class): web `components/ai/ai-tab.tsx`, `components/analysis/job-header.tsx` (`WrongModuleNotice`), `components/correlation/correlation-parts.tsx`, `components/reports/{report-sections,selection-pickers}.tsx`, `lib/{report-format,use-case,ops-metrics}.ts`, `app/(app)/o/[orgId]/ai-analyst/{page,[runId]/page}.tsx`; API `reports/redact.py` seeds the pseudonymizer from memory command lines.
- `test_m7_foundation.py::test_no_route_still_raises_the_501_stub` now exempts the eight M8 pending paths.

**1. Contract** `packages/py-jobs/src/cyberlab_jobs/memory.py` (exports in `__init__`: `MEMORY_SCHEMA`, `MemoryJobV1`, `MemoryLimits`, `MEMORY_ANALYZE`; `Queues.memory`):
- `MEMORY_SCHEMA = "memory.v1"`; `MemoryProfile{triage, full}`; `OsHint{auto, windows, linux}`; `MemoryOs = Literal["windows","linux"]`.
- `MemoryPlugin` (19 values, 2.28.2 names) and `PLUGINS_BY_PROFILE: Mapping[(MemoryOs, MemoryProfile), tuple[MemoryPlugin, ...]]` (run order), `PROCESS_LIST_PLUGIN[os]`.
- `MemoryErrorCode` / `MEMORY_ERROR_CODES`: `not_implemented, symbols_missing, symbols_corrupt, memory_parse_failed, os_undetermined, unsupported_memory_format, memory_image_too_large, memory_image_empty, insufficient_disk, identify_timeout, plugin_timeout, plugin_failed, engine_unavailable`.
- `MemoryLimits{max_bytes ≤ 16 GiB, timeout_s ≤ 6 h, identify_timeout_s, tool_timeout_s, max_processes ≤ 20 000, max_connections ≤ 50 000, max_injections ≤ 5 000, max_artifacts ≤ 50 000, max_findings ≤ 5 000, max_iocs ≤ 20 000, max_timeline ≤ 5 000, max_result_bytes ≤ 256 MiB}` (tool and identify < timeout); `.max_lines()` = caps + 3.
- `MemoryJobV1{schema_version, job_id, organization_id, evidence_id, expected_sha256, size_bytes, evidence_url, result_post, ingest_token, profile, os_hint, limits}`.
- `WindowsPdb{name ∈ KERNEL_PDB_NAMES, guid ^[0-9A-F]{32}$, age 0..65535}`, `LinuxBanner{banner: printable ASCII ≤ 512}`, `KernelIdentity`, `identity_os()`.
- Lines: `MemoryResultHeader{job_id, profile, os, engine volatility3|replay, tool_versions, symbols: SymbolsInfo{status resolved|missing, isf_sha256?, required?}, plugins[PluginStatus{plugin, status ok|failed|timeout|skipped|unsupported, rows, truncated, duration_ms, error_code?}] ⊆ the profile's allow-list, audit_events, engine_errors, truncated}`; `MemoryImageRecord{size_bytes, sha256, layer, arch x86|x64, nt_build?, pdb?, kernel_banner?, system_time?}`; `MemoryProcessRecord`, `MemoryConnectionRecord` (proto tcp|udp|raw|unix|other), `MemoryInjectionRecord`, `MemoryArtifactRecord` (`ARTIFACT_TYPES`, `WINDOWS_ARTIFACTS`, `LINUX_ARTIFACTS`), shared `FindingRecord` / `IocRecord`, `MemoryTimelineEvent`, `ResultTrailer`; `MEMORY_RECORD_ADAPTER`, `MEMORY_LINE_ADAPTER`; `check_diagnostic_kinds(kinds)` (header, [image], trailer).
- `SymbolManifestV1{version 1, volatility_version, files[SymbolFile{path (relative, no ./.., ≤ 255), sha256, os, identity, source msdl|operator|zip:<sha256>, imported_at, tool_version}]}`.
- `report.py`: `Omissions(Strict){memory_restricted ≥ 0}`, `ReportSnapshot.omissions: Omissions | None = None`, dropped from `canonical_json` when None (golden sha256 of both M6 fixtures pinned).

**2. Fixtures** `packages/py-jobs/tests/fixtures/memory/`: `windows_triage.ndjson` (40 pslist+psscan processes, 1 psscan-only, 3 connections, 1 injection, every Windows artifact type, 2 findings, 2 IOCs, 4 timeline), `linux_triage.ndjson`, `symbols_missing.ndjson`, `manifest.json`, `hostile/{wrong_job, nan, nul_char, oversize_cmdline, attributes_33, nested_attribute, float_attribute, extra_field, unknown_plugin, address_overflow, verdict_severity, bad_guid, non_kernel_pdb, banner_control_chars, after_trailer, no_trailer, diagnostic_with_records}.ndjson`, `hostile/manifest_dotdot.json`; generator `build_fixtures.py` (hand-written records; regenerate after an edit). Test: `apps/api/tests/unit/test_memory_contract.py`.

**3. Migration 0016 / models** (`app/modules/memory_analysis/models.py`): `Analyzer.MEMORY`; `analysis_jobs.os_hint` (+ `ck_…_os_hint_valid`, `ck_…_os_hint_iff_memory`), `ck_analysis_jobs_profile_valid` (full|av|triage) + `ck_analysis_jobs_profile_matches_analyzer`; job guard covers profile + os_hint; `ck_job_outcomes_kind` gains memory. Tables `memory_images` (PK job_id), `memory_processes`, `memory_connections`, `memory_injections`, `memory_artifacts` (each `id`, `organization_id`, `job_id`; `sources` bitmask `SOURCE_BITS = {pslist 1, psscan 2, pstree 4}`; addresses NUMERIC(20,0); columns named `offset`, `start`, `end` — quote them in raw SQL), `memory_sensitivity` (PK evidence_id, state restricted|released, defaulted_by/at, released_by/at, release_reason; trigger `memory_sensitivity_guard`: release once, never deleted). Function `memory_attributes_scalar(jsonb)`. Grants: app S/I (+ UPDATE state, released_by, released_at, release_reason); retention SELECT on all six, DELETE on the four bulk tables (`BULK_TABLES`). Models: `MemoryImage, MemoryProcess, MemoryConnection, MemoryInjection, MemoryArtifact, MemorySensitivity`, `SensitivityState`.

**4. Routes (501 stubs) and schemas** (`memory_analysis/{router,router_sensitivity,schemas,errors}.py`): `GET /orgs/{org_id}/analyses/{job_id}/memory` → `MemorySummaryOut`; `…/memory/processes` → `ProcessPage` (q, ppid, hidden, ref); `…/memory/processes/{pid}` → `ProcessDetailOut`; `…/memory/connections` → `ConnectionPage` (pid, q, ref); `…/memory/injections` → `InjectionPage` (pid, ref); `…/memory/artifacts` → `ArtifactPage` (type, pid, q, ref); `GET /orgs/{org_id}/evidence/{evidence_id}/memory-sensitivity` → `MemorySensitivityOut{state none|restricted|released, …}`; `POST …/memory-sensitivity/release` (`org.update`, `ReleaseIn{acknowledge, reason 1..500}`). `AnalysisCreate{analyzer, profile: JobProfile?, os_hint: OsHint?}` (memory defaults triage / auto), `AnalysisJobOut.os_hint`, `EvidenceOut.memory_sensitivity: "restricted"|"released"|None`, upload `?kind=memory`. Error classes: `MemoryImageTooLarge 413`, `MemoryImageEmpty 422`, `MemorySensitivityRestricted 409`, `MemorySensitivityReleased 409`, `AcknowledgementRequired 422`, `InsufficientStorage 507` (`ERROR_CODES`).

**5. Entry points:** `memory_analysis.sensitivity.apply_memory_default(session, org_id, evidence_id, actor_id) -> bool` (no-op stub); `memory_analysis.dispatch.build_memory_message(item, settings) -> MemoryJobV1` (+ `memory_limits(settings)`; `analysis.dispatch.presigned_common(item, settings, *, get_expires)` is shared); `memory_analysis.ingest.ingest_memory(job, msg, path)` / `ingest_memory_diagnostic(job, msg, path)` (stubs raise NotImplementedError → `ingest_error`), wired through `workers/ingest.py` `SUCCESS_INGESTERS[MEMORY]`, `DIAGNOSTIC_INGESTERS`, `is_diagnostic()` (failed + `symbols_missing` + result version, memory only); AI `builder._memory_digest` (stub raising, phase 8); worker `memory_worker.detections.run(view: MemoryView, limits: MemoryLimits) -> DetectionOutput` (empty stub); `memory_worker.view.{MemoryView(os, profile, image, processes, connections, injections, artifacts, truncated), DetectionOutput(findings, iocs, timeline, truncated)}`; `memory_worker.symbols.store.{SymbolStore(root).lookup(identity) -> SymbolHit | None, .manifest() -> SymbolManifestV1, SymbolHit(path, sha256, identity), SymbolsCorrupt}` (stubs); `memory_worker.analyzer.analyze(job, dirs, config) -> Path` (raises `JobFailed("not_implemented")`); `memory_worker.pipeline.run_job(raw, config, send)` (the call `celery_app` makes); `cyberlab_worker.iocs` (implemented; static shim re-exports).

**6. Error classes:** every `MEMORY_ERROR_CODES` entry in `ops/error_classes.py` (`symbols_missing`, `unsupported_memory_format`, `memory_image_*` → input; `memory_parse_failed`, `os_undetermined`, `plugin_failed` → parse; `symbols_corrupt`, `insufficient_disk`, `identify_timeout`, `plugin_timeout`, `engine_unavailable` → infra; `not_implemented` → other); the test scans `apps/workers/memory/memory_worker`.

**7. Settings:** API `MEMORY_MAX_BYTES` (8 GiB, ≤ 16 GiB), `MEMORY_MAX_RESULT_BYTES` (256 MiB), `MEMORY_MAX_RESULT_DECOMPRESSED_BYTES` (1 GiB), `ANALYSIS_MEMORY_TIMEOUT_S` (5 400, ≤ 21 600), `ANALYSIS_MEMORY_PLUGIN_TIMEOUT_S` (1 200), `ANALYSIS_MEMORY_IDENTIFY_TIMEOUT_S` (600), `MEMORY_MAX_ACTIVE_PER_ORG` (1), `MEMORY_MAX_ACTIVE_TOTAL` (2), `MEMORY_MAX_{PROCESSES,CONNECTIONS,INJECTIONS,ARTIFACTS,FINDINGS,IOCS,TIMELINE}`, `MEMORY_TREE_MAX_NODES` (5 000); `Settings.memory_max_result_lines()`. Worker (`memory_worker/config.py`): `BROKER_URL`, `QUEUE_PREFIX`, `WORK_DIR`, `MEMORY_SYMBOLS_DIR` (/symbols), `MEMORY_ENGINE` (volatility3 | replay only with `TEST_PROFILE=1`), `MEMORY_PLUGIN_RLIMIT_AS` (2.5 GiB); image `CYBERLAB_TOOL_UID/GID=10006`, `HOME=XDG_CONFIG_HOME=/nonexistent`.

**8. Services / infra:** compose anchors `x-memory-worker`, `x-memory-symbols`; services `memory-worker`, `memory-worker-test` (profile test, tmpfs `/work` 512m, `TEST_PROFILE=1`, `WORKER_QUEUE=memory`, bind mounts of `memory_worker/ tests/ samples/ dataset/ pyproject.toml` and both packages, `memory_symbols_test:/symbols:ro`), `memory-symbols-init` / `memory-symbols` / `memory-symbols-test` (profile tools, uid 10005, `symbols_egress` only, `./.memory-import:/import:ro`); network `symbols_egress`; volumes `memory_work`, `memory_symbols`, `memory_symbols_test`; prod overlay (prod image, `BROKER_MEMORY_PASSWORD` required). Broker user `memory` (`analyzer_keys memory`, `BROKER_MEMORY_PASSWORD`). `.env.example`: memory settings, `CADDY_EVIDENCE_MAX=8590983168`. `scripts/lane-test.sh`: `--service memory-worker-test`, `--heavy` (two slots, acquisition mutex `acquire`). `package.json`: `memory:symbols` (`scripts/memory-symbols.mjs`, `--store test`), `memory:metrics` (exit 2), `test:workers` gains the memory-worker-test step (ruff, mypy, pytest, worker-kit tests).

**9. Worker skeleton** `apps/workers/memory/`: `Dockerfile` (python:3.12-slim-trixie; tool 10006, symbols 10005; libmagic1 libseccomp2 xz-utils ca-certificates libsnappy1v5; dev/prod targets), `docker/finalize_image.py` (forbidden modules, volatility3 == 2.28.2, site-packages root-owned, LICENSE.txt → `/usr/share/doc/volatility3/`, `/etc/cyberlab/versions.json`), `NOTICE.md` (→ `/usr/share/doc/cyberlab-memory/NOTICE`), `pyproject.toml` (**`uv.lock` not generated yet**), `memory_worker/{celery_app,config,pipeline,analyzer,view}.py`, packages `probe/ normalize/ engines/ detections/ symbols/` (+ `symbols/__main__.py` CLI stub, exit 2, commands `fetch-windows import reindex verify list`), `samples/`, `dataset/`, `tests/{conftest.py (CONTRACT_FIXTURES, dirs, symbol_store), test_isolation.py, unit/test_config.py, unit/test_skeleton.py}`.

**10. Test helpers:** `tests/memory_helpers.py` (`memory_fixture(name)`, `seed_memory_job(t, evidence_id=None, *, status, profile, os_hint, fixture)`, `restricted_memory_evidence(t, evidence_id=None)`); `tests/security/idor_cases_memory.py` (6 pending) and `idor_cases_memory_sensitivity.py` (2 pending), wired as `M8_CASE_MODULES`; `test_rls_coverage.py`, `test_append_only.py` (`M8_TABLES`), `test_dynamic_gate.py` (analyzers `pcap, static, memory`), `test_migrations.py` (0016 down/up), new `test_m8_schema.py`, `test_m8_foundation.py`, `test_memory_acl.py`, `unit/test_analyzer_exhaustive.py`, `unit/test_memory_settings.py`, `unit/test_report_canonical_golden.py`.

**11. Web shared:** `lib/nav.ts` (memory live), `lib/audit-actions.ts` (`memory.sensitivity_defaulted`, `memory.sensitivity_released`), `lib/http-errors.ts` (the six codes), `lib/analysis.ts` (`ANALYZER_ROUTES`, `ANALYZER_MODULES`, `JobProfile`, `MemoryProfile`, `OsHint`, `MEMORY_PROFILE_LABELS`, `OS_HINT_LABELS`, memory error texts; `runKindOf` returns null for memory), `lib/ai.ts` (`JobRoute` + memory, `JOB_TASKS.memory = []`, memory link tabs), `lib/upload.ts` (`uploadEvidence(…, options: { kind?: "memory" })`), slots `components/memory/{run-memory-analysis (orgId, evidence, canRun, active, onRequested), memory-upload-option (value, onChange, disabled), memory-sensitivity-badge (orgId, evidence)}.tsx` mounted in `evidence-analyses-card.tsx`, `evidence-uploader.tsx`, the evidence page; `IocsTab.enrichDisabledReason?: string`.

**Remains to run (in order, Docker / network steps the agent could not do):**
1. `cd apps/workers/memory && uv lock` (creates `uv.lock`; check it resolves `volatility3==2.28.2` and pulls none of the forbidden packages), commit it.
2. Copy `.env` into the worktree; optionally set `BROKER_MEMORY_PASSWORD` and raise `CADDY_EVIDENCE_MAX` to 8590983168 in the real `.env`.
3. Heavy, alone: `docker compose build memory-worker` (dev) and `docker build --target prod` once; then rebuild, one at a time, api, pcap-worker, static-worker, report-worker (py-jobs / py-worker-kit changed; RT10 renderer must know `omissions`).
4. Recreate `redis-broker` (new ACL user) and run `migrate` (0016).
5. `pnpm gen:contracts` (OpenAPI → `packages/contracts`), then `pnpm --filter web test typecheck lint` (the web edits are written against the regenerated types: `JobProfile`, `OsHint`, `Analyzer` with memory, `AnalyzerKind`, `DeepLinkRoute` memory).
6. Lane 8 DB if missing (TESTING.md command).
7. `docker compose --profile test run --rm --no-deps memory-worker-test sh -c "ruff check . && ruff format --check . && mypy memory_worker tests && pytest -q -p no:cacheprovider && cd /packages/py-worker-kit && pytest -q -p no:cacheprovider -o cache_dir=/tmp/pc"`.
8. Static worker tests once in the rebuilt static image (IOC shim, heavy, alone).
9. Full API suite (`pnpm test:api`) incl. `ruff check`, `ruff format --check`, `mypy app` (`pnpm lint:api`); in particular `test_migrations`, `test_m8_schema`, `test_m8_foundation`, `test_memory_acl`, `test_idor_routes`, `test_error_classes`, `test_dynamic_gate` (compose/broker parts need the repo mounted), `test_m7_foundation`.
10. `pnpm test:workers` (pcap, static, report, memory).

**First Docker run (2026-11-06, main tree):** `uv.lock` resolves volatility3 2.28.2, pefile 2024.8.26, capstone 5.0.9, jsonschema 4.26.0 (no yara-python / yara-x / leechcorepyc / pycryptodome / pillow / pysmb); `memory-worker` dev + prod images build (`finalize_image.py` passes); broker user `memory` connects; contracts regenerated; web typecheck / eslint / 632 vitest green; API ruff / format / mypy green, memory lane 951 tests green after fixes (`test_m8_foundation` / `test_m7_foundation` now assert the final state: no pending M8 route, no 501 stub anywhere); `pnpm test:workers` green (the report-worker image had to be rebuilt: the RT10 `_findings` template is baked in, not mounted).
