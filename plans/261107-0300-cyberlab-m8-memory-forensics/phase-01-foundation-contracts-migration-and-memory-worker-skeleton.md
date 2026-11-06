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
