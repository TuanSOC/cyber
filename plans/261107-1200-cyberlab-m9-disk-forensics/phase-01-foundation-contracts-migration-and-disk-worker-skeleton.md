---
phase: 1
title: "Foundation contracts migration and disk worker skeleton"
status: pending
priority: P2
effort: "26h"
dependencies: []
---

# Phase 1: Foundation contracts, migration and disk worker skeleton (group A)

## Overview
One agent lays the frozen foundations for nine parallel lanes:
- the `disk.v1` / `disk-export.v1` contracts with fixtures (including psort-shaped rows);
- the migration (expected `0017`) and the models;
- the **sensitivity extension** (a `source` column on M8's `memory_sensitivity`, a generic service and routes over M8's; **no rename**, red team RT2; implemented);
- every new route as a **501 stub** with frozen schemas, then one `pnpm gen:contracts` run;
- the disk worker image (with the Plaso builder stage, RT11) and skeleton (with the phase-3a Plaso lock and the phase-4 generator package list merged in), the trusted `disk-hashsets` tool service, the `disk-ingest-worker` service and its queue (RT9), the broker user, volumes and compose wiring;
- the cross-phase entry points as stubs;
- implemented shared pieces: the disk error classes, the lifted masker (`cyberlab_worker.mask`) and YARA helpers (`cyberlab_worker.yara_rules`: M3's `rulefiles.py` plus the YARA parts of `detections/signatures.py`, RT8), the **analyzer sweep** (a disk arm in every analyzer-keyed branch) and `Omissions.disk_restricted`;
- the lane script extension (lane 9, `--service disk-worker-test`; M10 / M11 reuse lane 9 later, RT27), test helpers, IDOR modules, web shared files and slots.

After this phase the stack runs as before:
- the new routes answer `501 not_implemented`, except the generic sensitivity routes (which call M8's service; M8's own routes are unchanged);
- a manual disk request is accepted by schema, but the worker fails it `not_implemented`;
- nothing is automatic;
- the static and memory workers behave identically (shims).

**Everything listed under "Frozen interfaces" in plan.md is frozen at the end of this phase.**

## Requirements
- **Pre-flight:**
  - M8 merged and its `pnpm verify:prod` green.
  - Alembic head is M8's (expected `0016`); number M9 head + 1 and tell the parent.
  - Create `feat/m9-disk-forensics` from the M8 merge.
  - Merge the A′ branches (phase 4 `diskgen-packages.txt` + generator; phase 3a `plaso.lock` + spike notes) before step 6.
  - Re-read `analysis/{models,analyzers,service,dispatch}.py`, `workers/{celery_app,tasks,ingest,reaper}.py`, `ops/error_classes.py`, the M8 migration (profile and `os_hint` checks, `job_outcomes`, `memory_sensitivity` and `memory_sensitivity_guard`), `memory_analysis/{sensitivity,router_sensitivity}.py`, `evidence/share_policy.py`, `cyberlab_jobs/{memory,report}.py` (`Omissions`, `canonical_json`), `static_worker/{rulefiles,detections/signatures,probe/yarascan}.py`, `memory_worker/detections/mask.py`, the memory and static Dockerfiles, the compose anchors, `infra/redis-broker/entrypoint.sh`, `infra/caddy/*`, `infra/minio/*`, `scripts/lane-test.sh`. Compare with the M8 worktree state recorded in plan "What exists today" and report divergences to the parent.
  - Confirm `scripts/lane-test.sh` still accepts 2..8 only (M10 / M11 are not merged), and that uids 10007 / 10008 are unused.
- **Contract** (`packages/py-jobs/src/cyberlab_jobs/disk.py`, the `memory.py` style on the `Strict` base; plan "Frozen interfaces" 1):
  - Enums exactly as the plan lists them. `ARTIFACTS_BY_PROFILE[(os, profile)]` gives the artifact categories per profile.
  - `DiskLimits`:
    - the stage limits table (RLIMIT_AS, FSIZE, write budgets, timeout caps with `stage < job` validators, RLIMIT_NPROC 64, the 900 s deadline reserve, `min_free_bytes`, `max_media_bytes`);
    - budgets (hash bytes, YARA candidates / bytes, artifact files / bytes / per-file);
    - caps: partitions 128, file systems 32, files 500 000 (≤ 2 000 000), streams per file 16, stored events 250 000, events read 20 000 000, findings 5 000, IOCs 20 000, timeline 5 000, `max_result_bytes` 256 MiB;
    - per-category event quotas summing to the stored cap.
  - `DiskSegment` and `DiskJobV1`:
    - ordinals contiguous from 0;
    - unique evidence ids;
    - 1..64 segments;
    - the sum of `size_bytes` ≤ `limits.max_image_bytes`;
    - `deadline_at` (the job's deadline, for the worker's budget; RT5); no cache key (RT1).
  - `DiskExportJobV1`: 1..20 files, `expected_size` ≤ 64 MiB, one `result_posts` entry per file plus one for the result stream, `deadline_at`.
  - `NEVER_COLLECT_PATTERNS` (the classes of plan "Scope") and `never_collect(names, fs_case_insensitive) -> bool` (true when any name of the inode matches; case-folded on NTFS / FAT; RT7), with a table test over every class and over hard-link name sets; `YARA_MAGIC_CLASSES = frozenset({"pe"})` (RT8).
  - **Record bounds:**
    - `path` ≤ 4 096 bytes UTF-8, NUL-free, no control characters except those escaped by the probe (a `name_lossy` flag when the original bytes were not valid UTF-8 and were replaced; `path_truncated` when the probe cut a longer path, RT13); `parent_addr` (the directory's `meta_addr`); `hard_linked` when the inode has more than one name;
    - `name` ≤ 1 024, `stream` ≤ 255, `message` ≤ 2 048, EWF meta values ≤ 256;
    - addresses `0 ≤ x < 2^64`; timestamps aware within 1601..2200 (NTFS epoch to a sane future; out-of-range → NULL with a flag), `time_basis`;
    - hashes lowercase hex of the exact length;
    - `attributes` ≤ 32 scalar values (str ≤ 1 024, int, bool, null);
    - `DiskEventRecord.artifact` ∈ `DiskArtifact`; `ts_desc`, `parser`, `data_type` ≤ 64 printable.
  - `DiskView` (frozen detection input; events as an iterator) and `DetectionOutput` (findings, IOCs, timeline, `truncated`).
  - `HashSetManifestV1`:
    - `{version: 1, sets: [{name ^[a-z0-9][a-z0-9._-]{0,63}$, kind ∈ known_good|known_bad|notable, algorithms, files: [{algo, path (relative, no `..`), sha256, count}], source_sha256, imported_at, tool_version}]}`.
  - The diagnostic-stream rule.
  - `tasks.py`: `DISK_ANALYZE`, `DISK_EXPORT`, `Queues.disk`; exports in `__init__.py`.
- **Report snapshot field** (`cyberlab_jobs/report.py`): `Omissions.disk_restricted: int | None = None`; `canonical_json` pops `data["omissions"]["disk_restricted"]` when it is `None`, beside M8's pop of a `None` `omissions` (M8 built `memory_restricted: int = 0`, so without the pop every M8 snapshot with memory omissions would gain `"disk_restricted": null`; RT23). `test_report_canonical_golden.py`:
  - every M6 snapshot fixture and every M8 fixture with `omissions.memory_restricted` re-serializes to the same bytes and sha256;
  - a snapshot with both counts round-trips.
- **Fixtures** `packages/py-jobs/tests/fixtures/disk/`, all hand-written and labelled synthetic in their header:
  - `windows_triage.ndjson` (an MBR image with an NTFS partition: about 300 files including executables in user-writable paths, an ADS, a deleted entry, an orphan; EVTX / registry / Prefetch / LNK events; findings, IOCs, timeline);
  - `linux_triage.ndjson` (GPT + ext4);
  - `ewf_mismatch.ndjson`, `no_supported_filesystem.ndjson`, `export_result.ndjson`;
  - `hostile/` (wrong job, NaN, NUL in a path, an over-long path without `path_truncated`, `..` in a hash-set manifest path, 33 attributes, a nested attribute, an extra field, a bad hash length, non-contiguous segment ordinals, a stream after the trailer, an event with an unknown artifact, `media_hash_status` outside the enum).

  `tests/fixtures/psort/*.jsonl` holds psort `json_line`-shaped rows (from the phase-3a recorded sample; fields per Plaso's `shared_json`: `__container_type__`, `__type__`, the event-data attributes, `message`, `parser`, `pathspec`, `date_time`, `display_name`, `filename`, `inode`, `timestamp`, `timestamp_desc`) for `winevtx` (4624, 4625, 4720, 4732, 7045, 1102, 104), `winreg` (Run key, services, UserAssist), `amcache`, `prefetch`, `lnk`, `mft`, `chrome_history`, `syslog`, `utmp`, `bash_history`. `test_disk_contract.py` round-trips the valid ones and refuses every hostile one.
- **Migration** (`00NN_m9_disk_forensics.py`; plan "Data model"):
  - `ALTER TYPE analyzer ADD VALUE IF NOT EXISTS 'disk'` in an autocommit block.
  - Profile checks: `disk` ∈ (`triage`, `full`, `extract`). The `os_hint` iff check covers `memory` and `disk`. The job guard keeps both write-once.
  - `job_outcomes` kind check gains `disk`.
  - `analysis_job_segments` with the same-investigation trigger; `disk_images`, `disk_partitions`, `disk_files`, `disk_events`, `disk_exports` with FORCE RLS, `tenant_isolation`, composite FKs, named checks (`octet_length`, `jsonb` size, the scalar-only `attributes` check function from M8, hex hash patterns, the `media_hash_status` and `flags` domains).
  - `disk_files` indexes per plan "Data model": (`job_id`, `partition_index`, `parent_addr`, `id`), (`job_id`, `partition_index`, `meta_addr`), (`job_id`, `sha256`), one per time column (`mtime`, `atime`, `ctime`, `crtime`; RT14), the partial flags index.
  - The `disk_exports` forward-only transition trigger; `object_version_id`, `object_deleted_at` (retention UPDATE on that column only; RT19).
  - **No rename** (RT2): `ALTER TABLE memory_sensitivity ADD COLUMN source text NOT NULL DEFAULT 'memory'` with a named check (`memory` / `disk` / `derived`); app INSERT covers it; the guard trigger, policies and grants are untouched.
  - Grants: app S/I (+ the export columns); retention DELETE on `disk_files`, `disk_events`.
  - The downgrade drops the tables and the `source` column and restores the checks; the enum value stays (allowed by `test_migrations.py`).
- **Models** `app/modules/disk_forensics/models.py`, registered in `app/models.py`; `Analyzer.DISK`; `MemorySensitivity.source` (M8's model, one column added).
- **Sensitivity extension** (implemented here, the analyzer-sweep precedent; RT2):
  - `app/modules/evidence/sensitivity.py`: `apply_restricted_default(session, org_id, evidence_id, actor_id, source)`: M8's `apply_memory_default` body with `source` written and the audit action chosen by source (`memory.sensitivity_defaulted`, else `disk.sensitivity_defaulted` with `source` in the details); `memory_analysis/sensitivity.py:apply_memory_default` becomes a one-line wrapper (`source="memory"`), every M8 caller unchanged;
  - `evidence/router_sensitivity.py` with `GET /evidence/{id}/sensitivity` (state + source) and `POST …/sensitivity/release`, calling M8's `get` / `release` (the release audit action by source; the batch `job_id` arm is a stub answering 501 until phase 9);
  - M8's `/memory-sensitivity` routes, codes and audit actions unchanged, **not** deprecated;
  - the share-policy guard answers `evidence_sensitivity_restricted` for the `disk` / `derived` sources and keeps `memory_sensitivity_restricted` for `memory`;
  - `idor_cases_memory_sensitivity.py` gains the generic routes. The full M8 suite passes **unchanged** (no M8 test is edited).
- **Schemas and stubs:**
  - `disk_forensics/schemas.py` (`DiskSummaryOut`, `PartitionPage`, `FilePage`, `FileDetailOut`, `DirPage`, `EventPage`, `TimelinePage`, `DiskExportOut`, `ExportRequestIn`);
  - the analysis request body (`segments: list[uuid] | None`, required for disk, refused otherwise);
  - `EvidenceOut.sensitivity` (state + source, beside M8's field) and `EvidenceOut.derived_from`;
  - stub routers mounted in `main.py`: `disk_forensics/router.py` (phase 8) and `export_router.py` (phase 10, `POST /analyses/{job}/disk/file-exports` with `{file_ids}`, RT29);
  - the error codes; `pnpm gen:contracts`.
- **Entry-point stubs:** plan "Frozen interfaces" 5, with exact signatures. The calls from `analysis/service.py`, `analysis/dispatch.py`, `workers/ingest.py` (the hand-off to `disk.ingest`), the new `disk.ingest` task in `workers/tasks.py` (three schema branches, routed to `Queues.ingest_disk`) and `workers/reaper.py` are added as `if analyzer == DISK: <stub>` branches; their bodies belong to phases 7 and 10. `disk_worker/stage.py: run_stage(...)` and the budget object are stubs owned by phase 2.
- **Error classes:** every disk code mapped (plan "Frozen interfaces" 6; the segment download keeps the kit's `integrity_mismatch`, RT22), with a test that every code in `disk.py`'s `DiskErrorCode` literal is classified; `test_error_classes.py` also scans `apps/workers/disk`.
- **Analyzer sweep** (plan "Frozen interfaces" 12): every arm, the `_digest_selections` stub, and `test_analyzer_exhaustive.py` / `lib/analysis.test.ts` green.
- **Lifted helpers:**
  - `memory_worker/detections/mask.py` → `cyberlab_worker/mask.py`;
  - `static_worker/rulefiles.py` (rule files, namespaces, file hashes) **and** the YARA parts of `static_worker/detections/signatures.py` (`BASELINE_SHA256`, `TEST_RULES_SHA256`, `YARA_SEVERITY_ALLOWLIST`, `YARA_TEST_ALLOWLIST`, `yara_ceilings`, `yara_severity`) → `cyberlab_worker/yara_rules.py` (RT8);
  - the old modules become re-exports (the static unit test that compares `BASELINE_SHA256` with the file keeps passing). Run the memory and static unit tests once in their images (heavy, alone, one at a time) to prove no behaviour change.
- **Settings:** plan "Frozen interfaces" 7, with validators (`DISK_MAX_UPLOAD_BYTES ≤ 16 GiB`, `DISK_MAX_IMAGE_BYTES` 16 GiB default `≤ 64 GiB` (RT21), `DISK_MAX_MEDIA_BYTES` 2 TiB, `ANALYSIS_DISK_TIMEOUT_S ≤ 21 600`, the stage timeouts below it, `DISK_INGEST_TIMEOUT_S` 1 800 s, `DISK_WORK_MIN_FREE_BYTES` 4 GiB, `DISK_EXPORT_MAX_BYTES ≤ STATIC_MAX_BYTES`).
- **Disk worker image** (`apps/workers/disk/Dockerfile`, the memory Dockerfile structure):
  - `python:3.12-slim-trixie`; tool uid **10007** (`ENV CYBERLAB_TOOL_UID=10007 CYBERLAB_TOOL_GID=10007`) and `hashsets` uid 10008; `libmagic1`, `libseccomp2`, `ca-certificates`.
  - **The worker venv** from `uv.lock`: `pytsk3==20260715`, `libewf-python==20260924`, `yara-python` (the M3 pin), `celery`, `httpx`, and the path packages.
  - **`/opt/plaso`** from `plaso.lock` (`uv pip sync --require-hashes`), a separate venv so Plaso's 53 dependencies never mix with the worker's. A **builder stage** (`build-essential`, `zlib1g-dev`, and what the spike lists) compiles the sdist-only libyal bindings (libevtx, libregf, libfsntfs, libfsext, libfsfat, libbde, libfsapfs, libvsgpt at their 20261027-compatible versions; RT11) into hashed wheels; only the wheels are copied into the runtime stages; the prod stage has no compiler (asserted).
  - **`cyberlab_plaso_launch` / `cyberlab_plaso_export`** (phase 3's sources under `apps/workers/disk/plaso/`) installed as single modules into `/opt/plaso` (RT24).
  - **The M3 rules:** the source `.yar` files from the `static_rules` build context copied to `/opt/rules/image/` (root-owned, read-only); the probe compiles them at scan start; their sha256s go in `versions.json` and must equal the allow-list's `BASELINE_SHA256` (a build assertion; RT8).
  - **`finalize_image.py`:**
    - asserts the pins (`pytsk3`, `pyewf`, `plaso`, `yara`);
    - asserts that no Debian `sleuthkit`, `python3-tsk`, `ewf-tools`, `srch_strings`, `mkfs.*`, `mtools`, `ntfs-3g`, `sfdisk` binaries exist in the **prod** target;
    - asserts that no compiler (`cc`, `gcc`) is in the prod target (the Plaso builder stage stays behind);
    - makes `site-packages` root-owned and not writable;
    - copies each wheel's license text and writes `/usr/share/doc/cyberlab-disk/NOTICE` (TSK IBM-PL / CPL, libyal LGPL-3.0+ with source links, Apache-2.0 components);
    - writes `versions.json` (including `pytsk3.TSK_VERSION_STR` and the artifacts definitions version).
  - `ENV HOME=/nonexistent XDG_CONFIG_HOME=/nonexistent`.
  - **Targets:** dev and prod. The dev target adds the packages in `docker/diskgen-packages.txt` (phase 4), `tests/` and `samples/`.
- **Skeleton:**
  - `disk_worker/celery_app.py` (tasks `disk.analyze` and `disk.export`, the queue from the env, `--concurrency 1 --max-tasks-per-child 1`) and `config.py`;
  - `analyzer.py` sends `started` then `failed / not_implemented`;
  - empty packages for phases 2–6 and 10;
  - `tests/conftest.py`;
  - the py-worker-kit isolation tests wired into the disk image's test command.
- **Compose** (dev, test, prod; plan "Frozen interfaces" 8):
  - **`x-disk-worker` anchor:** `init: true`, `read_only`, `cap_drop: ALL` plus the six M3 caps, `no-new-privileges`, `pids_limit: 256`, `mem_limit: 3g`, `cpus: 2`, tmpfs `/tmp` 64m, `analysis` network only, volumes `disk_work:/work` and `disk_hashsets:/hashsets:ro`, the broker URL with user `disk`, `restart: unless-stopped`.
  - **`disk-ingest-worker`** (and `disk-ingest-worker-test`, test profile; RT9): the api image, `celery … worker --pool solo -Q <prefix>ingest_disk`, `PROCESS_ROLE: ingest`, the ingest worker's env, `backend` network and `ingest_tmp` volume, `mem_limit 1g`, `read_only`, tmpfs `/tmp` 64m; the broker's `ingest` user may read and write the `ingest_disk` queue keys.
  - **`disk-worker-test`:** test profile, `test.` queue prefix, `/work` a per-container tmpfs (1g), `disk_hashsets_test:/hashsets:ro`, bind mounts of `apps/workers/disk/{disk_worker,tests,samples,dataset}` and the two packages.
  - **`disk-hashsets`:** profile `tools`, the same image, `user: 10008`, `read_only`, `cap_drop: ALL`, **`network_mode: none`**, `mem_limit: 2g`, tmpfs `/tmp` 1g (external sort), volume `disk_hashsets:/hashsets` rw, `./.disk-import:/import:ro`, `entrypoint: python -I -m disk_worker.hashsets` (its parse children are plain forks with rlimits and seccomp, never `run_tool`, RT25). **`disk-hashsets-test`:** identical but with `disk_hashsets_test`.
  - Volumes `disk_work`, `disk_hashsets`, `disk_hashsets_test`; an init step makes the hash-set volumes owned by 10008 and world-readable. `.disk-import/` is in `.gitignore` and `.dockerignore`.
  - `CADDY_EVIDENCE_MAX` = max(…, `DISK_MAX_UPLOAD_BYTES`) + 1 MiB in `.env.example` with a comment.
  - The api gets the disk settings; `api-test` gets small test caps (`DISK_MAX_UPLOAD_BYTES` 64 MiB, `DISK_MAX_IMAGE_BYTES` 256 MiB).
  - The build passes `additional_contexts: static_rules=apps/workers/static/rules/yara`.
- **Broker:** `analyzer_user disk` in `infra/redis-broker/entrypoint.sh` (own queue keys, write-only ingest), `BROKER_DISK_PASSWORD`; the api user publishes to `disk`.
- **Lanes:** `scripts/lane-test.sh` accepts `disk-worker-test` (broker db only) and lane **9** (the check becomes `[2-9]`; Redis / broker db 9 is unused). The phase checks whether `cyberlab_b9_test` exists and creates it if not (a parent-approved one-off `createdb` + `db-bootstrap`), recorded in TESTING. M10 (lane 9 for `static-worker-test`) and M11 then find lane 9 present; the parent updates their plans (RT27).
- **Root scripts:**
  - `disk:hashsets` → `docker compose --profile tools run --rm disk-hashsets "$@"` (`MSYS_NO_PATHCONV=1`; `--store test` selects `disk-hashsets-test`), implemented;
  - `disk:gen` → `docker compose --profile test run --rm disk-worker-test python -m samples.diskgen "$@"`, implemented;
  - `disk:metrics` → stub, exit 2.
- **Test helpers and frozen tests:**
  - `tests/disk_helpers.py`;
  - `idor_cases_disk.py` with `PENDING_ROUTES` = the phase-8 routes; `idor_cases_disk_exports.py` with the phase-10 routes;
  - `test_rls_coverage.py`, `test_append_only.py` list the new tables;
  - `test_dynamic_gate.py` still passes (`disk` is not `dynamic`; the gate's `dynamic|sandbox` word pattern matches no new service, queue or task: `disk-worker`, `disk-ingest-worker`, `disk-hashsets`, `ingest_disk`, `disk.analyze`, `disk.export`, `disk.ingest`, `disk.expire_exports`).
- **Web shared:**
  - `nav.ts` drops `plannedFor` for forensics;
  - `audit-actions.ts`, `http-errors.ts`;
  - the analyzer badge;
  - the three slots mounted;
  - `components/evidence/sensitivity-badge.tsx` and `lib/evidence-sensitivity.ts` over the generic routes (state + source) for disk and derived evidence; M8's memory badge and `lib/memory-sensitivity.ts` are left as they are (RT2).

## Implementation Steps
1. Pre-flight, branch, merge A′.
2. `disk.py`, fixtures (including psort rows), the contract test and the `Omissions` golden test (py-jobs unit tests on the host).
3. Migration, models, the `source` column; `test_migrations` up / down on a fresh DB and on a seeded M8 DB with memory sensitivity rows (they keep `source = memory`); RLS and append-only coverage.
4. The sensitivity extension; the M8 sensitivity tests pass untouched, new tests cover the generic routes and the `disk` / `derived` guard code.
5. Schemas, stub routers, error codes, settings, entry-point stubs and branches; `gen:contracts`.
6. Lift the masker and the YARA allow-list; the analyzer sweep with its exhaustiveness tests.
7. Worker image, skeleton, compose (including `disk-ingest-worker`), broker user and queue, volumes, Caddy limit:
   - build the disk image with its Plaso builder stage (heavy, alone) and run the py-worker-kit isolation tests in it;
   - rebuild, one at a time, the api, pcap, static, memory and report images;
   - run the static and memory unit tests once in their new images (heavy).
8. Lane script, lane 9 DB, root scripts, test helpers, IDOR modules.
9. Web shared files and slots; `pnpm --filter web test typecheck lint`.
10. Full API suite once (the frozen state), then commit; record the frozen signatures below.

## Success Criteria
- [ ] The contract round-trips every valid fixture and refuses every hostile one; the canonical-bytes golden test passes over the M6 and M8 snapshots.
- [ ] The migration upgrades and downgrades; every new tenant table has FORCE RLS and is in the coverage tests; existing memory sensitivity rows keep `source = memory`.
- [ ] The M8 sensitivity tests pass unedited; the generic routes and the `disk` / `derived` guard code are covered.
- [ ] The disk image builds; the pins hold; the prod target has no Debian TSK / ewf / mkfs tools and no compiler; the py-worker-kit isolation tests pass inside it; `/opt/plaso` imports, `cyberlab_plaso_launch` is importable under `-I`, and `log2timeline.py --version` reports 20261027; the rule sources' sha256 equals `BASELINE_SHA256`.
- [ ] Every new route answers 501. A disk job request reaches the worker and fails `not_implemented`. The static and memory workers' tests are unchanged.
- [ ] `lane-test.sh 9` and `--service disk-worker-test --heavy` work; `disk-ingest-worker` consumes `ingest_disk` and a stub `disk.ingest` task reaches it.
- [ ] `pnpm gen:contracts` shows no drift after the commit, and the web shared changes pass typecheck.
- [ ] `test_analyzer_exhaustive.py` and `lib/analysis.test.ts` pass; a failed disk job does not break the org operations page.

## Risk Assessment
- **Wide shared surface:** mitigated by the M7 / M8 pattern (stubs, one commit, full suite before freezing) and a seeded-upgrade test; the M8 table is extended, not renamed (RT2), so M8's files gain only a wrapper and a column.
- **Plaso build time:** the builder stage compiles eight libyal bindings (minutes); the image is built once by the parent; the spike's lock pins hashes, so rebuilds are reproducible.
- **Report snapshot field:** the `None`-omission rule and the golden test guard the canonical bytes; the api and report-worker images are rebuilt together.
- **Analyzer sweep breadth:** the exhaustiveness tests catch a missed branch.

## Frozen interfaces (as built)
<!-- Filled by the phase-1 agent at commit time: exact signatures, settings names, fixture list, the migration number. -->

See "Frozen interfaces (as built, untested)" below.

## Frozen interfaces (as built, untested)

Code-only commit `wip(m9): phase 1 foundation (untested; Docker steps pending)` on `feat/m9-disk-forensics`, from `feat/m8-memory-forensics` 7b5db93 (head `0016_m8_memory_forensics`), then `feat/m8-memory-forensics` merged in. Nothing ran in a container. Host-only checks that passed: `test_disk_contract.py`, `test_report_canonical_golden.py`, `test_disk_settings.py`, `test_memory_contract.py`, the kit's `test_lifted.py`, the memory worker's `test_mask.py` and the static `test_detections.py` through the new shims, the disk worker's `test_config.py`, py_compile of every changed file, an OpenAPI smoke of the new routers. The A-prime work (phase 4 `diskgen-packages.txt`, phase 3a `plaso.lock`) was NOT merged: both files are placeholders.

**Deviations (parent to confirm):**
- A disk analysis request is validated by schema (`segments` required, `extract` not requestable) but `request_analysis` answers **501** before creating anything: the segment rows, the per-segment sensitivity default and `build_disk_message` belong to phase 7. The success criterion "a disk job reaches the worker" moves to phase 7.
- `?kind=disk` is NOT accepted yet (`UploadKind` unchanged): accepting it before phase 7's upload default would hand disk bytes to the automatic static `av` run (M8 RT3).
- `disk_events.file_id` and `disk_exports.file_id` are soft references (no FK): retention deletes `disk_files` per job.
- The analyzer broker pattern `%W~ingest*` also lets analyzers WRITE `ingest_disk` (never read); `disk.ingest` re-authenticates the per-job token like `ingest.event`.
- `integrity_mismatch` / `export_hash_mismatch` are classed `infra` (there is no `integrity` class).
- M8's `/memory-sensitivity` routes still act on rows of any source (unchanged code); the UI uses the generic routes for disk / derived evidence.
- `EvidenceOut.memory_sensitivity` is filled for `source = memory` rows only (its M8 meaning); `EvidenceOut.sensitivity` carries every source.

**1. Contract** `cyberlab_jobs/disk.py` (exported from `__init__`: `DISK_SCHEMA`, `DISK_EXPORT_SCHEMA`, `DiskJobV1`, `DiskExportJobV1`, `DiskLimits`; tasks `DISK_ANALYZE`, `DISK_EXPORT`, `DISK_INGEST = "disk.ingest"`, `DISK_EXPIRE_EXPORTS = "disk.expire_exports"`; `Queues.disk`, `Queues.ingest_disk`):
- `DiskProfile{triage, full, extract}`, `AnalysisProfile = Literal[triage, full]`, `DiskOs`, `PartitionOs`, `ImageFormat`, `DiskStage`, `StageStatus`, `FsType` (+ `CASE_INSENSITIVE_FS`), `DiskArtifact` (17), `ARTIFACTS_BY_PROFILE[(os, DiskProfile)]` (Amcache in triage), `EVENT_QUOTA_PERCENT`, `split_event_quotas(total)`, `YARA_MAGIC_CLASSES = {"pe"}`, `DiskErrorCode` / `DISK_ERROR_CODES` (16), `DIAGNOSTIC_ERROR_CODES`;
- `NEVER_COLLECT_PATTERNS` (6 classes of lowercase globs), `never_collect(names, fs_case_insensitive) -> bool` (always case-folded; NTFS / FAT also strip trailing dots and spaces);
- `StageLimits{rlimit_as, rlimit_fsize, write_budget, timeout_s, rlimit_nproc=64}`, `STAGE_LIMIT_KEYS` (verify, layout, walk, collect, scan, log2timeline, event_export, extract), `default_stage_limits(artifact_max_bytes, artifact_max_file_bytes)`, `PROFILE_BUDGETS[profile]`, `DiskLimits` (image <= 64 GiB, media <= 16 TiB, stages, budgets, caps, `event_quotas` summing to `max_events_stored`, `deadline_reserve_s` 900, `min_free_bytes` 4 GiB; `.max_lines()`);
- `DiskSegment{ordinal, evidence_id, expected_sha256, size_bytes, url}`, `DiskJobV1{..., segments 1..64 contiguous and unique, profile triage|full, os_hint, result_post, ingest_token, limits, deadline_at}`, `DiskExportFile`, `DiskExportJobV1{..., source_job_id, files 1..20, result_posts = files + 1, deadline_at}`;
- lines `DiskResultHeader{engine "tsk", timeline_engine plaso|replay|none, image: ImageInfo{format, segments, media_size, sector_size, media_sha256?, ewf?: EwfInfo}, hashsets, stages[StageReport], artifacts[ArtifactStat], engine_errors, truncated}`, `DiskPartitionRecord`, `DiskFileRecord` (`FILE_FLAG_BITS` allocated 1 ... hard_linked 64; path <= 4096 UTF-8 bytes, no control characters), `FileKey`, `DiskEventRecord` (`ordinal`; attributes <= 32 scalars / 4 KiB), `DiskTimelineEvent`, shared `FindingRecord` / `IocRecord` / `ResultTrailer`; `DISK_LINE_ADAPTER`, `DISK_RECORD_ADAPTER`, `LINE_ORDER`, `check_line_order`, `check_diagnostic_kinds`; `ExportedFile`, `DiskExportResultHeader`, `DISK_EXPORT_LINE_ADAPTER`; `HashSet*`, `HashSetManifestV1`; `DiskView(profile, image, partitions, files, events: Callable[[], Iterator], hashsets, truncated)`, `DetectionOutput(findings, iocs, timeline, cited_events, truncated)`.
- `report.Omissions.disk_restricted: int | None = None`, popped by `canonical_json` when None; fixtures `m8_omissions_snapshot.json`, `m8_omissions_zero_snapshot.json` pinned.

**2. Fixtures** `packages/py-jobs/tests/fixtures/disk/` (written by `build_fixtures.py`): `windows_triage` (~300 files, an ADS, a deleted entry, an orphan, a hard-link pair), `linux_triage`, `ewf_mismatch`, `no_supported_filesystem`, `export_result`, `hostile/` (23 streams plus `segments_not_contiguous.json`, `manifest_dotdot.json`); `fixtures/psort/*.jsonl` (10 files in the `shared_json` shape, to re-check against the 3a sample).

**3. Migration `0017`** (down_revision `0016`); models `disk_forensics/models.py`: `AnalysisJobSegment`, `DiskImage`, `DiskPartition`, `DiskFile`, `DiskEvent`, `DiskExport`, `DiskExportState`; `Analyzer.DISK`, `JobProfile.EXTRACT`, `REQUESTABLE_PROFILES`; `MemorySensitivity.source` + `SensitivitySource`. Checks `ck_analysis_jobs_profile_valid`, `ck_analysis_jobs_profile_matches_analyzer`, `ck_analysis_jobs_os_hint_iff_analyzer` (replaces `..._iff_memory`; `extract` implies `auto`), `ck_memory_sensitivity_source`; triggers `analysis_job_segments_guard`, `disk_exports_transition`.

**4. Routes.** 501 stubs: `GET /analyses/{job}/disk`, `.../partitions`, `.../files`, `.../files/{file_id}`, `.../dirs`, `.../events`, `.../timeline`, `.../exports/{name}` (bodyfile, timeline.csv, timeline.jsonl, notable-hashes.txt); `POST /analyses/{job}/disk/file-exports`, `GET /disk-exports/{id}`, `POST /disk-exports/{id}/promote`. Implemented: `GET /evidence/{id}/sensitivity`, `POST .../sensitivity/release` (`SensitivityReleaseIn{acknowledge, reason, job_id?}`; `job_id` answers 501). Schemas `disk_forensics/schemas.py`, `EvidenceSensitivityOut`, `EvidenceSensitivityDetailOut`, `EvidenceOut.sensitivity`, `EvidenceOut.derived_from`, `AnalysisCreate.segments`. Errors: `disk_forensics/errors.py` (8 codes), `evidence/sensitivity_errors.py` (2 codes).

**5. Entry points.** `evidence/sensitivity.apply_restricted_default(session, org_id, evidence_id, actor_id, source) -> bool` (implemented; also `restricted_error(source)`, `restriction_of`); `disk_forensics.dispatch.build_disk_message(job, segments, settings)`, `build_export_message(job, source_job, segments, exports, settings)`; `handoff.hand_off(job, msg)`; `ingest.ingest_disk` / `ingest_disk_diagnostic(job, msg, path)`; `ingest_export.ingest_disk_export(job, msg, path)`; `export_service.expire_exports(limit) -> int`, `fail_pending_exports(session, job) -> int` (no-op); `workers/ingest.handle_disk_ingest(raw)`, `DIAGNOSTIC_CODES_BY_ANALYZER`; task `disk.ingest`; beat `expire-disk-exports` (hourly; swallows NotImplementedError); `ai/context/builder._disk_digest` (raises). Worker: `analyzer.analyze(job, dirs, config)`, `DiagnosticResult(code, path)`, `pipeline.run_job` / `run_export_job(raw, config, send)`, `stage.run_stage(argv, dirs, stage, limits, budget) -> StageResult`, `budget.Budget(deadline_at, limits).timeout(stage)`, `export.handle_export(msg)`, `scan.build_candidates(files, profile, limits)` / `parse_scan_output(path)`, `detections.run(view, limits)`, `timeline.run_timeline(dirs, partitions, profile, limits, budget) -> TimelineOutput`, `timeline.catalog.match(files, os, profile) -> CollectPlan`, `hashsets.store.HashSetStore(root).match(sha256, sha1, md5)` / `.manifest()`, `hashsets.__main__` (exit 2). Kit: `cyberlab_worker.mask`, `cyberlab_worker.yara_rules` (shims: memory `detections/mask.py`, static `rulefiles.py`, `detections/signatures.py`).

**6-8. Error classes, settings, services.** Every disk code classified. Settings `DISK_MAX_UPLOAD_BYTES` 8 GiB (<= 16), `DISK_MAX_SEGMENTS` 64, `DISK_MAX_IMAGE_BYTES` 16 GiB (<= 64), `DISK_MAX_MEDIA_BYTES` 2 TiB, `DISK_MAX_RESULT_BYTES`, `DISK_MAX_RESULT_DECOMPRESSED_BYTES` 1.5 GiB, `ANALYSIS_DISK_TIMEOUT_S` 14400, `DISK_INGEST_TIMEOUT_S` 1800, `DISK_MAX_ACTIVE_PER_ORG` / `_TOTAL` 1 / 1, `DISK_MAX_{PARTITIONS,FILESYSTEMS,FILES,STREAMS_PER_FILE,EVENTS,EVENTS_READ,FINDINGS,IOCS,TIMELINE}`, `DISK_EXPORT_MAX_BYTES` / `_FILES` / `_TTL_S`, `disk_max_result_lines()`. Worker env `DISK_HASHSETS_DIR`, `DISK_WORK_MIN_FREE_BYTES`, `DISK_TIMELINE_ENGINE`, `DISK_RULES_DIR`, `DISK_TEST_RULES_DIR`. Compose anchors `x-disk-worker`, `x-disk-hashsets`; services `disk-worker`, `disk-ingest-worker` (`-Q ingest_disk`), `disk-hashsets-init`, `disk-hashsets`, `disk-hashsets-test` (network_mode none, uid 10008), `disk-worker-test`, `disk-ingest-worker-test`; volumes `disk_work`, `disk_hashsets`, `disk_hashsets_test`; prod overlay entries; broker user `disk` (`BROKER_DISK_PASSWORD`); api-test `TEST_BROKER_DISK_URL`, `TEST_BROKER_INGEST_URL`. `scripts/lane-test.sh` lanes 2..9 and `disk-worker-test`; `package.json` `disk:hashsets` (`scripts/disk-hashsets.mjs`), `disk:gen`, `disk:metrics`, the `test:workers` disk step.

**9-12. Worker, tests, web.** `apps/workers/disk/` (Dockerfile stages `plaso-builder`, `base`, `venv-dev`, `venv-prod`, `dev`, `prod`; uids 10007 / 10008; `docker/finalize_image.py --target dev|prod`; `NOTICE.md`; `pyproject.toml`; `plaso/` placeholders; tests `test_isolation.py`, `unit/test_config.py`, `unit/test_skeleton.py`). API test helpers `tests/disk_helpers.py` (`disk_fixture`, `seed_segment_set`, `seed_disk_job`, `restricted_disk_evidence`), `idor_cases_disk.py` (8 pending), `idor_cases_disk_exports.py` (3 pending), `test_m9_schema.py`, `test_m9_foundation.py`, `test_disk_acl.py`, `test_disk_settings.py`, `test_disk_contract.py`. Web: Forensics live in the nav, audit actions, HTTP error texts, the analyzer sweep (`forensics` route, "Disk (triage|full|file export)"), slots `components/disk/{run-disk-analysis,disk-upload-option,derived-evidence-badge}.tsx`, `components/evidence/sensitivity-badge.tsx`, `lib/{evidence-sensitivity,use-evidence-sensitivity}.ts`.

**Remains to run (in order):**
1. Merge A-prime (phase 4 `diskgen-packages.txt`, phase 3a `plaso.lock`), then `cd apps/workers/disk && uv lock` (check the pytsk3 / libewf-python pins and PyPI names).
2. Heavy, alone: build `disk-worker` (dev) and `--target prod` (finalize asserts the pins, no TSK or compiler in prod, the rules sha256; check the Debian base has no `mke2fs`); then rebuild api, pcap, static, memory and report images one at a time.
3. Recreate `redis-broker`; run `migrate` (0017).
4. `pnpm gen:contracts`, then `pnpm --filter web test typecheck lint`.
5. Lane 9 database `cyberlab_b9_test` (TESTING.md command).
6. `ruff format`, `ruff check`, `mypy` on the API, the kit and the disk worker (not run on the host).
7. The disk worker suite and kit isolation tests in `disk-worker-test`; the static and memory unit tests in their rebuilt images.
8. The full API suite (`test_migrations`, `test_m9_*`, `test_disk_acl`, `test_idor_routes`, `test_error_classes`, `test_analyzer_exhaustive`, `test_dynamic_gate`; the M8 sensitivity tests unchanged).
