---
phase: 13
title: "Hardening e2e fuzz metric and gate"
status: completed (code), gate pending Docker
priority: P2
effort: "15h"
dependencies: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
---

# Phase 13: Hardening, e2e, fuzz-lite, metric and gate (group D)

## Overview
The only phase allowed to touch other phases' files, and only for gate fixes (one commit per owning phase). It proves the milestone end to end on the merged branch, measures the §14 numbers for the disk analyzer and runs `pnpm verify:prod`.

**Owns:**
- `apps/web/e2e/forensics.spec.ts`;
- `scripts/disk_metrics.py`;
- `apps/workers/disk/tests/fuzz/**`;
- `plans/reports/disk-metric-YYMMDD.md`;
- the M9 lines of `scripts/verify.mjs` and `scripts/e2e.mjs`;
- `scripts/check-disk-worker-env.mjs`;
- gate fixes anywhere.

## Requirements
- **Never in this phase or the gate:** a download of a disk image, test corpus, Plaso test data, NSRL release or any hash set.
- **Pipeline test** (API suite, default lane; skipped in lanes 2–9 like the M2 pipeline test):
  1. Generate `ewf_multi` and `ext4_linux` with `pnpm disk:gen` into the test tmpfs.
  2. Upload their segments with `kind=disk`.
  3. Request `triage` with the ordered segments; the real `disk-worker-test` runs TSK, libewf and Plaso offline against `disk_hashsets_test` (a test set imported by `disk:hashsets --store test` from a generated list that marks one file known-good and one known-bad).
  4. Ingest on `disk-ingest-worker-test` (while a pcap fixture result ingests on the shared ingest worker without waiting). Then:
     - every read route and interop export answers;
     - the restricted default is set on every segment;
     - AI and job-scope TI are `policy_blocked`;
     - the expected findings of the ground truth are present (the YARA test marker through the test rules override, the known-bad match, the executable in a user-writable path, the auth-log remote logon);
     - the media hash is `matched` (shown as worker-reported);
     - the hard link to `etc/shadow` and every never-collected dummy are absent from the collected tree and the events.
  5. A second run uses the replay timeline engine with the Windows psort fixtures over `ntfs_windows`, so the EVTX / registry / Prefetch / LNK normalizers, detections and tables are covered end to end (labelled `timeline_engine: replay`).
- **Diagnostic and integrity paths end to end:**
  - a `multi_gpt` variant with no supported file system → `no_supported_filesystem` with the partitions visible;
  - a VMDK-magic file → `unsupported_disk_format` before any probe;
  - `ewf_bad_hash` → `mismatch` and the `integrity:ewf_media_hash@1` finding;
  - a segment set with a foreign E01 segment → refused by libewf with its reason.
- **Export end to end:** export `tool.exe` and a named stream from the `ntfs_windows` job, promote one:
  - the trusted sha256 equals the worker's;
  - the new evidence is restricted (`derived`) with inherited flags and custody on both sides;
  - its automatic static job runs;
  - an attempt to export `SAM`, a second name of `SAM` (when phase 4 could make the NTFS hard link), a deleted entry or a 65 MiB file is refused;
  - an unpromoted export expires (time travel through the settings in the test profile) and the retention worker deletes its object version.
- **Stage isolation proof** (RT3–RT5): in a pipeline run with a test-profile hook stage that `setsid`-forks a sleeper and tries to write into the sealed collect tree, the sleeper is gone before the next stage and the write fails; a hook stage writing past its write budget is killed `truncated`; a job with a short `ANALYSIS_DISK_TIMEOUT_S` ends with `skipped` (`deadline`) stages and a posted result, never a reaper `timed_out`.
- **Offline proof:**
  - for every stage of the pipeline runs, the probe and Plaso audit hooks record zero socket / urllib / subprocess / exec / process-start events (psort or the storage-reader fallback included);
  - seccomp (AF_UNIX only, no io_uring) refuses any other socket (a negative test inside a probe);
  - the worker container has only the broker URL in its env and the `analysis` network.
- **e2e** (`forensics.spec.ts`, Playwright):
  1. Upload the `ewf_multi` segments as disk images (the restricted badge appears at once, no automatic job), open the run dialog, check the natural-sort order, run triage.
  2. On the job page: the stage strip, the media hash `matched`, the partitions, the file browser (hide known-good on, an ADS shown, a deleted entry flagged), the timeline with both sources, a finding deep link.
  3. Download the body file and the timeline CSV (the audit entries exist).
  4. Export a file, promote it, see the derived badge and its static job.
  5. As admin, release the image with the acknowledgement, clear the AI / TI flags (two audited steps); only then does the IOC tab offer "Enrich".
- **Fuzz-lite** (`tests/fuzz/`, heavy step, alone, the parent runs it):
  - 60 mutations from phase 4's hostile mode across FAT, ext4, NTFS, MBR / GPT and EWF images;
  - 10 hostile mirrored artifact trees for Plaso (truncated / corrupt syslog, a 200 MiB single-line log, a gzip bomb in a `full` run and a gzip "auth.log" in `triage` (skipped), a malformed wtmp, hostile names);
  - an E01 claiming a media size above `DISK_MAX_MEDIA_BYTES`, a deep tree with paths over 4 096 bytes, a sparse NTFS claiming a huge MFT (RT6, RT13, RT30);
  - random 64 MiB blobs with each refused magic (refused by root).

  Every run must end cleanly: a result, a per-stage error, or a job failure with a known code; no tool process survives any stage; RSS stays under each stage's `RLIMIT_AS`; free space never falls below the watchdog floor; the audit hooks record no network or process event; the worker container never restarts. Counts by outcome are recorded.
- **Metrics** (`scripts/disk_metrics.py`, heavy step, alone, only infra and `disk-worker` up):
  - detector precision / recall from phase 6's `evaluate.py` (scenario set) and from the generated images' ground truth (real engine);
  - parse success over the generated images and their fuzz set;
  - latency per stage and per job (p50 / p95) over three runs of each generated image; a `full` run on a sparse-backed 4 GiB raw image (holes cost no disk) to extrapolate walk and hashing throughput; the walk's RSS against MFT entry count (RT30);
  - the ingest time, `disk-ingest-worker` RSS and Postgres size of a stream at every cap (from phase 7's test);
  - worker failure rate over the runs;
  - written to `plans/reports/disk-metric-YYMMDD.md` with the synthetic caveat ("generated images and replayed Windows rows only"). The numbers are copied into TESTING (a one-line edit allowed here).
- **Env check** (`check-disk-worker-env.mjs`, the `check-*-env.mjs` pattern), over the rendered dev and prod configs:
  - `disk-worker` has only the broker URL, the `analysis` network, its work volume and the read-only hash-set volume; no DB, MinIO credentials or app Redis;
  - `disk-ingest-worker` consumes only `ingest_disk`, has the ingest worker's env and `backend` network, and no analysis network;
  - `disk-hashsets` (and `-test`) has `network_mode: none`, the hash-set volume and the read-only import dir only;
  - no other service mounts a hash-set volume read-write;
  - the disk image's tool uid is 10007;
  - the prod image has no Debian TSK / ewf / mkfs tools and no compiler (from `versions.json` and a file check);
  - no compose service in any profile sets `privileged`, adds `SYS_ADMIN` or maps `/dev/loop*` / `/dev/fuse` (the parent's no-loop-mount decision, RT26).
- **Gate:** `pnpm verify:prod` green, including the M9 additions: contract drift check, the disk worker image tests (the py-worker-kit isolation tests run in the disk image too), the dynamic-gate test still green (disk analysis executes nothing from the image), the env checks, the e2e.
- **Restore drill:** unchanged in scope; it runs once with a disk job, an export and a derived evidence item seeded, to prove the new tables restore and verify (row counts in `tables.json`).

## Implementation Steps
1. Merge state check: full API suite, worker suite (`--heavy`), web tests.
2. Pipeline, diagnostic, integrity and export tests; offline proof.
3. e2e.
4. Fuzz-lite and metrics as heavy steps, alone; the metric report.
5. Env check; `pnpm verify:prod`; the restore drill.
6. Gate fixes in the owning files, one commit per phase.

## Success Criteria
- [ ] Every end-to-end path above passes on the merged branch with the real TSK / libewf / Plaso (and the labelled replay for Windows artifacts).
- [ ] Fuzz-lite ends cleanly for every input with outcome counts recorded.
- [ ] The metric report exists with the synthetic caveat, and TESTING carries its numbers.
- [ ] `pnpm verify:prod` is green, and the restore drill verifies the disk tables.

## Risk Assessment
- **Heavy steps on a RAM-tight host:** run alone, with only infra up; fuzz is chunked (10 mutations per worker restart) so a leak cannot accumulate.
- **Flaky Plaso timings:** latency is reported as measured with p50 / p95, never gated on absolute numbers.

## As built (code only; gate pending Docker)

Code-only commits (no container was run; ruff / mypy / tsc / Playwright not run on the host): `test(disk): frozen detections.run takes the keyword-only yara_severity`, `fix(web): custody timeline renders the M9 export custody actions`, `test(e2e): disk forensics golden path`, `feat(disk): generated test hash sets for the pipeline run`, `test(disk): fuzz-lite and in-pipeline stage proofs`, `feat(disk): disk metric harness and heavy-step scripts`, `test(api): disk pipeline, diagnostic and export runs on the real worker`, `build(gate): M9 disk steps in verify and the disk env check`.

**Files:**
- e2e: `apps/web/e2e/forensics.spec.ts`; `scripts/e2e.mjs` builds `ewf_multi` into `/data/disk/` with `cyberlab/disk-worker:dev` (generator sources mounted).
- API pipeline (default lane, `DISK_PIPELINE_IMAGES`): `apps/api/tests/disk_pipeline_helpers.py`, `tests/integration/test_disk_pipeline.py`, `test_disk_pipeline_diagnostics.py`, `test_disk_pipeline_export.py`. Dispatch budgets are lowered in-process (`small_budgets`: 96 / 32 MiB artifacts) so a job fits the test worker's 1 GiB `/work` (the default 2 GiB triage budget fails `insufficient_disk` there).
- Test hash sets: `samples/diskgen/hashlists.py` (+ `tests/unit/test_diskgen_hashlists.py`); `pnpm disk:gen --test-hashsets` imports `test-known-good` / `test-known-bad` into the test store.
- Fuzz-lite: `apps/workers/disk/tests/fuzz/` (`DISK_FUZZ=1`; `pnpm disk:fuzz`); proofs: `tests/engine/test_stage_proofs.py` (hook stages injected by the test through the real `run_stage`; no production seam added).
- Metrics: `scripts/disk_metrics.py` (`pnpm disk:metrics`) + `apps/workers/disk/dataset/metrics.py` (local-segment runner: `analyzer.download` patched in a child process).
- Env check: `scripts/check-disk-worker-env.mjs` (+ `--image` on the built prod image).
- Gate: `scripts/verify.mjs` (reload, `disk:gen --test-hashsets`, api-test with the samples volume, the replay pass, the disk engine tests; `verify:prod`: env check, prod worker probes, image check); `docker-compose.yml` `disk-worker-test` gets `DISK_TIMELINE_ENGINE: ${DISK_TEST_TIMELINE_ENGINE:-plaso}`.
- Gate fixes: the custody timeline crashed on phase 10's custody actions (web); the phase-1 frozen entry point test now lists phase 6's `yara_severity`.

**Deviations and gaps:**
- The replay pass recreates `disk-worker-test` (the timeline engine is a worker setting, not a request field).
- `no_supported_filesystem` uses a `multi_gpt` variant the test builds by wiping its two supported file systems (the generated `multi_gpt` has ext4 and FAT16).
- The YARA test-marker finding is **not covered**: the generated trees carry no M3 test marker and `disk-worker-test` mounts no test rules (a later generator + compose change).
- The 65 MiB export refusal is emulated by lowering the export cap; the deleted-entry and second-`SAM`-name checks are conditional on the generator's route (phase-4 gaps).
- The restore drill does not yet seed a disk job, an export and a derived evidence item (not written).
- Fuzz-lite runs in one-off containers: "the worker container never restarts" is covered by the gate's restart probe of the long-running `disk-worker`, not by the fuzz run.

**Remains (Docker):** phase 3a's `plaso.lock` and the worker's `uv.lock` (nothing builds before them); then `pnpm verify` / `verify:prod`, `pnpm disk:fuzz`, `pnpm disk:metrics` (alone), the metric report and its TESTING line, the restore drill with the disk tables, and the gate fixes those runs find.
