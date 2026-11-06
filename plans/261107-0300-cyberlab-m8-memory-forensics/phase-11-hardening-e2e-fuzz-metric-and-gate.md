---
phase: 11
title: "Hardening e2e fuzz metric and gate"
status: pending
priority: P2
effort: "13h"
dependencies: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
---

# Phase 11: Hardening, e2e, fuzz-lite, metric and gate (group D)

## Overview
The only phase allowed to touch other phases' files, and only for gate fixes. It proves the milestone end to end on the merged branch, measures the §14 numbers for the memory analyzer and runs `pnpm verify:prod`.

**Owns:** `apps/web/e2e/memory.spec.ts`, `scripts/memory_metrics.py`, `apps/workers/memory/tests/fuzz/**`, `plans/reports/memory-metric-YYMMDD.md`, the M8 lines of `scripts/verify.mjs` and `scripts/e2e.mjs`, `scripts/check-memory-worker-env.mjs`; gate fixes anywhere (one commit per owning phase).

## Requirements
- **Never in this phase or the gate:** a live `fetch-windows`, or any download of a memory image, corpus or symbol pack (parent decisions).
- **Pipeline test (API suite, default lane):**
  - Flow: upload the phase-4 synthetic Linux image with `kind=memory` → request `triage` → the real `memory-worker-test` runs Volatility offline against the test symbol store → ingest → every read route answers → the sensitivity default is set → AI and job TI are `policy_blocked`.
  - A second run uses the replay engine with the Windows row fixtures, so the Windows normalizers, detections and tables are covered end to end. It is labelled `engine: replay`.
  - With a phase-4 no-go, the replay run is the only pipeline run, and the docs say so.
  - Skipped in lanes 2–8 (like the M2 pipeline test).
- **Symbols-missing path end to end:** the phase-4 changed-banner image → failed `symbols_missing` with the banner visible through the summary route. After `memory:symbols import` of its ISF into the test store, a re-run succeeds. (No-go: the identify fixture of phase 2 through the replay engine.)
- **Offline proof:** with the worker's network namespace unchanged, a run against an image whose ISF is absent never attempts a connection: the probe's audit hook (phase 2) records zero socket / urllib / subprocess / exec events in every plugin status, the seccomp filter (AF_UNIX only, no io_uring) refuses any other socket, and `OFFLINE` / `REMOTE_ISF_URL` are set in code (RT7).
- **e2e** (`memory.spec.ts`, Playwright):
  1. Upload the synthetic Linux image as a memory image, run triage, open the job: the process tree, the plugin strip (with `failed` / `unsupported` plugins shown as such) and the restricted banner.
  2. Open a seeded replay-engine Windows job: the hidden-process flag and the memory-regions tab.
  3. As admin, release with the acknowledgement, then clear the AI / TI flags through the share-policy dialog (two audited steps); only then does the IOC tab offer "Enrich" (RT16).
  4. A `kind=memory` upload shows the restricted badge immediately and has no automatic job (RT3).
- **Fuzz-lite** (`tests/fuzz/`, heavy step, alone): 50 mutations of the synthetic images from the phase-4 fuzz helpers (truncation, random page corruption, a cyclic `tasks` list, a self-parent loop, huge `comm`, invalid pointers, zero-length, a LiME header with lying ranges; with a no-go, raw / LiME header mutations only), plus random 64 MiB blobs with each supported layer magic, compressed and archive files (refused by root before any probe, RT19), and 10 hostile ISF files (deep nesting, huge arrays, wrong types, oversize) placed in a temp test store. Every run must end cleanly: a result, an engine error per plugin, or a job failure with a known code; no tool process survives; RSS stays under the `RLIMIT_AS` cap; the audit hook records no network or process event; the worker container never restarts. Counts by outcome are recorded.
- **Metrics** (`scripts/memory_metrics.py`, heavy step, alone, only infra and `memory-worker` up):
  - detector precision / recall from phase 3's `evaluate.py`;
  - parse success over the phase-4 images and their fuzz set;
  - latency per plugin and per job (p50 / p95) over three replays of the synthetic images, the probe-smoke scan time of the sparse 8 GiB file, and the ingest time of a result at every cap;
  - no third-party image is run (parent decision); the report says the numbers cover synthetic Linux images and replayed Windows rows only;
  - written to `plans/reports/memory-metric-YYMMDD.md` with the synthetic caveat; the numbers are copied into TESTING by phase 10's follow-up (one-line edit allowed here).
- **Env check** (`check-memory-worker-env.mjs`, the `check-*-env.mjs` pattern): the rendered dev and prod configs give `memory-worker` only the broker URL, the `analysis` network, the read-only symbol volume and its work volume; no DB, MinIO credentials or app Redis; `memory-symbols` (and `memory-symbols-test`) has only the `symbols_egress` network, the symbol volume and the read-only import dir (no broker, no backend, no analysis, no shared `egress`); no other service is on `symbols_egress` or mounts a symbol volume read-write; the memory image's tool uid is 10006.
- **Gate:** `pnpm verify:prod` green, including the M8 additions: contract drift check, the memory worker image tests (`py-worker-kit` isolation tests run in the memory image too), the dynamic-gate test still green (memory is not dynamic analysis: nothing executes), the env checks, the e2e.
- **Restore drill:** unchanged in scope; it runs once with a memory job seeded to prove the new tables restore and verify (row counts in `tables.json`).
- **Audit coverage:** `test_rls_coverage.py`, `test_append_only.py` and the IDOR enumerator include every new table and route (no pending entries).

## Implementation Steps
1. Merge check: contracts regenerated, no drift; full API suite on the main stack.
2. Pipeline and symbols-missing tests; offline proof.
3. e2e spec.
4. Heavy steps, each alone: memory image build (if not cached), fuzz-lite, metrics replay, restore drill.
5. `pnpm verify:prod`; fix seams in the owning files.
6. Write the metric report; mark phases complete with notes.

## Success Criteria
- [ ] Pipeline, symbols-missing and offline tests pass.
- [ ] e2e passes.
- [ ] Fuzz-lite: every run ends cleanly, no surviving tool process, no container restart.
- [ ] `plans/reports/memory-metric-YYMMDD.md` exists with precision / recall, parse success and latency.
- [ ] `pnpm verify:prod` is green, restore drill included.

## Risk Assessment
- **Host RAM:** the memory worker (3 GiB cap) plus the stack. Heavy steps run alone with only the infra stack and the memory worker up.
- **Synthetic image limits:** the end-to-end proof covers the plugins phase 4 could exercise; the others are covered by our row fixtures, the replay engine and the column-drift test (phase 2), and stated as such in the docs. Windows is never executed in CI (RT4).
