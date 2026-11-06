---
phase: 12
title: "Hardening e2e fuzz metric and gate"
status: pending
priority: P2
effort: "14h"
dependencies: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
---

# Phase 12: Hardening, e2e, fuzz-lite, metric and gate (group D)

## Overview
The only phase allowed to touch other phases' files, and only for gate fixes. It proves the milestone end to end on the merged branch, measures the §14 numbers for the RE analyzer and runs `pnpm verify:prod`.

**Owns:** `apps/web/e2e/reverse.spec.ts`, `scripts/re_metrics.py` (the `re:metrics` script), `apps/workers/reverse/tests/fuzz/**`, `plans/reports/re-metric-YYMMDD.md`, the M10 lines of `scripts/verify.mjs` and `scripts/e2e.mjs`, `scripts/check-re-worker-env.mjs`; gate fixes anywhere (one commit per owning phase).

## Requirements
- **Never in this phase or the gate:** downloading any third-party binary or corpus; a live AI call (mock / replay providers only); executing a sample.
- **Pipeline test** (API suite, default lane; skipped in lanes 2–9 like the M2 pipeline test):
  - upload the phase-4 `injector` (x64, stripped) → automatic static `full` (M3, unchanged) → request RE `full` → the real `re-worker-test` runs Ghidra offline → ingest → every read route answers → capabilities of the static job link to the injector's injection function → `explain_function` with the mock provider verifies;
  - a second `full` with `decompile_addresses` = a function the first job did not decompile → decompiled, and the first job links to the newer one (RT10);
  - while that job is active, a memory or disk request is refused `429 heavy_analysis_busy` (RT2);
  - `quick` when phase 3 shipped;
  - the ELF `elf_net` builds (PIE and non-PIE) through the same flow, with real capa locations linked to the expected function on both (RT8: the real-engine proof of the file-VA join);
  - refusals and diagnostics: a pure-Python ARM ELF is refused at request time (`422 unsupported_architecture`); a minimal .NET-like PE with a CLR directory but no `mscoree` import passes the API check and ends as the worker's diagnostic result (`failed / unsupported_managed_code`, program line stored).
- **Never-executed and offline proof:** for every pipeline run, the header's audit counts after the JVM start are zero, the recorded decompile-stage children are only `jspawnhelper` and the decompiler binary (detection, RT15), the effective JVM arguments equal the expected list (RT1), and seccomp refuses an inet socket from a probe-test hook (the kit's isolation tests in the RE image).
- **e2e** (`reverse.spec.ts`, Playwright):
  1. From the Malware Lab job page, "Reverse engineer" → the RE job page with the stage strip; open the injection function: code viewer, callers / callees, linked capability.
  2. Open the `strings_refs` twin's function: the injected literal is shown as text; a U+202E literal shows its visible escape and the banner; "Copy" puts the escaped text on the clipboard; no script executes (CSP report-only listener empty).
  3. "Explain function" with the mock provider: claims with citations deep-link back to `?fn=…&tab=code`.
  4. "Decompile this function" on a non-decompiled function creates a new `full` job (after the confirmation) and the old page links to it.
  5. The capability row in Malware Lab shows "Functions (n)" and navigates to the function.
- **Fuzz-lite** (`tests/fuzz/`, heavy step, alone): 50 mutations of the phase-4 builds (truncation, random section-header corruption, entry point out of range, import table loops, overlapping sections, huge `SizeOfImage`, ELF program-header lies, symbol tables with 10⁵ entries, 64 KiB names, deep demangler inputs `_Z` with nesting) plus the 16 MiB random-code PE, the `bulk_gen` builds and 10 hostile stage-output files for root. Every run must end cleanly (a result, an engine error per stage, or a job failure with a known code such as `re_out_of_memory` / `re_work_too_large`); no tool process survives; the worker container is never OOM-killed (tool processes are, at `oom_score_adj` 1000); the audit hook records no event; the container never restarts. Counts by outcome recorded.
- **Metrics** (`scripts/re_metrics.py`, heavy step, alone, only infra and `re-worker` up):
  - function-recovery precision / recall, call-edge, string-ref and import-ref recall, decompile success rate per engine (from phase 4's tables, re-run on the merged image);
  - RE-heuristic precision / recall (phase 5's evaluation);
  - parse success over the builds and the fuzz set;
  - latency per stage and per job (p50 / p95 over three runs per sample), CPU time and peak container memory per stage (cgroup), the Ghidra project size, and the ingest time of a result at every cap;
  - the explain_function offline eval numbers (phase 9);
  - written to `plans/reports/re-metric-YYMMDD.md` with the synthetic caveat; numbers copied into TESTING / REVERSE_ENGINEERING with one-line edits.
- **Env check** (`check-re-worker-env.mjs`, the `check-*-env.mjs` pattern): the rendered dev and prod configs give `re-worker` only the broker URL, the `analysis` network and `re_work`; no DB, MinIO credentials, app Redis or egress network; `mem_limit` ≤ 4g, `pids_limit` above the probe's `nproc`; the image's tool uid is 10010 and unique among all images; `re-worker-test` `/work` is not a tmpfs (RT22).
- **Gate:** `pnpm verify:prod` green with the M10 additions: contract drift, the RE image tests (py-worker-kit isolation tests in the RE image), the dynamic-gate test (nothing here is dynamic; no `dynamic` / `sandbox` names), the env check, the e2e.
- **Restore drill:** runs once with an RE job seeded to prove the new tables restore and verify (row counts in `tables.json`).
- **Audit coverage:** `test_rls_coverage.py`, `test_append_only.py` and the IDOR enumerator include every new table and route (no pending entries).

## Implementation Steps
1. Merge check: contracts regenerated, no drift; full API suite on the main stack.
2. Pipeline, diagnostics and never-executed / offline tests.
3. e2e spec.
4. Heavy steps, each alone: RE image build (if not cached), fuzz-lite, metrics, restore drill.
5. `pnpm verify:prod`; fix seams in the owning files.
6. Write the metric report; mark phases complete with notes.

## Success Criteria
- [ ] Pipeline, diagnostics, never-executed and offline tests pass.
- [ ] e2e passes.
- [ ] Fuzz-lite: every run ends cleanly, no surviving tool process, no container restart.
- [ ] `plans/reports/re-metric-YYMMDD.md` exists with recovery, heuristic, parse-success, latency and RSS numbers.
- [ ] `pnpm verify:prod` is green, restore drill included.

## Risk Assessment
- **Host RAM:** the RE worker (4 GiB cap) plus the stack; heavy steps run alone with only the infra stack and the RE worker up; the e2e stack runs the RE worker with the other analyzers stopped.
- **Run time:** Ghidra runs make the pipeline test and e2e slow (minutes); they use the smallest builds and run once per gate.
