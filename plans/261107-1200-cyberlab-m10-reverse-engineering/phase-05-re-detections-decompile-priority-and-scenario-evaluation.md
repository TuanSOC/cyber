---
phase: 5
title: "Re detections decompile priority and scenario evaluation"
status: code-complete (untested in Docker)
priority: P2
effort: "10h"
dependencies: [1]
---

# Phase 5: RE detections, decompile priority and scenario evaluation (group B, 2d, lane 5)

## Overview
Pure functions over `ReView` (frozen in phase 1), with no engine dependency: the deterministic decompile priority, three verdict-free function-level heuristics, IOC extraction from strings referenced by code, and a generated scenario dataset with a precision / recall table.

**Owns:** `apps/workers/reverse/re_worker/priority.py` (implements the frozen `rank(view, job) -> list[int]`), `re_worker/detections/**` (implements the frozen `run(view, limits) -> DetectionOutput`), `apps/workers/reverse/dataset/**` (`generate.py`, `evaluate.py`), `tests/unit/test_{priority,detections_*,dataset_quality,finding_wording}.py`.

## Requirements
- **Priority** (plan "Outputs", deterministic; ties broken by entry ascending):
  1. `job.decompile_addresses` (optional, `full` only, RT10) that are function entries (others are recorded as `function_not_found` in `engine_errors`, at most 64);
  2. the program entry point and exported functions;
  3. functions whose body contains a file VA of `job.capa_file_vas` (RT8);
  4. functions calling an import of an M3 suspicious API set (the sets from `cyberlab_worker.apisets`, lifted from M3 in phase 1, RT7: no copy, no drift test);
  5. functions referencing a string that yields an IOC;
  6. the rest by size descending.

  Thunks, externals and `is_library` functions are skipped in classes 2–6; the output is capped at `limits.max_decompiled` (class 1 always first and never cut by the cap). Each function's rank (or `None`) is returned for storage.
- **Heuristics** (each a `FindingRecord`, severity ≤ `medium`, method names frozen):
  - `heuristic:re_api_set_function@1` (severity of the M3 set, capped at `medium`): an M3 `ApiSet` (process injection, keylogging hooks, anti-debugging, credential access, persistence, download-and-execute) fires **within one function** with the M3 semantics (RT7): every group of one `any_of` combination has at least one API called from that function, directly or through a thunk (A / W variants included as M3 lists them); the pseudo-API `string:run_key` counts when the function references a Run / RunOnce registry-path string. Title: "Function <name> calls the <set> API combination" with the APIs listed; attributes `function_entry`, `set`, `groups`, `apis`.
  - `heuristic:re_runtime_api_resolution@1` (`low`; `medium` when ≥ 3 resolved names belong to one suspicious set): a function calls `GetProcAddress` / `LdrGetProcedureAddress` / `dlsym` and references ≥ 3 strings that are exact API names (a bundled list of Win32 / libc export names, ≈ 2 000 entries, MIT-compatible source recorded). Title: "Function <name> resolves APIs by name at run time".
  - `heuristic:re_network_string_function@1` (`low`): a function references a URL / IP / domain string and calls a network API (`connect`, `InternetOpenUrl*`, `WinHttp*`, `URLDownloadToFile*`, `getaddrinfo`).
- **Wording:** templates describe what was found with measured values; function names are quoted and attributed ("named <x> by the engine"); `test_finding_wording.py` rejects verdict words (the M3 list) in every template and in rendered findings with hostile names.
- **IOCs:** the shared extractor (`cyberlab_worker.iocs`) over referenced strings only; each IOC's context names the referencing function(s) (≤ 3, by entry); caps from `ReLimits`.
- **Scenario dataset** (`dataset/generate.py`): generated `ReView`s (no engine), including a set whose groups are split across two functions (must not fire per function, while M3's file-level rule would): benign baselines (file I/O, GUI-like imports, a networked updater that references its own URL and calls `connect` → expected `re_network_string_function` low, labelled as a true positive of the rule, not of maliciousness), near misses (one API short of each set; a resolver with 2 names; a network API without a string), positives for each rule, and capa-location / requested-address priority cases. `evaluate.py` gives TP / FP / FN, precision and recall per rule and the priority-order checks; `test_dataset_quality.py` asserts the table and writes `dataset/quality.json`.

## Implementation Steps
1. `priority.py` with exhaustive unit tests (each class, ties, caps, requested addresses, missing addresses).
2. The per-function `ApiSet` matcher over `cyberlab_worker.apisets` with unit tests per set and combination; the API-name list with its source note.
3. The three heuristics with per-rule unit tests and wording tests.
4. IOC wiring; the scenario dataset and evaluation (lane 5, pure Python).

## Success Criteria
- [ ] `rank` is deterministic (same view → same list, property-tested with shuffled input) and respects every class and cap.
- [ ] Each heuristic fires on its positives and not on its near misses in the dataset; precision / recall table written with the synthetic caveat.
- [ ] No template or rendered finding contains a verdict word; no heuristic exceeds `medium`.

## Risk Assessment
- **False positives on real software** (updaters, installers, security tools call the same APIs): severity caps, verdict-free wording, the M3 caveat; analyst feedback is "Later".
- **Set drift from M3:** none: both analyzers read `cyberlab_worker.apisets` (RT7).

## Implementation notes (as built, untested in Docker)

Pure Python, no engine. Host checks that passed (Python 3.14, `PYTHONPATH` = py-jobs + kit +
worker): `python -m dataset.evaluate` (exit 0) and the RE `tests/unit` (204 passed, 3 skipped,
including phase 2's tests present in the worktree); `test_skeleton.py`'s frozen signatures
still hold. Not run: ruff / mypy (not installed on the host).

- **Priority** (`re_worker/priority.py`): `rank(view, job)` = class 1 (requested entries that
  are functions and not externals, request order) then classes 2-6 (entry point + exports;
  capa file VAs via `functions_at_file_va`; calling an `apisets.api_names()` API directly or
  through a thunk; referencing a string with a URL / domain / IP observable; the rest by size
  desc), each function at its best class, ties by entry, thunks / externals / library skipped.
  Length `max(limits.max_decompiled, len(class 1))`. Helpers: `ranks(view, job)` (entry ->
  index = `priority_rank`), `missing_addresses(view, job)` (for `engine_errors:
  function_not_found`), `classify`.
- **Detections** (`re_worker/detections/`): `base.py` (methods, `METHOD_MAX`, `TEMPLATES`,
  set labels, `api_name` normalization of `__imp_` / i386 `_X@n` / `@plt` / radare2
  `sym.imp.LIB.dll_X`, `called_api_names` = import refs + thunk / external callees, `Finding`
  -> `FindingRecord` with uuid5(program sha256, method, type, entry)), `apisets.py` (the M3
  combination semantics per function, run-key = a referenced `has_run_key` string),
  `rules.py` (resolution: `GetProcAddress` / `LdrGetProcedureAddress[Ex]` / `dlsym` /
  `dlvsym` + >= 3 exact API-name strings, `medium` when >= 3 are in one M3 set; network: a
  URL / IP / domain string + `connect`, `WSAConnect*`, `getaddrinfo` / `GetAddrInfo*`,
  `gethostbyname`, `InternetOpenUrl*`, `InternetConnect*`, `HttpOpenRequest*`,
  `URLDownloadTo*File*`, `WinHttp*`), `iocs.py`, `api_names.py` (1 904 names, hand-compiled
  from the public Win32 / Native API and POSIX / glibc names; source note in the module).
  Findings cite `attributes.function_entry` (`0x…`) and `function_name`, `evidence_refs[0] =
  function:0x…`; ordered severity desc, method, entry, type; capped at `max_findings` /
  `max_iocs` with `truncated`. Thunks, externals and library functions are never cited.
- **Dataset** (`dataset/generate.py` `Builder` / `build(name)` / `job(...)`, 33 scenarios;
  `dataset/labels.json` hand-written; `dataset/evaluate.py`): 4 baselines (the updater's
  `network_string_function` is labelled a TP of the rule), 14 positives (every set, thunks,
  three resolution cases, three network cases), 12 near misses (one group short per set, the
  split injection that M3's file-level rule would report, run key in another function, 2
  resolved names, names without a resolver, network API without a string, URL without a
  network API), 3 priority cases (all classes with a missing request, capa VA on a rebased
  PIE, requests beyond the cap). Result: 15 TP / 0 FP / 0 FN (1.00 / 1.00 per rule), IOC
  recall 7/7, 0 unexpected IOCs, priority 3/3; `dataset/quality.json` written by
  `test_dataset_quality.py` (skips the write on the read-only container mount).

**Deviations / notes for the parent and phase 2 / 7 / 8:**
- `IocRecord` has no context field (only `source`, 16 chars), so "the IOC's context names the
  referencing functions" cannot travel in the stream: every RE IOC has `source = "re_string"`;
  the referencing functions (<= 3) are computed (`iocs.IocHit.context()`) and are recoverable
  from `re_string_refs` (phase 8's strings route). A contract field would be a frozen-interface
  change.
- `run(view, limits)` has no time argument (frozen); findings / IOCs carry `detections.now()`
  (the analysis time, as M3's static worker does).
- Phase 2's `engines/ghidra.py` slices `rank()` at `limits.max_decompiled`, which would cut
  class-1 addresses when `max_decompiled < len(decompile_addresses)` (only with a setting below
  64): use `len(rank(...))` (already `max(cap, class 1)`) instead of re-slicing. Phase 2 does
  not yet call `priority.missing_addresses` for `function_not_found`.
- The `api_injection` set label reads "process-injection" (the M3 wording); the RE wording test
  keeps the M3 + M8 verdict list without M8's bare `inject`.

**Remains to run (Docker):** `lane-test.sh 9 --service re-worker-test pytest -q -m 'not engine'`
(the same unit tests in the image), `ruff format`, `ruff check`, `mypy` on the RE worker.
