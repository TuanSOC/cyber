---
phase: 3
title: "Radare2 quick profile engine"
status: code-complete (untested in Docker)
priority: P3
effort: "12h"
dependencies: [1]
---

# Phase 3: radare2 quick profile engine (group B, 2b, lane 3; optional)

## Overview
The `quick` profile: radare2 6.2.6, run **once, non-interactively, with a fixed script file** (no r2pipe, RT9), gives functions, call edges, imports with their callers and strings with their referencing functions in seconds, with about a tenth of Ghidra's memory, and **no decompilation**. It shares the contract, `ReView`, priority and detections with the Ghidra path.

**Optional and cut first** when the milestone runs late: the profile stays in the frozen enum and the API refuses it with `422 profile_unavailable` while `RE_QUICK_ENABLED=false` (the default until this phase merges). On a phase-2 **no-go** this phase becomes mandatory and grows the `full` fallback (bounded disassembly per prioritized function, `code_kind: disasm`); the parent re-plans its effort.

**Owns:** `apps/workers/reverse/re_worker/engines/r2.py` (implements the frozen `run_quick(ws, job, budget) -> EngineOutput`), `re_worker/probe/r2.py` (the reducer), proposals for `/opt/re/r2/quick.r2` (frozen in phase 1; the parent applies changes), `tests/unit/test_r2_*.py`, `tests/fixtures/stage_rows/r2/**`, `tests/engine/test_r2_smoke.py`.

## Requirements
- **Process (RT9):** two runs under the same sandbox as the Ghidra stages (`unix_sockets_only`, `deny_io_uring`), uid 10010, timeout `RE_QUICK_TIMEOUT_S` (300 s, a field of `ReLimits`):
  1. `radare2 -q -NN -S -2 -i /opt/re/r2/quick.r2 <input/sample>` through `sandbox.run_tool` with `stdout_name="r2.out"`, `Rlimits(as_bytes=1 GiB, cpu_s=2 × timeout, nproc=64, nofile=1024, fsize_bytes=RE_R2_MAX_OUTPUT_BYTES (256 MiB))`; `-NN` skips rc files and plugins, `-S` is r2's own sandbox (a second layer only), `-2` silences stderr; the file is opened read-only; `HOME` is the empty out dir. No interactive pipe, no command built at run time;
  2. the reducer probe `python -I -s -m re_worker.probe r2 <out>/r2.out` (tool uid, `RLIMIT_AS` 1 GiB) splits the output at fixed marker lines the script echoes, parses each JSON section with a per-section size cap and emits stage JSONL in the same shapes as the Ghidra `analyze` stage (the M3 `reduce` pattern: root never parses r2 output).
- **Script** (`quick.r2`, fixed, root-owned): `e cfg.sandbox=true`, `e scr.color=0`, `e scr.interactive=false`, `e bin.relocs.apply=true`, `e anal.timeout=<constant below RE_QUICK_TIMEOUT_S>`, `e io.cache=true` (no write-back), then `ij`, `iij`, `iEj`, `izj`, `aa`, `aac` (no `aaaa`, no ESIL), `aflj`, `agCj`, each preceded by an `echo` marker line; the exact 6.2.6 variable names are verified once in the engine smoke (`e??`). **No per-address command at all:** import and string references come from each function's `callrefs` / `datarefs` in `aflj` [I: field names verified by the smoke; if absent, the phase stops and reports to the parent rather than adding an interactive pipe]. A unit test checks the script contains only allow-listed lines; debugger, `!`, `#!`, `.`, `` ` ``, `=`, `o` and `@` never appear.
- **Normalization:** r2 names (`sym.imp.KERNEL32.dll_VirtualAlloc`, `fcn.00401000`, `entry0`) map to `NameSource` (`import`, `generated`, `export`, `symbol`); r2 function sizes and basic-block ranges map to body ranges (merge to ≤ 16); call edges from `agCj` (deduplicated, counted); import refs from each function's `callrefs` whose target is an import thunk / IAT address; string refs from `datarefs` that hit a string address from `izj`, capped by `ReLimits`. Header `engine: radare2`, `code_kind: disasm`, no `ReDecompiledRecord` lines in `quick`.
- **Robustness:** a missing or invalid JSON section is an empty result with `engine_errors += ["r2_<cmd>_failed"]`; a section larger than `RE_R2_MAX_JSON_BYTES` (64 MiB) is refused before parsing; the whole output is bounded by `RLIMIT_FSIZE` (a cut file → `truncated.r2_output`).
- **No-go extension (only if phase 2 is a no-go):** `full` via r2 = a second non-interactive run with a **root-written** script of `pdfj @ <int>` lines for the priority list (ints formatted by root from validated records, `0 ≤ addr < 2^64`; the only generated script, written to a root-owned dir, unit-tested), ≤ 400 instructions per function, rendered by the reducer as text lines `addr  bytes  mnemonic operands`, written as `ReDecompiledRecord(code_kind=disasm)`.

## Implementation Steps
1. `probe/r2.py`: the reducer (markers, bounded JSON sections, stage JSONL in the shapes of the Ghidra `analyze` stage).
2. `engines/r2.py`: `run_quick` (the r2 run, then the reducer) with the runner pattern of phase 2.
3. Normalizer tests from hand-written r2 output fixtures (lane 3); the script allow-list test.
4. `tests/engine/test_r2_smoke.py` on the M3 mingw builds (lane 3, single slot: no JVM).

## Success Criteria
- [ ] `quick` produces a valid `re.v1` stream for the PE and ELF fixtures with functions, edges, imports and strings, in seconds.
- [ ] The script allow-list test proves only fixed commands run (no `@`, debugger, shell or ESIL); no command is built from binary-derived data.
- [ ] Invalid or oversize r2 JSON is bounded and recorded, never fatal.

## Risk Assessment
- **r2 parser memory safety:** C parsers with frequent fixes; contained by the sandbox, recorded in THREAT_MODEL; version pinned and shown in every result.
- **r2 variable / command drift:** a pinned 6.2.6 and the engine-smoke check of variable names and `aflj` reference fields.
- **Weaker function recovery on stripped binaries:** measured in phase 4 against the same ground truth and stated in the docs.

## Notes (as built, untested in Docker)

Code-only (no container ran, no radare2 on the host). Host checks: `tests/unit/test_r2_reducer.py` and `tests/unit/test_r2_script.py` (12) pass; `test_pipeline.py::test_quick_*` (replay) and `tests/engine/test_r2_smoke.py` need the image.

- **Engine** (`engines/r2.py`): `run_quick(ws, job, budget)` raises `ProfileUnavailable` when `/usr/bin/radare2` or the script is missing, else `quick_with(ws, job, budget, runner, sample)`: one `r2` out dir shared by the radare2 run (`spec.r2_spec`: `radare2 -q -NN -S -2 -i /opt/re/r2/quick.r2 <sample>`, stdout `r2.out`, RLIMIT_AS 1 GiB, CPU 2 x t, NPROC 64, NOFILE 1024, FSIZE 256 MiB) and the reducer probe (`spec.reducer_spec`, step `r2_reduce`, RLIMIT_AS 2 GiB), sealed after the reducer; both under the watchdog. Time: `quick_timeout_s` split by `split_time` (reducer <= 120 s). The replay engine runs the same code (`r2.out` / `r2_reduce.jsonl` files of a case); the analyzer routes `quick` + replay to `quick_with`.
- **Reducer** (`probe/r2.py`, `python -I -s -B -m re_worker.probe r2`): audit hook first; bounded split at `===CYBERLAB:<section>===` lines in the script's order (repeats / out-of-order markers ignored and recorded; JSON strings cannot forge one since radare2 escapes newlines); each section <= 64 MiB before parsing; strict JSON (the normalize reader's `loads`); rows in the Ghidra `analyze` shapes. Mapping: `ij` `bin.baddr` -> image base, `entry0` -> entry and `export`; `aflj` (`addr` or 5.x `offset`; body `[minaddr, maxaddr)` when sane else `[addr, addr + size)`; `callrefs` CALL -> edges, a callref / dataref to an import `plt` slot -> import ref, a call to a `sym.imp.*` thunk -> import ref of the caller; `datarefs` to a string `vaddr` -> string ref); `iij` -> imports (`Ordinal_<n>` names are ordinals); `izj` -> strings (`wide` = utf16le). Header `engine: radare2`, `code_kind: disasm`, one `r2` stage, no decompiled lines, no ranks.
- **Deviations (parent to confirm):** the frozen script (phase 1) has no `iEj` / `agCj` and no `anal.timeout`: call edges come from `aflj` `callrefs` only, exports only from `entry0`, and the analysis time is bounded by the wall timeout alone. Engine errors are `radare_<section>_failed` / `radare_<section>_too_large` / `radare_marker_unexpected` / `quick_rows_*` (the contract's `ErrorCode` pattern has no digits, so `r2_<cmd>_failed` cannot be stored). A radare2 run killed at its timeout keeps what it printed: stage `timeout`, `truncated.r2_output`. The no-go `full` fallback (`pdfj`) is not built (the spike has not decided).
- **Frozen test to update (parent):** `tests/unit/test_skeleton.py::test_quick_is_unavailable_until_phase_3` calls `run_quick(ws, None, ...)` and expects `ProfileUnavailable`; it still holds on a host without radare2, but in the image (radare2 present) it now reaches the sample and fails. It should be removed or replaced by `test_pipeline.py::test_quick_replay`.
- **Phase 2 fix in the same session** (`e722d82`): root no longer cuts phase 5's `rank()` at `max_decompiled` (requested addresses are never dropped); `function_not_found` is reported for requested addresses that are not functions. Note: the contract's `StreamChecker` caps decompiled lines at `limits.max_decompiled`, so the API must send `max_decompiled >= len(decompile_addresses)` (e.g. `max(RE_MAX_DECOMPILED, len(addresses))` in `build_re_message`); otherwise a job requesting more addresses than `max_decompiled` is refused by the worker's own stream check (`re_parse_failed`).

**Remains (Docker):** `scripts/lane-test.sh 3 --service re-worker-test pytest -q tests/unit/test_r2_reducer.py tests/unit/test_r2_script.py tests/unit/test_pipeline.py`; `scripts/lane-test.sh 3 --service re-worker-test pytest -q -s -m engine tests/engine/test_r2_smoke.py` (confirms the 6.2.6 variable names, `-S` together with `-i`, and the `aflj` `callrefs` / `datarefs` fields; if those are absent the phase stops and reports, no interactive pipe is added); `ruff format`, `ruff check`, `mypy`; then `RE_QUICK_ENABLED=true` in the default settings is the parent's decision.
