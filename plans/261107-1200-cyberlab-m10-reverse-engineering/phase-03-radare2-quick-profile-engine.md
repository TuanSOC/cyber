---
phase: 3
title: "Radare2 quick profile engine"
status: pending
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
