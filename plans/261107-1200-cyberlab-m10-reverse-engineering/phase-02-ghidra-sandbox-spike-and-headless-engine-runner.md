---
phase: 2
title: "Ghidra sandbox spike and headless engine runner"
status: pending
priority: P2
effort: "36h"
dependencies: [1]
---

# Phase 2: Ghidra sandbox spike and headless engine runner (spike A′, then group B 2a, lane 2)

## Overview
Two parts.

**Part A′, the spike** (time-boxed **8 h**, starts with phase 1 in worktree `..\cyber-wt\m10-spike` from the M9 merge, no dependency on phase 1): prove that Ghidra 12.2 + PyGhidra 3.2 + JDK 25 can import, analyse, export and decompile a sample **inside the kit sandbox** on this host, and fix the values phase 1's Dockerfile and this phase's runner use. The parent builds the throwaway spike image and runs it (heavy, alone). The result is a recorded **go / no-go** before group B starts.

**Part B, the runner** (28 h; red-team items RT1, RT3, RT4, RT5, RT13–RT16, RT19, RT20, RT23 add about 4 h): the PyGhidra probe stages (`analyze`, `decompile`), the root-side runner and pipeline, the normalizers into `re.v1`, the test-only replay engine, hostile-output handling and the engine smoke on the real image.

**Owns:** `apps/workers/reverse/re_worker/{analyzer,pipeline}.py`, `probe/**` except `probe/r2.py` (launcher, stages, audit hook, export, decompile), `engines/{ghidra,replay,workspace,watch}.py`, `normalize/**`, `tests/fixtures/stage_rows/**`, `tests/unit/test_{pipeline,normalize_*,hostile_output,jvm_args,loader_choice,analysis_options,audit_hook,caps,rlimits,watch}.py`, `tests/engine/test_ghidra_smoke.py`, and the spike notes below. In the spike worktree only: `spike/**` (throwaway Dockerfile and scripts, never merged).

## Requirements

### Part A′: the spike (questions from research §10)
1. **Run under the sandbox:** a PyGhidra probe started by `sandbox.run_tool` as uid 10010 with `unix_sockets_only=True`, `deny_io_uring=True`, `Rlimits(as_bytes, nproc, nofile, fsize_bytes)` analyses `hello.c` and `injector.c` (mingw x64, compiled inside the spike image) and decompiles every function. Record the **smallest reliable `RLIMIT_AS`** for heap 2 GiB and 3 GiB (and 1 GiB for the decompile stage), the peak thread count (for `nproc`, which must stay below `pids_limit` 512 with ≥ 64 to spare, RT13), CPU time vs wall time per stage (for `cpu_s`, RT3), open files (for `nofile`), and whether the JVM starts with inet sockets denied (the IPv6 probe). If it does not, find the JVM flag that avoids the probe (e.g. `-Djava.net.preferIPv4Stack=true` does not help with AF_INET denied; record what works) or record the no-go.
2. **Launcher side effects (RT1):** list what `pyghidra.start()` does on this install: the `LaunchSupport` / `java -version` subprocesses (can a launcher subclass or argument pass the pinned JDK home and skip them?), the `launch.properties` `VMARGS` it merges (then replace the file with ours and check the effective `getInputArguments()`), plugin installation and its temp-dir lock. Record the design the probe uses: hook after `start()`.
2a. **JDK vs JRE:** does PyGhidra's launcher accept a JRE (`eclipse-temurin:25-jre`)? Record the size difference.
3. **Trim list:** delete `docs/`, `Extensions/`, `server/`, `Ghidra/Debug/`, `Ghidra/Features/Jython`, every processor except `x86` and `DATA` (and anything else measured as unused); after each deletion the four operations still work. Record sizes before / after.
4. **API checks:** `program_loader()` can force `PeLoader` / `ElfLoader` and refuses an archive; the full option list of each loader (the library-loading, search-path and project-link names, RT20); the 12.2 names of the analyzer options of plan "Ghidra in the sandbox"; `DecompileOptions` comment switches (RT16); the timeout task monitor cancels `analyze`; `DecompInterface.decompileFunction(f, timeout, monitor)` returns a timeout result and the decompiler child is killed; **`prlimit` on the decompiler child** lowers its `RLIMIT_AS`, a child that hits it fails one function and the interface reopens (RT4).
5. **Measurements:** wall time, CPU time and peak container memory (cgroup `memory.current` polled by root, RT14) per stage for hello, injector, a 4 MiB and a 16 MiB pure-Python-built PE (random code bytes: a robustness case) and a generated large C program (≈ 5 000 functions, `-O2`, built inside the spike image with the phase-4 generator idea: the realistic worst case, RT21); the Ghidra project size on disk for each (RT5).
6. **Write paths:** with `HOME`, `user.home`, `XDG_*`, `java.io.tmpdir` and the project in the out dir, list every path the JVM opens or writes (`strace -f -e trace=openat,creat,mkdir,execve` in the spike image only) and confirm nothing outside the out dir is written (the rootfs is read-only in the real service), every `execve` is the launcher's helpers before the hook or `jspawnhelper` / `decompile`, and a PE whose CodeView PDB path is `/etc/passwd` opens nothing outside the install, the input and the out dir (RT19).

**Go** if 1, 2, 4 and 5 succeed within `mem_limit 4g` and `RE_ANALYSIS_TIMEOUT_S` for ≤ 16 MiB. **No-go fallback:** radare2 becomes the only engine (plan "Engine choice"); phase 3 becomes mandatory and grows `full` = r2 analysis + bounded `pdfj` disassembly; this phase's part B shrinks to the replay engine, normalizers and pipeline (the parent re-plans effort). Either way the result goes into the notes below and to the parent, who applies the values to the frozen Dockerfile.

### Part B: the runner
- **Workspace** (`engines/workspace.py`, the static `Workspace.engine()` pattern, M8 RT26): `input/sample` root-owned 0444; per stage a fresh tool-owned out dir created after kill-by-uid; the Ghidra project dir `out/project` is created by the `analyze` stage and re-opened by `decompile`, which opens the program without saving (the project stays tool-writable: Ghidra writes its lock file; same uid, no trust boundary, RT23); the decompile stage's out dir is separate; root copies nothing between them except the priority list, which it writes as `stage/decompile_list.json` in a root-owned 0755 dir (file 0444), never into a tool-writable dir.
- **Before the download** (RT5): free space on `/work` ≥ size + `max_work_bytes` + 1 GiB, else `insufficient_disk`.
- **Watch** (`engines/watch.py`, RT5 / RT14): while a stage runs, root measures the job dir every 2 s (bounded `os.scandir` walk, no symlink follow) and polls the container cgroup `memory.current` and `memory.events`; above `max_work_bytes` it kills the tool uid → `re_work_too_large`; an `oom_kill` increase or the JVM's exit code 3 (`ExitOnOutOfMemoryError`) → `re_out_of_memory`; the stage's peak memory goes into the header's stage entry (added by root).
- **Root magic check** (`probe` never chooses the loader): `MZ` + in-bounds `PE\0\0` → `PeLoader`; `\x7fELF` with `e_type` EXEC / DYN → `ElfLoader`; a PE with a non-empty CLR data directory → diagnostic `unsupported_managed_code`; machine not i386 / amd64 → diagnostic `unsupported_architecture`. Root reads only the header bytes (bounded, `struct`), as the M3 root does for magic.
- **Stage `analyze`** (`probe/analyze.py`, `python -I -s -m re_worker.probe analyze …`):
  - `pyghidra.start(install_dir=/opt/ghidra)` through a launcher with the fixed vmargs (`jvm_args.py`, one function, unit-tested: heap from `RE_JVM_HEAP` / `RE_DECOMPILE_JVM_HEAP`, `-XX:+DisableAttachMechanism`, no user-supplied value ever reaches the list), the pinned JDK home passed when the launcher allows it (spike item 2, RT1); our `launch.properties` adds nothing; then the probe writes `RuntimeMXBean.getInputArguments()` to `status.json` and root compares it with `jvm_args.py`'s expected list (mismatch → `jvm_start_failed`);
  - **then** installs the audit hook (M8 pattern: refuse and count `socket.*`, `urllib.Request`, `subprocess.Popen`, `os.exec*`, `os.system`, `os.spawn*`; counts written to `status.json`), before the sample is opened (RT1: installed earlier, it would refuse the launcher's own helpers);
  - creates the project, loads the sample with the root-chosen loader and import options (`loader_choice.py`), refuses any other loader result; enumerates the chosen loader's options and fails `re_parse_failed` if a library-loading, library-search-path or project-link option is enabled or an option name is unknown (RT20);
  - sets the frozen analysis options (`analysis_options.py`), checks each option name exists (an unknown name fails the stage `re_parse_failed` with the name, so a Ghidra upgrade cannot silently drop a setting);
  - runs `analyze` under a timeout monitor (`RE_ANALYSIS_TIMEOUT_S`); a timeout is recorded and export proceeds;
  - exports bounded JSONL with per-kind caps (stop at the cap, set the truncated flag): program facts, functions (entry, RVA, name, source mapped to `NameSource`, body ranges ≤ 16, flags, signature, calling convention, instruction count), call edges (call references only, counted per pair), imports and import refs (call references to thunks / IAT pointers, resolved to the containing function), strings (≥ 5 characters, defined string data, value cut at 1 KiB) and string refs; every string field NUL-stripped and length-cut in the probe and re-validated by root;
  - saves the project and exits.
- **Root, between stages:** bounded reads of the JSONL, contract validation per line (per-record error isolation; a hostile line is counted, never fatal), caps, build `ReView`, call `priority.rank(view, job)` (phase-5 stub until merged: the stub returns requested addresses + entry point + exports + by-size order), write `stage/decompile_list.json` (entries only, ints formatted by root; RT23).
- **Stage `decompile`** (`probe/decompile.py`): JVM heap `RE_DECOMPILE_JVM_HEAP` (RT4); opens the saved project and the program without saving, `DecompInterface` with `setSimplificationStyle("decompile")` and a fixed `DecompileOptions` with every comment kind off (PLATE, PRE, POST, EOL, header; warnings kept, RT16); after each (re)spawn of the decompiler child the probe lowers its `RLIMIT_AS` with `prlimit` to `RE_DECOMPILER_AS` (RT4; a child that dies fails that function and the interface is reopened, at most 3 times per stage, then `skipped_budget` for the rest); for each listed entry (in order) `decompileFunction(f, RE_DECOMPILE_TIMEOUT_S, monitor)`, writes one line per function (status, code cut at 64 KiB at a line boundary with the marker, lines, sha256) until the total-bytes cap or the stage budget; one `DecompInterface` per stage, `dispose()` in `finally`; the stage records its children's executables right after each spawn and at the end (`/proc/<pid>/task/*/children`, then `/proc/<child>/exe`); only `jspawnhelper` of the pinned JDK and `/opt/ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile` are expected; anything else → `SandboxCompromised`. This is detection, not prevention (RT15).
- **Runner** (`engines/ghidra.py`): `sandbox.run_tool` per stage with the spike's `Rlimits` — `cpu_s` set explicitly to 2 × the stage timeout + 60 (RT3), `nproc` 256 (RT13) — `unix_sockets_only`, `deny_io_uring`, `extra_env` (JAVA_HOME, GHIDRA_INSTALL_DIR, MALLOC_ARENA_MAX, XDG dirs; a unit test asserts `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS` and `DEBUGINFOD_URLS` never reach the env, RT19), timeouts from the job budget; the `watch` thread runs for the stage (peak memory and disk, RT5 / RT14; `RUSAGE_CHILDREN` is not used); `jvm_start_failed` when the JVM exits before writing its ready line; `hs_err.log` presence → `engine_errors += ["jvm_crash"]` (its content is never parsed or returned).
- **Replay engine** (`engines/replay.py`): reads `tests/fixtures/stage_rows/<case>/{analyze,decompile}.jsonl`; refused unless `TEST_PROFILE=1` (env check at start-up, tested); header `engine: replay`.
- **Pipeline** (`pipeline.py`): download (kit `transfer`, sha256 and size verified) → magic → stages (or the phase-3 `run_quick` for `quick`) → detections (phase-5 `run`, stub until merged) → `re.v1` writer (header, program, records, findings, IOCs, trailer) → presigned POST; stage statuses in the header; job success needs `analyze` ok or timeout-with-functions; `decompile` failing leaves a partial success with `stages[decompile].status = failed`.
- **Hostile output** (`test_hostile_output.py`): oversize lines, invalid UTF-8, NUL, NaN, duplicate keys, unknown kinds, refs to unknown functions, 10⁶ lines, a symlink or FIFO planted in the out dir, a `status.json` claiming zero audit events with a tampered size: each is bounded, counted, and never crashes root.

## Implementation Steps
1. **Spike** (A′): throwaway Dockerfile (kit + JDK 25 + Ghidra 12.2 + PyGhidra + mingw), the probe prototype, the six checks; notes and go / no-go to the parent.
2. Workspace, magic check, `jvm_args.py`, `loader_choice.py`, `analysis_options.py` with unit tests.
3. `probe/analyze.py` and its exporters; `probe/decompile.py`.
4. Runner, replay engine, normalizers, pipeline.
5. Unit tests (lane 2), then `tests/engine/test_ghidra_smoke.py` (lane 2 `--heavy`): the M3 `hello` / `injector` builds (a local compile helper in the test; the phase-4 generator is not in this worktree, RT11) analyse and decompile, the audit counts after the JVM start are zero, the recorded children are only `jspawnhelper` and the decompiler, the effective JVM arguments equal the expected list, peak container memory < `mem_limit`.
6. `ruff`, `mypy`.

## Success Criteria
- [ ] Spike notes recorded with the go / no-go, the measured values and the trim list; the parent applied them to the Dockerfile.
- [ ] The real Ghidra analyses and decompiles the mingw samples in `re-worker-test` under the sandbox, offline, with zero audit events after the JVM start, only the expected children recorded and the expected JVM arguments.
- [ ] The disk watchdog and the cgroup poller turn an oversized project and an OOM into `re_work_too_large` / `re_out_of_memory` (unit tests with a fake cgroup dir and a fake walker).
- [ ] Every cap stops its exporter and sets its flag; a decompile timeout is recorded per function without failing the job.
- [ ] Hostile stage output never crashes root; the replay engine is refused outside the test profile.

## Risk Assessment
- **JVM vs seccomp / rlimits:** the main unknown; the spike answers it before any other engine work.
- **Ghidra API drift:** option and class names checked at run time (unknown option → explicit failure) and pinned to 12.2; an upgrade re-runs the spike checks.
- **Time on hostile or large inputs:** the analysis monitor, the per-function decompile timeout, the stage budget and the job timeout nest; the worst case (16 MiB of random code) is measured.

## Spike notes (filled by the spike)
<!-- go / no-go, RLIMIT_AS / CPU / NPROC / NOFILE, the decompiler prlimit result, the launcher's side effects and the final start sequence, JDK or JRE, trim list and sizes, loader / analyzer / decompiler option names, timings, CPU time, peak memory and project size per sample, write and exec paths. -->
