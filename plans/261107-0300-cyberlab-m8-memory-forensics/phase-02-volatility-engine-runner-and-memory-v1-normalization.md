---
phase: 2
title: "Volatility engine runner and memory v1 normalization"
status: pending
priority: P2
effort: "27h"
dependencies: [1]
---

# Phase 2: Volatility engine runner and memory.v1 normalization (group B, 2a, lane 2)

## Overview
The untrusted half of the pipeline: download → identify → per-plugin runs → normalize → detect → `memory.v1` → upload → ingest event. It is built on the worker kit exactly like the static worker:
- root never parses image bytes; it only hashes them during the download;
- every Volatility call runs as uid 10006 in `python -I -s -m memory_worker.probe …`, under seccomp (`unix_sockets_only=True`, `deny_io_uring=True`: every socket family but AF_UNIX denied, RT7), `RLIMIT_AS`, `RLIMIT_FSIZE` 512 MiB, a timeout, kill-by-uid and a fresh output directory;
- root accepts only bounded, contract-valid rows of the kinds that plugin may emit.

Volatility runs **offline in library mode** against `/symbols` (read-only). Research: [`researcher-261107-m8-volatility3.md`](../reports/researcher-261107-m8-volatility3.md).

**Owns:**
- `apps/workers/memory/memory_worker/{analyzer,pipeline}.py`, `probe/**`, `normalize/**`, `engines/**`;
- `tests/fixtures/vol_rows/**` (our own hand-written rows in the 2.28.2 column shapes);
- `tests/unit/test_{runner,probe,normalize_windows,normalize_linux,hostile_output,offline,plugin_allowlist,plugin_columns,symbol_paths,audit_hook}.py`;
- `tests/engine/test_probe_smoke.py` (`--heavy` for the sparse 8 GiB case).

## Requirements
- **Pipeline** (`analyzer.py`, `pipeline.py`):
  1. Validate `MemoryJobV1`; send `started`.
  2. `sandbox.reset` and `prepare` **once per job** (prepare resets the whole `/work`, so it is never called per plugin; RT26). Check free space on `/work` (≥ size + 1 GiB, else `insufficient_disk`).
  3. `transfer.download` to `input/image` (sha256 and size verified, `max_bytes` from the limits, `memory_image_too_large`); the file is root-owned 0444.
  3a. **Root magic check** before any probe: gzip, bz2, xz, zstd, zip and 7z magic → `unsupported_memory_format`. Volatility's `ResourceAccessor` would otherwise decompress such a file transparently (a small bomb becomes a CPU / disk DoS; RT19).
  4. **Identify** (probe `identify`, 600 s). It returns the layer chain, the OS, the arch, the kernel identity (Windows: PDB name, GUID and age from the PDB scan, without symbols; Linux: the banner from the banner scan; phase 2 verifies the exact 2.28.2 API: `pdbutil` / `PdbSignatureScanner`, `banners` and the stacker), `nt_build` and `system_time` when resolvable, and whether `/symbols` resolves the identity (`SymbolStore.lookup`, phase 5).
     - `os_hint` restricts the candidates.
     - No OS → `os_undetermined`. An unknown layer → `unsupported_memory_format`.
     - A Windows PDB name outside the kernel allow-list, or a banner that fails `LinuxBanner`, gives `os_undetermined` with the reason in the header, never a diagnostic stream with an invalid requirement.
  5. **Symbols missing** → write the diagnostic stream (header with `symbols.required`, the image line, trailer), upload it, and finish `failed / symbols_missing` with its version id.
  6. **Plugins:** for each plugin of `PLUGINS_BY_PROFILE[(os, profile)]`, in order, run the probe `run <plugin>` with `ANALYSIS_MEMORY_PLUGIN_TIMEOUT_S`, the remaining job budget (a plugin that cannot start within the budget is `skipped`), `RLIMIT_AS = MEMORY_PLUGIN_RLIMIT_AS`, and a fresh out dir `<job>/<plugin>-out` created after kill-by-uid (the static `Workspace.engine()` pattern; RT26).
     - Status `ok`, `failed`, `timeout`, `skipped` or `unsupported` (a missing requirement, for example no swap or a 32-bit-only plugin).
     - Duration, rows, `truncated`.
  7. **Success rule:** identify and the process list (`windows.pslist` / `linux.pslist`) are `ok`; otherwise the job fails with `memory_parse_failed`. Every other failure is an engine error of that plugin.
  8. Normalize (below) → `MemoryView` → `detections.run(view, limits)` (phase 3 stub until merge) → write `memory.v1` with the result writer → `transfer.upload` → `finished` with the version id. Then `sandbox.cleanup` and wipe `/work`.
- **Probe** (`probe/`, runs as the tool user; Volatility imported only here):
  - `python -I -s`, cwd = the read-only input dir; env reduced to `PATH`, `TMPDIR` (its out dir), `XDG_CACHE_HOME` (its out dir `/cache`, seeded by root with a copy of `/symbols/.cache/volatility3/identifier.cache` at `cache/volatility3/identifier.cache`, RT5), `HOME=/nonexistent`, `XDG_CONFIG_HOME=/nonexistent` (passed through `run_tool(extra_env=…)`, which overrides the kit's defaults).
  - **Offline** (verified against 2.28.2: `cli/__init__.py` only sets `constants.OFFLINE`; `ResourceAccessor`'s `OfflineHandler` refuses http(s) when it is set, and its TLS failure path retries **without verification** otherwise): the probe sets `constants.OFFLINE = True` and `constants.REMOTE_ISF_URL = None` before any automagic runs; a test asserts both and that an http location raises `OfflineException` (RT7).
  - **Audit hook** (PEP 578, `probe/guard.py`), installed after the imports: refuses (raises) and counts `socket.*`, `urllib.Request`, `subprocess.Popen`, `os.exec*`, `os.posix_spawn`, `os.spawn*` and `os.system` events; the counts go into `status.json` and root records them in the plugin status. Seccomp stays the enforcing layer underneath (RT7).
  - **Symbol paths** = `["/symbols", <site-packages>/volatility3/symbols, <site-packages>/volatility3/framework/symbols]`: our store first, then the two read-only built-in dirs that hold the bundled tables (netscan, PE, bash, generic types). The writable cache-fallback entry of `SYMBOL_BASEPATHS` is dropped, so `pdbutil` finds no writable path to store a conversion. The probe asserts the exact list at start; `test_symbol_paths.py` resolves the bundled netscan, PE and bash tables through it (RT2). Plugin paths are the built-in ones only. No remote ISF URL. The single location is `file:///work/<job>/input/image`.
  - **Fixed configuration per plugin** (`probe/plugins.py`, a table keyed by `MemoryPlugin`). Every `dump` option false and no output dir; in addition the plugin is constructed with a refusing `FileHandlerInterface` as `open_method` (any open raises), so no plugin can write a file whatever its options (RT20).
    - Process scans use their default physical / virtual choice.
    - Nothing comes from the job message except the profile and OS choice. The table is the allow-list, and a test proves no other plugin name is runnable.
  - **Streaming visitor:** `grid.populate(visitor)` writes one JSON object per row (children flattened with a `parent` index for tree plugins) to `out/rows.jsonl` through our own encoder:
    - ints as ints;
    - `datetime` as ISO UTC;
    - `bytes` / `HexBytes` / `LayerData` as lowercase hex, cut to 64 bytes;
    - `Disassembly` as text, cut to 1 KiB;
    - strings cut to 4 KiB with invalid UTF-16 replaced;
    - `NotApplicableValue` / `UnreadableValue` / `NotAvailableValue` as null plus a `_unreadable` marker.

    At `limits` rows the visitor stops the grid (an exception caught by the probe) and writes `{"_truncated": true}`.
  - Exit codes and a one-line `status.json` (Volatility exception class name only, never a message containing image bytes).
- **Normalizers** (`normalize/`, root side, reading tool output through `dir_fd`, `O_NOFOLLOW`, regular files only, bounded line length):
  - One row model per plugin (Pydantic, `extra="ignore"` for unknown columns, which are counted; types strict). A bad row is skipped and counted (`rows_skipped`), never fatal.
  - **Windows:** processes merged from `pslist` + `psscan` by (pid, offset, create time), with `sources` bits; `cmdline` and the `dlllist` image path joined by pid. `netscan` → connections. `malware.malfind` → injections (`has_pe` from the hex head: `MZ` plus an in-bounds `PE\0\0` when visible). `dlllist`, `svcscan`, `registry.hivelist`, `registry.userassist` and `malware.ldrmodules` → artifacts with fixed attribute keys.
  - **Linux:** `pslist` → processes; `psaux` → cmdline; `bash` → artifacts `bash`; `sockstat` → connections; `lsof` (`open_file`), `malware.malfind` (injections), `malware.check_syscall`, `malware.hidden_modules` → artifacts or injections.
  - **Column-drift test** (`test_plugin_columns.py`, RT4): parses the installed 2.28.2 source of every allow-listed plugin (AST of the `renderers.TreeGrid([...])` column list in `run()`) and asserts it equals the column set our row model and `tests/fixtures/vol_rows/` use. This is the only guard for the Windows plugins, which no test executes.
  - The image line from identify.
  - Caps per kind with `truncated`.
- **Replay engine** (`engines/replay.py`, plan "Testing" fallback): reads `tests/fixtures/vol_rows/<scenario>/<plugin>.jsonl` instead of running Volatility. It is active only when `MEMORY_ENGINE=replay` **and** `TEST_PROFILE=1`. Otherwise the worker refuses to start (exit 78), and the header says `engine: replay`. It shares every root-side code path with the real engine.
- **Isolation tests** (in the memory image): the py-worker-kit sandbox tests, plus:
  - the probe cannot open an inet, netlink or vsock socket, nor use io_uring, and the audit hook records the attempt;
  - it cannot write outside its out dir;
  - `HOME` and the config dirs are unreadable;
  - `site-packages` is not writable by the tool uid;
  - a probe killed at the timeout leaves no process.
- **Hostile output tests:** giant lines, invalid JSON, NaN, nested objects in scalar columns, symlinked or FIFO output files, rows beyond the cap, a probe that writes a fake `_truncated: false` after the real cap, a `status.json` claiming `ok` with no rows file.
- **Probe smoke** (`tests/engine/test_probe_smoke.py`; always, whatever phase 4 decides; RT4): the real Volatility in the worker, on (a) a seeded random 16 MiB blob and (b) a **sparse 8 GiB file** made with `truncate` in the test tmpfs `/work` (holes take no memory; never uploaded; `--heavy`): identify ends `os_undetermined` within its timeout, the offline constants and the audit hook are active, the hook recorded no network or process event, and peak RSS stays below `RLIMIT_AS` although the file is far larger (no layer maps the image). Duration is recorded as the baseline full-image scan time.
- **No reference corpus** (parent decision): no third-party image is downloaded or used by any test.

## Implementation Steps
1. Read the static worker (`analyzer.py`, `engines/probes.py`, `probe/main.py`, `pipeline.py`) and the worker kit.
2. Read the volatility3 2.28.2 sources for library use: `cli/__init__.py` (offline, symbol and plugin paths), `framework/constants` (`SYMBOL_BASEPATHS`, `CACHE_PATH`), `layers/resources.py` (offline handler, decompression), `framework/contexts`, `automagic`, `plugins/construct_plugin` (`open_method`), `renderers` (the TreeGrid visitor), `symbols/windows/pdbutil.py` (ISF path from the image's PDB name), the PDB and banner scanners, and the column names of every allow-listed plugin; confirm that no layer `mmap`s the image. Record the findings in the phase notes.
3. Probe: offline setup, the plugin table, the visitor and encoder, identify.
4. Root runner and pipeline; the success rule; the diagnostic path.
5. Normalizers with the hand-written row fixtures; replay engine.
6. Isolation, hostile-output, offline, audit-hook, symbol-path, column-drift and allow-list tests: `scripts/lane-test.sh 2 --service memory-worker-test pytest -q tests/unit/…`; the probe smoke's random-blob case on the same lane, its sparse 8 GiB case with `--heavy`.
7. `ruff` / `mypy` on own files.

## Success Criteria
- [ ] The replay engine produces a `memory.v1` stream from the Windows and Linux row fixtures that validates against the frozen contract and matches the phase-1 fixture counts.
- [ ] Offline is proven: `OFFLINE` and `REMOTE_ISF_URL` are set, the symbol paths are exactly the store plus the two read-only built-in dirs, a socket attempt from the probe fails (seccomp) and is recorded (audit hook).
- [ ] The column-drift test passes for every allow-listed plugin, and the bundled netscan / PE / bash tables resolve.
- [ ] The probe smoke passes on the random blob and on the sparse 8 GiB file within `RLIMIT_AS`.
- [ ] No plugin outside the allow-list can be run, and no `dump` option is ever set.
- [ ] Every hostile-output case ends as a skipped row, a plugin engine error or `invalid` output, never a crash of the root process.
- [ ] A missing symbol produces the diagnostic stream with the correct requirement (tested with the synthetic image from phase 4 after the merge, and with a fixture identify output before it).
- [ ] Compressed and archived files are refused by root before any probe runs.

## Risk Assessment
- **Library-mode API drift:** Volatility's internal API is less stable than the CLI. The pin, the phase notes and one adapter module (`probe/vol.py`) contain it.
- **Repeated layer stacking cost:** only the probe smoke's sparse-file scan time is measured (no real large image is used); if it projects `triage` beyond the job timeout for an 8 GiB image, the parent decides between grouping plugins per process and raising the timeout (recorded).
- **Windows never executed in CI** (RT4): the column-drift test, the row fixtures and the replay engine are the guards; the docs state it.
- **TreeGrid memory:** stopping the grid at the cap bounds rows, but Volatility may still build large internal structures; `RLIMIT_AS` and the plugin timeout are the backstop.

## Implementation notes (as built, untested in Docker)

Code-only commit `feat(memory): Volatility runner, normalizers, replay engine (M8 phase 2, untested in Docker)`. Host checks that passed (Python 3.14, Windows, no Volatility installed): `pytest --noconftest tests/unit` minus `test_skeleton.py` (celery) — 577 passed, the sandbox / Volatility tests skip; `test_plugin_columns.py` run once with the 2.28.2 wheel *source* on `PYTHONPATH` (AST only, never imported): every allow-listed plugin's `TreeGrid` columns and every fixed option name match; `ruff check` / `ruff format` on the phase-2 files. `mypy` not run.

**2.28.2 API findings (read from the wheel source):**
- `volatility3.symbols.__path__` *is* `constants.SYMBOL_BASEPATHS`; `[0..1]` = `volatility3/symbols`, `volatility3/framework/symbols`, `[2]` = `<CACHE_PATH>/symbols` (dropped). `CACHE_PATH` = `$XDG_CACHE_HOME/volatility3`, created (`os.makedirs`) at import of `framework.constants`.
- `cli` only sets `constants.OFFLINE`; `resources.OfflineHandler.default_open` raises `OfflineException` for http(s) when set; `ResourceAccessor.open` goes through `urllib.request.urlopen` for **every** location, so the audit hook must allow `file:` / `jar:file:` `urllib.Request` events.
- `plugins.construct_plugin(ctx, automagics, plugin, base, progress, open_method)`; config keys are `plugins.<Class>.<requirement name>` with names verbatim (`dump-regions`, `decorate_comm`, `files_only`, `include-corrupt`, `hexdump-size`).
- `TreeGrid.populate(visitor, acc, fail_on_errors=True)` re-raises the visitor's exception (row cap).
- `pdbutil.PdbSignatureScanner(names)` yields `(GUID upper hex, age, name bytes, offset)`; the Linux banner regex is `plugins/banners.py`'s; `LayerStacker.stack_layer(ctx, layer, stackers)` returns names highest first. The Linux stackers need banners from the cache (symbols), the Windows page-table stacker does not.
- `windows.pslist` / `psscan` default to virtual offsets (`Offset(V)`); `windows.info` reports `Symbols` (ISF URL), `NTBuildLab`, `Major/Minor`, `SystemTime`; `linux.malware.check_syscall` lists every table entry (`UNKNOWN` when unresolved); `windows.registry.userassist` is a tree (Key / Subkey / Value rows); `ModuleDisplayPlugin.columns_results` (hidden_modules) lives in `symbols/linux/utilities/modules.py`.
- No layer `mmap`s the image (`FileLayer` reads through the resource accessor); confirm with the sparse-file smoke.

**Design (deviations / additions):**
- One process per step: `identify`, then one probe per plugin (`python -I -s -B -m memory_worker.probe`); stdout = `rows.jsonl` (root-created), `status.json` written by the probe. Each out dir is **sealed** after its run (chowned to root): a later probe (same uid) cannot alter an earlier plugin's rows.
- Pure modules (host-testable): `identify.py` (OS choice, `ACCEPTED_LAYERS` → QEMU / Xen = `unsupported_memory_format`), `normalize/` (reader, row models, Windows / Linux), `result.py` (header, view, writer), `probe/{plugins,guard,encode}.py`, `engines/magic.py`. Sandbox-bound: `analyzer.py`, `engines/{workspace,volatility,replay}.py`.
- Diagnostic: `analyzer.DiagnosticResult(JobFailed)` carries the written stream; the pipeline uploads it and reports `failed / symbols_missing` with the version id.
- `os_undetermined` / identify refusals are `JobFailed` (no stream; the reason is logged).
- Replay scenario = the evidence file's marker line `CYBERLAB-REPLAY <scenario>` (tests/fixtures/vol_rows/{windows,linux}); `<plugin>.status.json` overrides (`_end`: failed / timeout). `celery_app.py` exits **78** on a refused config (only edit there).
- Free-space headroom 1 GiB; **16 MiB under `TEST_PROFILE=1`** (the 512 MiB test tmpfs could never hold size + 1 GiB).
- A failed or timed-out plugin keeps its rows, flagged `truncated` (partial, never "complete"); a status that is not provably offline drops the rows (`probe_offline_unverified`).
- Linux banner normalization uses phase 5's `normalize_banner` (store / probe agree).
- Processes merge by (pid, offset, create time), then a psscan-only twin with the same (pid, create time) merges into the single pslist entry. The first `dlllist` module of a pid becomes `image_path` and is not repeated as a `module` artifact (this reproduces the phase-1 fixture counts).
- Address attributes: int while ≤ 2**63-1, else `0x…` text (kernel addresses; the jsonb bigint check).

**Attribute keys emitted** (phase 3 reads the bold ones): `service` {**name**, **state**, **binary**, **type**, start, display, dll, order}; `ldr_unlinked` {**in_load**, **in_init**, **in_mem**, **path**, **base**} (only rows missing from ≥ 1 list); `bash` {**command**, **time**}; `module` {name, path, base, size, load_count, load_time}; `hive` {path, offset}; `userassist` {hive, path, key, count, focus_count, time_focused, last_updated}; `open_file` {fd, path, type, inode, mode, size, device}; `syscall_hook` {table, index, handler, table_address} (UNKNOWN handlers only); `hidden_module` {name, offset, code_size, taints, args}. Engine errors: `<plugin_key>_{failed,timeout,rows_skipped,unknown_columns}`, `probe_offline_unverified`, `isf_unreported`, `isf_mismatch`.

**Phase-1 test fixed:** `tests/unit/test_skeleton.py` — `test_detections_stub_and_view_types` asserted an empty `DetectionOutput`; with phase 3 an image-only view yields one `system_time` timeline event (now `test_detections_on_an_image_only_view`); the `not_implemented` test became three pipeline tests (failure, diagnostic upload, success).

**Remains to run (Docker, lane 2, `memory-worker-test`):**
1. `ruff check . && ruff format --check . && mypy memory_worker tests`.
2. `pytest -q tests/unit` — in particular `test_runner.py` (replay end to end, sealing, hostile rows files, sandbox arguments), `test_offline.py`, `test_symbol_paths.py`, `test_plugin_columns.py` against the installed wheel, `test_skeleton.py`.
3. `pytest -q -s tests/engine` (random 16 MiB blob: real probe, offline, zero audit events, `unsupported` pslist); then `--heavy` with `MEMORY_PROBE_HEAVY=1` (sparse 8 GiB: identify duration = baseline scan time, peak child RSS < `RLIMIT_AS`). Record the timings here.
4. Confirm in the image: `ctypes.util.find_library` / imports trigger no audit event after `prepare_imports`; `RefusingFileHandler` satisfies `set_open_method`; `ctx.config` iteration yields the `.isf_url` keys (else `isf_unreported` appears in every header); the probe's `RLIMIT_NOFILE` 512 suffices.
5. Isolation tests of the plan (inet / netlink / vsock / io_uring from the probe, writes outside the out dir, HOME unreadable, no process left after a timeout) are not written yet beyond the kit's own suite: add them to `tests/test_isolation.py` when the image builds.

**First Docker run (2026-11-06):** ruff / format / mypy green after fixes (a reused loop variable in `normalize/linux.py`, test typing); `pytest` 681 passed, 1 skipped (the heavy sparse case, `MEMORY_PROBE_HEAVY=1`, not run: host RAM); probe smoke: identify on the 16 MiB random blob 2.0 s, offline, no audit event. `volatility3.__version__` does not exist in 2.28.2 (use `importlib.metadata.version`); importing `volatility3.framework` creates `$XDG_CACHE_HOME/volatility3`, so never import it in the worker process.
