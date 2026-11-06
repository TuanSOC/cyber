---
phase: 3
title: "Plaso artifact timeline engine"
status: completed (code)
priority: P2
effort: "25h"
dependencies: [1, 4]
---

# Phase 3: Plaso artifact timeline engine (3a spike: A′; 3b: group B, 2b, lane 3)

## Overview
The timeline stage:
- the **artifact catalog** (which files to collect per OS and profile, and which are never collected);
- the collect plan built from the walk listing;
- the sandboxed Plaso runs (`log2timeline --single_process` on the read-only mirrored tree, then the event export: `psort -o json_line`, or our single-process storage reader when psort starts processes under the filter);
- the two-pass event normalizer (detections over every event, then storage selection with per-category quotas and every cited event; RT10);
- a test-profile-only **replay engine** feeding psort-shaped rows.

Plaso never sees the raw image (plan "Engines").

**3a: packaging spike (6 h, time-boxed, A′, parallel with phase 1).** In worktree `..\cyber-wt\m9-plaso`, in one-off unprivileged `python:3.12-slim-trixie` containers (no compose service, one at a time, `--memory 2g`):
- **The install and the builder stage** (RT11; the red team found eight libyal bindings sdist-only for cp312: libevtx, libregf, libfsntfs, libfsext, libfsfat, libbde, libfsapfs, libvsgpt):
  - in a builder container with `build-essential` (+ what the build asks for), `uv pip wheel` every sdist dependency into hashed wheels; record build time, the packages and the headers needed (the phase-1 Dockerfile's builder stage copies this list);
  - `uv pip install --only-binary=:all:` of `plaso==20261027` from those wheels plus PyPI wheels into `/opt/plaso` in a clean `python:3.12-slim-trixie`; record the venv size and `log2timeline.py --version`;
  - write `apps/workers/disk/plaso.lock` with hashes (`uv pip compile --generate-hashes`).
- **Imports:** record what is imported at start-up for `log2timeline` / `psort` with our flags (`python -X importtime`). `pyzmq`, `redis` and `opensearch-py` are hard requirements and `zmq` is imported by `extraction_tool` at import time: nothing is marked removable; the audit hook and seccomp must show that no socket is opened.
- **The sandbox run:** on a tiny hand-made tree (a syslog, an auth.log, a `utmpdump -r` wtmp, a bash history, a gzip-compressed "auth.log"), run `log2timeline --single_process …` and then `psort -o json_line` under the kit's `run_tool(unix_sockets_only=True, deny_io_uring=True)` (the kit mounted into the container). Record:
  - whether any refused syscall, socket, subprocess or **process start** is attempted (an audit-hook wrapper prototype). psort always runs `OutputAndFormattingMultiProcessEngine`: if it starts a process or a zmq TCP queue, write and test the fallback `cyberlab_plaso_export` (open the storage read-only with Plaso's storage reader, sort by time, serialize each event with `plaso.output.shared_json`, same `json_line` shape, single process);
  - run time and peak RSS;
  - a `json_line` sample (committed as the shape reference for the fixtures);
  - the exact parser names (`log2timeline.py --parsers list`) for every catalog entry;
  - that every flag the plan uses exists in 20261027 under Plaso's underscore spellings (`--single_process`, `--status_view`, `--unattended`, `--hashers`, `--no_dependencies_check`, `--archives`, `--vss_stores`, `--skip_compressed_streams`, `--process_memory_limit`, `--temporary_directory`; red-team source reading, RT11); missing ones are dropped from the argv and the reason recorded;
  - that `--skip_compressed_streams` leaves the gzip "auth.log" unparsed and that without it the stream is decompressed (the bomb surface of `full`);
  - how preprocessing on a mirrored directory tree resolves the time zone (Linux `etc/localtime` / `etc/timezone`; Windows SYSTEM hive), host name and users (directory sources are preprocessed, red team), including a user folder renamed by phase 2's sanitizer (RT31).
- **The report:** go / no-go notes at the end of this file. A **blocker** (a binding that will not compile, or psort that starts processes and a storage-reader fallback that does not work) goes to the parent before phase 1 freezes the Dockerfile.

**3b: engine (19 h, group B, lane 3).**

**Owns:**
- `apps/workers/disk/disk_worker/timeline/**` (`catalog.py`, `plan.py`, `runner.py`, `replay.py`);
- `apps/workers/disk/plaso/{cyberlab_plaso_launch,cyberlab_plaso_export}.py` (installed into `/opt/plaso` by phase 1's Dockerfile: `-I` cannot see `disk_worker`; RT24);
- `disk_worker/normalize/events.py`;
- `apps/workers/disk/plaso.lock` and the builder-stage wheel list (3a);
- `tests/fixtures/psort_extra/**`;
- `tests/unit/test_{catalog,collect_plan,events_*,plaso_flags,replay}.py`;
- `tests/engine/test_plaso_*.py`.

## Requirements
- **Catalog** (`catalog.py`; categories = the frozen `DiskArtifact` enum; plan "Scope" table):
  - **Path patterns per (OS, profile):** case-insensitive for NTFS / FAT, case-sensitive for ext, `*` within one component, `**` only where listed (the `Users/*` and `home/*` profile roots, `var/log/journal/**`).
  - **Per-file byte caps** (512 MiB; `$MFT` 1 GiB in `full`).
  - **Windows triage set:** EVTX (channels below), SYSTEM / SOFTWARE, NTUSER.DAT / UsrClass.dat, **Amcache.hve** (moved from `full`, RT28), Prefetch, Recent LNK; scheduled-task files under `Windows/System32/Tasks/**` are not collected (Plaso does not parse their XML), the detections use their listing only.
  - **Windows EVTX channels:** Security, System, Application, `Microsoft-Windows-PowerShell%4Operational`, `Windows PowerShell`, `Microsoft-Windows-TaskScheduler%4Operational`, `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational`, `Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational`, `Microsoft-Windows-Windows Defender%4Operational`, `Microsoft-Windows-Sysmon%4Operational`, `Microsoft-Windows-Bits-Client%4Operational`.
  - **`preprocess` category:** SYSTEM / SOFTWARE are already collected; Linux `etc/{timezone,localtime,hostname,passwd,os-release,lsb-release}`.
  - **The never-collected list** (`cyberlab_jobs.disk.NEVER_COLLECT_PATTERNS` / `never_collect()`, frozen in phase 1; plan "never collected"), checked **after** pattern matching over **every name** of each matched inode (a hard-linked `var/log/auth.log` whose inode is also `etc/shadow` is refused; RT7), so no pattern can ever include them; a test runs every pattern against a listing that contains each never-collected class and hard-link pairs.
  - **Compressed content** (RT11): dfVFS decompresses gzip / bzip2 / xz streams by default, whatever the name, with no size cap. In `triage` the argv carries `--skip_compressed_streams`; in both profiles root drops a collected file whose magic class is compressed or archive unless its catalog entry expects it (only `full`'s rotated `.gz` / `.xz` logs, ≤ 64 MiB each compressed; bounded inside Plaso by RLIMIT_AS, `--process_memory_limit`, CPU and the stage timeout).
- **Collect plan** (`plan.py: match(files, os, profile) -> CollectPlan`, called by phase 2):
  - allocated regular files only;
  - newest-first within a category when the category's file-count share is exceeded;
  - the total byte budget;
  - the target relative path from the original path (phase 2's sanitizer decides the final name).
- **Plaso runs** (`runner.py: run_timeline(dirs, partitions, profile, limits) -> TimelineOutput`):
  - **Scope:** one run per partition with a detected OS, at most 2 in `triage` and 4 in `full` (the largest first), each within phase 2's deadline budget (`budget.timeout`; RT5): a run that cannot fit is `skipped` (`deadline`).
  - **Input:** collect's out dir, sealed root-owned read-only by phase 2's stage runner before Plaso starts (RT3).
  - **`log2timeline`:** `/opt/plaso/bin/python -I -m cyberlab_plaso_launch log2timeline --single_process --status_view none --unattended --hashers none --no_dependencies_check --archives none --vss_stores none [--skip_compressed_streams] --process_memory_limit <RLIMIT_AS − 256 MiB> --parsers <fixed list,!filestat> --temporary_directory <out>/tmp --storage_file <out>/timeline.plaso <artifacts/p<i>>` (spellings as the spike confirmed). Add `--timezone UTC` only when preprocessing found none (recorded in the header).
  - **Export:** `… cyberlab_plaso_launch psort --status_view none -o json_line -w <out>/events.jsonl <out>/timeline.plaso`, with **no `--analysis`**; or, when the spike chose the fallback, `… -m cyberlab_plaso_export <out>/timeline.plaso <out>/events.jsonl` (same shape).
  - **Flags:** fixed in code from the catalog, never from the image or the job (`test_plaso_flags.py` asserts the exact argv per (OS, profile)).
  - **`cyberlab_plaso_launch`:**
    - sets `sys.flags`-safe defaults (no user site);
    - installs the audit hook (refusing `socket.*`, `urllib.Request`, `subprocess.Popen`, `os.exec*`, `os.system`, `os.spawn*`, `multiprocessing` process start), writing counts to `status.json` at exit;
    - then calls the Plaso tool's `Main()`.
  - **Limits:** through phase 2's `stage.run_stage` (watchdog with write budgets 3 × the artifact budget / 4 GiB, post-stage kill and sealing): RLIMIT_AS 2.5 GiB / 2 GiB, FSIZE 8 GiB / 4 GiB, timeout caps 5 400 s / 1 800 s within the budget, RLIMIT_NPROC 64, `unix_sockets_only=True`, `deny_io_uring=True`.
  - **Exit:** a non-zero exit, timeout or FSIZE kill marks the stage `failed` / `timeout` / `truncated`. Whatever complete lines psort wrote are still read.
- **Event normalizer** (`normalize/events.py`, root, streaming):
  - **Reading:** `events.jsonl` line by line with a line-length cap (64 KiB; longer → dropped and counted) and the `events_read` cap.
  - **Per-`data_type` field maps:** the allow-listed scalar attributes for each data type (e.g. `windows:evtx:record` → `event_identifier`, `source_name`, `record_number`, `computer_name`, `user_sid`, `strings` (first 32, each ≤ 1 024)). Plaso `message` is truncated to 2 048 characters.
  - **`ts`:** from `timestamp` (µs since epoch, int); out-of-range → dropped and counted. `ts_desc` from `timestamp_desc`.
  - **`path`:** `filename` / `display_name` rewritten from the mirrored tree back to the original path through `collected.jsonl` (unknown → dropped and counted).
  - **`artifact`:** from the collect manifest's category.
  - **Pass 1, detections** (RT10): every normalized event is passed to phase 6's streaming `observe()`; `finish()` returns the findings with the event ordinals they cite.
  - **Pass 2, storage selection:** a second read of `events.jsonl` (sealed, on disk) keeps per category the most recent events within the `DiskLimits` quotas (a bounded heap per category) **plus every cited ordinal**, so no finding loses its evidence to eviction. Per-category `events_read` / `events_stored` go into the header.
  - **Memory:** bounded regardless of the number of events (the cited set is ≤ findings cap × refs).
- **Replay engine** (`replay.py`, `DISK_TIMELINE_ENGINE=replay`):
  - refused unless `TEST_PROFILE=1`;
  - reads psort-shaped fixture files (`tests/fixtures/psort/` from phase 1 and `psort_extra/`) in place of the Plaso runs, through the same normalizer;
  - sets `timeline_engine: replay` in the header.
- **Engine tests** (`--heavy`):
  - the real Plaso on phase 4's generated Linux tree (syslog, auth.log with `Accepted` / `Failed password` / `useradd`, wtmp, bash history, cron, dpkg): the expected events by data type and count;
  - original paths restored; the time zone from `etc/timezone`; zero audit-hook counts; a gzip "auth.log" in `triage` produces no events;
  - if phase 4 produced hivex hives, the Run key and UserAssist events from NTUSER.DAT.
  - The replay run over the Windows fixtures gives the expected normalized events.

## Implementation Steps
1. 3a spike (A′) and its notes; the lock file and parser names merged into the phase-1 branch.
2. 3b: the catalog and never-collected tests (hard-link name sets included); `plan.match` with phase 1's fixtures.
3. Runner, launcher (and the export fallback if chosen), flags test; the two-pass normalizer with field maps and quotas; the replay engine.
4. Engine tests on the generated trees (lane 3, `--heavy`), the time-zone check, the audit counts.
5. `ruff`, `mypy`.

## Success Criteria
- [ ] (3a) A reproducible `plaso.lock` and builder-stage wheel list, a recorded `json_line` sample, the parser names, the confirmed flag spellings, and a seccomp-confined extraction and export with zero refused network / process attempts (psort, or the storage-reader fallback); or a recorded blocker decided by the parent.
- [x] No pattern can select a never-collected path under any of its names; the collect plan respects every budget; compressed content is dropped unless expected. (unit tests, host)
- [ ] Plaso runs only on the sealed mirrored tree with the exact fixed argv; the audit hook records zero events in every engine test.
- [ ] The normalizer keeps memory bounded at 2 M events, restores original paths, applies the quotas and keeps every finding-cited event, including events cited by a finding raised after the quota was full.
- [x] The replay engine is refused outside the test profile and labelled inside it. (unit tests, host shim; re-run in `disk-worker-test`)

## Risk Assessment
- **Plaso imports or IPC beyond the spike's observation** (a parser that spawns a helper, psort's multi-process engine, a lazy import of a network module): the audit hook refuses and counts it, seccomp refuses inet sockets, and the stage fails visibly instead of silently degrading; the storage-reader fallback removes psort from the path.
- **Builder-stage drift:** the eight compiled bindings are pinned by hash in `plaso.lock`; a Plaso upgrade rebuilds them deliberately.
- **Preprocessing differences on a mirrored tree** (users, time zone): recorded by the spike; the header states the time zone used; the UI labels events whose source had no zone.
- **Parser drift on upgrades:** `plaso.lock` pins every dependency; a Plaso upgrade is a deliberate change with the fixtures and engine tests re-run.

## Spike notes (3a)
<!-- Filled by the 3a agent: sdist list, venv size, import-time packages, removable packages, parser names, json_line sample path, run time / RSS, time-zone behaviour, go / no-go. -->

**Not run yet** (code-only phase, no Docker). The 3a spike, in its one-off `python:3.12-slim-trixie` containers, must still establish and record here:
- **Packaging:** the builder stage's sdist list and build-time packages / headers, the compile of `plaso.lock` from `apps/workers/disk/plaso.in` (`uv pip compile --python-version 3.12 --generate-hashes plaso.in -o plaso.lock`), the `/opt/plaso` venv size, `log2timeline.py --version` = 20261027, and `import cyberlab_plaso_launch, cyberlab_plaso_export` under `-I` (`finalize_image.py`).
- **Flags** (`disk_worker/timeline/flags.py`, asserted by `test_plaso_flags.py`): that each exists in 20261027 with these spellings: `--single_process`, `--status_view none`, `--unattended`, `--hashers none`, `--no_dependencies_check`, `--archives none`, `--vss_stores none`, `--skip_compressed_streams`, `--process_memory_limit <bytes>`, `--parsers`, `--temporary_directory`, `--logfile` (added here: Plaso otherwise writes a default log into the cwd, which is the read-only collect dir), `--storage_file`, `--timezone`; psort `--status_view none --logfile … -o json_line -w …`. A missing flag is dropped in `flags.py` and its test, with the reason here.
- **Parser names** (`catalog.PARSERS`): `winevtx, winreg, prefetch, lnk` (+ `mft, recycle_bin, sqlite` in `full`); `text/syslog, text/bash_history, text/zsh_extended_history, text/dpkg, text/apt_history, utmp` (+ `systemd_journal, sqlite`); always `!filestat`. Also whether Amcache is the `winreg/amcache` plugin (covered by `winreg`) or a separate parser, and whether `text/syslog` runs the `ssh` / `cron` plugins.
- **The `json_line` shape** against the fixtures (`packages/py-jobs/tests/fixtures/psort*/`): `__container_type__`, `timestamp` (µs int), `timestamp_desc`, `data_type`, `parser`, `message`, and what `filename` / `display_name` / `pathspec.location` hold for a directory source (the full mirrored path, or a path relative to the source: the normalizer accepts both, `test_plaso_paths_relative_to_the_source_also_map`); the attribute names of every data type in `normalize.events.FIELD_MAPS` (EVTX `strings`, `event_identifier`, `source_name`; syslog `reporter` / `body`; ssh `address` / `username` / `authentication_method`; utmp `ip_address`; the `shell:zsh:history` and `apt:history:line` names). Commit the recorded sample and correct the fixtures / maps where they differ.
- **Sandbox run** of `log2timeline` then psort through `stage.run_stage` (`tests/engine/test_plaso_engine.py`, `--heavy`, root in the worker image): zero audit-hook counts (the hook is installed **before** Plaso is imported: if an import-time `socket.*` / `os.fork` event is refused, record it and decide whether `guard.install()` moves after the import), no refused syscall, run time and peak RSS; whether psort starts a process or a zmq TCP queue under the filter. If it does: implement `plaso/cyberlab_plaso_export.py` (still the phase-1 placeholder, exit 2) with Plaso's storage reader + `shared_json` in one process, switch `flags.EXPORT_TOOL` to `"export"` and re-run.
- **Compressed streams:** the gzip "auth.log.1" yields no event with `--skip_compressed_streams` (asserted by the engine test) and is decompressed without it (`full`).
- **Preprocessing on the mirrored tree:** the time zone from `etc/timezone` (the engine test expects 10:02 Europe/Berlin = 08:02 UTC), `etc/localtime` (often a symlink: never collected, only regular files are), the Windows `SYSTEM` hive, the host name, the users (including a user folder renamed by phase 2's sanitizer, RT31). `runner.has_time_zone` adds `--timezone UTC` only when no zone source was collected (reported as `timezone_assumed_utc`); adjust if Plaso already defaults to UTC.
- **Phase 4 trees:** the engine test writes its own tiny tree; an engine test over phase 4's `ext4_linux` image (walk → collect → Plaso, against its `ground_truth.json` Plaso events by data type) and the hivex NTUSER.DAT Run key / UserAssist events (if the hive stretch succeeded) remain to be written once phase 4's ground-truth format is merged.

## As built (untested in Docker)

Code-only commit `feat(disk): Plaso artifact timeline engine (M9 phase 3, untested in Docker)`. Host-only checks: the pure unit tests (`test_catalog`, `test_collect_plan`, `test_events_normalize`, `test_events_selection` incl. phase 6's detections over the replayed rows, `test_plaso_flags`), and `test_replay` / `test_timeline_runner` through a throwaway host shim (kit `resource` / seccomp / celery stubs). No ruff / mypy on the host (not installed); nothing ran with Plaso.

**Modules:** `timeline/catalog.py` (entries per (OS, profile), the parser lists, the frozen `match`), `timeline/plan.py` (`build`, `timeline_partitions`), `timeline/flags.py` (the exact argv), `timeline/runner.py` (the Plaso engine), `timeline/replay.py`, `normalize/events.py`, `plaso/cyberlab_plaso_launch.py`; `plaso.in` (the `plaso==20261027` pin that `plaso.lock` is compiled from; never in the worker's `uv.lock`); fixtures `packages/py-jobs/tests/fixtures/psort_extra/` (`windows_extra.jsonl`, `linux_extra.jsonl`, and `hostile/edge_cases.jsonl`, which is never replayed).

**Seams and deviations (parent to confirm):**
- `TimelineOutput.events_path` is a root-written **sources manifest** (`<job>/timeline-sources.json`: per run the sealed `events.jsonl`, `collected.jsonl`, root's `input/collect-p<i>.json`, the mirror root and its realpath), not a single JSONL: one run per partition, ordinals global across them. `TimelineOutput.stage_partitions` (new, defaulted) gives each stage report its partition.
- The analyzer now uses `normalize.events.EventSource` directly: pass 1 (`events()`) feeds the detections and fills the per-category heaps; `select(cited)` fixes the stored set **and** the header's `events_read` / `events_stored` before `write_result` writes the header (the module functions `iter_events` / `select_events` remain). Dropped rows → `timeline_events_dropped` in `engine_errors`; the read cap → `truncated.events`; a catalog budget cut → `truncated.collect`.
- Collect manifest rows are trusted for the target name only: the original path, natural key and category come from root's own collect arguments, matched by item number, natural key and category (a lying probe maps nothing).
- Compressed / archive content (magic `archive` or a compressed name) is dropped by the plan, except `full`'s rotated `.gz` / `.xz` logs ≤ 64 MiB. Per-category file shares (newest first by mtime) are constants in `catalog.Entry.max_files`.
- `config.timeline_engine()` (new, public) reads `DISK_TIMELINE_ENGINE` for the runner; `replay` is refused outside `TEST_PROFILE=1` by both `config` and `replay.check_allowed`.
- The launcher refuses a non-isolated interpreter and any argv outside the fixed shape (no `--analysis`, network outputs or workers; psort `-o json_line` only) before importing Plaso; its status goes to `$TMPDIR/status.json` (the stage's out dir).
- EVTX attributes follow phase 6's convention (`event_identifier`, `source_name`, `strings_count`, `strings.<i>` for 28, then `record_number`, `computer_name`, `user_sid`, `event_level` while ≤ 32); strings are shortened, never dropped, to fit the 4 KiB column.
- Pre-existing, not phase 3: `test_skeleton.test_frozen_entry_points` expects `detections.run(view, limits)`, but phase 6 added the `yara_severity` keyword.

**Remains to run (Docker):** the spike items above; `pytest tests/unit` in `disk-worker-test` (incl. `test_replay`, `test_timeline_runner`, and `test_pipeline` with the new analyzer tail); `tests/engine/test_plaso_engine.py` (`--heavy`); ruff / mypy in the image; a 2 M-event normalizer run for the memory bound (the unit test uses 20 000 events).
