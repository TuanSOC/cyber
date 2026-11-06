---
phase: 2
title: "TSK probe image volumes filesystems and file walk"
status: pending
priority: P2
effort: "25h"
dependencies: [1, 4]
---

# Phase 2: TSK probe: image, volumes, file systems and file walk (group B, 2a, lane 2)

## Overview
The core of the disk worker:
- the root pipeline (download, magic check, stage orchestration with the shared stage runner, result assembly);
- the sandboxed **probe** that opens raw / split / EWF images through pytsk3 + pyewf and runs the stages `verify`, `layout`, `walk`, `collect`, `extract` and the `scan` shell;
- the normalizers that turn probe rows into `disk.v1` records.

Phases 3 (timeline), 5 (hash sets, YARA) and 6 (detections) plug in through the frozen entry points.

**Owns:**
- `apps/workers/disk/disk_worker/{analyzer,pipeline,stage,budget}.py` (`stage.run_stage` and the deadline budget are used by phases 3, 5 and 10);
- `probe/**` except `probe/scan_yara.py`;
- `normalize/**` except `normalize/events.py`;
- the unit tests `tests/unit/test_{probe_*,normalize_*,walker,names,image_open,stage_isolation,watchdog,budget,pipeline,offline,audit_hook}.py`;
- the engine tests `tests/engine/test_tsk_*.py` (on phase 4's generated images).

## Requirements
- **Root pipeline** (`pipeline.py`; root never parses image bytes beyond magic):
  1. `sandbox.reset`; free-space check (plan "Resources"); `insufficient_disk` otherwise. The deadline budget (`budget.py`) starts from `msg.deadline_at` (RT5).
  2. `transfer.download` each segment (sha256 + size verified; the kit's `integrity_mismatch` on failure, RT22). No image cache (RT1): every job, re-run and export downloads.
  3. **Magic check** of segment 0: EWF (`EVF\x09\x0d\x0a\xff\x00`), or raw. Refused (`unsupported_disk_format`) before any probe: gzip, bz2, xz, zstd, zip, 7z, rar, VMDK (`KDMV`, `# Disk DescriptorFile`), VHDX (`vhdxfile`), a VHD footer (`conectix` at end − 512), QCOW (`QFI\xfb`), AFF (`AFF10`), EWF2 (`EVF2`), LEF (`LVF`; libewf's L01 parser has CVE-2026-111159). A raw image's format is `split_raw` when there is more than one segment.
  4. Split raw: the concatenated media sha256 (root, streaming).
  5. **Stages** in a fixed order (OS partitions' `walk` first), each through `stage.run_stage(argv, dirs, stage, limits, budget)`:
     - `run_tool([python, -I, -m, disk_worker.probe, <stage>, …])` with a fresh out dir (`Workspace.engine()` pattern; never `sandbox.prepare`, which resets `/work`, the M8 RT26 lesson), a root-owned read-only `cwd`, `unix_sockets_only=True`, `deny_io_uring=True`, the plan's per-stage rlimits plus RLIMIT_NPROC 64, and timeout = `budget.timeout(stage)` (min of the stage cap and the time left − 900 s; a stage that cannot fit is `skipped` / `deadline`);
     - **watchdog** (RT4): a root thread polls `statvfs(/work)` every 2 s; bytes written since the stage started above the stage's write budget, free bytes below `DISK_WORK_MIN_FREE_BYTES` or free inodes below 100 000 kill the stage's process group (`truncated`; `insufficient_disk` for the job when the floor is hit before any `walk` succeeded);
     - **after the stage** (RT3): `sandbox.kill_tool_processes()` (fail closed: `SandboxCompromised` stops the container), then the out dir is chowned to root and made read-only (directories 0555, files 0444) with `os.fchownat` / `fchmodat` on `O_NOFOLLOW` descriptors (a symlink planted by the tool is removed, never followed); later stages only read it.
  6. Assembly: the normalized records, phase 5's hash-set matches, phase 3's timeline output, phase 6's detections → `disk.v1` through the kit's result writer → presigned POST → `finished`.
- **Probe** (`python -I -m disk_worker.probe`):
  - **Hardening:** a PEP 578 audit hook installed after imports, refusing and counting `socket.*`, `urllib.Request`, `subprocess.Popen`, `os.exec*`, `os.system`, `os.spawn*`, `ctypes.dlopen` of anything outside the venv (the counts go into `status.json`). Arguments come from a root-written JSON in `input/` (never from argv strings built from image data).
  - **Image openers** (`probe/image.py`):
    - raw: `pytsk3.Img_Info(path)`;
    - split raw: an `Img_Info` subclass concatenating the segment files with bounds-checked reads;
    - EWF: `pyewf.handle().open(pyewf.glob(input/image.E01))` wrapped in an `Img_Info` subclass. libewf checks each segment's stored number against its position, so a reordered, foreign or missing segment, or a lying segment count → `unsupported_disk_format` with the libewf error class. Never pass a path from the image to `glob`. A claimed media size above `DISK_MAX_MEDIA_BYTES` → `unsupported_disk_format` (reason `media_size`; RT6).
  - **`verify`** (EWF only):
    - read the whole media in 4 MiB chunks, computing MD5 and SHA-1, within `budget.timeout("verify")`; a timeout gives `not_verified`, not a failure (RT6);
    - compare them with the **stored** values `handle.get_hash_value("MD5")` / `("SHA1")` (pyewf has no `get_hash_value_md5`; RT16); status `matched` / `mismatch` / `absent` / `not_verified`. libewf zero-fills or passes through a chunk with a bad Adler-32 without failing the read, so `absent` means content corruption cannot be detected (stated in the summary; RT17);
    - emit `media_size`, `sector_size`, and the header values (case number, description, examiner, evidence number, notes, acquiry date, acquiry software, all bounded and NUL-free) → `ewf_meta`.
    - A mismatch makes root emit `integrity:ewf_media_hash@1` (medium, verdict-free wording: "stored media hash does not match the content").
  - **`layout`:**
    - `Volume_Info(img, type, offset)` (type before offset; RT16) with `TSK_VS_TYPE_DOS`, then `TSK_VS_TYPE_GPT`. Neither → one pseudo-partition at offset 0.
    - Per allocated partition (RT15):
      - **first** the refusal signatures: `-FVE-FS-` (BitLocker), `LUKS\xba\xbe`, APFS `NXSB`, LVM `LABELONE`, HFS+ `H+` / `HX`, ISO `CD001` → `encrypted` / `unsupported`, never offered to any parser;
      - then `FS_Info(img, offset=…, type=…)` with the families NTFS (`TSK_FS_TYPE_NTFS`), FAT incl. exFAT (`TSK_FS_TYPE_FAT_DETECT`: FATxx then exFAT), ext (`TSK_FS_TYPE_EXT_DETECT`); the family named by the MBR type byte (0x07 NTFS / exFAT, 0x0b / 0x0c / 0x0e FAT, 0x83 Linux) or GPT type GUID goes first, then the fixed order. The red team read in TSK source that a non-DETECT or family-DETECT type reaches only that family's opener; phase 2 re-checks the pytsk3 20260715 keyword names;
      - nothing opens → `undetermined` ("unknown or encrypted"; no entropy guess).
    - Partitions overlapping or beyond the media are reported as `error` and never opened.
    - OS markers: Windows = `Windows/System32/config/SYSTEM` exists; Linux = `etc/os-release` or `etc/debian_version` exists. `os_name` is read only from `etc/os-release` `PRETTY_NAME` (≤ 4 KiB read, inert text).
  - **`walk --fs i`:**
    - an iterative directory walk (no recursion; TSK's own loop guard lives only in `tsk_fs_dir_walk`, so ours is the visited set) with a visited set of (meta_addr, seq) for directories, depth ≤ 64, ≤ 200 000 entries per directory, the files cap. TSK opens a whole directory before we see an entry and, on the first NTFS listing, walks the entire MFT to build a parent map: RLIMIT_AS (2 GiB) is the real bound; a `MemoryError` or TSK allocation error is a partition `error` (`walk_memory`), and the job still posts the layout (diagnostic stream when no other walk succeeded; RT30). Phase 2 records RSS against MFT entry count on a generated sparse NTFS;
    - **every name** of an entry: each directory entry is its own record (`parent_addr` = the walked directory's `meta_addr`), so an inode with several names (NTFS or ext hard links) appears once per name with `hard_linked` set; root groups names by (partition, `meta_addr`) for the never-collected check (RT7);
    - deleted names (`TSK_FS_NAME_FLAG_UNALLOC`), orphans (`$OrphanFiles`), reallocated entries flagged;
    - NTFS named `$DATA` streams listed as their own records (≤ 16 per file; `Zone.Identifier` included);
    - `.` / `..` skipped; symlink targets never followed.
    - Per entry: metadata (size, mode, uid, gid, the four times with nanoseconds where TSK has them; FAT times marked `local_unknown`), the magic class from the first 512 bytes (allocated regular files and streams only), hashes (md5, sha1, sha256 in one pass) for files selected by the profile's hashing rule within the byte budget (executables and scripts first, then path order). `hash_status` ∈ `hashed`, `skipped_size`, `skipped_budget`, `skipped_deleted`, `not_regular`, `error`.
    - Names: TSK bytes decoded as UTF-8 with replacement (`name_lossy` set), control characters escaped as `\xNN`, so paths are printable and single-line. A path longer than 4 096 bytes is cut on a UTF-8 boundary with `path_truncated` set (64 levels of 255-character names reach about 49 KB; such rows are valid, never "bad rows"; RT13).
    - Rows are written as JSONL with a byte cap; the walker stops at the cap and records `truncated`.
  - **`collect --fs i`:**
    - input: phase 3's `CollectPlan` (natural keys + target relative paths, chosen by root from the walk listing after `never_collect()` over **all names** of each inode; RT7);
    - copies each file's content (allocated only; the plan's per-file and total byte caps) into `out/artifacts/p<i>/<sanitized relative path>`;
    - **sanitization:** components from a fixed canonical-case table for known directories (`Windows/System32/config`, `Users/<name>/…`), every other component reduced to `[A-Za-z0-9 ._-]` with each replaced run turned into `_` plus a 6-hex suffix of the original component's sha256 (so `José` and `Jos?` stay distinct; RT31), max 255 bytes, with a collision suffix; results that are empty or made only of dots refused; the original path always comes back through `collected.jsonl`;
    - files only (no symlinks, no devices), created with `O_CREAT | O_EXCL | O_NOFOLLOW` under the out dir, with a manifest `collected.jsonl` (target path → natural key, original path).
  - **`scan`** (the stage shell): loads phase 5's `probe/scan_yara.py`, reads candidate contents through the same openers and passes bytes to it; the output is bounded JSONL.
  - **`extract`** (used by phase 10): a single allocated regular file or named stream by natural key, with `meta_seq` re-checked (a reallocated entry → `disk_export_not_allowed`) and `size ≤ expected_size ≤ 64 MiB`, written to `out/export/<n>` with the sha256 computed in the probe.
- **Normalizers** (`normalize/`, root): the per-stage row models (pydantic, `extra="forbid"`, bounded) → `DiskPartitionRecord` / `DiskFileRecord`. Every probe row is re-validated; a bad row increments `engine_errors` and is dropped, and a stage with more than 1 % bad rows is marked `failed`. The probe's own counts are never trusted for caps.
- **Offline proof:** the probe imports nothing that opens sockets; the audit hook counts are zero in every stage of the engine tests (`test_offline.py`); seccomp refuses AF_INET in a negative test (`socket.socket()` inside the probe fails).
- **Stage isolation tests** (`test_stage_isolation.py`, `test_watchdog.py`, `test_budget.py`; RT3 / RT4 / RT5): a fake stage that `setsid`-forks a sleeper is killed after the stage and the next stage sees no tool process; a write into a sealed earlier out dir fails with `EACCES`; a stage writing past its write budget is killed and `truncated`; a budget with 20 min left gives `skipped` / `deadline` to a stage whose cap cannot fit.
- **Engine tests** (`--heavy`, on phase 4's generated images, in the test tmpfs): every image type gives the `ground_truth.json` partitions, files (names, flags, sizes, times, ADS, hard links), hashes and OS markers exactly; the E01 set gives `matched`, and the mutated stored hash gives `mismatch`; a GPT with an unsupported partition (an HFS+ signature) shows `unsupported` without any parser opening it; the hard link to `etc/shadow` is never collected.

## Implementation Steps
1. Read the M8 probe / pipeline (the closest pattern), the kit's sandbox / transfer / result writer, phase 4's generator output and ground truth.
2. Image openers and `layout` against the generated MBR / GPT / no-table images.
3. `walk` with names, streams, times, magic, hashing budget; `test_walker.py` with cycles and huge directories (generated by phase 4's hostile mode).
4. `verify` for EWF; `collect` with the sanitizer (`test_names.py`: `..`, `/`, NUL, RTLO, case collisions, 300-byte names, non-ASCII user folders, all-dot names); `extract`; the `scan` shell.
5. `stage.py` (runner, watchdog, post-stage kill and sealing) and `budget.py`; root pipeline, magic check, assembly with the phase-3 / 5 / 6 stubs; `test_pipeline.py` with the stubs.
6. Lane 2: unit tests with one slot, engine tests with `--heavy`; `ruff`, `mypy`.

## Success Criteria
- [ ] Every generated image type matches its ground truth (partitions, files, flags, streams, hashes, OS) in the real engine.
- [ ] No probe can write outside its out dir, follow a symlink or read another job's input; the audit hook counts are zero; seccomp refuses inet sockets.
- [ ] Unsupported formats are refused by root before any probe runs; unsupported and encrypted partitions are reported and never opened.
- [ ] Caps and budgets stop the walker deterministically with `truncated`; a directory cycle and a 300 000-entry directory end within the timeout and RSS limit.
- [ ] No tool process survives a stage, no stage can change an earlier stage's output, the watchdog stops a stage at its write budget or the free-space floor, and the deadline budget never lets the stage sum pass the job deadline.
- [ ] A path over 4 096 bytes is truncated and flagged, never a bad row; every name of a hard-linked inode is listed.

## Risk Assessment
- **pytsk3 type constants:** the "explicit family" assumption is verified in source; if a family constant probes widely, the probe instead checks the family's own boot-sector / superblock signature first and only then opens it.
- **libtsk defects on hostile data:** contained by the per-stage process, limits and caps; a crash is a stage `failed`, never a job crash.
- **Hashing time on large images:** budgets bound it; `full` on a 16 GiB image may approach the job timeout (phase 13 measures); the deadline budget turns an overrun into `skipped`, not a reaper kill.
- **Sealing cost:** chown / chmod of a collected tree of up to 20 000 files after `collect` takes seconds; measured.

## As built (untested in Docker)

Code-only commit `feat(disk): TSK probe stages (M9 phase 2, untested in Docker)`. Host-only checks: ruff, mypy (strict, `--platform linux`) on every phase-2 module, and the pure unit tests (`test_names`, `test_probe_magic`, `test_budget`, `test_watchdog`, `test_walker`, `test_normalize_records`, `test_audit_hook`, `test_probe_layout`, `test_image_open` pure parts); `test_pipeline` passed on the host only through a throwaway shim (kit `resource` / seccomp / `O_NOFOLLOW`). Nothing ran with pytsk3 / pyewf.

**Seams for the other phases:**
- `stage.fresh(dirs, name) -> JobDirs` (fresh tool-owned `<job>/<name>-out`), then `stage.run_stage(argv, stage_dirs, key, limits, budget)`; `StageResult` gained `rows`, `counts`, `facts`, `has_status`, `usable` (defaults keep the frozen constructor). `status.json` is read as `normalize.models.StageStatusDoc` (`status`, `error`, `error_code`, `reason` (snake_case), `rows`, `truncated`, `counts`, `facts`, `audit`).
- Phase 3: `collect` runs per OS partition (≤ `max_plaso_partitions`, largest first) from `catalog.match(files_of_partition, os, profile)`, after `NameIndex.refused()` over every name of each inode (RT7; a truncated path is refused too). The sealed tree is `stage.collect_out(dirs, i).out / "artifacts" / f"p{i}"`, the manifest `collected.jsonl` beside it (`normalize.models.CollectedRow`: `n`, `status`, `target` relative to the tree, `meta_addr`, `meta_seq`, `stream`, `path` (original), `artifact`, `size`). Root does NOT drop compressed / archive magic (RT11): `catalog.match` should (it sees `magic`). Events are read through `disk_worker.normalize.events.iter_events(path, limits)` (pass 1) and `select_events(path, limits, cited)` (pass 2), looked up with `importlib` (absent → no events, `events_unavailable`).
- Phase 5: `scan.select_candidates` → `scan.check_rules` (tampered → stage `failed`, `rules_tampered`) → `scan` stage (`probe/scan_stage.py` calls `scan_yara.scan(rule_dirs, items, emit, deadline)`, output `hits.jsonl`) → `scan.parse_scan_report` → `scan.resolve_hits`. `yara_rules` stores `<namespace>.<rule>` (phase 6's format; phase 5's `rules_by_file` stores the rule alone and is not used), and the rule → severity map goes to `detections.run(view, limits, yara_severity=…)`. Hash sets: `HashSetStore.status` / `.refs()` / `.annotate()`; invalid → `hashsets_invalid` in `engine_errors`.
- Phase 10: probe `extract` (args `offset`, `family`, `meta_addr`, `meta_seq`, `stream`, `expected_size`, `n`; output `export/<n>`, facts `size` / `sha256`; refusal → `error_code` `disk_export_not_allowed`).

**Deviations (parent to confirm):**
- Stage order is `layout` → `verify` (not verify → layout): `verify`'s budget scales with the media size, which only `layout` learns for EWF. `layout` also reports the EWF stored hashes and header values, so a skipped / killed `verify` still gives `not_verified` (the contract's `EwfInfo` forbids `not_verified` without a stored hash).
- Volume systems are tried GPT first, then DOS (a GPT disk's protective MBR parses as one DOS partition of type 0xEE). Only allocated partitions are listed.
- Raw and split raw are also handed to TSK as `TSK_IMG_TYPE_EXTERNAL` images over our own bounds-checked reader (TSK never opens a path, so its image back ends are never probed).
- The walker's visited set is keyed on the directory meta_addr alone (stricter than (addr, seq)); deleted directories are not entered; TSK's virtual FAT files (`$MBR`, `$FAT1`, `$FAT2`) and the `$OrphanFiles` directory itself are not listed (orphans are, with `orphan`).
- Hashing: executables / scripts (and empty files) during the walk, the rest afterwards in walk order (not path order) while the budget lasts (`hashes.jsonl`). `hard_linked` comes from nlink on ext and from root's name grouping on every file system (NTFS link counts include 8.3 names).
- `insufficient_disk` before any walk succeeded is raised from any stage whose watchdog hit the floor; after that it only truncates the stage.
- `tests/unit/test_skeleton.py`: the phase-1 `not_implemented` disk-job assertion now accepts the real early failures (`insufficient_disk` / `evidence_unavailable`).
- New root modules beside the owned ones: `formats.py` (magic check, segment names), `watchdog.py`, `result.py` (facts, header, streams).

**Remains to run (Docker):** the disk worker unit suite in `disk-worker-test` (`test_stage_isolation`, `test_offline`, `test_pipeline`, `test_image_open`, the kit isolation tests); `tests/engine/test_tsk_images.py` with `DISK_ENGINE_IMAGES` on phase 4's images (`--heavy`; the ground-truth fields it reads are listed in its docstring), plus the RSS-vs-MFT measurement (RT30) and the sealing cost; verify the pytsk3 20260715 names used (`TSK_IMG_TYPE_EXTERNAL`, `TSK_FS_TYPE_*_DETECT`, `TSK_FS_ATTR_TYPE_NTFS_DATA`, `TSK_VS_PART_FLAG_ALLOC`, `read_random(offset, len, type, id)`, `info.name.meta_seq`) and pyewf (`glob`, `read_buffer_at_offset`, `get_hash_value`, `get_header_value`, `get_bytes_per_sector`); ruff / mypy in the image.
