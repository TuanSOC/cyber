---
phase: 6
title: "Disk detections and scenario dataset"
status: pending
priority: P2
effort: "15h"
dependencies: [1]
---

# Phase 6: Disk detections and scenario dataset (group B, 2d, lane 5)

## Overview
Deterministic, verdict-free triage heuristics over the normalized disk view (partitions, files, Plaso events, YARA hits, hash-set matches), plus a generated scenario dataset that gives the §14 precision / recall table with the M2 / M3 / M8 caveat (synthetic, built alongside the detectors). Pure Python over the frozen phase-1 records: no image, no TSK, no Plaso at test time.

**Owns:**
- `apps/workers/disk/disk_worker/detections/**` (the phase-1 stub `run(view: DiskView, limits: DiskLimits) -> DetectionOutput`, one module per rule, `paths.py` with the path-class tables, `evtx_fields.py` with the positional `strings` maps);
- `apps/workers/disk/dataset/**` (`generate.py`, `evaluate.py`, the labelled scenarios);
- `tests/unit/test_detections_*.py`, `test_dataset_quality.py`, `test_finding_wording.py`, `test_path_classes.py`, `test_evtx_fields.py`.

It uses (never edits) `cyberlab_worker.mask` (lifted in phase 1 from the M8 masker) and `cyberlab_worker.iocs`.

## Requirements
- **Input:** `DiskView` (phase 1, frozen): partitions, file records (path, name, stream, type, flags, size, times, `time_basis`, magic class, hash status / hashes, `known`, `yara_rules`), event records (`artifact`, `data_type`, `ts`, the allow-listed scalar `attributes`), the OS detected per partition. The view is streamed for events: rules that need events implement `observe(event)` + `finish()`, so detection runs over **every** event the normalizer read, not only the stored subset (plan "Timeline storage").
- **Rules** (method ids frozen in plan "Detections"; `heuristic:*` caps at `medium`):

  | Method | Fires on | Severity |
  |---|---|---|
  | `heuristic:disk_exec_user_writable@1` | PE / ELF magic in a user-writable path class (`Users\*\AppData\Local\Temp`, `Downloads`, `Users\Public`, `ProgramData\` root, `Windows\Temp`, `$Recycle.Bin`; `/tmp`, `/var/tmp`, `/dev/shm`, hidden dirs under `/home/*`) | low |
  | `heuristic:disk_double_extension@1` | `name.<doc ext>.<exec ext>` and RTLO (U+202E) in names | medium |
  | `heuristic:disk_extension_mismatch@1` | PE / ELF magic under a non-executable extension (`.jpg`, `.txt`, `.dat`…) | medium |
  | `heuristic:disk_ads_executable@1` | an NTFS named stream with PE magic (`Zone.Identifier` is never one) | medium |
  | `heuristic:disk_persistence@1` | Run / RunOnce values, services (`ImagePath`) and Startup-folder entries pointing into a user-writable class; a scheduled-task file under `Windows/System32/Tasks` created or modified inside the analysed window (listing only: the XML is never parsed; RT28); Linux cron entries, systemd units, `rc.local`, `/etc/ld.so.preload` present, `authorized_keys` modified inside the analysed window | medium (low when the target is outside the user-writable classes) |
  | `heuristic:disk_log_cleared@1` | EVTX Security 1102, System 104; a zero-length or truncated `auth.log` / `wtmp` next to rotated siblings | medium |
  | `heuristic:disk_service_installed@1` | EVTX 7045 (medium when the image path is user-writable, else low) | low / medium |
  | `heuristic:disk_account_change@1` | EVTX 4720 / 4722 / 4732 / 4728; `useradd` / `usermod -aG sudo` in auth logs | low |
  | `heuristic:disk_remote_logon@1` | EVTX 4624 logon types 3 / 10 from a non-loopback address; `sshd Accepted …`; bursts of 4625 / `Failed password` (≥ 20 in 10 min from one source) | low / medium |
  | `heuristic:disk_dual_use_execution@1` | execution evidence (Prefetch, UserAssist, BAM, shell history, 4688 when present) of a fixed dual-use list (`psexec`, `procdump`, `rclone`, `wevtutil cl`, `vssadmin delete shadows`, `certutil -urlcache`, `powershell -enc`, `curl … \| sh`, `nc -e`) | low / medium |
  | `heuristic:disk_correlated_indicators@1` | ≥ 2 distinct heuristics on the same file path or within 10 min on the same host | medium |
  | `signature:yara@1` | each YARA hit (phase 5), severity from the M3 sha256-keyed allow-list | per rule |
  | `known_file:hashset@1` | a `known_bad` / `notable` hash-set match (phase 5); operator lists are unverified, so ≤ `medium` | medium |

  `known_good` matches are never findings: they only set `known = good`, which the UI hides by default (phase 11). `known` never suppresses any heuristic above (a known file in a user-writable path still fires; RT18). `heuristic:disk_timestamp_anomaly@1` is cut (RT28; "Later").
- **EVTX fields:** event-specific values are read from Plaso's positional `strings` through fixed per-(provider, event id) index tables (`evtx_fields.py`, e.g. 4624 → `TargetUserName`, `LogonType`, `IpAddress`), never by parsing `xml_string` (attacker-controlled XML in the trusted root process). An unknown layout (wrong length) skips the rule for that event and is counted.
- **Path classes** (`paths.py`): case-insensitive on NTFS / FAT, case-sensitive on ext; normalised separators; `%SystemRoot%`-style variables expanded only from a fixed table. Clean-system exclusions are a constant list (Windows Defender platform dir, OneDrive / Teams per-user installs, `Windows\Installer`, package caches), tested with benign baselines (the M8 RT21 lesson).
- **Wording and masking:** titles and descriptions follow the M8 wording rules (no verdict words: "malicious", "infected", "compromised"…; "executable in a user-writable location", not "malware"). Every text quoted from shell history, registry values, service paths, command lines or URLs into findings, IOC context and timeline titles passes `cyberlab_worker.mask` (secrets keep 2 chars + length; URL query values masked); the raw text stays only in `disk_events` / `disk_files` (plan "Sensitivity").
- **IOCs** (`cyberlab_worker.iocs`): sha256 / sha1 / md5 of every file referenced by a finding; source IPs of remote-logon findings; URLs / domains / IPs quoted in findings' command lines. No IOC from the unflagged file listing or browser history (thousands of benign rows; plan "Correlation").
- **Evidence refs:** each finding references its records by natural key (`partition_index`, `meta_addr`, `seq`, `stream`) or event ordinal; `finish()` returns the cited ordinals so phase 3's second pass stores every cited event (RT10); phase 7 resolves them to row ids at ingest.
- **Caps:** findings 5 000, IOCs 20 000, shared timeline 5 000 (finding-linked events first, then by severity); every cap hit sets `truncated`.
- **Scenario dataset** (`dataset/generate.py`, seeded, deterministic): `DiskView`s for clean Windows 10 / 11-shaped and Debian-shaped systems (file trees of a few thousand paths with realistic install paths, events of a quiet week) and labelled positives per rule (≥ 10 each, including the hard negatives: Defender updates, OneDrive, `Zone.Identifier` streams, FAT 2-second times, a legitimate service install by an installer path, `sudo` usage). `evaluate.py` prints precision / recall per method and overall (the table phase 13 copies). Every scenario is labelled synthetic in its header.

## Implementation Steps
1. Read the M3 / M8 detection modules, `cyberlab_worker.mask`, `cyberlab_worker.iocs`, the frozen `DiskView` and the phase-1 event fixtures.
2. `paths.py`, `evtx_fields.py` with table tests.
3. File rules, then streaming event rules, then correlation; evidence refs and caps.
4. Wording / masking tests over every rule's output (`test_finding_wording.py`).
5. Dataset generator and evaluator; `test_dataset_quality.py` (each rule has ≥ 10 positives and hard negatives; no duplicate scenario ids).
6. Lane 5: `scripts/lane-test.sh 5 --service disk-worker-test uv run pytest -q -p no:cacheprovider tests/unit/test_detections_* …`, `ruff`, `mypy`.

## Success Criteria
- [ ] Every rule fires on its positives and stays silent on the benign baselines and hard negatives; the precision / recall table is produced by `evaluate.py`.
- [ ] No `heuristic:*` finding exceeds `medium`; no verdict word in any title or description; secrets in quoted text are masked.
- [ ] Event rules run in a single streaming pass with bounded memory (a 2 M-event synthetic stream stays under 300 MiB RSS).
- [ ] EVTX rules never read `xml_string`; unknown layouts are skipped and counted.

## Risk Assessment
- **Noise on real systems:** clean-system exclusions are a maintained constant; severities stay low / medium; the dataset is synthetic (stated in TESTING and the metric report).
- **EVTX layout drift** across Windows versions: index tables are keyed by provider + event id + string count; a mismatch skips, never guesses.
- **Masking misses** a secret format: masker shared with M8, extended only through its own tests.
