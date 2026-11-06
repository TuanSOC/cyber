---
title: "CyberLab M9 Disk Forensics"
description: >-
  Disk forensics triage with The Sleuth Kit (through pytsk3 20260715, bundling TSK 4.15.0)
  and Plaso 20261027 as a fourth untrusted analyzer on the M2/M3/M8 pattern: an isolated,
  network-less worker that downloads an ordered segment set (raw, split raw or E01 through
  libewf-python), verifies every segment and the E01 stored media hash, lists volumes and
  allow-listed file systems (NTFS, FAT, exFAT, ext2/3/4; no autodetection), walks and hashes
  files within byte budgets, matches operator-imported known-file hash sets (NSRL RDSv3,
  offline), scans selected files with the M3 YARA rules, extracts a bounded set of triage
  artifacts into a mirrored tree and runs Plaso on that tree only (single-process, fixed
  parsers, json_line), each stage in its own sandboxed process; a versioned `disk.v1`
  contract; trusted ingest (a dedicated disk ingest worker) into new disk tables plus the
  shared findings, IOCs and timeline. No carving, no recovery of deleted content. Disk images
  are TLP:RED by default (M8's sensitivity table and service, extended with a `source`, not
  renamed). Analysts can export single allocated files as derived evidence (inheriting the
  restriction) for M3 static analysis. Synthetic images are generated at test time (mkfs,
  mtools, ntfs-3g as a library, sfdisk, ewfacquirestream; no privileged loop mount); no real
  disk image is ever downloaded. Autopsy is documented as an analyst-side tool.
  Red-teamed 2026-11-07 (RT1-RT41).
status: pending
priority: P2
effort: 224h
branch: "feat/m9-disk-forensics"
tags:
  - feature
  - disk-forensics
  - sleuthkit
  - plaso
  - analyzer
  - security
blockedBy: [261107-0300-cyberlab-m8-memory-forensics]
blocks: [261107-1200-cyberlab-m10-reverse-engineering]
created: "2026-11-07T12:00:00.000Z"
createdBy: "ck:plan"
source: skill
---

# CyberLab M9 Disk Forensics

## Overview

**Requirements this milestone covers** (`requirement.txt`):
- §1 and §3: "Digital Forensics & Incident Response", "Forensics: Plaso, The Sleuth Kit, Autopsy integration where appropriate" (Autopsy: analyst-side interop only, see "Autopsy").
- §4: the `disk_forensics` module, with a clear interface and a versioned job schema; "the web API must never execute untrusted files directly".
- §10: evidence hashing, chain of custody (segment sets, derived evidence), findings, IOCs, timeline.
- §11: `forensic_artifacts` (mapped: memory artifacts are `memory_artifacts` (M8); disk artifacts are `disk_files`, `disk_events` and `disk_partitions`; findings stay in `analysis_findings`).
- §12: the "Forensics" navigation item (a planned placeholder today).
- §13: secure uploads, file size limits, parser vulnerabilities, evidence integrity, data retention, archive bombs (compressed artifacts).
- §14: parsing success, analysis latency, detection precision and recall, worker failure rate, for the disk analyzer; an anonymized, controlled test dataset (generated synthetic images only).
- §16: "Do not use mock results as real analysis findings": every fixture is labelled, and the timeline replay mode is test-profile only.

**Inputs:**
- ROADMAP "Later" (disk forensics: TSK, Plaso, Autopsy);
- the coverage audit `plans/reports/requirements-coverage-261106.md` (gaps: disk forensics; Autopsy undocumented);
- the research report [`plans/reports/researcher-261107-m9-disk-forensics.md`](../reports/researcher-261107-m9-disk-forensics.md);
- the M8 plan [`261107-0300-cyberlab-m8-memory-forensics`](../261107-0300-cyberlab-m8-memory-forensics/plan.md), the structural template: an untrusted isolated analyzer, presigned URLs, a versioned contract, trusted ingest, the TLP:RED sensitivity default, offline only, synthetic data, the lanes;
- the analyzer pattern in `docs/PCAP_ANALYSIS.md` and `docs/MALWARE_ANALYSIS.md`.

**What exists today (scout, 2026-11-06, main tree):**
- **Alembic head:** `0015_m7_hold_sync` (an M7 follow-up took 0015). M8 takes head + 1 (**0016**). M9 adds **head + 1 after the M8 merge, expected `0017`**; phase 1 confirms.
- **M8 is planned, not merged:** `apps/workers/memory/` does not exist yet. M9 builds on M8's frozen interfaces (the analyzer sweep and `test_analyzer_exhaustive.py`, `memory_sensitivity`, `ReportSnapshot.omissions`, `cyberlab_worker.iocs`, `--heavy` lanes, lane 8, `os_hint`). Phase 1 re-reads the merged M8 code first; any divergence from the M8 plan is reported to the parent.
- **Analyzers:**
  - `analysis/models.py:Analyzer` (`pcap`, `static`, + `memory` from M8);
  - `analysis/service.py:auto_choice` gives every non-empty upload ≤ `STATIC_MAX_BYTES` (64 MiB) an automatic static `av` job, and PE / ELF a static `full` job;
  - M8 adds `?kind=memory` uploads that get no automatic analysis.
- **Worker kit** (`packages/py-worker-kit`):
  - `sandbox.run_tool(argv, dirs, timeout_s, rlimits, unix_sockets_only, deny_io_uring, …)`;
  - tool uid / gid from `CYBERLAB_TOOL_UID` / `GID` (pcap and static 10003, renderer 10004; M8 memory 10006, symbols 10005);
  - `transfer.download` (streamed, sha256 and size verified);
  - the result writer and bounded parsers.
- **Static worker:**
  - `rules/yara/cyberlab_baseline.yar` with a severity allow-list keyed on (rule-file sha256, rule name) in `detections/signatures.py` (`YARA_SEVERITY_ALLOWLIST`, `yara_ceilings`, `yara_severity`); `rulefiles.py` only lists and hashes the rule files (namespaces `image.<stem>` / `test.<stem>`), and `probe/yarascan.py` compiles the sources at scan time (RT8);
  - every baseline rule is anchored on `pe.*` / `uint16(0) == MZ` (file rules: they fit extracted files, unlike memory);
  - `yara-python>=4.5,<5`; Python 3.12 (`python:3.12-slim-trixie`).
- **Limits:**
  - `max_evidence_bytes` 2 GiB; M8 adds `MEMORY_MAX_BYTES` (8 GiB default, ≤ 16 GiB, Caddy `read_body 30m`);
  - `default_storage_quota_bytes` 20 GiB;
  - `static_max_bytes` 64 MiB;
  - multipart `fput_object` handles objects above 5 GiB.
- **Correlation (M7):** `correlation/indexer.py` reads `evidence_hashes`, `malware_samples` hashes and every `iocs` row into `correlation_keys` per job (capped, idempotent).
- **Web:** `lib/nav.ts` lists "Forensics" (segment `forensics`, `HardDrive` icon) with `plannedFor`; the summary already says "Disk forensics with The Sleuth Kit and Plaso timelines".
- **Docs:** `DATABASE.md` lists `forensic_artifacts` as "not implemented"; Autopsy is mentioned only in PRD's "Later" row.
- **Red-team scout additions (2026-11-07):**
  - **Kit:** `sandbox.reset(work_dir)` deletes every entry of the work dir and kills tool processes, and runs before every job; `run_tool` kills only the tool's own process group afterwards (a `setsid` child survives until the next `reset`); `transfer.download` fails with `integrity_mismatch` (RT1, RT3, RT22).
  - **Ingest:** the ingest worker is `--pool solo`, and the beat sends the reaper and the M7 correlation tick to the same ingest queue (RT9).
  - **MinIO:** the api user may Get / Put in the results bucket but not Delete; only the retention worker's purge user deletes versions there (RT19).
  - **M8 worktree (`cyber-m8`, phases 2 / 6–9 committed, not merged):** migration `0016_m8_memory_forensics` creates `memory_sensitivity` with the `memory_sensitivity_guard` trigger; `memory_analysis/sensitivity.py:apply_memory_default(session, org_id, evidence_id, actor_id)` is already called from `evidence/uploads.py`, `analysis/service.py`, `share_policy.py`, `reports/snapshot_sections.py`, `retention/select.py` and ten web files; `Omissions.memory_restricted` is `int = 0` inside `ReportSnapshot.omissions: Omissions | None` (RT2, RT23). Memory tool uid 10006, symbols tool 10005.
  - **Other plans:** M10 (blocked by M9) takes uid 10010, migration `0018` and uses lane 9 for `static-worker-test`; M11 takes `0019` and also says "phase 1 adds lane 9" (RT27).

Decisions taken by the planner are marked **(decision)**. The red-team pass ran on 2026-11-07; its changes are applied below and in the phase files (table under "Red-team changes").

## Architecture (decided)

    analyst: upload ?kind=disk (each segment ≤ DISK_MAX_UPLOAD_BYTES, 8 GiB default) -> evidence
             (hashes, custody, quota) + memory_sensitivity 'restricted' (source disk) + share
             policy AI/TI excluded, in the upload transaction; no automatic analysis of any kind
             "Run disk analysis" {segments [ordered evidence ids], profile triage|full,
                                  os_hint auto|windows|linux}          (never automatic)
      -> API: job row + analysis_job_segments + sensitivity default (idempotent) + custody + audit
      -> redis-broker queue `disk` (ACL user `disk`) -> disk.analyze {DiskJobV1}
    disk-worker (UNTRUSTED, analysis network only, broker URL only)
      -> root: free-space check; GET every segment (presigned, exact version) to
         /work/<job>/input/image.<ext>, sha256 + size verified, root-owned 0444 (no image
         cache: every job downloads, RT1)
      -> root: magic check (raw / EWF only; VMDK, VHD(X), QCOW, AFF, EWF2, LEF / L01,
         compressed and archive magic -> unsupported_disk_format); concatenated sha256 for
         split raw
      -> probe `verify` (EWF: claimed media size ≤ DISK_MAX_MEDIA_BYTES, read the whole
         media within the deadline budget, compare our MD5 / SHA-1 with the stored ones;
         libewf does not fail reads on chunk-checksum errors, so this is the only content
         check; RT6)
      -> probe `layout`: volume system (DOS, GPT, or none) -> per partition: refusal
         signatures first (BitLocker, LUKS, APFS, LVM, HFS+, ISO), then explicit FS types in
         an order hinted by the partition type (NTFS, FAT incl. exFAT, ext), OS markers (RT15)
      -> per file system: probe `walk --fs i`: entries (allocated, deleted names, orphans,
         NTFS named streams, every name of a hard-linked inode), metadata, magic class,
         md5/sha1/sha256 within the byte budget
      -> root: known-file hash sets (mmap, read-only /hashsets); the artifact catalog matched
         against the listing, the never-collected list applied to every name of an inode
         (RT7) -> collect list; YARA candidate list (PE magic, RT8)
      -> probe `collect --fs i`: copies the listed artifact files into a mirrored tree
         /work/<job>/artifacts/p<i>/<original relative path> (sanitized names, byte caps)
      -> probe `scan`: yara-python compiling the baked M3 rule sources over the candidates
      -> per OS partition (≤ 2 triage, ≤ 4 full): plaso `log2timeline --single_process` on
         the read-only mirrored tree with the fixed parser list, then the event export
         (`psort -o json_line`, or our single-process storage reader if psort starts
         processes under the filter; RT11)
      -> root: bounded reads, per-stage row models -> normalized records -> detections over
         every event (pass 1), storage selection (pass 2, RT10) -> disk.v1 (gzip NDJSON:
         header, partitions, files, events, findings, iocs, timeline, trailer) -> presigned
         POST -> ingest.event finished
      (every probe and Plaso process: tool uid 10007, seccomp AF_UNIX-only + no io_uring,
       PEP 578 audit hook, RLIMIT_AS / FSIZE / CPU / NPROC, a timeout from the job's deadline
       budget (RT5), a statvfs write-budget watchdog (RT4), fresh out dir; after each stage
       root kills every tool-uid process and makes the stage's out dir root-owned read-only
       (RT3))
    ingest-worker (trusted, solo): validates the `finished` event, hands the stream to the
      queue `ingest_disk` and moves the job deadline by DISK_INGEST_TIMEOUT_S (RT9)
    disk-ingest-worker (trusted, solo, its own process): token + org from the job index ->
      validate the whole stream (pass 1) -> one transaction (pass 2): disk_* tables +
      analysis_findings + iocs + analysis_timeline + custody + the in-org known-IOC-hash join

    analyst: "Export files" on allocated files -> disk job profile `extract` -> worker
      (downloads the segments again, probe `extract`, ≤ 64 MiB per file, ≤ 20 files) ->
      presigned POST per file to the results bucket `exports/` -> ingest marks the export
      `ready`
      -> "Add to case" (API, evidence.write): streams the object through the evidence upload
         pipeline (hash, sniff, quota, object lock) -> derived evidence, restriction inherited,
         normal auto choice (static) -> custody `derived_from` on both sides

    operator: pnpm disk:hashsets -- import-nsrl|import-list|list|verify|remove  [--store test]
      -> disk-hashsets (trusted tool, profile `tools`, network_mode none, uid 10008; parses in
         a forked child with rlimits, no uid change, RT25) -> writes the `disk_hashsets`
         volume + manifest.json -> mounted read-only into disk-worker(-test)

    retention worker (purge user): deletes the exact versions of expired export objects (RT19)

**Engines** (decision; research §1–§4)
- **TSK through pytsk3 in library mode, not the CLI.**
  - **Pinned:** `pytsk3==20260715` (Apache-2.0 wrapper; bundles TSK 4.15.0, statically embedded) and `libewf-python==20260924` (LGPL-3.0+).
  - **Never installed:** the Debian `sleuthkit`, `python3-tsk` and `ewf-tools` packages in the prod image. Debian's TSK is 4.12.1 and probably exposed to CVE-2026-40025 / 40026; `python3-tsk` targets Python 3.13.
  - **Why not the CLI:** it has no JSON output, and parsing `fls -m` text with attacker-chosen names (`|`, newlines) in the trusted root is fragile. The probe (`python -I -m disk_worker.probe <stage>`) opens the image itself:
    - a Python `Img_Info` subclass concatenating split-raw segments;
    - or a `pyewf` handle wrapped in an `Img_Info` subclass;
    - writes bounded JSONL rows, which root re-validates.
- **No autodetection** (decision; checked in TSK source by the red team: with a non-DETECT type `tsk_fs_open_img` calls only that family's opener, and `tsk_vs_open` with DOS / GPT only that opener):
  - volume systems: `TSK_VS_TYPE_DOS`, then `TSK_VS_TYPE_GPT`, else the whole image is treated as one file system at offset 0 (`Volume_Info(img, type, offset)`: type before offset);
  - file systems: NTFS, FAT (12/16/32 and exFAT through `TSK_FS_TYPE_FAT_DETECT`, which tries FATxx then exFAT), ext2/3/4 (`TSK_FS_TYPE_EXT_DETECT`), tried explicitly, the first family chosen from the MBR type byte / GPT type GUID when it names one (RT15);
  - **refusal signatures first:** a partition showing BitLocker (`-FVE-FS-`), LUKS, APFS (`NXSB`), LVM (`LABELONE`), HFS+ (`H+` / `HX`) or ISO 9660 (`CD001`) is reported `encrypted` / `unsupported` and never offered to any parser (FAT's weak boot-sector check could otherwise "open" foreign data; RT15); a partition no parser opens is `undetermined` ("unknown or encrypted"; no entropy guess);
  - APFS, HFS+, ISO 9660, UFS, YAFFS2 and LVM are never tried. Most TSK CVEs sit in those parsers (APFS keybag, ISO 9660 SUSP, HFS, YAFFS; research §1; two more HFS CVEs published 2026-11-02 affect 4.15.0 itself; none was found for NTFS / FAT / exFAT / ext).
- **Plaso on extracted artifacts only** (decision; research §4):
  - **Pinned:** `plaso==20261027` in its own venv `/opt/plaso` (dependencies locked with hashes in `plaso.lock`; the phase-3a spike establishes the lock). The red team found that the latest libevtx, libregf, libfsntfs, libfsext, libfsfat, libbde, libfsapfs and libvsgpt bindings are **sdist-only** (no cp312 wheel), and that `pyzmq`, `redis` and `opensearch-py` are hard requirements (`extraction_tool` imports `zmq` at import time). So the Dockerfile has a **builder stage** with a C toolchain by default that builds hashed wheels for `/opt/plaso`; only the wheels reach the prod stage; no dependency is "removable" (RT11).
  - **Never on the raw image:**
    - the TSK `collect` stage copies the matched artifact files into a tree that mirrors the original layout, so Plaso's preprocessors still find `Windows/System32/config/SYSTEM`, `etc/timezone`, the user profiles;
    - Plaso then never parses image, volume or file-system formats (dfVFS / libfs* stay off the raw image);
    - one hostile-parser stack per surface: TSK for file systems, the libyal format parsers for artifact contents.
  - **Fixed flags** (Plaso's underscore spellings, confirmed by the spike): `--single_process` (no multi-process IPC under the AF_UNIX-only filter), `--status_view none`, `--unattended`, `--hashers none`, `--no_dependencies_check`, `--archives none`, `--vss_stores none`, **`--skip_compressed_streams` in `triage`** (dfVFS decompresses gzip / bzip2 / xz streams by default whatever the file name, with no size cap; RT11), `--process_memory_limit` below the stage's RLIMIT_AS (RLIMIT_DATA: a clean error instead of a kill), an explicit `--parsers` list per (OS, profile) with `!filestat` (the copies' own times are meaningless), `--temporary_directory` in the out dir, the session storage in the out dir.
  - **Event export:** `psort.py -o json_line -w <out>/events.jsonl --status_view none` with **no analysis plugins** (virustotal and nsrlsvr are network clients; the opensearch outputs and redis storage are network sinks: never used). psort always runs `OutputAndFormattingMultiProcessEngine`; if the spike sees it start a process or a zmq TCP queue under the filter, the export is instead our own single-process reader `cyberlab_plaso_export` (Plaso's storage reader plus its `shared_json` serializer, same sandbox, same JSONL shape) (RT11).
  - **Wrapper:** both run through `/opt/plaso/bin/python -I -m cyberlab_plaso_launch <tool>` (a single module installed into `/opt/plaso` at build: under `-I` that interpreter cannot see the worker's `disk_worker` package; RT24), which installs the PEP 578 audit hook (refusing and counting `socket.*`, `urllib.Request`, `subprocess.Popen`, `os.exec*`, `os.system`, `os.spawn*`, `multiprocessing` process starts) before calling the Plaso entry point.
- **YARA:** `yara-python` (the M3 pin), the **M3 baseline rule sources** copied at build from the `static_rules` build context into `/opt/rules/image/` and compiled by the probe at scan start (the M3 `yarascan.py` pattern), and the severity allow-list keyed on (rule-file sha256, rule name) (RT8):
  - phase 1 lifts `static_worker/rulefiles.py` **and** the YARA parts of `static_worker/detections/signatures.py` (`YARA_SEVERITY_ALLOWLIST`, `YARA_TEST_ALLOWLIST`, `yara_ceilings`, `yara_severity`) into `cyberlab_worker.yara_rules`, with shims; no `.yarc` (a compiled file has no source sha256 to key the allow-list on);
  - the test marker comes from the M3 `test` source directory (`test.<stem>` namespace, test profile only), as in the static worker.
  - The M3 rules are file rules (every one anchored on `pe.*` / `MZ`), which fit extracted files; YARA candidates are therefore PE files only, in both profiles (`YARA_MAGIC_CLASSES = {pe}`, a constant to widen when ELF or script rules exist).
  - No ClamAV in the disk worker (DB size, updates): an exported file gets ClamAV through its normal static job.
- **One process per stage** (decision): `verify`, `layout`, `walk` (one per file system), `collect` (one per file system), `scan`, `log2timeline` and the event export (one each per OS partition). Re-opening an image costs milliseconds to seconds. Root sees only bounded files in each stage's fresh out dir.
  - **Stage isolation** (RT3): every stage runs as the same tool uid, and `run_tool` kills only the tool's process group, so after each stage root calls `sandbox.kill_tool_processes()` (a `setsid` survivor cannot reach the next stage) and then makes the stage's out dir root-owned and read-only (directories 0555, files 0444). A crash, hang or compromised parser in one stage then cannot alter another stage's output, and Plaso reads the collected tree without being able to change it.
  - **Deadline budget** (RT5): the worker tracks the job deadline; each stage's timeout is min(its own cap, the time left - a 900 s reserve for assembly and upload). A stage the budget cannot fit is `skipped` (`deadline`). Stage order puts the OS partitions' `walk` first.
  - **Write watchdog** (RT4): `disk_work` is a named volume on the host disk that also holds MinIO and Postgres, and RLIMIT_FSIZE bounds single files only. Root polls `statvfs` every 2 s during a stage and kills it (`truncated`, or `insufficient_disk` for the job) when the bytes written since the stage started exceed its write budget (the "Write budget" column below), or free bytes / inodes fall below `DISK_WORK_MIN_FREE_BYTES` (4 GiB) / 100 000.
- **Job success:** the downloads, `verify` (when EWF; a `verify` timeout leaves `media_hash_status: not_verified` and is not a failure, RT6), `layout` and at least one `walk` succeed. Every other stage is best effort, and its status (`ok`, `failed`, `timeout`, `skipped`, `truncated`, `unsupported`) is reported per stage and per partition in the header, so a partial result is never shown as complete. When no file system can be opened, the worker uploads a **diagnostic stream** (header + partitions) and fails `no_supported_filesystem`.
- **Real-engine coverage:**
  - The real TSK and libewf always run in tests on phase 4's generated images: FAT12/16/32, exFAT, ext2/3/4, NTFS, MBR and GPT, split raw, multi-segment E01. NTFS directory trees are built without any mount (libntfs-3g used as a library, else our own MFT writer, else the Windows-shaped tree on FAT32 plus a flat NTFS image for the NTFS-only features; parent decision: no privileged loop-mount container, RT26).
  - The real Plaso runs on generated Linux artifacts (syslog, auth.log, wtmp, bash history, cron, dpkg) and, if the phase-4 spike succeeds, on a hivex-built NTUSER.DAT / SOFTWARE hive.
  - **EVTX, Prefetch and LNK are never generated** (no Linux writer; research §7). They are covered by psort-shaped row fixtures and a test-profile-only timeline replay engine (`DISK_TIMELINE_ENGINE=replay`, labelled in every header).
  - The docs say "Windows event-log, Prefetch and LNK parsing: replay-tested, not validated on a real image in CI"; DEPLOYMENT gives an operator smoke procedure on the operator's own image (never automatic).

**Scope: triage, not full forensics** (decision)
- **In:**
  - partition listing;
  - file-system metadata (`fsstat`-like: type, label, UUID, block size, counts);
  - a file listing with metadata, deleted names and orphans flagged, NTFS named streams;
  - hashes within budgets;
  - known-file hash-set matching;
  - YARA on selected files;
  - a timeline of selected artifacts (Plaso) merged with the file-system MACB times;
  - deterministic findings, IOCs;
  - single-file export of allocated files to derived evidence;
  - interop exports (body file, timeline CSV / JSONL, a notable-hash list).
- **Out (recorded):**
  - carving and recovery of deleted content (deleted entries are listed, never hashed, scanned or exported);
  - `strings` over unallocated space;
  - VSS;
  - encrypted volumes;
  - APFS / HFS+ / ISO / UFS / XFS / btrfs, LVM / mdraid;
  - VMDK / VHD(X) / QCOW / AFF / Ex01 / L01;
  - Plaso on the whole image;
  - Autopsy as a server component;
  - full-text search of file contents.
- **Profiles:**

  | | `triage` | `full` |
  |---|---|---|
  | Hashing | allocated regular files ≤ 64 MiB, executables and scripts first, budget 16 GiB read | allocated regular files ≤ 1 GiB, budget = the image size |
  | YARA candidates | PE magic (RT8), ≤ 32 MiB, ≤ 20 000 files, 4 GiB | PE magic, ≤ 64 MiB, ≤ 100 000 files, 16 GiB |
  | Windows artifacts | EVTX (a fixed channel list), SYSTEM / SOFTWARE, NTUSER.DAT / UsrClass.dat, Amcache.hve (RT28), Prefetch, Recent LNK | + `$MFT` (≤ 1 GiB), browser history (Chrome / Edge / Firefox), Recycle Bin `$I` files |
  | Linux artifacts | syslog / messages, auth.log / secure, wtmp / btmp / utmp, shell history, cron, dpkg / apt logs, `etc/{timezone,localtime,hostname,passwd,os-release}` (preprocessing inputs) | + systemd journal, rotated `.gz` logs, browser history |
  | Artifact budget | ≤ 2 GiB, ≤ 20 000 files, ≤ 512 MiB each | ≤ 8 GiB, ≤ 20 000 files |

  **Never collected and never exported** (`NEVER_COLLECT_PATTERNS`, tested; RT7), by class:
  - **hives and their copies:** SAM, SECURITY (with `.LOG1` / `.LOG2`), `config/RegBack/*`, `Windows/repair/*`, `NTDS.dit`;
  - **credential stores:** DPAPI master keys (`Microsoft/Protect/**`), `Microsoft/Credentials/**`, `Microsoft/Vault/**`, `/etc/shadow`, `/etc/gshadow`, `/etc/krb5.keytab`, keyrings, `.gnupg/private-keys-v1.d/**`, NetworkManager `system-connections/*`, `wpa_supplicant*.conf`;
  - **browser secrets:** Chrome / Edge `Login Data*`, `Cookies`, `Web Data`, `Local State`; Firefox `logins.json`, `key3.db`, `key4.db`, `cookies.sqlite`;
  - **keys and tokens:** SSH private keys (`ssh_host_*_key`, `.ssh/id_*`), `*.pfx`, `*.p12`, `*.pem`, `*.key`, `/etc/ssl/private/**`, `.netrc`, `.git-credentials`, `.pgpass`, `.my.cnf`, `.aws/credentials`, `.azure/**`, `.kube/config`, `.docker/config.json`, password-manager files (`*.kdbx`);
  - **plaintext-secret configs:** `unattend.xml`, `sysprep.xml`, GPP `Groups.xml`;
  - **memory on disk:** `pagefile.sys`, `hiberfil.sys`, `swapfile.sys`, `MEMORY.DMP`, `*.dmp`.

  Matching is case-folded (NTFS / FAT) and applies to **every name of an inode**: a hard link (NTFS or ext) gives a second path to the same `meta_addr`, so a file is refused for collect and export when any of its names, or the file a named stream belongs to, matches (RT7).

**Image formats and segment sets** (decision; research §3, §9)
- **Accepted:** raw / dd (single), split raw (`.001…` or any ordered set), EWF E01 (EnCase 1–7 / FTK, single or multi-segment). The worker names segments `image.raw`, `image.001…`, or `image.E01`, `image.E02…` by the job's order; `pyewf` validates the set itself. Everything else → `unsupported_disk_format` (by root's magic check, before any probe runs).
- **Segment sets:** a job takes an **ordered list of 1..`DISK_MAX_SEGMENTS` (64) evidence items** of the same investigation (`analysis_job_segments`). `analysis_jobs.evidence_id` is segment 0.
  - Each segment is uploaded as ordinary evidence within the per-request limit.
  - The total is ≤ `DISK_MAX_IMAGE_BYTES` (16 GiB default, under the 20 GiB default org quota; validated ≤ 64 GiB) and within the org quota (RT21).
  - This keeps the platform's single-request upload, Caddy `read_body 30m` and the quota model unchanged, and matches how images arrive (E01 segments, split raw).
- **Integrity:**
  - every segment's sha256 and size are verified on download (the kit);
  - split raw also gets a concatenated media sha256 (root, streaming);
  - EWF's stored MD5 / SHA-1 (`pyewf` `get_hash_value("MD5")` / `("SHA1")`: stored values, not computed) are compared with our own hashes over a full read by the `verify` probe: `media_hash_status` `matched` / `mismatch` / `absent` / `not_verified` (timeout); a mismatch is a finding (`integrity:ewf_media_hash@1`, medium) and shown in the summary, not a job failure. libewf does not fail a read on a chunk checksum error, so with `absent` a corrupted chunk goes unnoticed (the summary says so).
  - **What is trusted** (RT17): only each segment's sha256, computed by the API at upload and re-checked on download. `media_sha256` and `media_hash_status` are **reported by the worker** (an untrusted container) and an acquirer can write a consistent stored hash for any content, so the UI and API say "reported by the worker; consistent with the hash stored at acquisition", never "verified".
  - The claimed EWF media size must be ≤ `DISK_MAX_MEDIA_BYTES` (2 TiB default), else `unsupported_disk_format` (reason `media_size`): a 1 GiB E01 claiming petabytes would otherwise keep `verify` reading zeros for the whole job budget (RT6).
  - EWF acquisition values (case number, examiner, notes, acquiry date) are attacker- or acquirer-chosen text: stored bounded and shown as quoted, inert text.
- **Ingest by reference** (an operator intake directory read by a trusted importer, for images above the per-request limit without segmenting) → **"Later"**. It needs a new trusted service with evidence-bucket write and a host path shared by tenants (sketch in "Out of scope").

**Resources and limits** (decision)
- **Upload** (`?kind=disk`):
  - `DISK_MAX_UPLOAD_BYTES` 8 GiB default, validated ≤ 16 GiB (the M8 Caddy bound: 16 GiB needs ≥ 9.2 MB/s within `read_body 30m`);
  - `CADDY_EVIDENCE_MAX` becomes max(`MAX_EVIDENCE_BYTES`, `MEMORY_MAX_BYTES`, `DISK_MAX_UPLOAD_BYTES`) + 1 MiB on the upload route;
  - the API enforces the per-kind limit on the declared length and while streaming.
- **No auto-run for disk** (decision): a run costs minutes to hours and gigabytes of disk, so it is always an explicit action. A `kind=disk` upload gets no static `av` job (the M8 RT3 lesson: no content reaches any engine or provider before the restriction).
- **Worker:**
  - concurrency 1, `--max-tasks-per-child 1`;
  - tool uid **10007** (`CYBERLAB_TOOL_UID` / `GID`; RLIMIT_NPROC is per host uid);
  - seccomp `unix_sockets_only=True`, `deny_io_uring=True`;
  - `mem_limit: 3g`, `cpus: 2`, `pids_limit 256`, read-only rootfs, `oom_score_adj=1000` for tools.
- **Per stage:**

  | Stage | RLIMIT_AS | RLIMIT_FSIZE | Write budget (RT4) | Timeout cap (RT5: never beyond the deadline budget) |
  |---|---|---|---|---|
  | `verify` | 1 GiB | 64 MiB | 64 MiB | media size / 100 MB/s + 600 s |
  | `layout` | 1 GiB | 64 MiB | 64 MiB | 600 s |
  | `walk` | 2 GiB | 2 GiB | 2 GiB | 3 600 s |
  | `collect` | 1 GiB | the per-file cap | the artifact budget + 64 MiB | 1 800 s |
  | `scan` | 2 GiB | 256 MiB | 256 MiB | 3 600 s |
  | `log2timeline` | 2.5 GiB | 8 GiB | 3 × the artifact budget | 5 400 s |
  | event export | 2 GiB | 4 GiB | 4 GiB | 1 800 s |
  | `extract` | 1 GiB | 64 MiB | 64 MiB × files | 600 s |

  Every stage also gets RLIMIT_NPROC 64 (threads count; the tool uid is the disk worker's alone). The job is bounded by `ANALYSIS_DISK_TIMEOUT_S` = 14 400 s (≤ the 6 h `JobLimits` bound); the reaper adds the M2 grace. The caps above sum past the job bound on purpose (up to 32 file systems, 4 Plaso partitions): the deadline budget decides, and what does not fit is `skipped` (`deadline`), never a reaper kill.
- **`/work`:**
  - the named volume `disk_work` (not tmpfs: images are GiBs);
  - before the download, a free-space check ≥ image + 3 × artifact budget + `DISK_WORK_MIN_FREE_BYTES` + 2 GiB, else `insufficient_disk`; the write watchdog (RT4) holds the floor during the stages;
  - the image is read from local files: TSK and libewf need random access; HTTP range reads through a block cache are "Later".
- **No image cache** (RT1; decision): `sandbox.reset` empties the whole work dir before every job, a cache beside it would need a second root with its own reset rules, and hard links do not cross volumes. Every job (including a `full` re-run and a file export) downloads and re-verifies its segments; at MinIO-on-localhost speeds that is minutes for 16 GiB. A cache returns with HTTP range reads ("Later").
- **Caps** (`DiskLimits`):
  - partitions 128, file systems 32;
  - files 500 000 (bound ≤ 2 000 000), NTFS streams ≤ 16 per file;
  - stored events 250 000 (events read through detections ≤ 20 000 000);
  - findings 5 000, IOCs 20 000, shared timeline 5 000;
  - text: path ≤ 4 096 bytes (a longer path, e.g. 64 levels of 255-character NTFS names, is cut on a UTF-8 boundary by the probe and flagged `path_truncated`, never a bad row; RT13), name ≤ 1 024, message ≤ 2 048, EWF header values ≤ 256, event `attributes` ≤ 32 scalars (str ≤ 1 024).

  Every cap hit sets a `truncated` flag (per stage, per partition). The disk ingest passes its own framing bounds to `check_framing` (`DISK_MAX_RESULT_DECOMPRESSED_BYTES` 1.5 GiB, lines = the sum of the caps + 3; the M8 RT9 pattern). A unit test proves a stream at every cap fits the 256 MiB upload cap and these bounds.
- **Timeline storage** (decision): two passes over the exported `events.jsonl` (on disk, ≤ 4 GiB; RT10). Pass 1 runs the detections over **every** event and records the ordinals findings cite. Pass 2 keeps, per artifact category, the most recent events within a per-category quota (quotas sum to 250 000), plus every cited event. A single pass with a ring buffer could evict an event before a later finding (a burst, a correlation) cites it. Per-category `read` / `stored` counts are in the header.
- **Active jobs:** `DISK_MAX_ACTIVE_PER_ORG` = 1, `DISK_MAX_ACTIVE_TOTAL` = 1 (one worker container; RAM on the host). Queue TTL 12 h. The presigned GETs expire with the queue TTL plus the job timeout.

**Known-file hash sets: offline only** (decision; research §8)
- **Nothing is downloaded** by any tool, test or gate. The operator obtains NSRL RDSv3 (for example the `modern_minimal` SQLite) or any md5sum / sha1 / sha256 list, places it in `./.disk-import/` and runs `pnpm disk:hashsets -- import-nsrl --file <db> --name <n>` or `import-list --file <txt> --name <n> --kind known_good|known_bad|notable --algo sha256|sha1|md5`.
- **Trusted tool `disk-hashsets`:**
  - the disk image, uid 10008, compose profile `tools`, **`network_mode: none`**, `mem_limit 2g`;
  - volume `disk_hashsets` rw at `/hashsets` and the import dir read-only.
  - Every parse (SQLite, text) runs in a forked child with `RLIMIT_AS` 2 GiB, a timeout and the kit's seccomp filter, but **no uid change** (the tool already runs as 10008 with no capabilities, so `sandbox.run_tool`, which switches to the tool uid, cannot be used; RT25); it sorts externally in a temp dir (bounded memory) and is verified before an atomic move.
  - **Sizes** (research, red team): the full RDSv3 Modern set is hundreds of GB uncompressed; operators import the `minimal` set (distinct FILE rows; the FILE view has `sha256`, `sha1`, `md5`, `file_name`, `file_size`, `package_id`).
  - **Layout:** `<name>/{sha256,sha1,md5}.bin` (sorted unique fixed-width records) and `manifest.json` (`HashSetManifestV1`: name, kind, algorithms, counts, per-file sha256, source sha256, `imported_at`, tool version).
  - Other commands: `list`, `verify` (re-hash against the manifest), `remove --name`.
- **Matching:** root mmaps the sets read-only and binary-searches each hashed file. `known_good` sets only set `known = good`, hidden by default in the UI and labelled "known (reference set)", not "benign": NSRL lists dual-use tools and old vulnerable drivers too. A `known = good` file in a user-writable path class is still YARA-scanned, and `known` never suppresses a heuristic (RT18). `known_bad` / `notable` sets produce `known_file:hashset@1` findings (≤ `medium`: operator lists are unverified). The header records every set's name, kind, count and manifest sha256 (reproducibility).
- **In-org matching** at ingest (trusted): every hashed file's sha256 / sha1 / md5 is joined with the org's `iocs` hash values and `correlation_keys` hash kinds from other jobs (`correlation:disk_known_org_hash@1`, `low`, with "also seen in" links). No hash leaves the org; nothing is sent to TI automatically (and job-scope TI is blocked while restricted).

**Sensitivity: TLP:RED by default** (decision)
- **Why:** a disk image holds everything the machine held: documents, mail, browser data, credentials in files, keys.
- **Extended, not renamed** (decision, RT2; phase 1): M8's `memory_sensitivity` table is already evidence-scoped (PK `evidence_id`) and, in the M8 worktree, already read by the uploads, analysis, share-policy, report, retention and ten web files. Renaming it while M8 is still landing would rewrite all of them, a trigger, its policies and grants, and add route and field aliases. Instead:
  - the M9 migration adds `source text NOT NULL DEFAULT 'memory'` (`memory` / `disk` / `derived`, checked) to `memory_sensitivity`; DATABASE documents it as the evidence-level sensitivity table, and the rename is a "Later" cleanup;
  - `app/modules/evidence/sensitivity.py: apply_restricted_default(session, org_id, evidence_id, actor_id, source) -> bool` is M8's `apply_memory_default` body with the source (and the audit action `memory.sensitivity_defaulted` / `disk.sensitivity_defaulted`, details carry `source`); `apply_memory_default` becomes a one-line wrapper (`source="memory"`);
  - generic routes `GET /evidence/{id}/sensitivity` and `POST …/sensitivity/release` call M8's `get` / `release`; M8's `/memory-sensitivity` routes, `memory_sensitivity_restricted` / `_released` codes and `memory.*` audit actions stay unchanged and are **not** deprecated;
  - the share-policy guard answers `evidence_sensitivity_restricted` for the `disk` / `derived` sources and keeps `memory_sensitivity_restricted` for `memory`;
  - **batch release** (RT20): the generic release body may carry `job_id` of a disk job whose segments include the path evidence; then every restricted segment of that job is released in one acknowledged request (one audit row per item). Derived evidence is never included.

  Alternative considered: a parallel `disk_sensitivity` table, which would duplicate the release trigger, guard and routes.
- **Applied:** a `kind=disk` upload inserts `restricted` (source `disk`) and upserts the M6 share policy to `ai_excluded = ti_excluded = true` (never loosening) in the upload transaction, with no automatic analysis. The first disk job on any segment applies the same default to **every** segment (idempotent).
- **Derived evidence** (exports) inherits the source's state: `restricted` when any segment is restricted (source `derived`), plus the source's share-policy flags, in the promote transaction.
- **Machinery (M6 / M8):**
  - AI runs and job-scope TI are `409 policy_blocked`;
  - incident summaries skip it;
  - the workers re-check;
  - release is `org.update`, acknowledged, reasoned, once, audited; while restricted, the share-policy route refuses to clear the flags.
- **Reports:** disk-derived rows of restricted evidence go into a report only at TLP:RED; otherwise they are omitted and counted in `ReportSnapshot.omissions.disk_restricted` (a new `int | None = None` field of M8's `Omissions`, whose `memory_restricted` is `int = 0` as built; `canonical_json` pops `omissions.disk_restricted` when it is `None`, beside M8's existing pop of a `None` `omissions`, so M8-signed snapshots with memory omissions keep their bytes; a golden test over the M6 and M8 snapshot fixtures; the api and report-worker images rebuilt together; RT23).
- **Collection minimisation:**
  - no file content is stored by the analysis (metadata, hashes, matched rule names, Plaso events of allow-listed artifacts only);
  - the never-collected list above;
  - browser history only in `full`;
  - no carving.
  - File contents leave the image only through an explicit, audited, per-file export.
- **Secret masking:** text quoted into findings, IOC context and timeline titles (shell history, registry values, service paths, task commands, URLs with their query values) passes `cyberlab_worker.mask` (the M8 masker, lifted from `memory_worker/detections/mask.py` into the kit by phase 1 with a shim). The raw text stays only in `disk_events` / `disk_files` (job pages, `evidence.read`).
- **Correlation inside the org** is allowed: the M7 indexer reads the disk `iocs` rows (keys only, never across orgs).

**Licenses** (decision; research §1–§4; not legal advice)
- **The licenses:**
  - TSK (embedded in the pytsk3 wheel): IBM-PL-1.0 / CPL-1.0 (weak copyleft for the library itself);
  - pytsk3: Apache-2.0;
  - libewf-python and the libyal bindings Plaso pulls in: LGPL-3.0+;
  - Plaso, dfVFS, dfwinreg, artifacts: Apache-2.0;
  - yara-python: Apache-2.0 (YARA BSD-3).
- **Our obligations:** ship the license texts and a NOTICE with source links (`/usr/share/doc/cyberlab-disk/NOTICE` plus each wheel's `LICENSE`); never patch TSK, libewf or Plaso; keep the LGPL libraries as replaceable dynamically loaded modules (they are, in the venv).
- **No copyleft reaches our adapter.** Unlike the VSL of M8, no "wrapper" clause applies. No GPL component is in the prod image: TSK's only GPL file is `srch_strings.c`, not built into pytsk3 [I, phase 1 verifies the wheel]; the GPL test tools (dosfstools, mtools, e2fsprogs, ntfs-3g, util-linux `sfdisk`, ewf-tools) are installed in the dev / test target only.

**Autopsy** (decision; research §6)
- Autopsy 4.23.1 (Apache-2.0) is a Java / NetBeans desktop application, fully tested only on Windows. Its Command Line Ingest still starts the platform, adds one data source per invocation and needs GUI-made profiles; multi-user mode needs Solr, PostgreSQL and ActiveMQ; there is no REST API.
- It is **not integrated as a server-side worker** (it cannot meet the untrusted, network-less, resource-bounded worker model).
- "Integration where appropriate" means **analyst-side interop**:
  - the original segments can be downloaded (audited, `evidence.read`) and opened in Autopsy;
  - CyberLab exports a TSK **body file** (for TSK's `mactime` and other body-file tools; Autopsy has no body-file or CSV timeline import), the timeline **CSV / JSONL** in Timesketch's import columns (`message`, `datetime`, `timestamp_desc`, plus ours), and a **plain hash list** of flagged files (one md5 per line, `.txt`), importable as an Autopsy hash set (RT12);
  - docs describe the workflow (Autopsy: open the downloaded segments, import the hash list as a "notable" set; Timesketch / mactime for the timeline). Server-side Autopsy is recorded as "not planned".

**Detections** (decision; phase 6): deterministic heuristics over normalized records. The methods:
- `heuristic:disk_exec_user_writable@1`;
- `heuristic:disk_double_extension@1`;
- `heuristic:disk_extension_mismatch@1`;
- `heuristic:disk_ads_executable@1`;
- `heuristic:disk_persistence@1`;
- `heuristic:disk_log_cleared@1`;
- `heuristic:disk_service_installed@1`;
- `heuristic:disk_account_change@1`;
- `heuristic:disk_remote_logon@1`;
- `heuristic:disk_dual_use_execution@1`;
- `heuristic:disk_correlated_indicators@1`;
- `signature:yara@1` (M3 severities);
- `known_file:hashset@1`;
- `integrity:ewf_media_hash@1` (worker);
- `correlation:disk_known_org_hash@1` (ingest).

Rules:
- `heuristic:disk_timestamp_anomaly@1` is cut (RT28: it needs `$SI` / `$FN` pairs that only the `full` `$MFT` events carry, and zero sub-second times are common after installs and archive extraction); "Later".
- Heuristics cap at `medium`; only `signature:yara@1` can reach `high` (the M3 allow-list).
- No verdict words.
- IOCs: hashes of files referenced by findings, source IPs of remote-logon findings, URLs / domains / IPs quoted in findings; never the whole listing or browser history.

**Testing and data** (decision; research §7)
1. **Generated synthetic images** (phase 4, A′, run first). Inside the dev / test target only, at test time, deterministic (fixed seeds, `SOURCE_DATE_EPOCH`-style fixed times, `debugfs` / `mtools` timestamps), each ≤ 64 MiB:
   - FAT12 / 16 / 32 (`mkfs.fat` + `mtools`, deleted entries via `mdel`);
   - exFAT (`mkfs.exfat`);
   - ext2 / 3 / 4 (`mke2fs -d` + `debugfs`);
   - NTFS (`mkntfs -F` + `ntfscp`; directories without any mount: libntfs-3g as a library (`ntfs_mount` on the image file, `ntfs_create` of directories), else a minimal MFT writer of our own, else the Windows-shaped tree on FAT32 plus a flat NTFS image; no privileged container and no committed image, parent decision, RT26; see phase 4);
   - MBR and GPT layouts (`sfdisk` on a file + `dd conv=notrunc`);
   - split raw (`split`);
   - single and multi-segment E01 (`ewfacquirestream -S`);
   - a Linux system tree (syslog, auth.log, `utmpdump -r` wtmp, bash history, cron, dpkg logs);
   - a Windows-shaped tree (Users, Windows\System32\config with a hivex-built SOFTWARE / NTUSER.DAT on a base hive written by our own regf writer if the spike succeeds (never hivex's test images), executables in user-writable paths, an ADS with PE magic, a double extension, Startup folder entries, hard links to `SAM` and `etc/shadow` for RT7).

   A `ground_truth.json` per image lists the expected partitions, files, hashes and findings.
2. **psort-shaped row fixtures** (our own, hand-written in the 20261027 `json_line` shape recorded by the spike) for EVTX, Prefetch, LNK, registry, browser and MFT events, and the **timeline replay engine** (test profile only, refused otherwise by an env check, labelled `timeline_engine: replay`).
3. **Scenario dataset** (phase 6): generated `DiskView`s with benign baselines and labelled positives give the precision / recall table, with the M2 / M3 / M8 caveat (synthetic, designed alongside the detectors).
4. **Hostile inputs** (phases 2 and 13): mutated generated images (truncation, corrupted boot sectors / superblocks / MFT records, directory cycles, huge directories, names with `|`, newlines, NUL, `..`, RTLO, overlong UTF-8, lying partition tables, overlapping partitions, an EWF with a lying segment count, a stored-hash mismatch), plus compressed / archive / VMDK / QCOW / VHD magic (refused before any probe).
5. **No real disk image, no third-party test corpus** (CFReDS, DFTT, Plaso test data with real artifacts, hivex's test hives) and no NSRL download, by any tool, test or gate (`requirement.txt` §14: no real data or malware); no committed binary image at all (every image is generated at test time).

### Data model (migration **head + 1, expected 0017**; the M4–M8 conventions: FORCE RLS on every tenant table, composite same-org FKs, S/I grants plus per-column UPDATE, named checks with `octet_length` caps, no DELETE grant to the app role)

| Table / change | Scope / grants | Notes |
|---|---|---|
| `analyzer` enum | existing | `ALTER TYPE analyzer ADD VALUE 'disk'` (autocommit block, like 0006) |
| `analysis_jobs.profile` checks | existing | `disk` ∈ (`triage`, `full`, `extract`) added to the M8 checks |
| `analysis_jobs.os_hint` | existing (M8) | the iff check becomes: NOT NULL iff analyzer ∈ (`memory`, `disk`) (`auto` for `extract`) |
| `job_outcomes` kind check | existing | gains `disk` |
| `analysis_job_segments` | tenant; app S/I | (`job_id`, `ordinal` 0..63) PK, `organization_id`, `evidence_id` (composite FKs to the job and the evidence, same org); unique (`job_id`, `evidence_id`); a trigger checks every segment's investigation equals the job's; insert-only |
| `disk_images` | tenant; app S/I | PK `job_id`; `format` (`raw` / `split_raw` / `ewf`), `segments`, `media_size`, `sector_size`, `media_sha256`, `ewf_md5`, `ewf_sha1`, `media_hash_status` (`matched` / `mismatch` / `absent` / `not_verified`; worker-reported, RT17), `ewf_meta` jsonb ≤ 2 KiB (case number, examiner, notes, acquiry date; text), `volume_system`, `stages` jsonb ≤ 16 KiB, `counts` jsonb ≤ 4 KiB, `tool_versions` jsonb ≤ 2 KiB, `hashsets` jsonb ≤ 4 KiB, `engine`, `timeline_engine`, `truncated` |
| `disk_partitions` | tenant; app S/I | `id`, `organization_id`, `job_id`, `index`, `start_sector`, `length_sectors` (`numeric(20,0)`), `description` ≤ 128, `vs_flags`, `fs_type`, `fs_status` (`ok` / `unsupported` / `encrypted` / `undetermined` / `error` / `truncated`), `fs_label` ≤ 128, `fs_uuid` ≤ 64, `block_size`, `os` (`windows` / `linux` / `none`), `os_name` ≤ 128 (inert text), `counts` jsonb; unique (`job_id`, `index`) |
| `disk_files` | tenant; app S/I; retention DELETE | `id` uuid PK, `organization_id`, `job_id` (every bulk table has these three; RT23 of M8), `partition_index`, `meta_addr` (`numeric(20,0)`), `meta_seq`, `stream` ≤ 255 NULL (NTFS named stream), `path` ≤ 4 096, `parent_addr` (`numeric(20,0)`, the `meta_addr` of the directory the walker listed the entry in; replaces a path hash, which collides on truncated paths and cannot be indexed from 4 KiB paths; RT13), `name` ≤ 1 024, `ext` ≤ 32, `type` (`reg` / `dir` / `lnk` / `other`), `flags` (bitmask: allocated, deleted, orphan, reallocated, name_lossy, path_truncated, hard_linked), `size`, `mode`, `uid`, `gid`, `mtime` / `atime` / `ctime` / `crtime` (timestamptz), `time_basis` (`utc` / `local_unknown`), `magic` (`pe` / `elf` / `script` / `archive` / `document` / `other` / `empty`), `hash_status`, `md5`, `sha1`, `sha256` (lowercase hex, checked), `known` (`good` / `bad` / `notable` NULL), `known_set` ≤ 64, `yara_rules` text[] ≤ 16; indexes (`job_id`, `partition_index`, `parent_addr`, `id`), (`job_id`, `partition_index`, `meta_addr`) (every name of an inode, RT7), (`job_id`, `sha256`), one (`job_id`, `<time>`, `id`) per time column `mtime` / `atime` / `ctime` / `crtime` (the merged timeline reads all four in index order; RT14), and (`job_id`, `flags`) partial on flagged rows |
| `disk_events` | tenant; app S/I; retention DELETE | `id`, `organization_id`, `job_id`, `ts` timestamptz, `ts_desc` ≤ 64, `artifact` (the frozen `DiskArtifact` enum), `parser` ≤ 64, `data_type` ≤ 64, `partition_index`, `path` ≤ 1 024, `file_id` NULL (resolved at ingest by natural key), `message` ≤ 2 048, `attributes` jsonb ≤ 4 KiB (scalar values only, checked); indexes (`job_id`, `ts`, `id`), (`job_id`, `artifact`, `ts`, `id`) |
| `disk_exports` | tenant; app S/I + UPDATE (`state`, `object_key`, `object_version_id`, `size`, `worker_sha256`, `evidence_id`, `promoted_by/at`, `error_code`, `object_deleted_at`); retention UPDATE (`object_deleted_at`) | `id`, `organization_id`, `export_job_id`, `source_job_id`, `file_id`, `path` (snapshot), `state` (`pending` / `ready` / `failed` / `promoted` / `expired`), `worker_sha256` (untrusted, display only), `object_version_id` (the exact version the retention worker deletes, RT19), `evidence_id` NULL (after promote; composite FK); transition trigger (forward only) |
| `memory_sensitivity` (M8, kept) | existing | + `source` (`memory` / `disk` / `derived`, default `memory` for existing rows, checked; RT2); the M8 trigger, grants and RLS unchanged; no rename |
| retention grants | — | DELETE to `cyberlab_retention` on `disk_files`, `disk_events`; never on `disk_images`, `disk_partitions`, `disk_exports`, `analysis_job_segments`, `memory_sensitivity` |

Findings, IOCs and the timeline use the shared `analysis_findings`, `iocs` and `analysis_timeline`. Job-level disk summary: `analysis_jobs.summary` (≤ 32 KiB). Postgres footprint at the caps is about 0.5–1 GiB per job with indexes (phase 7 measures and DEPLOYMENT states it).

## Red-team changes (2026-11-07)

**Reviewers and sources.** Four hostile reviewers (security, reliability, product, scope / parallelism) checked this plan, its phase files and the research report against the code:
- worker kit `packages/py-worker-kit/src/cyberlab_worker/{sandbox,seccomp,transfer}.py` (`reset`, `prepare`, `run_tool`, `kill_tool_processes`, the AF_UNIX allowlist, `download`'s error codes);
- the static worker: `rules/yara/cyberlab_baseline.yar`, `static_worker/rulefiles.py`, `detections/signatures.py` (the YARA allow-list), `probe/yarascan.py`;
- api: `evidence/uploads.py`, `core/{config,hashing,storage}.py`, `analysis/{service,result_stream}.py` (`auto_choice`, the two-pass framing), `workers/{celery_app,reaper,retention}.py`, `retention/select.py` (`BULK_TABLES`), `correlation/indexer.py`, `ops/error_classes.py`, `tests/unit/test_dynamic_gate.py`, migrations up to `0015_m7_hold_sync`;
- infra and scripts: `docker-compose.yml` (ingest worker and beat, the analysis network), `infra/minio/{init.sh,api-policy,purge-policy}`, `scripts/lane-test.sh` (lanes 2..8, Redis / broker db = lane);
- the M8 worktree `D:\Downloads\learn\cyber-m8` (read only): migration `0016`, `memory_analysis/{sensitivity,router_sensitivity}.py` and their callers, `memory_worker/detections/mask.py`, `cyberlab_worker/iocs.py`, `cyberlab_jobs/report.py` (`Omissions`, `canonical_json`), the memory Dockerfile (uid 10006) and compose anchors;
- the M10 and M11 plans (lanes, uids, migration numbers);
- the web: TSK `fs_open.c` / `fatfs.cpp` / `mm_open.c` / `fs_dir.cpp` / `ntfs_dent.cpp`, pytsk `tsk3.cpp` / `_build.py`, NVD / OSV for TSK and libewf CVEs, libewf `pyewf_handle.c` / `libewf_chunk_data.c`, Plaso 20261027 `requires_dist`, `cli/*` (flag names), `single_process/extraction_engine.py`, `cli/psort_tool.py`, `multi_process/zeromq_queue.py`, `preprocessors/{windows,linux}.py`, `output/shared_json.py`, PyPI wheel listings of the libyal bindings, the NIST RDSv3 README.

No container was run, nothing was downloaded beyond documentation, and no code or git state was touched.

**Parent decision encoded:** no privileged loop-mount container for NTFS test images; only the mount-free fallbacks remain (RT26).

**Result:** 41 findings: 4 High, 13 Medium, 24 Low. 31 were accepted and applied, 10 rejected. Seed questions: Q1 → RT3 / RT4 / RT5 / RT6 / RT30; Q2 → RT15 / RT16; Q3 → RT11 / RT24; Q4 → RT10 / RT11 / RT31; Q5 → RT3 / RT7 / RT11 / RT13 / RT31; Q6 → RT1 / RT17 / RT21; Q7 → RT2 / RT18 / RT20 / RT35; Q8 → RT7 / RT17 / RT19 / RT29 / RT34; Q9 → RT9 / RT14 / RT36; Q10 → RT1 / RT28 / RT32 / RT33 / RT34 / RT39.

| ID | Finding (failure scenario) | Severity | Disposition |
|---|---|---|---|
| RT1 | **The image cache can never hit.** `sandbox.reset(work_dir)` deletes every entry of the work dir (and kills tool processes) before every job, so `disk_work/.cache` is wiped each time; keeping it outside the reset path needs a second volume, where hard links do not work (a copy doubles the disk). It is also a cross-job store of TLP:RED bytes that outlives evidence purges. | High | Accepted → the image cache is cut (`cache.py`, `cache_key`, `DISK_IMAGE_CACHE_*` removed); every job, re-run and export downloads and re-verifies; a cache returns with HTTP range reads ("Later") (plan Architecture, Resources; phases 1, 2, 7, 10, 11, 12). |
| RT2 | **Renaming M8's table from M9 is a cross-milestone rewrite of unmerged code.** In the M8 worktree `memory_sensitivity` (with `memory_sensitivity_guard`) is already used by uploads, analysis, share policy, report sections, retention and ten web files; the rename adds a trigger / policy / grant rename, a model move, route and field aliases and two error codes, all while M8 is still landing (phase 1 would chase a moving target). | High | Accepted → no rename: the M9 migration adds `source` to `memory_sensitivity`; `evidence/sensitivity.py:apply_restricted_default(…, source)` generalizes M8's function (which becomes a one-line wrapper); generic routes are added beside M8's, whose codes, routes and audit actions stay; the rename is a "Later" cleanup (plan Sensitivity, Data model, Frozen interfaces; phases 1, 7, 9, 10, 11, 12). |
| RT3 | **A compromised stage can tamper with the next one.** Every stage runs as uid 10007; `run_tool` kills only its process group, so a `setsid` child survives until the next job's `reset` and can rewrite the next stage's out dir or the collected tree Plaso parses (both tool-owned). | Medium | Accepted → after each stage root calls `kill_tool_processes()` and makes the stage's out dir root-owned read-only (0555 / 0444); Plaso reads the tree read-only; RLIMIT_NPROC 64; a test plants a `setsid` sleeper and a late write (plan Engines; phases 2, 3, 13). |
| RT4 | **A stage can fill the host disk.** `disk_work` is a named volume on the Docker Desktop disk that also holds MinIO and Postgres; RLIMIT_FSIZE bounds one file, not the total or the inode count (collect, Plaso storage, psort output). | Medium | Accepted → a `statvfs` watchdog per stage with write budgets (stage table) and a floor `DISK_WORK_MIN_FREE_BYTES` (4 GiB) / 100 000 inodes; overrun kills the stage (`truncated` / `insufficient_disk`) (plan Engines, Resources; phases 1, 2, 13). |
| RT5 | **Stage timeouts add up past the job timeout.** `verify` scales with media size, `walk` is 3 600 s × up to 32 file systems, Plaso 7 200 s × 4 partitions, against 14 400 s: the reaper fails the job while the worker keeps running. | Medium | Accepted → a deadline budget: each stage gets min(its cap, time left − 900 s); what cannot fit is `skipped` (`deadline`); Plaso on ≤ 2 OS partitions in `triage`, ≤ 4 in `full`; OS partitions walked first (plan Engines, Resources; phases 1, 2, 3). |
| RT6 | **A lying EWF media size burns the only worker.** `verify` reads the claimed media; a 1 GiB E01 claiming petabytes of compressed zeros keeps it busy for the whole job budget, every time it is re-run. | Medium | Accepted → `DISK_MAX_MEDIA_BYTES` (2 TiB) refuses implausible media (`unsupported_disk_format`, reason `media_size`); `verify` is budget-bounded and a timeout reports `media_hash_status: not_verified`, not a failure (plan Image formats, Resources, Data model; phases 1, 2, 11). |
| RT7 | **The never-collected list is bypassed by hard links and is incomplete.** A path check misses a second name of the same inode (NTFS or ext hard links: `var/log/auth.log` → the `/etc/shadow` inode is collected and parsed into events; `x.txt` → `SAM` is exportable). The list also misses RegBack / repair hive copies, `.LOG1/2`, Credential Manager / Vault, Firefox `logins.json` / `key4.db`, Chrome `Local State`, keytabs, `*.pfx` / `*.pem` / `*.key`, cloud CLI credentials, `.kdbx`, `unattend.xml`, `*.dmp`. | High | Accepted → `NEVER_COLLECT_PATTERNS` extended by class; case-folded matching on **every name of an inode** (the walk emits all names; index on `meta_addr`), a named stream inherits its file's refusal, for collect and export; tested with generated hard links to `SAM` and `etc/shadow` (plan Scope, Data model; phases 1, 2, 3, 4, 10, 13). |
| RT8 | **The YARA plan lifts the wrong module and breaks the keying.** The severity allow-list lives in `static_worker/detections/signatures.py`, keyed on (rule-file sha256, rule); `rulefiles.py` only lists and hashes files. A compiled `.yarc` has no source sha256; a `DISK_YARA_RULES` override differs from M3's `test` source dir. Every baseline rule is `pe`-anchored, so ELF / script candidates are wasted scans. | Medium | Accepted → lift `rulefiles.py` and the YARA parts of `signatures.py` into `cyberlab_worker.yara_rules`; ship the rule sources and compile them in the probe (the `yarascan.py` pattern); test rules via the M3 `test` directory; candidates PE only (`YARA_MAGIC_CLASSES`) (plan Engines, Scope; phases 1, 5). |
| RT9 | **One ≈ 750 000-row transaction stalls the platform.** The ingest worker is `--pool solo` and the beat sends the reaper and the M7 correlation tick to the same queue: minutes of disk ingest delay every analyzer's results, timeouts and correlation. | Medium | Accepted → a dedicated `disk-ingest-worker` (api image, solo, queue `ingest_disk`, `mem_limit 1g`); the ingest worker only validates the `finished` event, hands off and moves the deadline by `DISK_INGEST_TIMEOUT_S` (1 800 s); one transaction and the two-pass `body_lines()` framing kept (plan Architecture, Frozen interfaces; phases 1, 7, 13). |
| RT10 | **"Every finding-cited event is stored" is false with one streaming pass.** The per-category ring buffer can evict an event before a later burst or correlation finding cites it, so the ingest drops the ref. | Medium | Accepted → two passes over `events.jsonl` (detections and cited ordinals, then storage selection) (plan Timeline storage; phases 3, 6). |
| RT11 | **Plaso packaging and run-time assumptions are wrong.** Eight libyal bindings Plaso needs are sdist-only for cp312; `pyzmq`, `redis`, `opensearch-py` are hard requirements and `zmq` is imported at start-up (nothing is "removable"); psort always runs a multi-process engine; dfVFS decompresses gzip / bzip2 / xz by default with no size cap, whatever the name; Plaso's flags use underscores (`--archives`, not `--process_archives`). | High | Accepted → a builder stage with a toolchain by default (wheels only into prod); no "removable" assertion; `--skip_compressed_streams` in `triage`, `--archives none`, `--vss_stores none`, `--process_memory_limit`; root drops collected files with compressed / archive magic unless the catalog entry expects it; the spike runs psort under the filter, with a single-process storage reader `cyberlab_plaso_export` as the fallback (plan Engines, Open risks; phases 1, 3, 13). |
| RT12 | **The Autopsy interop claims do not hold.** Autopsy imports neither a body file nor a CSV timeline; a body file serves `mactime`; the Plaso ecosystem's timeline tool (Timesketch) imports CSV / JSONL with `message`, `datetime`, `timestamp_desc`. | Medium | Accepted → body file labelled for `mactime`; CSV / JSONL in Timesketch's columns; the flagged-file list as one md5 per line (`.txt`, Autopsy hash-set import); docs corrected (plan Autopsy; phases 8, 11, 12). |
| RT13 | **Long hostile paths and `dir_hash`.** 64 levels of 255-character names exceed 4 096 bytes: invalid rows fail the walk by the 1 % rule (the job fails); truncated paths make `dir_hash` collide. | Low | Accepted → the probe cuts paths on a UTF-8 boundary (`path_truncated`); directories keyed by `parent_addr` (the walked directory's `meta_addr`), not a path hash (plan Caps, Data model; phases 1, 2, 8). |
| RT14 | **The merged timeline sorts.** Only `mtime` / `crtime` are indexed; the `UNION ALL` over four time columns then sorts 500 000 rows past the 5 s timeout. | Low | Accepted → one (`job_id`, time, `id`) index per time column (plan Data model; phase 8). |
| RT15 | **Foreign partitions reach the allow-listed parsers.** FAT's weak boot-sector check can "open" an HFS+ / ISO / BitLocker partition because signatures are checked only after every parser failed. (Red team confirmed in source that explicit types reach only their family's opener, and that `FAT_DETECT` covers exFAT.) | Low | Accepted → refusal signatures first; family order from the MBR type byte / GPT type GUID; no entropy guess (`undetermined`) (plan Engines; phase 2). |
| RT16 | **API names in the plan are wrong.** pyewf has `get_hash_value("MD5")`, not `get_hash_value_md5`; `Volume_Info(img, type, offset)` takes the type first; the `FS_Info` keyword is `type`. | Low | Accepted → corrected; phase 2 still verifies the 20260715 API (phase 2). |
| RT17 | **`matched` looks like proof.** The media hash and its status come from the untrusted worker, an acquirer can store a consistent hash for any content, and libewf does not fail reads on chunk-checksum errors (invisible when no hash is stored). | Low | Accepted → "reported by the worker; consistent with the stored hash", never "verified"; `absent` warns that chunk corruption goes unnoticed; only segment sha256s are trusted (plan Image formats; phases 8, 11, 12). |
| RT18 | **"Known good" hides what NSRL also lists** (dual-use tools, vulnerable drivers), and skipping YARA for it blinds the scan. | Low | Accepted → label "known (reference set)"; known files in user-writable classes still scanned; `known` never suppresses a heuristic (plan Hash sets; phases 5, 6, 11). |
| RT19 | **Expired exports are never deleted.** The api MinIO user has no Delete on the results bucket; only the retention worker's purge user has. TLP:RED file copies would linger. | Medium | Accepted → the beat marks `expired`; the retention worker deletes the exact version (`object_version_id`) with the purge user and stamps `object_deleted_at`; promote refuses `expired` (plan Data model, Architecture; phases 9, 10). |
| RT20 | **Releasing a 40-segment image takes 40 acknowledged releases.** | Low | Accepted → the generic release accepts a disk `job_id` and releases its restricted segments in one request (one audit row each); the UI loops the share-policy PUT (plan Sensitivity; phases 1, 9, 11). |
| RT21 | **Defaults contradict each other.** `DISK_MAX_IMAGE_BYTES` 32 GiB exceeds the 20 GiB default org quota. | Low | Accepted → default 16 GiB (≤ 64 GiB validated) (plan Resources; phases 1, 12). |
| RT22 | **Error code drift.** The kit raises `integrity_mismatch`; the plan maps `evidence_mismatch`. | Low | Accepted → the existing code (plan Frozen interfaces 6; phase 2). |
| RT23 | **`disk_restricted: int \| None` changes M8 bytes.** M8 built `memory_restricted: int = 0` inside an `omissions` object that is popped only when `None`; a `None` field would dump as `null` in M8 snapshots with memory omissions. | Low | Accepted → `canonical_json` also pops `omissions.disk_restricted` when `None`; golden test (plan Sensitivity, Frozen interfaces 1; phases 1, 9). |
| RT24 | **The Plaso launcher cannot be imported.** `/opt/plaso/bin/python -I` does not see the worker's `disk_worker` package. | Low | Accepted → `cyberlab_plaso_launch` (and `cyberlab_plaso_export`) installed into `/opt/plaso` at build (plan Engines; phases 1, 3). |
| RT25 | **The hash-set tool cannot use `run_tool`.** It runs as 10008 with no capabilities; `run_tool` switches to the tool uid. | Low | Accepted → a forked child with rlimits and seccomp, no uid change (plan Hash sets; phase 5). |
| RT26 | **NTFS fallback 2 needs a privileged loop-mount container** (parent decision: not allowed), and the hive base would come from hivex's test images (third-party data). | Medium | Accepted → order: libntfs-3g as a library (`ntfs_mount` on the image file, `ntfs_create` directories; no kernel mount), our own MFT writer, else the Windows-shaped tree on FAT32 plus a flat NTFS image for NTFS-only features; no committed image; the base hive comes from our own regf writer (plan Testing; phase 4). |
| RT27 | **Lane 9, uids and plan links collide across M9–M11.** M10 uses lane 9 for `static-worker-test`; M11 also "adds lane 9"; M9 says `blocks: []` though M10 is blocked by it. | Low | Accepted → M9 phase 1 adds lane 9 (`cyberlab_b9_test`, Redis / broker db 9; the script accepts 2..9); M10 / M11 phase 1 find it present (the parent updates their plans); uids: 10005 / 10006 M8, 10007 / 10008 M9, 10010 M10; `blocks` set to M10 (plan frontmatter, Parallel execution; phase 1). |
| RT28 | **Rules and artifacts out of balance.** `disk_timestamp_anomaly` needs `$SI` / `$FN` pairs (only `full` `$MFT` events) and fires on installs and extracted archives; scheduled-task XML is never parsed, so "task pointing into a user-writable path" cannot be evaluated; Amcache (small, prime execution evidence) is `full`-only. | Low | Accepted → the timestamp rule is cut ("Later"); the task condition uses task-file presence and times only; Amcache moves to `triage` (plan Scope, Detections; phases 1, 3, 6). |
| RT29 | **The export route shape is odd** (`…/files/{file_id}/export` with a batch body that repeats the path file). | Low | Accepted → `POST /analyses/{job}/disk/file-exports {file_ids}` (plan Frozen interfaces 4; phases 1, 10, 11). |
| RT30 | **NTFS listing memory grows with the MFT.** TSK walks the whole MFT on the first directory listing to build a parent map; a hostile `$MFT` size drives the walk into `RLIMIT_AS`, and a failed walk on the only file system fails the job. | Low | Accepted → phase 2 measures RSS against MFT entry count on a generated sparse NTFS; an out-of-memory walk is a partition `error` (`walk_memory`) with the layout still shown (the diagnostic stream when it was the only file system) (phases 2, 13). |
| RT31 | **Name sanitizing loses meaning.** Reducing components to `[A-Za-z0-9 ._-]` turns non-ASCII user folders into `_` runs (Plaso's user attribution breaks), and a component made only of dots or emptied by the reduction is ambiguous. | Low | Accepted → replaced characters become `_` plus a 6-hex suffix of the original bytes' sha256; all-dot or empty results are refused; the original path always comes back through `collected.jsonl`; the spike records Plaso's user mapping on such a tree (phases 2, 3). |
| RT32 | Cut E01 support (raw / split only). | Low | Rejected → E01 is the dominant acquisition format, libewf ships cp312 wheels and the segment-set model is built around it; LEF / L01 (CVE-2026-111159) stays refused by magic. |
| RT33 | Cut the known-file hash sets. | Medium | Rejected → known-file filtering is the main noise reduction of a file listing, and operator lists are the hunt input; the tool is offline and small. |
| RT34 | Cut file export to derived evidence. | Medium | Rejected → it is the triage-to-malware workflow; RT7 and RT19 bound it, and promotion re-hashes on the trusted side. |
| RT35 | Hide file listings and shell history from non-admins. | Medium | Rejected (M8 RT31) → needs per-field RBAC beyond the M1 org model; masking covers the shared surfaces; THREAT_MODEL residual. |
| RT36 | Ingest in committed chunks (staging tables) instead of a dedicated worker. | Low | Rejected → partial state, no app DELETE grant to clean it, and redelivery duplicates; RT9 keeps one transaction off the shared queue. |
| RT37 | A privileged loop-mount one-off container for NTFS images. | Low | Rejected (parent decision) → RT26's mount-free fallbacks. |
| RT38 | Bound `/work` with a loop-mounted ext4 file or XFS project quotas. | Low | Rejected → needs privileges or host features Docker Desktop lacks; RT4's watchdog bounds it. |
| RT39 | Cut exFAT. | Low | Rejected → common on removable media, covered by `FAT_DETECT` at no parser cost; the generator falls back to an empty file system. |
| RT40 | Run Plaso on the raw image for completeness. | Low | Rejected → dfVFS's image / volume / file-system stack on hostile input and hours of runtime (research §4). |
| RT41 | Put `disk-worker` behind an opt-in compose profile. | Low | Rejected → consistency with M8; `mem_limit` is a cap, not a reservation; DEPLOYMENT states the sum of worker caps against host RAM. |

Seed questions given to the reviewers (kept for traceability):

1. Can a hostile image make a probe escape its limits: RSS above `RLIMIT_AS` through mmap in pytsk3 / libewf, a directory cycle or a deep tree defeating the walker's visited set and depth cap, a lying EWF segment table, gigabytes of rows before the visitor's cap?
2. Is "explicit FS types, no autodetection" enough to keep the APFS / ISO 9660 / HFS parsers unreachable in pytsk3 20260715, or does `FS_Info` with an explicit type still probe others?
3. Does Plaso 20261027 in `--single-process` mode, with no analysis plugins and `json_line` output, really open no socket, spawn no subprocess and load no network module at run time (pyzmq, opensearch-py, redis, requests)? Is the audit-hook wrapper around the Plaso entry points sound?
4. Is the extraction-first design (Plaso only on the mirrored artifact tree) correct for Plaso's preprocessing (time zone, users, host name) and for path attribution, or does it lose events that matter for triage?
5. Is collect-and-mirror safe: hostile names (`..`, `/`, NUL, very long, case collisions, reserved names) written to the worker's ext4 `/work`; symlink entries; hard-link loops; a compressed artifact (`.gz`) decompression bomb inside Plaso?
6. Segment sets: can an analyst combine evidence across investigations or orgs, reorder segments to confuse integrity checks, or exhaust the quota / `/work` with 64 × 8 GiB? Is the image cache (hard links, org + sha256 keys, TTL) a cross-job or cross-tenant leak?
7. Is "TLP:RED by default, admin release, derived evidence inherits" right for disk images and exported files? Should the file listing (paths and names of personal documents) be hidden from non-admins? Is the in-org known-hash join acceptable?
8. Export: does promoting a worker-produced object through the evidence pipeline keep the "API never executes untrusted files" rule, and is the untrusted `worker_sha256` never shown as verified?
9. Do 500 000 files + 250 000 events per job fit the ingest worker (a solo pool shared with the reaper and the correlation indexer, M7 RT19), Postgres size and the read API's 5 s statement timeout?
10. Scope: is anything YAGNI for a learning-grade single-node platform (the `full` profile, exFAT, the image cache, multi-file exports, the timestamp-anomaly rule, the body-file export), and is anything missing that analysts expect first (VSS, BitLocker with a recovery key, APFS)?

## Phases

| Phase | Name | Group | Depends on | Status |
|-------|------|-------|------------|--------|
| 1 | [Foundation contracts migration and disk worker skeleton](./phase-01-foundation-contracts-migration-and-disk-worker-skeleton.md) | A | — | Pending |
| 2 | [TSK probe image volumes filesystems and file walk](./phase-02-tsk-probe-image-volumes-filesystems-and-file-walk.md) | B (2a, lane 2, `--heavy` for image runs) | 1, 4 | Pending |
| 3 | [Plaso artifact timeline engine](./phase-03-plaso-artifact-timeline-engine.md) | spike 3a: A′ (parallel with phase 1, one-off container); rest 3b: B (2b, lane 3, `--heavy`) | 3a: —; 3b: 1, 4 | Completed (code), Docker pending (3a spike, `plaso.lock`) |
| 4 | [Synthetic disk image generator](./phase-04-synthetic-disk-image-generator.md) | A′ (parallel with phase 1, one-off container; merged before group B) | — | Completed (code), Docker pending |
| 5 | [Known file hash sets and YARA file scan](./phase-05-known-file-hash-sets-and-yara-file-scan.md) | B (2c, lane 4) | 1 | Pending |
| 6 | [Disk detections and scenario dataset](./phase-06-disk-detections-and-scenario-dataset.md) | B (2d, lane 5) | 1 | Pending |
| 7 | [Disk dispatch segment sets and trusted ingest](./phase-07-disk-dispatch-segment-sets-and-trusted-ingest.md) | B (2e, lane 6) | 1 | Pending |
| 8 | [Disk read API and timeline export](./phase-08-disk-read-api-and-timeline-export.md) | B (2f, lane 7) | 1 | Pending |
| 9 | [Sensitivity reports AI TI retention and correlation integration](./phase-09-sensitivity-reports-ai-ti-retention-and-correlation-integrat.md) | B (2g, lane 8) | 1 | Pending |
| 10 | [File export to derived evidence](./phase-10-file-export-to-derived-evidence.md) | B (2h, lane 9) | 1 | Pending |
| 11 | [Disk forensics frontend](./phase-11-disk-forensics-frontend.md) | B (2i, web only) | 1 (frozen contracts) | Pending |
| 12 | [Docs threat model and license notices](./phase-12-docs-threat-model-and-license-notices.md) | C | B merged | Pending |
| 13 | [Hardening e2e fuzz metric and gate](./phase-13-hardening-e2e-fuzz-metric-and-gate.md) | D | all | Completed (code), gate pending Docker |

Effort (after the red team: the cache, the rename and one rule cut; stage isolation, the watchdog, the deadline budget, the disk ingest worker, the Plaso builder stage and export fallback, hard-link names and batch release added): 26 + 25 + 25 + 14 + 15 + 15 + 21 + 14 + 13 + 14 + 18 + 9 + 15 = **224 h** (phase 3 = 6 h spike + 19 h engine). Critical path: max(phase 1 26 h, A′ 14 h) → max(B) (phase 2, 25 h) → 12 (9 h) → 13 (15 h) ≈ **75 h** of wall time with nine group-B agents. At most three lane slots at once, and a `--heavy` lane takes two.

## Dependencies and parallelism

**Cross-plan:** blocked by `261107-0300-cyberlab-m8-memory-forensics`. Its gate (`pnpm verify:prod`) must be green and merged first. Phase 1 then:
- confirms the alembic head (expected `0016` from M8 → M9 is `0017`; M10 then takes `0018`, M11 `0019`);
- re-reads the M8 files it extends: `memory_analysis/sensitivity.py` (only a wrapper is added there, RT2), `router_sensitivity.py`, `evidence/share_policy.py`, `cyberlab_jobs/report.py` (`Omissions`, `canonical_json`), `memory_worker/detections/mask.py`, `tests/unit/test_analyzer_exhaustive.py`, `scripts/lane-test.sh` (`--heavy`, lane 8), compose anchors, `infra/redis-broker/entrypoint.sh`;
- reports any divergence from the M8 worktree state recorded in "What exists today" to the parent before freezing;
- creates `feat/m9-disk-forensics` from the M8 merge.

The MinIO image decision of M7 (user) and the VSL publishing decision of M8 (user) do not block M9.

**Group A′ (parallel with phase 1, before group B):**
- **Phase 4:** the image generator, in worktree `..\cyber-wt\m9-gen` from the M8 merge, developed against a one-off `debian:trixie-slim` container (unprivileged: no `--privileged`, no loop device, no FUSE; parent decision) with the package list it owns (`apps/workers/disk/docker/diskgen-packages.txt`). No compose service, no slot.
- **Phase 3a:** the Plaso packaging spike, in worktree `..\cyber-wt\m9-plaso` from the M8 merge, in one-off `python:3.12-slim-trixie` containers: the builder stage that compiles the sdist-only libyal bindings (RT11), the lock file `plaso.lock`, the `--single_process` run and the psort run under the kit's seccomp filter on a tiny generated tree, a recorded `json_line` sample and the parser names of 20261027. No slot.
- Both are merged into the phase-1 branch **before** phase 1 builds the image (the Dockerfile reads `diskgen-packages.txt` in the dev target and installs `/opt/plaso` from the builder stage's wheels per `plaso.lock`). A spike blocker (a binding that will not compile, or psort that cannot run single-process and no working storage-reader fallback) is reported to the parent, which decides (the official Plaso image as a separate stage, or replay-only timelines) before phase 1 freezes the Dockerfile.

**Group A: phase 1, one agent; frozen when committed.** Only the parent changes frozen files afterwards. A change request goes to the parent, which decides and broadcasts it.

**Frozen interfaces** (phase 1 notes record the exact signatures):
1. **Contract `packages/py-jobs/src/cyberlab_jobs/disk.py`**, exported from `__init__.py`:
   - `DISK_SCHEMA = "disk.v1"`, `DISK_EXPORT_SCHEMA = "disk-export.v1"`;
   - `DiskProfile` (`triage`, `full`, `extract`), the M8 `OsHint`, `ImageFormat` (`raw`, `split_raw`, `ewf`), `DiskStage` (`download`, `verify`, `layout`, `walk`, `collect`, `scan`, `timeline`, `extract`), `StageStatus` (`ok`, `failed`, `timeout`, `skipped`, `truncated`, `unsupported`; `skipped` carries a reason such as `deadline`), `FsType` (`ntfs`, `fat12`, `fat16`, `fat32`, `exfat`, `ext2`, `ext3`, `ext4`), `DiskArtifact` (`evtx`, `registry_system`, `registry_user`, `prefetch`, `lnk`, `mft`, `amcache`, `browser`, `recycle_bin`, `syslog`, `auth_log`, `utmp`, `shell_history`, `cron`, `systemd_journal`, `packages`, `preprocess`), `ARTIFACTS_BY_PROFILE`, `NEVER_COLLECT_PATTERNS` (the never-collected classes of plan "Scope", shared by the catalog of phase 3 and the export checks of phase 10) with `never_collect(names: Iterable[str], fs_case_insensitive: bool) -> bool` (true when **any** name of the inode matches; RT7), `YARA_MAGIC_CLASSES`;
   - `DiskLimits` (the caps, budgets, stage limits and write budgets above, `DISK_MAX_MEDIA_BYTES`, `min_free_bytes`, the 900 s deadline reserve; `stage timeouts < timeout_s`);
   - `DiskSegment` {`ordinal`, `evidence_id`, `expected_sha256`, `size_bytes`, `url`};
   - `DiskJobV1` {`job_id`, `organization_id`, `segments[]` (1..64, ordinals 0..n-1 contiguous), `profile` (`triage` / `full`), `os_hint`, `result_post`, `ingest_token`, `limits`, `deadline_at`} (no cache key, RT1);
   - `DiskExportJobV1` {`job_id`, `organization_id`, `source_job_id`, `segments[]`, `files[]` (1..20: `export_id`, `partition_index`, `meta_addr`, `meta_seq`, `stream?`, `expected_size` ≤ 64 MiB), `result_posts[]` (one per file + one for the result stream), `ingest_token`, `limits`}.
   - **The result lines:**
     - `DiskResultHeader` {`job_id`, `profile`, `engine` (`tsk`), `timeline_engine` (`plaso` | `replay` | `none`), `tool_versions` (pytsk3, TSK, libewf, plaso, artifacts, yara, rules sha256), `image` {`format`, `segments`, `media_size`, `sector_size`, `media_sha256?`, `ewf?` {`stored_md5?`, `stored_sha1?`, `media_hash_status` (`matched` / `mismatch` / `absent` / `not_verified`), `meta`}}, `hashsets[]`, `stages[]` {`stage`, `partition_index?`, `status`, `rows`, `truncated`, `duration_ms`, `error_code?`, `audit_counts`}, `artifacts[]` {`artifact`, `files`, `bytes`, `events_read`, `events_stored`}, `truncated`};
     - `DiskPartitionRecord`, `DiskFileRecord` (natural key `partition_index` + `meta_addr` + `meta_seq` + `stream` + `parent_addr` + `name`: one record per name, so a hard-linked inode appears once per directory entry with `hard_linked` set; `parent_addr` for directory browsing, RT13), `DiskEventRecord` (with `ordinal` and an optional file natural key);
     - the shared `FindingRecord`, `IocRecord` and timeline record, and `ResultTrailer`.
   - `DiskExportResultV1` {header {`job_id`, `files[]` {`export_id`, `status`, `size`, `sha256` (worker-computed), `error_code?`}}, trailer}.
   - `HashSetManifestV1` (the store manifest shared by the worker and the tool).
   - `DiskView` (the detection input: partitions, files, an event iterator) in `cyberlab_jobs.disk` so phase 6 and phase 2 build against one type.
   - **Framing:** header first, trailer last, the M3 value bounds; the **diagnostic stream** (`no_supported_filesystem`, `unsupported_disk_format`): header + at most the partitions + trailer.

   Tasks `DISK_ANALYZE = "disk.analyze"`, `DISK_EXPORT = "disk.export"`, `Queues.disk`.

   **Report snapshot field** (RT10 pattern of M8): `Omissions.disk_restricted: int | None = None`; `canonical_json` pops `omissions.disk_restricted` when it is `None` (M8 built `memory_restricted: int = 0`, RT23); `test_report_canonical_golden.py` gains the M8 omissions fixtures.
2. **Fixtures `tests/fixtures/disk/`** (in py-jobs, shared by the API and the worker): `windows_triage.ndjson`, `linux_triage.ndjson`, `ewf_mismatch.ndjson`, `no_supported_filesystem.ndjson`, `export_result.ndjson`, `hostile/*.ndjson`; and `tests/fixtures/psort/*.jsonl` (psort `json_line`-shaped rows, hand-written from the spike's recorded shape, labelled synthetic). Round-tripped by `test_disk_contract.py`.
3. **Migration (expected 0017)** and the models in `app/modules/disk_forensics/models.py`; `Analyzer.DISK`; the `source` column on M8's `memory_sensitivity` (no rename, RT2). Later schema needs go into the next number, assigned by the parent.
4. **Schemas and 501 stubs** for every new route, then one `pnpm gen:contracts` run:
   - `disk_forensics/schemas.py`;
   - the analysis request body gains `segments` (for disk);
   - `EvidenceOut.sensitivity` (state + `source`, beside M8's field, which stays) and `EvidenceOut.derived_from`;
   - the error codes `disk_image_too_large` (413), `disk_image_set_too_large` (413), `disk_segments_invalid` (422), `disk_image_empty`, `evidence_sensitivity_restricted`, `evidence_sensitivity_released` (disk / derived sources; M8's memory codes unchanged), `disk_export_not_allowed` (409: deleted, not regular, too large, not allocated, never-collected), `disk_export_not_ready`, `disk_export_already_promoted`, `disk_export_expired`, `insufficient_storage` (507, M8).

   Routes (under `/api/v1/orgs/{org_id}`):

   | Method and path | Permission | Phase |
   |---|---|---|
   | existing `POST /investigations/{inv}/evidence?kind=disk` | `evidence.write` | 7 |
   | existing `POST /evidence/{id}/analyses` (`analyzer: disk`, `segments`) | `evidence.write` | 7 |
   | `GET /analyses/{job}/disk` (summary) | `evidence.read` | 8 |
   | `GET /analyses/{job}/disk/partitions` | `evidence.read` | 8 |
   | `GET /analyses/{job}/disk/files`, `…/files/{file_id}`, `…/dirs` | `evidence.read` | 8 |
   | `GET /analyses/{job}/disk/events`, `…/timeline` | `evidence.read` | 8 |
   | `GET /analyses/{job}/disk/exports/{bodyfile,timeline.csv,timeline.jsonl,notable-hashes.txt}` | `evidence.read` (audited) | 8 |
   | `GET /evidence/{id}/sensitivity`, `POST …/sensitivity/release` (optional `job_id`: batch release of a disk job's segments, RT20) | `evidence.read` / `org.update` | 1 (generic routes over M8's service, implemented; batch arm phase 9) |
   | `POST /analyses/{job}/disk/file-exports` (body `{file_ids}`: 1..20; distinct from the interop `GET …/disk/exports/*`; RT29) | `evidence.write` | 10 |
   | `GET /disk-exports/{id}`, `POST /disk-exports/{id}/promote` | `evidence.read` / `evidence.write` | 10 |
5. **Cross-phase entry points** (stubs; ownership moves to the named phase, which never changes the signature):
   - `disk_forensics/dispatch.py: build_disk_message(job, segments, settings) -> DiskJobV1` and `build_export_message(...) -> DiskExportJobV1` (phases 7 / 10);
   - `disk_forensics/ingest.py: async ingest_disk(job, msg, path) -> None`, `async ingest_disk_diagnostic(job, msg, path) -> None` (phase 7) and `disk_forensics/ingest_export.py: async ingest_disk_export(job, msg, path) -> None` (phase 10); `workers/ingest.py` hands a disk `finished` event to the task `disk.ingest` on the queue `ingest_disk` (`disk_forensics/handoff.py: async hand_off(job, msg) -> None`, phase 7: deadline moved by `DISK_INGEST_TIMEOUT_S`), whose task body dispatches by schema version (the branches are added by phase 1; RT9);
   - `evidence/sensitivity.py: async apply_restricted_default(session, org_id, evidence_id, actor_id, source) -> bool` (**implemented** in phase 1 over M8's function, RT2; phase 9 adds the disk-specific callers' tests and the batch release);
   - worker `disk_worker/detections/__init__.py: run(view: DiskView, limits: DiskLimits) -> DetectionOutput` (phase 6; called by phase 2);
   - worker `disk_worker/hashsets/store.py: HashSetStore(root).match(sha256, sha1, md5) -> HashSetHit | None` and `.manifest()` (phase 5); `disk_worker/scan.py: build_candidates(files, profile, limits) -> list[Candidate]` and `parse_scan_output(path) -> list[YaraHit]` (phase 5); all called by phase 2's pipeline;
   - worker `disk_worker/timeline/__init__.py: run_timeline(dirs, partitions, profile, limits, budget) -> TimelineOutput` and `catalog.match(files, os, profile) -> CollectPlan` (phase 3; called by phase 2; `budget` is phase 2's deadline budget object, `budget.timeout(stage) -> float`);
   - worker `disk_worker/stage.py: run_stage(argv, dirs, stage, limits, budget) -> StageResult` (phase 2: the shared stage runner with the watchdog, the post-stage kill and read-only sealing, RT3 / RT4 / RT5; used by phases 3, 5, 10);
   - worker `disk_worker/export.py: handle_export(msg: DiskExportJobV1) -> None` (phase 10; uses phase 2's `probe extract`);
   - the beat task `disk.expire_exports` (registered on the ingest beat by phase 1) → `disk_forensics/export_service.py: async expire_exports(limit) -> int` (phase 10: marks `expired`); the object versions are deleted by the retention worker's export arm (phase 9, the purge user; RT19);
   - `cyberlab_worker/mask.py`, `cyberlab_worker/yara_rules.py` (**implemented** in phase 1: the M8 masker, and M3's `rulefiles.py` plus the YARA parts of `detections/signatures.py`, lifted verbatim with shims; RT8).
6. **`ops/error_classes.py`** gains every disk code (**implemented** in phase 1), for example:
   - `unsupported_disk_format`, `no_supported_filesystem`, `disk_image_too_large`, `disk_segments_invalid` → input;
   - `disk_parse_failed`, `timeline_failed` → parse;
   - `insufficient_disk`, `stage_timeout` → infra;
   - the kit's existing `integrity_mismatch` (segment download) and `export_hash_mismatch` → integrity (RT22).
7. **Settings** (`core/config.py`): `DISK_MAX_UPLOAD_BYTES` (≤ 16 GiB), `DISK_MAX_SEGMENTS`, `DISK_MAX_IMAGE_BYTES` (16 GiB default, ≤ 64 GiB), `DISK_MAX_MEDIA_BYTES` (2 TiB), `DISK_MAX_RESULT_BYTES`, `DISK_MAX_RESULT_DECOMPRESSED_BYTES`, `ANALYSIS_DISK_TIMEOUT_S`, `DISK_INGEST_TIMEOUT_S` (1 800 s), `DISK_MAX_ACTIVE_PER_ORG`, `DISK_MAX_ACTIVE_TOTAL`, `DISK_EXPORT_MAX_BYTES` (64 MiB), `DISK_EXPORT_MAX_FILES` (20), `DISK_EXPORT_TTL_S` (7 days, then `expired`; the retention worker deletes the object), the per-kind caps.

   Worker settings: the stage limits table, `DISK_HASHSETS_DIR`, `DISK_WORK_MIN_FREE_BYTES` (4 GiB), `DISK_TIMELINE_ENGINE` (`plaso`; `replay` refused unless `TEST_PROFILE=1`), the M3 `test` rule directory (test profile only, phase 5), `CYBERLAB_TOOL_UID` / `GID` = 10007 in the image.
8. **Services** (compose; dev, test and prod):
   - `disk-worker`: the analysis network, the broker URL only, `disk_work` and `disk_hashsets:ro` volumes, the M3 / M8 isolation keys;
   - `disk-ingest-worker` (and `-test`): the api image, `--pool solo`, queue `ingest_disk`, `mem_limit 1g`, the ingest worker's env, network and `ingest_tmp` volume (RT9); the broker's ingest user may consume `ingest_disk`;
   - `disk-worker-test`: the same, but `/work` is a per-container tmpfs (1 GiB; generated images are ≤ 64 MiB) and `disk_hashsets_test:ro` (used only by phase 13's pipeline run; unit tests build temp stores), with bind mounts of `disk_worker/`, `tests/`, `samples/`, `dataset/` (the M8 RT6 pattern);
   - `disk-hashsets` and `disk-hashsets-test` (profile `tools`, `network_mode: none`, uid 10008, the store rw at `/hashsets`, `./.disk-import:/import:ro`);
   - the broker ACL user `disk`;
   - `CADDY_EVIDENCE_MAX` raised;
   - `scripts/lane-test.sh` accepts `--service disk-worker-test` and **lane 9** (`2..9`; `cyberlab_b9_test`, Redis / broker db 9, created if missing; M10 and M11 then find lane 9 present, RT27);
   - `package.json`: `disk:hashsets` (the compose run wrapper, implemented), `disk:gen` (runs phase 4's generator in `disk-worker-test`, implemented once phase 4 is merged) and `disk:metrics` (stub, exit 2).
9. **Worker skeleton** `apps/workers/disk/`:
   - `Dockerfile`:
     - `python:3.12-slim-trixie`;
     - the worker venv (pytsk3, libewf-python, yara-python, celery, the path packages) and `/opt/plaso` from `plaso.lock`;
     - a builder stage with a C toolchain compiling the sdist-only Plaso dependencies into hashed wheels (only wheels reach prod; RT11);
     - the M3 rule sources from the `static_rules` build context in `/opt/rules/image/` (compiled by the probe, RT8);
     - `cyberlab_plaso_launch` / `cyberlab_plaso_export` installed into `/opt/plaso` (RT24);
     - tool uid 10007 and hashsets uid 10008;
     - the forbidden-packages assertion (no Debian `sleuthkit` / `python3-tsk` / `ewf-tools` in prod, no `srch_strings`);
     - site-packages root-owned; `HOME=/nonexistent`;
     - license texts and `NOTICE` in `/usr/share/doc/cyberlab-disk/`; `versions.json`;
     - a dev target adding `diskgen-packages.txt` tools, `tests/` and `samples/`;
   - `pyproject.toml`, `uv.lock`, `plaso.lock`;
   - `disk_worker/{celery_app,config}.py` (implemented);
   - `analyzer.py` (stub: fails `not_implemented`); `stage.py` (stub signature, phase 2);
   - empty `probe/`, `normalize/`, `timeline/`, `detections/`, `hashsets/`, `samples/`, `dataset/` packages;
   - `tests/conftest.py`;
   - the py-worker-kit isolation tests wired into the image.
10. **Test helpers:**
    - `tests/disk_helpers.py` (`seed_disk_job()` from the fixture, `restricted_disk_evidence()`, `seed_segment_set(n)`);
    - `tests/security/idor_cases_disk.py` (phase-8 routes), `idor_cases_disk_exports.py` (phase-10 routes), each with `PENDING_ROUTES`;
    - `test_rls_coverage.py`, `test_append_only.py`, `test_analyzer_exhaustive.py` and the dynamic-gate test updated, then frozen.
11. **Web shared:**
    - `lib/nav.ts` (Forensics live), `lib/audit-actions.ts` (`disk.*`, including `disk.sensitivity_defaulted`), `lib/http-errors.ts` (the codes above);
    - the analyzer badge value `disk`;
    - the empty slots mounted once: `components/disk/run-disk-analysis.tsx` (in `evidence-analyses-card.tsx`), `components/disk/disk-upload-option.tsx` (in `evidence-uploader.tsx`), `components/disk/derived-evidence-badge.tsx` (in the evidence page);
    - `components/evidence/sensitivity-badge.tsx` over the generic sensitivity route (state + source) for disk and derived evidence; M8's `memory-sensitivity-badge.tsx` stays as it is (RT2).
12. **Analyzer sweep** (the M8 RT1 lesson, implemented): a disk arm in every analyzer-keyed branch:
    - `search/service.py:_job_href` (`/forensics/{job}`), `case_attack/sources.py`, `investigations/timeline.py:_ANALYZER_TITLE` ("Disk analysis"), `ops/{metrics,models,schemas}.py` (kinds and Literals), `reports/{citations,redact}.py`, `ai/service_outputs.py`, `analysis/{schemas,service}.py` (profile rules, the too-large error map);
    - web `lib/{analysis,correlation,ai}.ts` (route `forensics/{id}`, labels "Disk (triage)" / "Disk (full)" / "Disk (file export)", `JOB_TASKS.disk = []`);
    - the disk arm of `ai/context/builder.py:_digest_selections`: a stub raising `NotImplementedError` until phase 9;
    - `test_analyzer_exhaustive.py` and `lib/analysis.test.ts` fail when a map misses an `Analyzer` member.

**Group B: phases 2, 3b and 5–11, in parallel** (one subagent each, own worktree from the phase-1 commit, file-disjoint). Each phase's tests pass in isolation against the phase-1 stubs, fixtures and frozen schemas, and phase 4's generator (merged before the fork). Cross-phase behaviour is tested after the merge (phase 13). Nobody runs `pnpm verify` or the full suite in a lane.

| Phase | Owns (creates or edits; nobody else touches these in group B) |
|---|---|
| 2 (2a) | `apps/workers/disk/disk_worker/{analyzer,pipeline,stage,budget}.py`, `probe/**` except `probe/scan_yara.py` (image openers, `verify`, `layout`, `walk`, `collect`, the `scan` stage shell, `extract`), `normalize/**` except `normalize/events.py`, `tests/unit/test_{probe_*,normalize_*,walker,names,image_open,stage_isolation,watchdog,budget,pipeline,offline,audit_hook}.py`, `tests/engine/test_tsk_*.py` |
| 3 (3a spike, 3b) | `disk_worker/timeline/**` (catalog, collect plan, Plaso runner, the replay engine), `apps/workers/disk/plaso/{cyberlab_plaso_launch,cyberlab_plaso_export}.py` (installed into `/opt/plaso` by phase 1's Dockerfile), `disk_worker/normalize/events.py`, `apps/workers/disk/plaso.lock` and the builder-stage wheel list (3a, merged before phase 1 freezes), `tests/fixtures/psort_extra/**`, `tests/unit/test_{catalog,collect_plan,events_*,plaso_flags,replay}.py`, `tests/engine/test_plaso_*.py` |
| 4 (A′) | `apps/workers/disk/samples/diskgen/**`, `apps/workers/disk/docker/diskgen-packages.txt`, `samples/hives/**` (hivex `.reg` inputs), `tests/unit/test_diskgen.py`, `tests/engine/test_diskgen_images.py` |
| 5 (2c) | `disk_worker/hashsets/**` (store, manifest, import, sort, tool CLI), `disk_worker/scan.py`, `probe/scan_yara.py` (the in-probe YARA call, imported by phase 2's `scan` shell), `tests/unit/test_hashsets_*.py`, `test_scan_*.py`, `tests/integration/test_hashsets_tool.py` |
| 6 (2d) | `disk_worker/detections/**`, `apps/workers/disk/dataset/**`, `tests/unit/test_detections_*.py`, `test_dataset_quality.py`, `test_finding_wording.py`, `test_path_classes.py`, `test_evtx_fields.py` |
| 7 (2e) | `disk_forensics/{dispatch,handoff,ingest,stream,segments}.py`, the disk branches of `analysis/{service,dispatch,analyzers}.py`, the bodies of the disk branches in `workers/{ingest,reaper}.py` and of the `disk.ingest` task, `evidence/uploads.py` (the `kind=disk` default), `core/filetypes.py`, its tests |
| 8 (2f) | `disk_forensics/{router,repository,service,exports_interop}.py`, `tests/security/idor_cases_disk.py`, its tests |
| 9 (2g) | the guards in `reports/snapshot_sections.py`, the `disk_restricted` line in `apps/workers/report/report_worker/render_{md,html}.py`, the disk arm of `ai/context/builder.py`, `retention/select.py` (`BULK_TABLES`), the export-object arm of `app/workers/retention.py` (RT19), the batch-release arm of `evidence/sensitivity.py` (RT20), `correlation/indexer.py` (only if a test shows an analyzer filter), its tests |
| 10 (2h) | `disk_forensics/{export_router,export_service,ingest_export}.py` (the phase-1 stub `ingest_disk_export`; the dispatch call in `workers/ingest.py` is phase 1's branch, its body phase 7's file), `disk_worker/export.py`, `tests/security/idor_cases_disk_exports.py`, its tests |
| 11 (2i) | `apps/web/lib/{disk,disk-timeline,disk-exports}.ts` (+ tests), `lib/use-disk-job.ts`, `components/disk/**` (the slots included), `app/(app)/o/[orgId]/forensics/**`; no mount edits |

- **Shared files touched only by phase 1:**
  - `core/config.py`, `app/main.py`, `app/models.py`, `analysis/models.py`, `ops/error_classes.py`;
  - `workers/{celery_app,tasks}.py`;
  - compose files, `.env.example`, `package.json`, `infra/redis-broker/entrypoint.sh`, `infra/caddy/*`, `scripts/lane-test.sh`;
  - `packages/py-jobs/**`, `packages/py-worker-kit/**`, `packages/contracts/**` (generated after phase 1, then after the merge);
  - `apps/workers/static/static_worker/{rulefiles,detections/signatures}.py` and `apps/workers/memory/memory_worker/detections/mask.py` (the shims);
  - `apps/workers/disk/{Dockerfile,pyproject.toml,uv.lock}`, `disk_worker/{celery_app,config}.py`;
  - the sensitivity extension (`evidence/sensitivity.py`, `evidence/router_sensitivity.py`, the one-line wrapper in `memory_analysis/sensitivity.py`, `evidence/share_policy.py`; phase 9 later adds only the batch-release arm);
  - `apps/web/lib/{nav,audit-actions,http-errors}.ts`, the analyzer badge, the slot mounts, the sensitivity badge;
  - the analyzer-sweep files (Frozen interfaces 12);
  - the frozen test files.
- **Group B merge (parent):**
  1. Merge the nine worktrees; any conflict is a plan bug.
  2. Full API suite.
  3. `pnpm gen:contracts` with no drift.
  4. `pnpm --filter web test typecheck`.
  5. Rebuild the disk image once (heavy, alone) and run the worker suite with `--heavy`. Every image that copies py-jobs / py-worker-kit (api, pcap, static, memory, report) was rebuilt once after phase 1, one at a time (the renderer must know `disk_restricted`).
  6. Fix seams in the owning files, one commit per phase.
- **Group C: phase 12** (docs) after the merge.
- **Group D: phase 13 last.** It is the only phase allowed to touch other phases' files, and only for gate fixes.
- **One commit per phase.** The stack stays deployable after each:
  - new routes answer 501 until their phase lands;
  - the disk worker fails jobs with `not_implemented`;
  - no disk job is ever created automatically.

### Parallel execution on this host (the M5–M8 lane scheme, `scripts/lane-test.sh`; 4–8 GB free RAM)

1. **One shared infra stack**, started by the parent after the M8 gate: `postgres`, `redis`, `redis-broker`, `minio` (+ init, `db-bootstrap`). Everything else is stopped during group B: web, gateway, every analyzer, report, enrich, analyst, retention and disk-ingest workers.
2. **Worktrees** `..\cyber-wt\m9-b{n}` (`-b m9/b{n}` from the phase-1 commit), with `.env` copied in.
3. **Image:** the parent builds `cyberlab/disk-worker:dev` once after phase 1 (heavy, alone: the Plaso builder stage compiles the sdist-only libyal bindings and the venv is large, RT11), then the api, pcap, static, memory and report images, one at a time. Lanes never build.
   - **A′ (phases 4 and 3a):** during phase 1, one-off unprivileged containers (`docker run --rm`, `mem_limit 2g`; no `--privileged`, no loop device, no FUSE: parent decision, RT26), **one at a time** beside phase 1's light work; never a compose service.
4. **Worker lanes** (`--service disk-worker-test`, broker db only):
   - phase 2 → lane 2;
   - phase 3b → lane 3;
   - phase 5 → lane 4;
   - phase 6 → lane 5.

   Runs that generate or open images, or run Plaso, add `--heavy` (two of the three slots). Pure unit runs take one.
5. **API lanes:**
   - phase 7 → lane 6;
   - phase 8 → lane 7;
   - phase 9 → lane 8;
   - phase 10 → lane 9 (`cyberlab_b9_test`, created by phase 1 if missing; its worker-side export test uses lane 9 with `--service disk-worker-test` afterwards, never concurrently). M10 and M11 reuse lane 9 after M9 (RT27).

   Run with `scripts/lane-test.sh <lane> uv run pytest -q -p no:cacheprovider <own paths>`.
6. **Never from a lane:** `up`, `down`, `build`, `restart` or `stop`.
7. **Heavy steps (the parent runs each alone, with only the infra stack up):**
   - the disk image build;
   - the A′ one-off containers when they build or install Plaso (3a);
   - phase 13's fuzz-lite and metrics replay.
   - **Never, anywhere:** a download of a disk image, a test corpus, Plaso test data, NSRL or any hash set (parent-level rule; the hashsets tool has no network at all).
8. **Web lane (phase 11):** host `pnpm --filter web test -- <own paths>`, `typecheck`, `lint`. No containers and no slot.
9. **Fallback** when worktrees misbehave on Windows: the M5 fallback (main tree, lane variables in the shell, `python -m compileall` before each run).

## Definition of done

- **Pipeline:**
  - An ordered set of 1–64 `kind=disk` segments (each ≤ 8 GiB, total ≤ 16 GiB by default) in raw, split raw or E01 can be analyzed on request with `triage` or `full`.
  - The worker verifies every segment's sha256 (and compares the EWF stored hash, shown as worker-reported), opens only DOS / GPT layouts and allow-listed file systems, each stage in its own sandboxed process (killed and sealed read-only after it, within the deadline budget and the write watchdog), offline, and posts a `disk.v1` stream.
  - The dedicated disk ingest worker validates it as a whole and writes it in one transaction, without delaying the shared ingest queue (reaper, correlation, other analyzers).
  - A partial run shows per-stage and per-partition status and `truncated` / `skipped` (`deadline`) flags.
- **Content:**
  - partitions, file-system facts, a file listing with deleted / orphan flags and NTFS streams, hashes within budgets, known-file matches, YARA hits, a merged timeline (file-system MACB + Plaso events from the allow-listed artifacts), findings, IOCs;
  - body file (`mactime`), timeline CSV / JSONL (Timesketch columns) and notable-hash list (Autopsy hash-set import) exports (audited).
- **Export:** an allocated regular file (≤ 64 MiB) none of whose names is on the never-collected list can be exported, promoted to derived evidence through the evidence pipeline (re-hashed by the trusted side), inherits the restriction and gets its normal static job; the custody of both items records the derivation; unpromoted objects are deleted by the retention worker after the TTL.
- **Sensitivity:**
  - A `kind=disk` upload (or else the first disk job) marks every segment restricted and AI / TI excluded, with no automatic analysis.
  - Secrets quoted into findings, IOC context and timeline titles are masked.
  - Release is admin-only, acknowledged, audited and once per item (a disk job's segments in one request).
  - Reports include restricted disk rows only at TLP:RED, else they are counted in `omissions.disk_restricted`; M6 and M8 signed snapshots keep their bytes.
  - The never-collected list is enforced on every name of an inode (tested on a generated image that contains each class and hard links to `SAM` and `etc/shadow`).
  - M8's `memory_sensitivity` table, routes and codes behave exactly as before (the M8 suite passes unchanged).
- **Hash sets:** `disk:hashsets` imports an RDSv3-schema SQLite (generated in tests) and plain lists without any network, verifies and lists; the result records each set's manifest sha256.
- **Detections:** every heuristic behaves as specified on the scenario set (precision / recall table, with the caveat); no heuristic exceeds `medium`; no verdict words.
- **Real engine:** TSK and libewf run on every generated image type; Plaso runs on the generated Linux tree (and the hive if the spike succeeds); EVTX / Prefetch / LNK are replay-tested and documented as such.
- **Security:**
  - Every new route is in the IDOR enumerator and every new tenant table in RLS coverage.
  - The env checks prove the worker has only the broker URL and read-only hash sets, and the hashsets tool has no network.
  - Fuzz-lite ends cleanly, and the audit hooks record no network, subprocess or exec attempt in any probe or Plaso process; no tool process survives a stage, and no stage changes an earlier stage's output.
  - Every analyzer-keyed branch has a disk arm (`test_analyzer_exhaustive.py`).
- **Gate:** `pnpm verify:prod` is green (the dynamic-gate test included). The e2e covers segment upload, run, the job page (partitions, files, timeline), the restricted banner, an export and its promotion.
- **Docs:**
  - `docs/DISK_FORENSICS.md` (new);
  - ARCHITECTURE, THREAT_MODEL (M9), DATABASE (the new migration and the §11 `forensic_artifacts` mapping), API, DEPLOYMENT (sizes, disk footprint, the hash-set runbook, the operator smoke, the Autopsy workflow), TESTING (metrics), ROADMAP, PRD and README updated;
  - the license notices recorded.

## Out of scope

- **Acquisition:** imaging tools, agents, remote collection, write blockers.
- **Recovery:** carving, recovery of deleted file content, unallocated-space search, slack-space analysis, `tsk_recover`.
- **Formats:** VMDK, VHD / VHDX, QCOW, AFF / AFF4, Ex01 / Lx01 logical evidence, compressed or archived uploads, APFS, HFS+, ISO 9660, UFS, XFS, btrfs, LVM, mdraid, Storage Spaces, VSS.
- **Decryption:** BitLocker, LUKS, FileVault, VeraCrypt (detected and reported only).
- **Engines:** Plaso on the whole image, Plaso analysis plugins, Autopsy as a server component, ClamAV in the disk worker, full-text content indexing.
- **Cut by the red team ("Later"):** the image cache (RT1), renaming `memory_sensitivity` (RT2), `heuristic:disk_timestamp_anomaly@1` (RT28).
- **Automation:** auto-run on upload, automatic hash-set or NSRL download, online hash lookups (CIRCL hashlookup, nsrlsvr).
- **Upload:**
  - resumable or direct-to-MinIO multipart upload (ROADMAP "Later", shared with M8);
  - **ingest by reference** ("Later"; sketch: a trusted `evidence-intake` service, profile-gated, reading `./.intake/<org_id>/` read-only, streaming into the evidence bucket through the same hashing code, creating evidence with custody `imported_by_operator`, requested from the UI by `org.update` and confirmed by an operator CLI, so no tenant can name another tenant's file);
  - HTTP range reads instead of a local copy ("Later").
- **AI:** disk-specific AI tasks or prompts (generic AI over disk findings works only after release).
- **Never:** downloading any real disk image, test corpus, Plaso test data or NSRL release from a tool, test or gate.

## Open risks

- **Plaso packaging (phase 3a):** 53 direct dependencies, about 35 libyal bindings, eight of them sdist-only for cp312 (RT11): the builder stage compiles them (build time and a toolchain in the build only); if one will not compile, the parent chooses the official Ubuntu-based Plaso image as a separate stage, before phase 1 freezes the Dockerfile.
- **Plaso network and IPC:** extraction in `--single_process` starts only a status thread (red team, source); psort always uses a multi-process engine, so the spike runs it under the filter, and the storage-reader fallback replaces it if it starts a process (RT11); `zmq` is imported but must open no socket (audit hook, seccomp).
- **Windows artifacts not validated on a real image:** EVTX, Prefetch and LNK are replay-tested only (no Linux writer, no third-party data); the first real run happens on the operator's own image (operator smoke runbook).
- **Hostile images:** TSK's CVE history (research §1) is contained by the explicit FS allow-list, the sandbox, timeouts, `RLIMIT_AS` and caps, not prevented. pytsk3 is upgraded deliberately, with the generated-image suite as the regression check.
- **Ingest volume:** a result at the caps (≈ 750 000 rows) takes minutes in one transaction; it runs on the dedicated disk ingest worker (RT9), so the shared ingest queue is not delayed; phase 7 measures and records the time and size, and two disk results ingest one after the other.
- **Disk on the dev host:** a 16 GiB image set holds about 32 GiB plus the artifact tree at any moment (MinIO + `/work`; the write watchdog keeps a 4 GiB floor, RT4), MinIO keeps it at least `EVIDENCE_LOCK_DAYS`, and Docker Desktop's virtual disk does not shrink by itself; tests never upload more than 64 MiB. DEPLOYMENT states the sizing.
- **Contents exposure:** org-wide RBAC means every case reader sees paths, names and shell history of a released or TLP:RED image (THREAT_MODEL residual; per-case ACLs are future work).
- **Time zones:** FAT times are local without a zone (`time_basis = local_unknown`); text logs without a year or zone depend on Plaso's preprocessing of the mirrored tree (phase 3a checks); the UI labels both.
- **Scale ceiling:** segment sets do not remove the 16–64 GiB working limit; larger images need ingest by reference and range reads ("Later").
- **Repeated downloads** (RT1): an export or a `full` re-run downloads and re-verifies the whole segment set again (minutes for 16 GiB on localhost MinIO); the UI says so.
- **Integrity of EWF content:** libewf does not fail reads on chunk-checksum errors; without a stored media hash (`absent`) corruption is invisible (RT17).
