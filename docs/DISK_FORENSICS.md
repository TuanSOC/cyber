# Disk Forensics (Milestone 9, in progress)

> **Status: draft, M9 in progress.** Every phase (1–13) is committed on `feat/m9-disk-forensics` as code; phase 13's gate run (`pnpm verify:prod`), fuzz-lite and metric run are pending. **Nothing has run in a container yet**: the disk image cannot be built until phase 3a's spike replaces the `plaso.lock` placeholder and the worker's `uv.lock` exists. Every section says what is **built (untested in Docker)** and what is **pending (phase N)**. Nothing marked pending exists in code. Phase 13 replaces this banner once the gate (`pnpm verify:prod`) is green. Plan: [`plans/261107-1200-cyberlab-m9-disk-forensics/plan.md`](../plans/261107-1200-cyberlab-m9-disk-forensics/plan.md).

The fourth analysis engine triages uploaded **disk images** (raw, split raw, E01) with [The Sleuth Kit](https://github.com/sleuthkit/sleuthkit) through [pytsk3](https://github.com/py4n6/pytsk) (library mode) and [libewf](https://github.com/libyal/libewf), and builds an artifact timeline with [Plaso](https://github.com/log2timeline/plaso) run on a small extracted artifact tree, never on the image. It reuses the M2 / M3 / M8 pipeline:

1. An isolated, untrusted worker runs a fixed sequence of stages, **one sandboxed process per stage**, fully offline. It produces a versioned result stream (`disk.v1`).
2. A dedicated trusted ingest worker validates that stream as a whole, then writes it into the disk tables plus the shared findings, IOCs and timeline, in one transaction.
3. The Forensics UI shows the results (phase 11, untested).

Known-file hash sets come only from a local store that an operator fills with `pnpm disk:hashsets` from files they supply: nothing is ever downloaded. A disk image is treated as **TLP:RED material by default**.

**Scope: triage, not full forensics.** In: the partition table, file-system facts, a file listing with deleted names, orphans and NTFS named streams, hashes within budgets, known-file matching, YARA on PE files, an artifact timeline merged with the file-system times, deterministic findings, IOCs, single-file export of allocated files, interop exports. **Out:** carving and recovery of deleted content (deleted entries are listed, never hashed, scanned or exported), `strings` over unallocated space, VSS, decryption (BitLocker, LUKS, FileVault, VeraCrypt are detected and reported only), APFS / HFS+ / ISO 9660 / UFS / XFS / btrfs, LVM / mdraid / Storage Spaces, VMDK / VHD(X) / QCOW / AFF / Ex01 / L01, Plaso on the whole image, Plaso analysis plugins, Autopsy as a server component, full-text search of file contents.

See [MEMORY_ANALYSIS.md](MEMORY_ANALYSIS.md) for the analyzer this one is modelled on, and [PCAP_ANALYSIS.md](PCAP_ANALYSIS.md) for the shared job model.

## Build status

| Area | Phase | Status |
|---|---|---|
| `disk.v1` / `disk-export.v1` contract, `DiskLimits`, `PROFILE_BUDGETS`, `NEVER_COLLECT_PATTERNS`, `HashSetManifestV1`, fixtures (`packages/py-jobs/src/cyberlab_jobs/disk.py`) | 1 | built, untested in Docker (`test_disk_contract.py`, `test_disk_stream.py`) |
| Migration `0017`, models, RLS, grants, `source` on `memory_sensitivity`, generic sensitivity routes | 1 | built, untested |
| Compose: `disk-worker(-test)`, `disk-ingest-worker(-test)`, `disk-hashsets(-test)`, `disk-hashsets-init`, volumes, broker user `disk`, lane 9 | 1 | built, untested |
| Root magic check, image openers, `verify`, `layout`, `walk`, `collect` / `extract` probe code, stage runner (kill + seal), write watchdog, deadline budget | 2 | built, untested |
| Artifact catalog (`timeline/catalog.py`), collect plan, Plaso launcher and exporter, `run_timeline`, the event normalizer, the replay engine | 3 | built, untested (the 3a packaging spike and the real `plaso.lock` are **pending**: no image build until then) |
| Synthetic image generator (`samples.diskgen`, `pnpm disk:gen`), its package list | 4 | built, untested in Docker (pure-Python writers host-tested; the tool-built images and their tool checks pending Docker) |
| Hash-set store and tool, YARA candidates and scan | 5 | built, untested |
| Detections, scenario dataset | 6 | built, untested |
| `?kind=disk` upload, segment sets, dispatch, hand-off, trusted ingest, diagnostic ingest | 7 | built, untested |
| Read API, merged timeline, interop exports | 8 | built, untested |
| Sensitivity default, batch release, reports, AI / TI, retention, correlation | 9 | built, untested |
| File export to derived evidence | 10 | built, untested |
| Web: Forensics pages | 11 | built, untested |
| Hardening: e2e spec, pipeline tests, fuzz-lite, metric harness, env check, gate wiring | 13 | code written; the gate run, fuzz-lite and the metric report are **pending Docker** |

**Until the disk image is built and Plaso has run on the generated Linux tree** (phase 3a, then the gate), the event-based detections (log cleared, service installed, account change, remote logon, dual-use execution, the registry and cron-command persistence rules) are exercised only by unit tests and the replay engine.

## When it runs

| Upload | Analysis |
|---|---|
| `POST …/evidence?kind=disk` | **none, of any kind** (no static `av` scan either: the M8 RT3 rule). The evidence is marked restricted (source `disk`, AI and TI excluded) in the upload transaction |
| any other upload | the M2 / M3 automatic routing; disk analysis is never automatic |

- **Always manual.** An analyst runs "Run disk analysis" with `analyzer: disk`, the ordered `segments` (evidence ids, segment 0 = the evidence of the request path), a `profile` (`triage`, default, or `full`) and an `os_hint` (`auto`, `windows`, `linux`). The API refuses an automatic disk job. A run costs minutes to hours and gigabytes of disk.
- **Images uploaded without `kind=disk`** can still be analyzed: the request applies the same restricted default to **every** segment (idempotent). Jobs that already ran on a segment (an automatic static `av` scan of a small file) are covered only from then on.
- **Caps.** `DISK_MAX_ACTIVE_PER_ORG` = 1 and `DISK_MAX_ACTIVE_TOTAL` = 1 (one worker container). They do not share the pcap, static or memory caps. Queue TTL 12 h.

## Segment sets and limits

A job reads an **ordered list of 1–64 evidence items** of one investigation (`analysis_job_segments`). Each segment is uploaded as ordinary evidence within the per-request limit, which keeps the platform's single-request upload, Caddy's `read_body 30m` and the quota model unchanged.

- **E01:** upload `.E01`, `.E02`, … and list them in that order. The worker names them `image.E01`, `image.E02`, … by the job's order and libewf checks each segment's stored number against its position, so a reordered, foreign or missing segment, or a lying segment count, fails the open (`unsupported_disk_format`).
- **Split raw:** upload `.001`, `.002`, … and list them in order. **Order matters and nothing can check it**: raw segments carry no sequence numbers, so a wrong order yields a garbled image (layout errors, unreadable file systems), not a refusal. The worker also computes a concatenated media sha256.
- **Single raw / dd:** one segment.

| Limit | Value | Status |
|---|---|---|
| Segment size (`DISK_MAX_UPLOAD_BYTES`) | 8 GiB default; the setting is refused above 16 GiB (the M8 Caddy bound) | built (phase 7) |
| Segments (`DISK_MAX_SEGMENTS`) | 64 | built |
| Set total (`DISK_MAX_IMAGE_BYTES`) | 16 GiB default (under the 20 GiB default org quota, RT21); validated ≤ 64 GiB | built |
| Claimed EWF media size (`DISK_MAX_MEDIA_BYTES`) | 2 TiB; above it `unsupported_disk_format` (reason `media_size`), so a small E01 claiming petabytes cannot keep `verify` busy (RT6) | built |
| Gateway (`CADDY_EVIDENCE_MAX`) | max(`MAX_EVIDENCE_BYTES`, `MEMORY_MAX_BYTES`, `DISK_MAX_UPLOAD_BYTES`) + 1 MiB on the upload route | built |
| Upload time | Caddy `read_body 30m`: 8 GiB needs ≥ 4.6 MB/s sustained, 16 GiB ≥ 9.2 MB/s; no resume | as M8 |
| Job | `ANALYSIS_DISK_TIMEOUT_S` 14 400 s (≤ 21 600); each stage gets min(its cap, time left − 900 s) | built |
| Ingest | `DISK_INGEST_TIMEOUT_S` 1 800 s after the hand-off; framing `DISK_MAX_RESULT_DECOMPRESSED_BYTES` 1.5 GiB, lines = the sum of the caps + 3 | built |
| Result | ≤ 256 MiB compressed | built |
| Record caps | partitions 128, file systems 32, files 500 000 (≤ 2 000 000), NTFS streams 16 per file, stored events 250 000 (events read through detections ≤ 20 000 000), findings 5 000, IOCs 20 000, shared timeline 5 000; path ≤ 4 096 bytes, name ≤ 1 024, message ≤ 2 048, EWF header values ≤ 256, event attributes ≤ 32 scalars (≤ 4 KiB) | built |

Segment refusals (`422 disk_segments_invalid` with a `reason` and the offending `ordinal`): `first_segment`, `too_many`, `duplicate`, `not_found` (another org's id is indistinguishable from an unknown one), `other_investigation`, `purged`, `archived`, `empty`. A trigger on `analysis_job_segments` re-checks the investigation at insert. Size refusals are `413 disk_image_too_large` / `disk_image_set_too_large`.

**No image cache** (RT1). The worker empties its whole work dir before every job, so every job, including a `full` re-run and a file export, downloads and re-verifies the whole segment set again (minutes for 16 GiB on localhost MinIO). A cache returns with HTTP range reads ("Later").

## Pipeline

```mermaid
sequenceDiagram
  participant U as Analyst
  participant A as API
  participant B as redis-broker
  participant W as disk-worker (untrusted)
  participant S as MinIO
  participant I as ingest-worker (trusted)
  participant DI as disk-ingest-worker (trusted)
  participant D as Postgres
  U->>A: upload segments ?kind=disk (no auto-run; restricted + AI/TI excluded in the upload transaction)
  U->>A: POST analyses {analyzer: disk, segments, profile, os_hint}
  A->>D: job + analysis_job_segments + default on every segment + custody + audit
  A->>B: disk.analyze {DiskJobV1: one presigned GET per segment, presigned POST, token, DiskLimits, deadline}
  B->>W: job (queue disk, ACL user disk)
  W->>W: root: free space >= image + 3 x artifact budget + floor + 2 GiB
  W->>S: GET every segment to /work/<job>/input (sha256 + size verified, root-owned 0444)
  W->>W: root: magic check (refused formats -> unsupported_disk_format)
  W->>W: probe layout -> verify (EWF) -> walk per file system (OS partitions first)
  W->>W: root: hash sets, never-collect over every name, YARA candidates
  W->>W: probe collect per OS partition -> probe scan -> Plaso per OS partition (phase 3)
  W->>W: root: bounded reads -> detections over every event -> event storage selection -> disk.v1
  W->>S: POST result (fixed key, size cap)
  W->>B: ingest.event finished {result version}
  B->>I: event (token + org checked)
  I->>D: job deadline += DISK_INGEST_TIMEOUT_S
  I->>B: disk.ingest (queue ingest_disk)
  B->>DI: disk.ingest
  DI->>S: GET exact result version, validate every line + trailer (pass 1)
  DI->>D: one transaction (pass 2): disk_* + findings + iocs + timeline + known-hash join + custody
```

- **States** are the M2 ones: `queued → running → succeeded | failed`, enforced by the database.
- **Job success:** the downloads, `layout`, `verify` (EWF only; a timeout or skip leaves `not_verified`, never a failure) and at least one `walk` succeed. Every other stage is best effort, and its status (`ok`, `failed`, `timeout`, `skipped` with a reason such as `deadline` or `not_available`, `truncated`, `unsupported`) is reported per stage and per partition in the header, so a partial run is never shown as complete.
- **Diagnostic stream.** When no file system can be opened, the worker uploads the header and the partitions only and fails `no_supported_filesystem`; a format refused by a probe (libewf, the media-size cap) fails `unsupported_disk_format` with the same kind of stream. The ingest stores `disk_images` and `disk_partitions` only.
- **Why a separate ingest worker** (RT9): a result at the caps is about 750 000 rows in one transaction. The shared ingest worker is `--pool solo` and also runs the reaper and the M7 correlation tick, so it only authenticates the `finished` report, moves the job deadline and hands the report to the queue `ingest_disk`. Two disk results ingest one after the other.
- **Error codes** (`DISK_ERROR_CODES`, classified in `ops/error_classes.py`):

  | Code | Class | Meaning |
  |---|---|---|
  | `unsupported_disk_format`, `disk_image_too_large`, `disk_image_set_too_large`, `disk_segments_invalid`, `disk_image_empty`, `no_supported_filesystem`, `disk_export_not_allowed` | input | refused before or instead of any analysis |
  | `disk_parse_failed`, `timeline_failed`, `walk_memory` | parse | TSK or Plaso could not make sense of the image, or a walk ran out of memory |
  | `insufficient_disk`, `stage_timeout`, `engine_unavailable` | infra | disk, time, engine |
  | `integrity_mismatch`, `export_hash_mismatch` | integrity | a segment differs from its evidence record (the kit's code, RT22); an exported file's trusted hash differs from the worker's |
  | `not_implemented` | other | an unimplemented stub |

## Stages

Root never parses image bytes beyond the magic check: the first 4 KiB of segment 0 and the last 512 bytes of the last segment (a VHD footer).

| Stage | Process | Reads | Writes |
|---|---|---|---|
| download | root (kit) | presigned GETs | `input/image.*` (sha256 + size verified) |
| `layout` | probe | the image | partitions, file-system facts, OS markers, the EWF stored hashes and media size |
| `verify` (EWF only) | probe | the whole media in 4 MiB chunks | our MD5 / SHA-1 / sha256 vs the stored ones |
| `walk` (one per file system) | probe | the file system | one row per name, hashes within the budget |
| `collect` (one per OS partition) | probe | the planned artifact files | the mirrored tree `artifacts/p<i>/…` + `collected.jsonl` (phase 3, untested) |
| `scan` | probe | the YARA candidates | hit lines (rule, namespace, tags, counts; never matched data) |
| `log2timeline`, event export (one each per OS partition) | Plaso venv | the sealed mirrored tree | Plaso storage, `events.jsonl` (phase 3, untested) |
| `extract` (export jobs) | probe | one file by natural key | `export/<n>` (phase 10) |

### Stage isolation (RT3–RT5)

Every probe runs as `python -I -s -B -m disk_worker.probe <stage> <input/<name>.json>`: every argument comes from a root-written JSON file in the read-only `input/` dir, never from argv strings built from image data.

| Control | Detail | Status |
|---|---|---|
| Tool uid | **10007** (`CYBERLAB_TOOL_UID` / `GID`), the disk worker's own: `RLIMIT_NPROC` counts every process of a uid on the host | built |
| seccomp | `unix_sockets_only=True`, `deny_io_uring=True` | built |
| rlimits per stage | `RLIMIT_AS` / `FSIZE` per stage (below), `RLIMIT_NPROC` 64, CPU = the timeout | built |
| Audit hook | a PEP 578 hook installed after the imports refuses and counts `socket.*`, `urllib.Request`, `subprocess.Popen`, `os.exec*`, `os.posix_spawn*` / `os.spawn*`, `os.system`, `os.fork`, and `ctypes.dlopen` outside the venv; the counts reach the stage report | built (probe and the Plaso launcher, phase 3); untested |
| Fresh out dir | created by root after every tool process was killed, tool-owned 0700; `TMPDIR` / `XDG_CACHE_HOME` inside it, `HOME` = `XDG_CONFIG_HOME` = `/nonexistent` | built |
| Kill + seal | after each stage root kills every tool-uid process (a `setsid` survivor cannot reach the next stage; `SandboxCompromised` stops the container) and makes the out dir root-owned read-only (dirs 0555, files 0444) through `O_NOFOLLOW` descriptors; planted symlinks, FIFOs, sockets and devices are removed, never followed | built |
| Deadline budget | each stage's timeout is min(its cap, time left before the job deadline − 900 s); a stage that cannot get its minimum run time is `skipped` (`deadline`) and never started, so the reaper never kills a running job | built |
| Write watchdog | a root thread polls `statvfs` every 2 s and kills the stage when the volume grew past the stage's write budget, or free bytes fall below `DISK_WORK_MIN_FREE_BYTES` (4 GiB) or free inodes below 100 000 (`truncated`; `insufficient_disk` for the job when no walk has succeeded yet) | built |
| Probe exit | `status.json` carries the exception class name only, never a message that could quote image bytes | built |

| Stage | `RLIMIT_AS` | `RLIMIT_FSIZE` | Write budget | Timeout cap |
|---|---|---|---|---|
| `verify` | 1 GiB | 64 MiB | 64 MiB | media size / 100 MB/s + 600 s |
| `layout` | 1 GiB | 64 MiB | 64 MiB | 600 s |
| `walk` | 2 GiB | 2 GiB | 2 GiB | 3 600 s |
| `collect` | 1 GiB | the per-file artifact cap | the artifact budget + 64 MiB | 1 800 s |
| `scan` | 2 GiB | 256 MiB | 256 MiB | 3 600 s |
| `log2timeline` | 2.5 GiB | 8 GiB | 3 × the artifact budget | 5 400 s |
| event export | 2 GiB | 4 GiB | 4 GiB | 1 800 s |
| `extract` | 1 GiB | 64 MiB | 20 × 64 MiB | 600 s |

The caps sum past the job timeout on purpose (up to 32 file systems, 4 Plaso partitions): the deadline budget decides, and what does not fit is `skipped`.

## Formats and the TSK scope

**Accepted image formats:** raw / dd, split raw, EWF E01 (EnCase 1–7 / FTK, single or multi-segment). **Refused by root's magic check before any probe runs** (`unsupported_disk_format`, with the reason): gzip, bzip2, xz, zstd, lz4, zip, 7z, rar, cab, VMDK, VHD (header or footer), VHDX, QCOW, AFF, EWF2 (Ex01) and LEF / L01 (libewf's L01 parser has CVE-2026-111159).

**TSK never opens a path itself** (`TSK_IMG_TYPE_EXTERNAL`): our own readers (bounds-checked concatenation of the root-named segments, or a `pyewf` handle on exactly root's segment files) are the only code reading the files, so TSK's own image back ends (VMDK, VHD, AFF where built in) never see hostile bytes.

**No autodetection.** With an explicit type, TSK calls only that family's opener (red-team check of `fs_open.c` and `mm_open.c`):

1. **Volume system:** GPT first, then DOS / MBR (a GPT disk's protective MBR would otherwise parse as one DOS partition of type `0xEE`); neither: the whole image is one pseudo-partition at offset 0.
2. **Per partition**, in order:
   1. outside the media, or overlapping an earlier partition: `error`, never opened;
   2. **refusal signatures first:** BitLocker (`-FVE-FS-`) and LUKS → `encrypted`; APFS (`NXSB`), LVM (`LABELONE`), HFS+ (`H+` / `HX`) and ISO 9660 (`CD001`) → `unsupported`. Such a partition is never offered to any parser (FAT's weak boot-sector check could otherwise "open" foreign data; RT15);
   3. the explicit families **NTFS**, **FAT** (`TSK_FS_TYPE_FAT_DETECT`: FAT12 / 16 / 32, then exFAT) and **ext** (`TSK_FS_TYPE_EXT_DETECT`: ext2 / 3 / 4), the one hinted by the MBR type byte or the GPT type GUID first;
   4. nothing opened: `undetermined` ("unknown or encrypted"; no entropy guess).
3. **OS markers:** Windows = `Windows/System32/config/SYSTEM`; Linux = `etc/os-release` or `etc/debian_version`. `os_name` comes only from `PRETTY_NAME` (≤ 4 KiB read, symlinks never followed) and is inert text.

**Why the allow-list:** most published TSK parser CVEs sit in the parsers that are never tried: APFS keybag (CVE-2026-40025), ISO 9660 SUSP (CVE-2026-40026), HFS (CVE-2019-1010065, CVE-2018-19497), YAFFS (CVE-2020-10232); two more HFS CVEs published 2026-11-02 affect TSK 4.15.0 itself (red team, plan "Engines"). The NTFS one found (CVE-2020-10233) is old and fixed. A pytsk3 build without one of the family constants fails the open (`engine_unavailable`) instead of silently falling back to autodetection. **Pinned:** `pytsk3==20260715` (TSK 4.15.0 statically embedded) and `libewf-python==20260924`. The Debian `sleuthkit` (4.12.1, probably exposed to the 2026 CVEs), `python3-tsk` and `ewf-tools` packages are never installed in the prod image ([research §1](../plans/reports/researcher-261107-m9-disk-forensics.md#1-the-sleuth-kit-tsk)).

### The walk

- **Iterative**, with a visited set of directory `meta_addr`s (TSK's own loop guard lives only in `tsk_fs_dir_walk`, which is not used), depth ≤ 64, a per-directory entry cap, the file cap and a byte cap. Only allocated directories and TSK's `$OrphanFiles` are entered; symlinks are never followed.
- **Every name is its own row** (`parent_addr` = the walked directory's `meta_addr`), so an inode with several names (NTFS or ext hard links) appears once per name. Deleted names, orphans and reallocated entries are flagged; their content is never read. NTFS named `$DATA` streams are rows of their own (`Zone.Identifier` included).
- **Names:** decoded as UTF-8 with replacement (`name_lossy`), control characters escaped as `\xNN`, names cut to 1 024 bytes and paths to 4 096 on a UTF-8 boundary (`path_truncated`; 64 levels of 255-character names are valid rows, RT13).
- **Times:** NTFS and ext times are UTC; FAT times are local without a zone (`time_basis = local_unknown`, labelled in the UI).
- **NTFS memory** (RT30): TSK walks the whole MFT on the first listing; a walk that exceeds `RLIMIT_AS` makes the partition `error` (`walk_memory`) and keeps the layout.
- **Hashing:** md5 + sha1 + sha256 in one pass. Executables and scripts are hashed during the walk; other eligible files afterwards in walk order while the byte budget lasts. `hash_status`: `hashed`, `too_large`, `budget`, `not_allocated`, `not_regular`, `error`.

| | `triage` | `full` |
|---|---|---|
| Hashing | allocated regular files ≤ 64 MiB, budget 16 GiB read | allocated regular files ≤ 1 GiB, budget = the image size |
| YARA candidates | PE magic, ≤ 32 MiB each, ≤ 20 000 files, 4 GiB | PE magic, ≤ 64 MiB each, ≤ 100 000 files, 16 GiB |
| Artifact budget | ≤ 2 GiB, ≤ 20 000 files, ≤ 512 MiB each | ≤ 8 GiB, ≤ 20 000 files, ≤ 1 GiB each |
| Plaso partitions | ≤ 2 OS partitions | ≤ 4 |

## Artifact timeline: Plaso on a bounded tree (phase 3, untested in Docker)

Plaso never parses image, volume or file-system formats. The `collect` stage copies the catalog's artifact files out of the image into a tree that mirrors the original layout (`artifacts/p<i>/Windows/System32/config/SYSTEM`, `…/etc/timezone`, the user profiles), so Plaso's preprocessors still find the time zone, the users and the host name; then the tree is sealed read-only and Plaso parses it. One hostile-parser stack per surface: TSK for file systems, the libyal format parsers for artifact contents.

**The catalog** (`ARTIFACTS_BY_PROFILE`, frozen in the contract):

| OS | `triage` | `full` adds |
|---|---|---|
| Windows | EVTX (a fixed channel list), `SYSTEM` / `SOFTWARE`, `NTUSER.DAT` / `UsrClass.dat`, `Amcache.hve` (RT28), Prefetch, Recent LNK | `$MFT` (≤ 1 GiB), browser history (Chrome / Edge / Firefox), Recycle Bin `$I` files |
| Linux | `syslog` / `messages`, `auth.log` / `secure`, `wtmp` / `btmp` / `utmp`, shell history, cron, dpkg / apt logs, `etc/{timezone,localtime,hostname,passwd,os-release}` (preprocessing inputs only) | systemd journal, rotated `.gz` logs, browser history |

**The mirrored tree is written safely** (built in the probe, phase 2): allocated regular files and named streams only; directories created relative to the parent's descriptor and re-opened `O_DIRECTORY | O_NOFOLLOW`, files `O_CREAT | O_EXCL | O_NOFOLLOW`, so nothing resolves outside the out dir; known Windows components take their canonical spelling, every other component is reduced to `[A-Za-z0-9 ._-]` plus a 6-hex suffix of the original's sha256 when it changed (`José` and `Jos?` stay distinct), ≤ 255 bytes; empty or all-dot components are refused, so `.` and `..` can never reach the file system; a `_cN` suffix on a collision; per-file and total byte caps. The original path always comes back through `collected.jsonl` (RT31).

**Plaso** (`plaso==20261027` in its own venv `/opt/plaso`; dependencies locked with hashes in `plaso.lock`, built from wheels compiled in a builder stage, RT11) runs through `/opt/plaso/bin/python -I -m cyberlab_plaso_launch`, which installs the audit hook before the Plaso entry point, with fixed flags: `--single_process`, `--status_view none`, `--unattended`, `--hashers none`, `--no_dependencies_check`, `--archives none`, `--vss_stores none`, `--skip_compressed_streams` in `triage` (dfVFS would otherwise decompress gzip / bzip2 / xz streams with no size cap), `--process_memory_limit` below the stage's `RLIMIT_AS`, an explicit parser list per (OS, profile) with `!filestat`. The event export is `psort.py -o json_line` with **no analysis plugins** (virustotal and nsrlsvr are network clients), or our single-process storage reader `cyberlab_plaso_export` if the phase-3a spike sees psort start a process under the filter. Root also drops collected files with compressed or archive magic unless the catalog entry expects them.

**Event storage** (RT10): two passes over `events.jsonl` (≤ 4 GiB on disk). Pass 1 runs the detections over **every** event and records the event ordinals findings cite. Pass 2 keeps, per artifact category, the most recent events within a quota (`EVENT_QUOTA_PERCENT`: EVTX 30 %, syslog 12 %, `$MFT` 10 %, auth logs 8 %, …; sum 250 000), plus every cited event. Per-category `read` / `stored` counts are in the header.

**Time zones:** text logs without a year or zone depend on Plaso's preprocessing of the mirrored tree (phase 3a checks it); FAT times are local; the UI labels both.

**The timeline replay engine** (`DISK_TIMELINE_ENGINE=replay`: hand-written psort-shaped rows) is refused unless `TEST_PROFILE=1`, and every result it produces says `timeline_engine: replay` (`requirement.txt` §16). `DISK_TIMELINE_ENGINE=none` skips the stage.

## Never collected, never exported

`NEVER_COLLECT_PATTERNS` (`cyberlab_jobs.disk`) is applied to the collect plan and to file exports. Files of these classes are listed with their metadata and hashes like any other file, but their content never leaves the image:

| Class | Patterns (lowercase globs) |
|---|---|
| hives and their copies | `**/system32/config/sam`, `sam.log*`, `security`, `security.log*`, `**/config/regback/**`, `**/windows/repair/**`, `**/ntds.dit` |
| credential stores | `**/microsoft/protect/**` (DPAPI), `**/microsoft/credentials/**`, `**/microsoft/vault/**`, `etc/shadow(-)`, `etc/gshadow(-)`, `etc/krb5.keytab`, `*.keytab`, `**/keyrings/**`, `.gnupg/private-keys-v1.d/**`, `.gnupg/secring.gpg`, `networkmanager/system-connections/**`, `wpa_supplicant*.conf` |
| browser secrets | `login data*`, `cookies`, `cookies-journal`, `web data*`, `local state`, `logins.json`, `key3.db`, `key4.db`, `cookies.sqlite*` |
| keys and tokens | `ssh_host_*_key`, `.ssh/id_*`, `*.pfx`, `*.p12`, `*.pem`, `*.key`, `etc/ssl/private/**`, `.netrc`, `.git-credentials`, `.pgpass`, `.my.cnf`, `.aws/credentials`, `.azure/**`, `.kube/config`, `.docker/config.json`, `*.kdbx` |
| plaintext-secret configs | `unattend.xml`, `autounattend.xml`, `sysprep.xml`, `sysprep.inf`, `groups.xml` (GPP) |
| memory on disk | `pagefile.sys`, `hiberfil.sys`, `swapfile.sys`, `memory.dmp`, `*.dmp` |

- **Every name of an inode** (RT7): a hard link (NTFS or ext) gives a second path to the same `meta_addr`, so a file is refused when **any** of its names matches, and a named stream inherits its file's refusal. `var/log/auth.log` hard-linked to the `etc/shadow` inode is never collected; `x.txt` hard-linked to `SAM` is never exportable.
- **Case-folded always** (a refusal list errs toward refusing: a Linux Chrome profile's `Login Data` is refused on ext too); on NTFS / FAT / exFAT the Win32-ignored trailing dots and spaces are stripped too (`SAM.` = `SAM`).
- Browser history is collected only in `full`.

## Known-file hash sets

**Offline only.** Nothing is downloaded by any tool, test or gate. The operator obtains a set (for example the NSRL RDSv3 `minimal` SQLite) or any md5 / sha1 / sha256 list, places it in `./.disk-import/` and imports it with the trusted `disk-hashsets` tool (runbook: [DEPLOYMENT.md](DEPLOYMENT.md#disk-forensics-m9)).

- **The tool** (built, phase 5): the disk image as uid 10008, compose profile `tools`, **`network_mode: none`**, `mem_limit 2g`, the store rw at `/hashsets`, the import dir read-only. Every parse (SQLite opened read-only and immutable with `trusted_schema=OFF`, `query_only`, no extensions and a read-only authorizer; or a text list) and the external sort run in a forked child with `RLIMIT_AS` 2 GiB, a 4 h timeout and the kit's seccomp network filter, without a uid change (RT25). The parent re-reads every output file (count, strict order, sha256), moves the set into place with one rename and only then lists it in the manifest, so an interrupted import never leaves a matched partial set.
- **Layout:** `<name>/{sha256,sha1,md5}.bin` (sorted unique fixed-width records) and `manifest.json` (`HashSetManifestV1`: name, kind, algorithms, counts, per-file sha256, source sha256, `imported_at`, tool version). At most 64 sets.
- **Matching** (root, in the worker): the store is mounted read-only; root checks each file's size against the manifest, mmaps the files and binary-searches each hashed file in the order `known_bad` → `notable` → `known_good`. An invalid manifest or file disables **all** matching for the job (reported in the header, never a job failure). The header records every set's name, kind, count and manifest sha256.
- **What a match means:** `known_good` only sets `known = good`: hidden by default in the listing and labelled **"known (reference set)", not "benign"**, because NSRL also lists dual-use tools and old vulnerable drivers (RT18). A known-good file in a user-writable path is still YARA-scanned, and `known` never suppresses a heuristic. `known_bad` / `notable` sets produce `known_file:hashset@1` findings (≤ `medium`: operator lists are not verified by CyberLab).
- **In-org matching** (trusted ingest): every hashed file's sha256 / sha1 / md5 is joined with the org's `iocs` hash values and `correlation_keys` hash kinds of other jobs (`correlation:disk_known_org_hash@1`, `low`, at most 500 findings then one summary; a 120 s timeout skips the join, never fails the ingest). No hash leaves the org; nothing is sent to TI automatically.

## YARA

`yara-python` (the M3 pin) with the **M3 baseline rule sources** baked into `/opt/rules/image/` and compiled by the `scan` probe at scan start (never a `.yarc`: root keys the severity allow-list on each source file's sha256; RT8). Root refuses to scan when the baked baseline does not hash to the image's recorded `rules_sha256`. Every M3 baseline rule is anchored on `pe.*` / `MZ`, so **candidates are PE files only** (`YARA_MAGIC_CLASSES = {pe}`), allocated, hashed, within the budgets above; user-writable paths first, then by size; one candidate per inode stream. `rules.match(data=…, timeout=10)` per file; matched string data is never emitted. Severities come from the lifted M3 allow-list (`cyberlab_worker.yara_rules`; unknown rules `low`); the M3 `test` rules load only with `TEST_PROFILE=1`. No ClamAV in the disk worker: an exported file gets ClamAV through its normal static job.

## Findings (never verdicts)

Deterministic heuristics over the normalized records (built, phase 6): one streaming pass over every event, then the file listing, then correlation. Titles and descriptions come from fixed templates that describe what was observed and name the benign explanations; a test rejects verdict words; quoted text passes the secret masker.

| Method | Fires on | Max severity | What it does **not** mean |
|---|---|---|---|
| `heuristic:disk_exec_user_writable@1` | an executable in a user-writable path class (fixed glob classes per OS; Defender's platform directory, per-user OneDrive / Teams installs, `Windows\Installer`, package and developer caches excluded) | low | installers and updaters unpack there too |
| `heuristic:disk_double_extension@1` | a document extension before an executable one, or a U+202E right-to-left override in a name | medium | — |
| `heuristic:disk_extension_mismatch@1` | executable magic under a non-executable extension | medium | such files are not started by a double click |
| `heuristic:disk_ads_executable@1` | an NTFS named stream starting with an executable header | medium | — |
| `heuristic:disk_persistence@1` | `medium`: Run / RunOnce values or service image paths naming a program in a user-writable path, executables placed directly in a Startup folder, cron runs of a program in a user-writable path, a non-empty `/etc/ld.so.preload`. `low` (listing only, contents never read): other Startup entries, scheduled-task files, cron files, systemd units or `authorized_keys` created or modified in the analysed window (the 7 days before the newest activity; task XML is not parsed, RT28), `/etc/rc.local` present | medium | installers, administrators and package upgrades create these too |
| `heuristic:disk_log_cleared@1` | EVTX Security 1102 / System 104; a log empty or truncated while rotated copies exist | medium | administrators clear logs too |
| `heuristic:disk_service_installed@1` | EVTX 7045 | medium | installers register services |
| `heuristic:disk_account_change@1` | account created / enabled / added to a group (EVTX; `useradd` in auth logs for UID 0 or ≥ 1000) | low | administrators and installers do this |
| `heuristic:disk_remote_logon@1` | successful remote logons from an address; 20 or more failed logons from one address within 10 minutes | medium | a stale client password also produces bursts |
| `heuristic:disk_dual_use_execution@1` | execution evidence (Prefetch, Amcache, UserAssist, BAM, shell history, EVTX 4688) of a fixed list: `low` for `psexec`, `procdump`, `rclone`, Windows netcat; `medium` for `wevtutil cl`, `vssadmin delete shadows`, `certutil -urlcache`, `powershell -enc`, `curl` / `wget` piped into a shell, `nc -e` | medium | these tools have administrative uses |
| `heuristic:disk_correlated_indicators@1` | several independent observations on one subject; refs the others, never raises them | medium | — |
| `signature:yara@1` | a YARA rule match on a PE candidate | high (M3 allow-list) | a pattern observation |
| `known_file:hashset@1` | a hash listed in an operator `known_bad` / `notable` set | medium | operator lists are unverified |
| `integrity:ewf_media_hash@1` (worker) | the EWF stored hash differs from the hash over the media read | medium | see "Integrity" below |
| `correlation:disk_known_org_hash@1` (ingest) | a file hash already seen in this org (IOCs, other jobs) | low | — |

- **Only `signature:yara@1` can reach `high`.** Heuristics cap at `medium`.
- **`heuristic:disk_timestamp_anomaly@1` is cut** (RT28): it needs `$SI` / `$FN` pairs that only `full` `$MFT` events carry, and zero sub-second times are common after installs and archive extraction ("Later").
- **IOCs** (observables only): hashes of files referenced by findings, source IPs of remote-logon findings, URLs / domains / IPs quoted in findings. Never the whole listing or browser history.
- **Event-based rules depend on Plaso events** (phase 3): until the disk image runs Plaso they are exercised by unit tests and the replay engine only. EVTX field layouts are read defensively; an unknown layout is counted (`evtx_layout_unknown`), never guessed.

**Quality metrics:** the harness is written (phase 13, `pnpm disk:metrics`); the run is pending Docker (`plans/reports/disk-metric-YYMMDD.md`). The precision / recall table per detector, parse success, latency per stage and per job, the ingest time at the caps and the fuzz-lite outcome will be **synthetic numbers on scenarios designed alongside the detectors**: they show that the detectors behave as specified, not real-world detection quality.

## Integrity: what "matched" means

- **Trusted:** only each segment's sha256, computed by the API at upload and re-checked by the worker on download (`integrity_mismatch` otherwise).
- **Worker-reported** (RT17): `media_sha256` (split raw: a concatenated hash; EWF: computed by `verify`) and `media_hash_status` for EWF: `matched` (our MD5 / SHA-1 over a full read equal the hashes stored at acquisition), `mismatch` (a finding, not a job failure), `absent` (no stored hash), `not_verified` (the read did not finish within the budget). They come from the untrusted worker, and an acquirer can store a consistent hash for any content, so the UI and API say **"reported by the worker; consistent with the hash stored at acquisition"**, never "verified".
- **libewf does not fail a read on a chunk checksum error**: with `absent`, a corrupted chunk goes unnoticed (the summary says so).
- EWF acquisition values (case number, examiner, notes, acquiry date and software) are acquirer-chosen text: bounded, control-escaped and shown as quoted, inert text.

## Sensitivity: TLP:RED by default

A disk image holds everything the machine held: documents, mail, browser data, credentials in files, keys.

- **One table, not renamed** (RT2). M8's `memory_sensitivity` is already evidence-scoped, so 0017 adds `source` (`memory` / `disk` / `derived`) instead of renaming it; DATABASE documents it as the evidence-level sensitivity table, and the rename is a "Later" cleanup. `evidence/sensitivity.py:apply_restricted_default(…, source)` generalizes M8's function, which is now a one-line wrapper.
- **Default** (built, phases 1, 7). A `kind=disk` upload, or else the first disk job on any segment (for **every** segment), inserts `restricted` (source `disk`) and sets the M6 share policy to `ai_excluded = ti_excluded = true`, never loosening. Idempotent; audited `disk.sensitivity_defaulted`.
- **Release** (built, phases 1, 9). `POST …/evidence/{id}/sensitivity/release` (`org.update`, `{acknowledge: true, reason}`) moves `restricted → released` once (`disk.sensitivity_released`). With `job_id` it releases every still-restricted segment of that disk job in one request, one audit row each (RT20). M8's `/memory-sensitivity` routes, codes and `memory.*` actions are unchanged. The release does not clear the share-policy flags; while restricted, the share-policy route refuses to clear them (`409 evidence_sensitivity_restricted` for disk / derived, `memory_sensitivity_restricted` for memory).
- **Derived evidence** (phase 10) inherits: `restricted` (source `derived`) when any segment is restricted, plus the source's share-policy flags, in the promote transaction. A batch release never includes derived evidence.
- **Collection minimisation.** The analysis stores no file content: metadata, hashes, matched rule names and Plaso events of allow-listed artifacts only. The never-collected list; browser history only in `full`; no carving. File contents leave the image only through an explicit, audited, per-file export.
- **Secret masking.** Text quoted into findings, IOC context and timeline titles (shell history, registry values, service paths, task commands, URL query values) passes `cyberlab_worker.mask` (the M8 masker, lifted into the kit). The raw text stays only in `disk_events` / `disk_files`, on the job pages (`evidence.read`).

| Module | Behaviour for restricted disk evidence (built, phase 9) |
|---|---|
| AI analyst (M5) | AI runs on the job answer `409 policy_blocked`; incident summaries skip it; the analyst worker re-checks. After release + share-policy PUT, a disk job's AI digest is its findings and IOCs only (masked). No disk-specific AI task |
| Threat intel (M4) | job-scope enrichment answers `409 policy_blocked` |
| Reports (M6) | disk-derived rows go into a report only at TLP:RED; otherwise they are omitted and counted in `omissions.disk_restricted` (absent from the canonical bytes when unused, so M6 and M8 signed snapshots keep their bytes, RT23) |
| Retention (M7) | `disk_files` and `disk_events` are bulk rows purged for closed cases; `disk_images`, `disk_partitions`, `disk_exports`, segments and sensitivity rows are never purged; expired export objects are deleted by the retention worker (RT19) |
| Correlation (M7) | in-org only: disk IOCs are `iocs` rows (keys only, never across orgs) |
| Interop exports | served to `evidence.read` like any read, labelled `X-CyberLab-Sensitivity: restricted` and `-TLP-RED` in the file name |

## Exports

### Interop files (built, phase 8)

`GET …/analyses/{job}/disk/exports/{name}` streams one of four files, each an audited download (`disk.interop_exported`, committed before the first byte):

| Name | Format | Real consumer |
|---|---|---|
| `bodyfile` | TSK body file 3.x: `MD5\|name\|inode\|mode_as_string\|UID\|GID\|size\|atime\|mtime\|ctime\|crtime`, epoch seconds (0 when unknown), md5 `0` when not hashed; `name` = `/p<partition>/<path>` (`:stream`, ` (deleted)` / ` (deleted-realloc)` as TSK writes them); `inode` = `<meta_addr>[-<meta_seq>][-<stream>]` | TSK's `mactime` and other body-file tools. **Not** an Autopsy import (RT12) |
| `timeline.csv` | Timesketch's required columns first (`message`, `datetime` ISO 8601 UTC, `timestamp_desc`), then `source`, `artifact`, `partition`, `path`, `time_basis`; formula-safe RFC 4180 cells; UTF-8 without BOM (`?excel=1` adds one) | Timesketch CSV import, spreadsheets |
| `timeline.jsonl` | the same columns, one JSON object per line | Timesketch JSONL import |
| `notable-hashes.txt` | one lowercase md5 per line: files with a finding, a YARA match or a `known_bad` / `notable` set match | Autopsy's plain-text hash-set import (as a "notable" set) |

- **Escaping differs from TSK on purpose:** `|`, `\` and control characters in a name or stream are written as `\xNN` (`|` → `\x7c`, newline → `\x0a`), so no image-supplied name can add a field or a line. TSK's own `fls -m` does not escape, so a body file from `fls` and ours differ on such names.
- No comment line in any file (it would break both importers): the sensitivity label travels in the header and the file name.
- Streamed in batches from their own tenant session (`statement_timeout` 120 s); nothing buffers the whole result.

### File export to derived evidence (phase 10, in progress)

"Export files" on 1–20 listed files of a succeeded `triage` / `full` job (`POST /analyses/{job}/disk/file-exports {file_ids}`, `evidence.write`):

1. **Eligibility:** allocated, a regular file or a stream of one, ≤ 64 MiB (`DISK_EXPORT_MAX_BYTES`), no name of the inode on the never-collected list (`409 disk_export_not_allowed`), source evidence not purged; the quota checked against the sum.
2. **An `extract` job** with the source job's segments: the worker downloads and re-verifies the segments again (no cache), runs `probe extract` per file (natural key and `meta_seq` re-checked: a reallocated entry fails), and POSTs each file into the results bucket under `exports/`. The ingest marks each `disk_exports` row `ready` with its exact object version and the **untrusted** `worker_sha256` (display only), or `failed`.
3. **"Add to case"** (`POST /disk-exports/{id}/promote`, `evidence.write`): the API streams the exact object version through the **existing evidence upload pipeline** (trusted md5 / sha1 / sha256, 8 KiB type sniff, quota, object lock, custody). It never parses or executes the bytes. The trusted sha256 must equal `worker_sha256`, else `export_hash_mismatch` and nothing is promoted. The new evidence inherits the restriction (source `derived`) and the share-policy flags; custody `derived_from` on the new item and `export_promoted` on each segment; then the normal automatic choice (PE → static `full`, else `av`).
4. **Expiry:** `ready` exports not promoted within `DISK_EXPORT_TTL_S` (7 days) become `expired` (beat task `disk.expire_exports`); the api MinIO user cannot delete in the results bucket, so the retention worker deletes the exact object version with the purge user and stamps `object_deleted_at` (built, phase 9; RT19). Promote refuses `expired` (`409 disk_export_expired`).

## Autopsy: analyst-side only

[Autopsy](https://github.com/sleuthkit/autopsy) 4.23.1 (Apache-2.0) is a Java / NetBeans desktop application, fully tested only on Windows. Its Command Line Ingest still starts the platform, adds one data source per invocation and needs ingest profiles made in the GUI; multi-user mode needs Solr, PostgreSQL and ActiveMQ; there is no REST API ([research §6](../plans/reports/researcher-261107-m9-disk-forensics.md#6-autopsy)). It cannot meet the untrusted, network-less, resource-bounded worker model, so it is **not a server component; server-side Autopsy is "not planned"**. "Integration where appropriate" (`requirement.txt` §3) is analyst-side interop:

1. Download the original segments from the evidence page (audited, `evidence.read`; restricted evidence stays TLP:RED on your workstation too).
2. In Autopsy, create a case and add the segments as a disk image data source (E01: select `.E01`, Autopsy finds the rest; split raw: select `.001`).
3. Import `notable-hashes.txt` as a hash set marked "notable" (Hash Lookup settings) and run the Hash Lookup ingest module: CyberLab's flagged files are tagged in Autopsy's own view.
4. For the timeline use the tools that read our files: `mactime -b bodyfile -d` for a TSK-style timeline, or import `timeline.csv` / `timeline.jsonl` into Timesketch. Autopsy has no body-file or CSV timeline import.

## Real-engine coverage

No real disk image, no third-party test corpus (CFReDS, DFTT, Plaso test data, hivex's test hives) and no NSRL release is downloaded by any tool, test or gate (`requirement.txt` §14); no binary image is committed.

| Engine | Coverage | Status |
|---|---|---|
| TSK, libewf | generated images at test time (FAT12 / 16 / 32, exFAT, ext2 / 3 / 4, NTFS, MBR and GPT, split raw, single and multi-segment E01, a stored-hash mismatch, hard links to `SAM` and `etc/shadow`) compared against each image's `ground_truth.json` | generator and engine tests written (phases 2, 4); not yet run in Docker |
| FAT12 / 16 / 32, MBR / GPT, split raw | written byte by byte by our own Python (`fs_fat.py`, `layouts.py`): VFAT long names, a `0xE5` deleted entry, explicit times; deterministic | host-tested (an independent reader in `test_diskgen.py`); `fsck.fat -n` / `sfdisk` checks pending Docker |
| ext2 / 3 / 4 | `mke2fs -d` of a staged tree, then `debugfs -w` sets owners and every time; the hard link `var/log/old.log` → `etc/shadow` is one inode with two names | pending Docker (`e2fsck -fn`) |
| exFAT | `mkfs.exfat` only: an **empty** file system (exfatprogs has no userspace copy tool), the volume serial patched to a fixed value | pending Docker |
| NTFS directory trees | built without any mount (parent decision: no privileged container, RT26): **route 1**, libntfs-3g as a library through ctypes in a child process (`ntfs_create` / `ntfs_link`), tried first; on any failure **route 3**, the Windows-shaped tree on FAT32 plus `ntfs_flat` (a flat NTFS image with the named streams). Route 2 (our own MFT writer) was not attempted. The route taken is in each `ground_truth.json` (`ntfs_route`) | whether route 1 works on trixie's libntfs-3g 2022.10.3 is pending Docker. Gaps on route 3: named streams and the second name of `SAM` exist only on NTFS (`ntfs_flat` has the streams but no directories and no hard link); no deleted MFT entry on any route (no userspace delete tool) |
| Registry hives | our own base hive (`hives.py`), merged with `hivexregedit --merge` from `.reg` text built in code (a Run key, a service with its ImagePath in Temp, UserAssist); without hivex the base hive stays (`hive_outcome` per hive) | pending Docker |
| E01 | `ewfacquirestream -f encase6` (single and multi-segment), case data fixed; `ewf_bad_hash` from our own section patcher | pending Docker (`ewfverify`); EWF acquiry dates are the one determinism exception besides NTFS times |
| Plaso | the generated Linux tree (syslog, auth.log, wtmp written by our own `struct utmp` packer, bash history, cron, dpkg), and the hivex-merged hives when hivex is present | code written (phases 3, 4); pending the 3a spike's `plaso.lock` and Docker |
| **Windows event logs, Prefetch and LNK** | **replay-tested only, not validated on a real image in CI**: no Linux writer exists, so they are covered by hand-written psort-shaped row fixtures and the test-only replay engine | replay engine and fixtures written (phase 3) |

Hostile mode (`python -m samples.diskgen --hostile N --seed S`) writes 15 seeded mutations under `<out>/hostile/<nn>_<name>/` with a `mutation.json` each: a 64-level tree of 255-character names, a huge claimed MFT / inode table (sparse), an E01 claiming a media size above the cap, truncation, corrupted boot sectors / superblocks / MFT records, a directory cycle, a 300 000-entry directory, hostile names, overlapping and beyond-media partitions, a lying EWF segment count and refused-format magic. Phase 13's fuzz-lite runs them through the real stages.

The first real Windows run therefore happens on the operator's own image: [DEPLOYMENT.md](DEPLOYMENT.md#disk-forensics-m9) has a manual smoke procedure (never automatic).

## Limitations

- **Untested in Docker** (banner). The image cannot be built until phase 3a's `plaso.lock` and the worker's `uv.lock` exist.
- **Windows event logs, Prefetch and LNK: replay-tested only.** A real image may break the event normalizer or the event detectors.
- **No VSS, no decryption, no APFS / HFS+ / LVM / ISO**; encrypted and unsupported partitions are reported, not opened.
- **No carving**, no recovery of deleted content, no unallocated-space search, no slack space. Deleted names are listed only.
- **Hostile images:** TSK's CVE history is contained by the family allow-list, the sandbox, timeouts, `RLIMIT_AS` and caps, not prevented. A bad image costs up to the job timeout (4 h).
- **Scale ceiling:** 16 GiB per set by default (64 GiB max); larger images need ingest by reference and HTTP range reads ("Later"). Every re-run and export re-downloads the whole set.
- **Single-request upload** of up to 16 GiB per segment within Caddy's 30-minute body timeout; no resume.
- **Contents exposure:** every case reader with `evidence.read` sees paths, names, metadata, EWF header text and raw shell history (org-wide RBAC); secrets are masked on the shared surfaces only.
- **Time:** FAT times have no zone; text logs without a year depend on Plaso's preprocessing.
- **EWF content integrity** is only as good as the stored hash (above).
- **Engine drift:** pytsk3, libewf-python and Plaso upgrades are deliberate pinned changes with the generated-image suite as the regression check.

## Licenses

**Not legal advice.** The image redistributes, unmodified: TSK 4.15.0 inside the pytsk3 wheel (IBM Public License 1.0 / Common Public License 1.0, weak copyleft for the library itself), pytsk3 (Apache-2.0), libewf-python and the libyal bindings Plaso pulls in (LGPL-3.0-or-later; dynamically loaded Python extension modules in their own venvs, replaceable by the user), Plaso, dfVFS, dfWinReg, dfDateTime and artifacts (Apache-2.0), yara-python (Apache-2.0; YARA BSD-3-Clause). The image carries every installed distribution's license text and [`apps/workers/disk/NOTICE.md`](../apps/workers/disk/NOTICE.md) under `/usr/share/doc/cyberlab-disk/`. Nothing is patched. Unlike the VSL of M8, no "wrapper" clause reaches the adapter code. No GPL component is in the prod image: TSK's only GPL file (`srch_strings.c`) is not built into pytsk3, and the GPL test tools of the image generator live in the dev / test target only. The docs link to upstream and never paste upstream source.
