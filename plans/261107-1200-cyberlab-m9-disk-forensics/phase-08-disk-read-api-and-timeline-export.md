---
phase: 8
title: "Disk read API and timeline export"
status: pending
priority: P2
effort: "14h"
dependencies: [1]
---

# Phase 8: Disk read API and timeline export (group B, 2f, lane 7)

## Overview
Read routes over one disk job's persisted results, on the M3 / M8 router pattern (`evidence.read`, RLS, keyset pagination, capped pages), plus the **interop exports** that make "Autopsy integration where appropriate" concrete (RT12: Autopsy imports hash sets, not timelines):
- a TSK body file (for `mactime` and body-file tools);
- the timeline as CSV / JSONL in Timesketch's import columns;
- a plain list of flagged files' md5s (Autopsy hash-set import).

Findings, IOCs and the shared timeline already have generic routes; they work for disk jobs unchanged.

**Owns:**
- `app/modules/disk_forensics/{router,repository,service,exports_interop}.py` (after the phase-1 stubs; schemas frozen in `disk_forensics/schemas.py`);
- `tests/security/idor_cases_disk.py` (fills phase 1's `PENDING_ROUTES`);
- `tests/integration/test_disk_{reads,dirs,timeline_merge,interop_exports}.py`, `tests/unit/test_{bodyfile,csv_safety}.py`.

## Requirements
- **Routes** (all `GET`, under `/api/v1/orgs/{org_id}/analyses/{job_id}/disk`, `evidence.read`; `404` for a non-disk job, an extract job and another org's job; `409 analysis_not_ready` while queued or running):

  | Path | Returns |
  |---|---|
  | `` (summary) | `DiskSummaryOut`: the segments (ordinal, evidence id, name, sha256, size; the only trusted hashes), format, media size, media sha256 and EWF stored hashes and `media_hash_status` (all marked `worker_reported: true`; RT17), EWF meta (as text), the volume system, per-stage and per-partition status, per-artifact read / stored counts, the hash sets used, the tool versions, `engine` / `timeline_engine`, the audit counts, counts, `truncated`, the sensitivity state (read only) |
  | `/partitions` | `PartitionPage` |
  | `/dirs?partition=&dir=<file_id>|root&cursor=` | `DirPage`: the children of one directory (rows whose `parent_addr` equals the directory's `meta_addr` in that partition; no path hash, no collision check; RT13), directories first, then name order within the page |
  | `/files?partition=&q=&flags=deleted,orphan,ads,yara,known_bad,notable&magic=&known=hide_good|only_good|all&hash=<hex>&ext=&from=&to=&cursor=` | `FilePage` (`known=hide_good` by default) |
  | `/files/{file_id}` | `FileDetailOut`: all columns, its other names (rows with the same `meta_addr`; RT7), its NTFS streams, its findings, its events (≤ 200 with totals), "also seen in" (the M7 correlation keys for its hashes), and `exportable` with a reason (allocated, regular, size, never-collected over every name) |
  | `/events?artifact=&from=&to=&q=&cursor=` | `EventPage` (`disk_events` only) |
  | `/timeline?from=&to=&sources=fs,events&artifact=&cursor=` | `TimelinePage`: the merge of the file-system MACB times (from `disk_files`: one virtual row per non-null time column) and `disk_events`, ordered by (`ts`, `kind`, `id`), with keyset cursors that encode all three; FAT `local_unknown` times are labelled |
  | `/exports/bodyfile` | TSK body file 3.x for `mactime` (not an Autopsy import), streamed: `MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime` (research §1). `name` is the full path with `|` and newlines escaped as `\x7c` / `\x0a` (documented); inode = `meta_addr-seq` (`-stream` for NTFS streams) |
  | `/exports/timeline.csv`, `/exports/timeline.jsonl` | the merged timeline, streamed, with Timesketch's required columns first (`message`, `datetime` ISO 8601 UTC, `timestamp_desc`) then ours (`source`, `artifact`, `partition`, `path`, `time_basis`); CSV formula-safe (the M6 rule: cells starting with `= + - @ \t \r` are prefixed with `'`), UTF-8 (the BOM only on `?excel=1`, since Timesketch's importer expects none), the TLP / restricted label in the `X-CyberLab-Sensitivity` header and the file name (no comment line, which would break both importers) |
  | `/exports/notable-hashes.txt` | one lowercase md5 per line for files with a finding, a YARA hit or a `known_bad` / `notable` match (Autopsy's plain-text hash-set import; RT12) |

- **Indexes used:** the merged timeline reads `disk_files` through one (`job_id`, time, `id`) index per time column (phase 1; RT14) and `disk_events` through (`job_id`, `ts`, `id`); `EXPLAIN` on the cap fixture must show no sort node.
- **Bounds:**
  - page size ≤ 200;
  - `q` 1–128 characters: a substring match on path / name (files) or message (events), inside the job only;
  - `hash` must be 32 / 40 / 64 hex characters;
  - `from` / `to` aware datetimes;
  - `SET LOCAL statement_timeout = '5s'` for pages and `'120s'` for streamed exports;
  - exports stream with a server-side cursor in pages of 5 000 and never buffer the whole result.
- **Audit:** each interop export writes `disk.export_downloaded` (`kind`, job, row count at completion). Pages are not audited beyond the M7 evidence view audit (the static / memory decision).
- **Restricted evidence:** the reads and exports are allowed for `evidence.read` (the same rule as downloading the evidence itself). The response header `X-CyberLab-Sensitivity: restricted` and a `-TLP-RED` suffix in the download file name mark the content; the UI shows the TLP:RED banner (phase 11).
- **Output safety:** every text field is returned as stored (bounded, NUL-free, single-line); the web renders text only.
- **IDOR:** every route in `idor_cases_disk.py` (a cross-org job id, a pcap / memory job id, an unknown file id, a file id of another job of the same org).

## Implementation Steps
1. Read the M3 static and M8 memory routers, repositories and pagination helpers, and the M6 CSV formula-safety helper.
2. Repository queries with keyset cursors; the directory query by `parent_addr`; the merged timeline query (a `UNION ALL` of the four time columns and the events, each side index-ordered, `LIMIT page + 1`), checked with `EXPLAIN` on the cap fixture.
3. Router and service; error mapping.
4. The streamed interop exports; `test_bodyfile.py` (escaping, inode format, a round-trip through our own reference parser of the 11 fields), `test_csv_safety.py`, and a column test for the Timesketch header and the plain md5 list.
5. IDOR cases; integration tests seeded through `seed_disk_job()`; a timing check on the 500 000-file cap fixture (pages < 1 s on the dev host, recorded).
6. Lane 7, `ruff`, `mypy`.

## Success Criteria
- [ ] Every route answers from the seeded job with correct pagination, filters and `404`s; no page exceeds the statement timeout on the cap fixture.
- [ ] The merged timeline is totally ordered and stable across pages (no duplicates or gaps across cursor boundaries).
- [ ] The body file parses with the 11-field format, and names with `|` or newlines cannot break a line; the CSV is formula-safe and starts with `message,datetime,timestamp_desc`; the hash list is one md5 per line.
- [ ] Exports are audited and stream without buffering.
- [ ] `idor_cases_disk.py` has no pending route.

## Risk Assessment
- **Merged-timeline query cost:** five index-ordered streams (all four time columns indexed, RT14) with a 5 s timeout; if `EXPLAIN` still shows sorts, the fallback is a materialized per-job `disk_fs_times` table filled at ingest (the parent decides; it would be a schema change through the next migration number).
- **Path search** is a sequential scan of one job's rows; bounded by the timeout; a trigram index is "Later" if needed.
- **Body file escaping** differs from TSK's own (TSK does not escape): documented in DISK_FORENSICS.md.
