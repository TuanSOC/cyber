---
phase: 12
title: "Docs threat model and license notices"
status: pending
priority: P2
effort: "9h"
dependencies: [2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
---

# Phase 12: Docs, threat model and license notices (group C)

## Overview
Documentation for the merged group B, in the house style of the M2–M8 docs (plain sentences, tables, no marketing, honest limits). One agent after the group-B merge; it touches only docs, the NOTICE text and the README.

**Owns:**
- `docs/DISK_FORENSICS.md` (new);
- the M9 sections of `docs/{ARCHITECTURE,THREAT_MODEL,DATABASE,API,DEPLOYMENT,TESTING,ROADMAP,PRD}.md` and `README.md`;
- `apps/workers/disk/NOTICE.md` and the image's `NOTICE` source text;
- `plans/reports/requirements-coverage-*.md` (a short M9 addendum).

## Requirements
- **`docs/DISK_FORENSICS.md`:**
  - scope (triage, not full forensics) and the out-of-scope list;
  - accepted formats and segment sets (how to upload E01 segments or split raw, why order matters for raw);
  - the stages and their limits, the deadline budget, the write watchdog and the post-stage kill and sealing (RT3–RT5);
  - the file-system and volume allow-list with the reason (TSK CVE history; research §1; the 2026-11 HFS CVEs that affect 4.15.0 itself), and the refusal-signatures-first order;
  - profiles and the artifact catalog with the never-collected classes and the every-name (hard-link) rule;
  - hashing and YARA budgets;
  - known-file hash sets;
  - the timeline (Plaso on extracted artifacts only; time zones; FAT local times; per-category storage quotas);
  - the detections table (methods, severities, what they do **not** mean);
  - exports (interop files with their real consumers: `mactime`, Timesketch, Autopsy's hash-set import; and derived evidence, re-downloaded per export);
  - what "matched" means for EWF (worker-reported, consistent with the acquisition's stored hash; libewf passes chunk-checksum errors silently);
  - sensitivity;
  - **Autopsy** (why it is not a server component; the analyst-side workflow with the body file, timeline CSV and notable-hash list; research §6);
  - known limitations ("Windows event logs, Prefetch and LNK: replay-tested only"; the NTFS directory coverage outcome of phase 4; no VSS / encryption / APFS).
- **ARCHITECTURE:**
  - the disk worker in the service diagram (analysis network, broker only);
  - the `disk-hashsets` tool (no network);
  - the stage-per-process model;
  - the `disk-ingest-worker` and the hand-off from the shared ingest queue (RT9);
  - the segment-set data flow (no image cache, RT1);
  - the export / promote flow, why the API never parses the bytes, and the retention worker deleting expired export objects (RT19);
  - the `source` column on M8's `memory_sensitivity` and the generic sensitivity routes (no rename, RT2).
- **THREAT_MODEL (M9 section):** one row per threat with the mitigation and the test that proves it.
  - Threats: hostile images (parser CVEs, cycles, bombs, lying tables, lying EWF media sizes, huge MFTs); hostile names written to `/work`; a compromised stage persisting into or tampering with the next (RT3); a stage filling the host disk (RT4); a Plaso network, IPC or decompression attempt; hash-set store tampering; cross-tenant segment sets; export abuse (never-collected files and their hard links, worker hash lies); sensitive-content exposure through search, reports, AI and TI; interop exports of restricted content; operator commands built from image data (none: hash-set commands take only operator input).
  - **Residuals:** org-wide RBAC sees paths and shell history; EVTX replay-only; Debian TSK not used but pytsk3 upgrade cadence matters; Docker Desktop disk growth.
- **DATABASE:**
  - the new migration and every table with its checks and grants;
  - the `source` column on `memory_sensitivity` (the evidence-level sensitivity table despite its name; the rename is "Later");
  - the §11 mapping: `forensic_artifacts` → `memory_artifacts` + `disk_files` / `disk_events` / `disk_partitions`;
  - `parent_addr` instead of a path hash (truncated paths, B-tree entry size) and the four time indexes;
  - the per-job size at the caps (from phase 7's measurement).
- **API:** every new route, the segment-set rules and reason codes, the export / promote flow, the generic sensitivity routes beside M8's unchanged `/memory-sensitivity` routes, the batch release, the error codes.
- **DEPLOYMENT:**
  - **Sizing:** per segment and total limits (16 GiB default total against the 20 GiB default org quota); the Caddy throughput needed for 8 / 16 GiB segments; the disk footprint (MinIO + `/work` + the artifact tree + the Plaso storage, about 2 × image + 3 × artifact budget, plus the 4 GiB watchdog floor); Docker Desktop's growing virtual disk; worker RAM 3 GiB plus the 1 GiB `disk-ingest-worker`; the sum of every worker's `mem_limit` against host RAM; one job at a time; every re-run and export re-downloads.
  - **The hash-set runbook:** obtaining NSRL RDSv3 by hand, `.disk-import/`, import / verify / remove, temp space, update cadence.
  - **The operator smoke procedure** on the operator's own image (never automatic, never in CI).
  - **Recovery:** `insufficient_disk`, `skipped` (`deadline`) stages (raise `ANALYSIS_DISK_TIMEOUT_S` or use `triage`).
  - **Building the image:** the Plaso builder stage and its build time.
- **TESTING:**
  - the generated image set and how to regenerate it (`pnpm disk:gen`);
  - the replay engine and what it covers;
  - the precision / recall table (copied from phase 13's metric report) with the synthetic caveat;
  - parse success, latency per stage and per job, the ingest time at the caps;
  - lane 9 and its DB;
  - any phase-4 coverage gaps (the NTFS route chosen without any mount; whether the `SAM` hard link exists on NTFS).
  - The red-team cuts: the image cache, the `memory_sensitivity` rename and the timestamp-anomaly rule ("Later").
- **ROADMAP:** M9 row (done, pending its gate) with the deferred list:
  - ingest by reference;
  - HTTP range reads;
  - VSS, BitLocker with a recovery key, APFS, LVM;
  - VMDK / VHD / QCOW;
  - carving;
  - Plaso analysis plugins (offline ones);
  - the image cache (with range reads);
  - renaming `memory_sensitivity` to an evidence-level name;
  - `heuristic:disk_timestamp_anomaly@1`;
  - a trigram path index;
  - per-case ACLs;
  - server-side Autopsy ("not planned").
- **PRD / README:** the Forensics module status, links.
- **NOTICE** (`apps/workers/disk/NOTICE.md` and the image text):
  - TSK (IBM-PL-1.0 / CPL-1.0, embedded in pytsk3; source link to the tag pytsk3 20260715 bundles);
  - pytsk3 (Apache-2.0);
  - libewf-python and each libyal binding (LGPL-3.0+, source links, "dynamically loaded, replaceable");
  - Plaso / dfVFS / dfwinreg / artifacts (Apache-2.0);
  - yara-python (Apache-2.0) / YARA (BSD-3);
  - the test-only GPL tools, with a statement that they are not in the prod image.
  - Docs link to upstream and never paste upstream source.
- **Requirements coverage addendum:** §3 Autopsy now documented; disk forensics implemented (triage scope); `forensic_artifacts` mapped.

## Implementation Steps
1. Read the merged code, the phase notes (spike notes of phases 3a and 4, phase 7 measurements) and the M8 docs as the style reference.
2. Write `DISK_FORENSICS.md`, then the cross-doc sections, then NOTICE and the coverage addendum.
3. Check every claim against code or a test (a short checklist at the end of the PR description); mark anything unverified as such.

## Success Criteria
- [ ] Every new route, table, setting, service, volume and error code is documented once, in the right doc.
- [ ] THREAT_MODEL names a test for each mitigation; the residuals are explicit.
- [ ] DEPLOYMENT states the sizing and the hash-set runbook; TESTING states what is synthetic and what is replay-only.
- [ ] Autopsy's status is stated in DISK_FORENSICS, PRD and ROADMAP.
- [ ] NOTICE lists every bundled component with its license and source link.

## Risk Assessment
- **Docs drifting from code:** written after the merge, checked claim by claim; phase 13 can make one-line metric edits.
