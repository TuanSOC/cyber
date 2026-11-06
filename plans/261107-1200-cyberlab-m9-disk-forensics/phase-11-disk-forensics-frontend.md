---
phase: 11
title: "Disk forensics frontend"
status: pending
priority: P2
effort: "18h"
dependencies: [1]
---

# Phase 11: Disk forensics frontend (group B, 2i, web only)

## Overview
The "Forensics" module in the dark dashboard (§12):
- the run dialog with an ordered segment picker;
- the `kind=disk` upload option;
- the job page with partitions, a directory browser, a filtered file table, the merged timeline, findings, IOCs and exports;
- the export / promote flow;
- the restricted (TLP:RED) banner;
- the derived-evidence badge.

It builds against the frozen phase-1 schemas and generated contracts. Host only (no containers, no slot).

**Owns:**
- `apps/web/lib/{disk,disk-timeline,disk-exports}.ts` (+ tests), `lib/use-disk-job.ts`;
- `components/disk/**` (including the phase-1 slots `run-disk-analysis.tsx`, `disk-upload-option.tsx`, `derived-evidence-badge.tsx`);
- `app/(app)/o/[orgId]/forensics/**`;
- no mount edits (phase 1 mounted the slots).

## Requirements
- **Forensics index** (`/forensics`): the org's disk jobs (status, profile, segments, media size, partitions, findings by severity, the restricted badge), filters by investigation and status; the empty state explains how to start (upload segments as "Disk image", then run).
- **Upload option** (`disk-upload-option.tsx` in the evidence uploader):
  - a "Disk image (segment)" choice that sends `?kind=disk`;
  - the text says that the item will be TLP:RED with AI / TI disabled, and that no automatic analysis runs;
  - multi-file selection uploads each file as its own segment (sequentially, with per-file progress; existing uploader behaviour, no new upload protocol).
- **Run dialog** (`run-disk-analysis.tsx` on an evidence item):
  - **Segment picker:** candidate evidence of the same investigation, pre-sorted by natural name order (`.E01 < .E02 … < .E10`, `.001 < .002`, `aa < ab`), reorderable with keyboard-accessible up / down controls (no drag-only interaction), the current item first. It shows the total size against `DISK_MAX_IMAGE_BYTES` and blocks submission above it.
  - The profile (`triage` default, `full` with a time / disk warning) and the OS hint; a note that every run downloads and re-verifies the whole set (no image cache, RT1).
  - A note that segment order matters for split raw and that EWF validates its own set.
  - The restricted-default notice ("all selected segments become restricted; earlier jobs on them are covered from now on").
  - Error mapping for `disk_segments_invalid` reasons.
- **Job page** (`/forensics/[jobId]`, tabs):
  - **Overview:**
    - the segments with sha256;
    - format, media size and media sha256 (labelled "reported by the worker"; only the per-segment sha256s are platform-computed; RT17);
    - **media hash status** (`matched` / `mismatch` / `absent` / `not_verified`, worded "consistent with the hash stored at acquisition", never "verified"; mismatch as a prominent warning that is not a verdict; `absent` notes that chunk corruption cannot be detected);
    - EWF meta as quoted inert text;
    - the stage strip (per stage and partition: ok / failed / timeout / skipped (with its reason, e.g. "deadline": not enough job time left) / truncated / unsupported);
    - per-artifact read / stored counts;
    - the hash sets used;
    - the tool versions;
    - the `timeline_engine: replay` label when set;
    - the restricted banner with the release path (admin: release dialog, which on a disk job releases every restricted segment in one acknowledged request (RT20) and then offers to clear the AI / TI flags segment by segment through the share-policy PUT; others: "ask an admin").
  - **Partitions:** a table with `fs_status` badges (encrypted / unsupported explained in plain words).
  - **Files:**
    - a directory tree (lazy, via `/dirs`) beside a virtualized table (`/files`);
    - filters: deleted, orphan, ADS, YARA, known bad / notable, magic, extension, time range;
    - "Hide known files (reference sets)" on by default, labelled as "known software, not necessarily benign" (RT18);
    - hash search;
    - FAT times labelled "local time, zone unknown";
    - lossy and truncated paths marked; hard-linked files marked, with their other names in the drawer;
    - a row opens the file detail drawer: all metadata, other names, streams, hashes, `known` set, YARA rules, findings, events, "also seen in", and **Export** (enabled from the API's `exportable` flag: allocated regular files ≤ 64 MiB none of whose names is on the never-collected list; otherwise a disabled button with the reason; RT7).
  - **Timeline:**
    - the merged view (`/timeline`) with source toggles (file system / events), an artifact filter and a time-range picker;
    - virtualized rows with `ts`, description, source, path and message (text only);
    - a per-hour histogram from the loaded page window only (no full-scan aggregate);
    - deep links from findings.
  - **Findings, IOCs:** the shared components. The `IocsTab` gets `enrichDisabledReason` while restricted (the M8 RT16 prop).
  - **Exports:**
    - the interop downloads with the TLP:RED reminder and what each is for: body file ("for mactime"), timeline CSV / JSONL ("Timesketch import columns"), notable hashes ("Autopsy hash-set import, one md5 per line"; RT12);
    - the list of file exports with state (`expired` ones say the file was deleted after the TTL); a `ready` export shows size and "sha256 reported by the worker (unverified)"; the export action posts to `…/disk/file-exports` (RT29) and says it re-downloads the image;
    - **Add to case as evidence** (promote) shows the trusted hashes and links the new evidence when done.
- **Derived-evidence badge** (evidence page): "Exported from disk job … (partition, path)", linking back; the sensitivity badge (generalized in phase 1).
- **Accessibility and safety:**
  - every attacker-chosen string (paths, names, EWF meta, `os_name`, messages) is rendered as text, never as HTML or a link target;
  - long values wrap or truncate with a full-value tooltip;
  - a CSV / download link is never built from row text;
  - table virtualization for 500 000 rows (keyset pages of 200, windowed rendering).
- **Labels:** "Disk (triage)", "Disk (full)", "Disk (file export)"; route `forensics/{id}` (the phase-1 analyzer sweep).

## Implementation Steps
1. Read the M8 memory frontend (closest pattern), the shared analysis components, the evidence uploader and the generated contract types.
2. `lib/disk*.ts`: API clients, segment natural sort (tests with E01, split raw and mixed names), timeline cursor helpers, label maps.
3. Run dialog and upload option; error mapping.
4. Job page tabs: overview, partitions, files (tree + table + drawer), timeline, exports.
5. Export / promote flow; derived badge.
6. `pnpm --filter web test -- <own paths>`, `typecheck`, `lint`.

## Success Criteria
- [ ] Segments can be selected, ordered and submitted; invalid sets show the API's reason.
- [ ] The job page renders the fixture job (through the generated types and mocked fetches in tests): stage strip, media hash states, the file browser with filters, the merged timeline, and exports.
- [ ] Restricted jobs show the banner, hide Enrich, and label downloads; derived evidence links back to its source.
- [ ] No attacker-chosen string is rendered as markup (a test with `<script>`, `javascript:` and RTLO names).

## Risk Assessment
- **Large tables in the browser:** virtualization and keyset pages; no client-side full loads.
- **Contract drift:** the response models are frozen in phase 1; the web builds against the generated types.
