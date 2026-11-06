---
phase: 9
title: "Memory analysis frontend"
status: pending
priority: P2
effort: "13h"
dependencies: [1]
---

# Phase 9: Memory analysis frontend (group B, 2h, web only)

## Overview
The "Memory Analysis" module of `requirement.txt` §12 replaces the planned-module placeholder: a job list, a job page with the process tree and the triage tabs, the "Run memory analysis" action on evidence, the memory upload option, and the sensitivity banner with the admin release. Built against the phase-1 contracts and mocked fetch; no containers.

**Owns:**
- `apps/web/lib/{memory,memory-sensitivity}.ts` (+ tests), `lib/use-memory-job.ts`;
- `components/memory/**` (after the phase-1 slots);
- `app/(app)/o/[orgId]/memory/page.tsx` and `app/(app)/o/[orgId]/memory/[jobId]/page.tsx`;
- the phase-1 slots `components/memory/run-memory-analysis.tsx` (mounted in `components/analysis/evidence-analyses-card.tsx`), `components/memory/memory-upload-option.tsx` (mounted in `components/evidence/evidence-uploader.tsx`) and `components/memory/memory-sensitivity-badge.tsx` (mounted in the evidence page); no mount edits.

## Requirements
- **List** (`/o/{org}/memory`): memory jobs of the org (the existing `GET /analyses?analyzer=memory`), status, OS, profile, case, evidence, symbols status, finding counts.
- **Job page** (`/o/{org}/memory/{job}`):
  - header: the shared `job-header.tsx` (status, trusted hashes, versions);
  - **sensitivity banner** while restricted: "TLP:RED material by default: memory can contain credentials, keys and personal data. Not sent to AI or threat-intel providers." Admins see "Release…" (a dialog with the acknowledgement checkbox and a reason, then a link to the evidence share policy);
  - **symbols missing state** (RT12): never shown as "no findings".
    - Windows: the PDB name, GUID and age, and the operator command `pnpm memory:symbols -- fetch-windows --pdb <name> --guid <GUID> --age <n>` to copy, built client-side from the three validated fields only (re-checked against the same patterns before rendering).
    - Linux: the banner as inert, quoted text (never inside a command or a copy button), and a link to the DEPLOYMENT runbook (build the ISF with dwarf2json elsewhere, then `memory:symbols -- import`).
    - Members without `org.update` see "Ask your operator to add these symbols" instead of a command.
    - "Re-run" is always offered (the API cannot see the store); a re-run that still misses gives the same state;
  - **plugin status strip:** every plugin with ok / failed / timeout / skipped and `truncated` markers, so a partial result is never shown as complete;
  - tabs: **Processes** (tree and list toggle; flags hidden / terminated / private-executable-region / lineage; search inside the job; a side panel per process with its connections, memory regions and artifacts), **Network**, **Memory regions** (malfind: hex and disassembly as monospace text, never rendered as HTML), **Modules**, **Services**, **Registry** (hives, UserAssist), **Linux** (bash history, open files, syscall checks, hidden modules; Linux jobs only), **Findings**, **IOCs**, **Timeline** (the shared tabs). No YARA tab (RT8).
  - The IOC tab hides "Enrich" while the evidence is restricted or its TI flag is set, through the shared `IocsTab`'s `enrichDisabledReason` prop added by phase 1 (RT16); the M6 policy also refuses server-side.
  - A "replay engine" label when the header says `engine: replay` (test profile only).
- **Run action:** "Run memory analysis" on any evidence (profile `triage` / `full`, OS `auto` / `windows` / `linux`), with a notice that the run takes minutes and marks the evidence restricted, and, when the evidence already has other jobs, that their results were not restricted before (RT3). Errors from the API (`memory_image_too_large`, `analysis_queue_full`, `evidence_purged`) map to messages through `lib/http-errors.ts` (phase 1 adds the codes).
- **Upload option:** a "This is a memory image" checkbox that sends `?kind=memory`, shows the memory size limit, and says the upload is TLP:RED material from the start and is not analyzed automatically.
- **Navigation:** `lib/nav.ts` drops `plannedFor` from the Memory Analysis item (phase 1 does it, so the placeholder route stops matching).
- **Large tables:** virtualized or paged (the existing pager), never more than 200 rows per request.

## Implementation Steps
1. Read the Malware Lab pages and `components/analysis/*` for the shared pieces.
2. `lib/memory.ts` (typed client calls, tree helpers) with tests.
3. The list and job pages; the tabs; the tree component (keyboard accessible, collapsible).
4. Sensitivity banner and release dialog; run action; upload option.
5. `pnpm --filter web test -- <own paths>`, `typecheck`, `lint`.

## Success Criteria
- [ ] The job page renders the phase-1 fixture: tree, flags, every tab, plugin strip.
- [ ] The symbols-missing and restricted states render as specified and never as "clean"; a test with shell metacharacters in a Linux banner proves it never appears in a command or a copy button.
- [ ] Release is offered only to `org.update` members and needs the acknowledgement.
- [ ] No memory text is rendered as HTML (a test with markup in a cmdline).

## Risk Assessment
- **Contract drift:** built against frozen schemas; the merge regenerates contracts and checks.
- **Tree size:** the server caps it at 5 000 nodes; the client falls back to the list view on `truncated`.
