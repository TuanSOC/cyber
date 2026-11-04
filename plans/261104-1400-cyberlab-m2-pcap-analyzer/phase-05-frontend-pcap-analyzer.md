---
phase: 5
title: Frontend PCAP analyzer
status: completed
priority: P2
effort: 14h
dependencies:
  - 4
---

# Phase 5: Frontend PCAP analyzer

## Overview
Turn the "PCAP Analyzer" nav placeholder into a real module and show analyses on evidence.

## Requirements
- `/o/[orgId]/pcap`: list of analyses (status, evidence, case, started, duration, finding
  counts by severity), filters by status; links to detail.
- Evidence detail: "Analyses" card — status badge with polling while queued/running
  (TanStack Query `refetchInterval` 3 s, stops on terminal state), Run / Re-run (evidence.write),
  error code shown on failure.
- Analysis detail `/o/[orgId]/pcap/[jobId]` tabs: Overview (capture meta, protocol hierarchy
  bars, top talkers table, tool/rule versions, truncation/engine-error warnings), Findings,
  Alerts, Flows, DNS, HTTP, TLS, IOCs (copy buttons), Timeline; all paginated + filters
  debounced; every finding/alert links to its flow by `flow_ref`.
- Case detail: analyses list (status + finding counts) per evidence.
- All untrusted strings (domains, URIs, UAs, cert subjects) rendered as text, truncated with
  title tooltip; no auto-linking of URLs (copy only).

## Related Code Files
- Create: `apps/web/app/(app)/o/[orgId]/pcap/{page,[jobId]/page}.tsx`,
  `components/analysis/*`
- Modify: nav (`lib/nav.ts`: PCAP enabled), evidence detail, investigation detail, contracts.

## Success Criteria
- [ ] Browser walkthrough: upload dataset `mixed.pcap` → job auto-runs → all tabs populated.
- [ ] No console errors; typecheck/eslint/build green.

## Implementation Notes (2026-11-04)
- Built by subagents in two parts (A: list, evidence card, case section, detail skeleton, on the phase-1 API; B: overview and result tabs, on the phase-4 API).
- **Overview:** capture facts, engine-error and "results are partial" warnings, protocol hierarchy bars, top sources/destinations/ports (link to filtered flows), counts from `summary.counts` (never the analyzer-reported `engine_counts`), tool versions and rules digest.
- **Tabs:** findings, alerts, flows, DNS, HTTP, TLS, IOCs, timeline, all paged with debounced filters. The active tab and flow filters live in the URL.
- **Flow links:** they filter by IP/port and highlight the referenced flow uid (the API has no uid filter).
- **Untrusted text:** every packet-derived string is rendered as text, truncated with a tooltip. Nothing is linked; no `dangerouslySetInnerHTML`.
- **Polling:** every 3 s, only while a job is queued or running; on success the custody timeline is refreshed.
- **Browser walkthrough** (parent, dev stack, real ET Open run on `mixed.pcap`): 9 findings matching the labels; the beaconing flow link filters 12 flows and highlights one; TLS shows the self-signed, expired and TLSv10 sessions; no console errors.
  - It found a layout bug: wide tables widened the whole page. Fixed with `min-w-0` on the shell inset, tabs and table wrappers.
- **Not done:** per-severity finding counts (the summary has totals only); other tabs' filters are not in the URL; case links show "Open case" (no `case_ref` in the job response).
