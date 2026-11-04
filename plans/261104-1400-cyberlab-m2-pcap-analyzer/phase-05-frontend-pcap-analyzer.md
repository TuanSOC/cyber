---
phase: 5
title: "Frontend PCAP analyzer"
status: pending
priority: P2
effort: "14h"
dependencies: [4]
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
