---
phase: 8
title: "Search and correlation frontend"
status: pending
priority: P1
effort: "9h"
dependencies: [1]
---

# Phase 8: Search and correlation frontend (group B, 2g, web only)

## Overview
The §12 "search" and the analyst's pivot:
- a global search box in the shell header and an org search page;
- an "Also seen in" panel on the IOC tabs of pcap and static jobs;
- a key detail drawer (jobs and cases for one observable, TI history count, collections);
- a "Related cases" card on the case page.

It builds against the phase-1 contracts with mocked fetch. No containers.

**Owns:**
- `apps/web/lib/{search,correlation}.ts` (+ tests) and `lib/use-search.ts`;
- `components/search/**` (after the phase-1 `search-box.tsx` stub) and `components/correlation/**` (including the phase-1 slots `ioc-seen-in.tsx` and `related-cases-card.tsx`);
- `app/(app)/o/[orgId]/search/**`.

**Mount points:** none (RT16). Phase 1 mounted the empty slots in `components/analysis/iocs-tab.tsx` and `components/investigations/overview-tab.tsx`; this phase fills the slot components only and edits no file outside the owned paths.

## Requirements
- **Search box** (header):
  - `/` focuses it; Enter navigates to `/o/{org}/search#q=…` (the fragment never reaches a server or a log, RT13); the page calls `POST /search` with the query in the body;
  - it trims and enforces 2–256 characters on the client;
  - it never puts the query in a URL query string, `localStorage`, analytics or the console.
- **Search page:**
  - type filter chips (observable, case, evidence, finding, alert, note) and per-type result sections with counts;
  - a "timed out" notice per type (`error: "timeout"`);
  - hits rendered as text only: snippet ranges become `<mark>` built from ranges, never from HTML;
  - a TLP badge and case number per hit, and deep links through the existing link descriptors (the M5 / M6 `deep_link` shape);
  - "load more" per type through the cursor;
  - empty, loading and error states; 429 shows "slow down" with `Retry-After`.
- **"Also seen in" panel** on the IOC tab (pcap and static):
  - a per-row chip "seen in N other cases" (from `GET /analyses/{job}/correlations`, fetched once per tab and joined client-side by the IOC row id in each key's `source_ids`, never by re-normalizing values in the browser, RT8);
  - the `common` badge ("common across N jobs; excluded from related cases");
  - clicking opens the key drawer.
- **Key drawer** (`GET /correlations?kind=&value=`): the list of jobs and cases with links, first and last seen, the TI history count (link to the existing IOC history page) and the collection memberships. Wording is neutral: "also observed in", never "linked to the same attacker".
- **Related cases card** on the case page (`GET /investigations/{inv}/related`): ranked cases with shared key counts, sample keys and links; archived cases labelled; empty state "no shared observables".
- **Accessibility:** keyboard navigation through the results, ARIA live region for counts, visible focus.
- **Tests** (vitest + testing-library, the repo's pattern):
  - hostile snippet text (`<img src=x>`, U+202E) renders inert, with the M6 `vis` rule applied;
  - range-to-mark conversion is correct at the boundaries;
  - the timed-out type is isolated;
  - the query is absent from storage and from every request URL (only the POST body);
  - the chips join correctly;
  - the wording test (no "malicious", "attacker", "linked" verdict words, like the M4 `ti-wording.test.ts`).

## Implementation Steps
1. `lib/search.ts` and `lib/correlation.ts` (typed clients from the contracts) and `use-search.ts`.
2. The search box and the page, with their tests.
3. The "Also seen in" chips and the key drawer, plus the mount lines.
4. The Related cases card, plus its mount line.
5. `pnpm --filter web lint typecheck test` on the owned files.

## Success Criteria
- [ ] Global search works from the header, with typed sections, per-type timeouts, deep links and inert text rendering.
- [ ] IOC tabs show "also seen in" chips and a key drawer, and the case page shows related cases, all in neutral wording.
- [ ] The query never reaches browser storage or logs.
- [ ] Web tests, typecheck and lint pass on the owned files.

## Risk Assessment
- **IOC tab components belong to M2–M4 code:** untouched by this phase; the phase-1 slot receives `{jobId, rows}` props, frozen in phase 1.
- **Large IOC tabs:** fetch the correlations once per tab and join in memory. No per-row request.
