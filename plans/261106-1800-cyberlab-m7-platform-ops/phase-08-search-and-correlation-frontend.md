---
phase: 8
title: "Search and correlation frontend"
status: completed
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
- [x] Global search works from the header, with typed sections, per-type timeouts, deep links and inert text rendering. — `components/search/search-results.test.tsx` ("renders hostile snippet text as text with marks built from ranges", "makes bidi overrides visible (M6 vis rule)", "a timed-out type shows its notice and no hits", "a hit links internally and shows the case number", "shows the case TLP and marks the server's snippet ranges"); `lib/search.test.ts` ("marks at the start and the end of the text", "never splits a surrogate pair", "isolates a timed-out type…", "refuses external, scheme, other-org and unknown p[aths]") (9316433). The browser run (`e2e/search-correlation.spec.ts`) is pending gate.
- [x] IOC tabs show "also seen in" chips and a key drawer, and the case page shows related cases, all in neutral wording. — `components/correlation/correlation-parts.test.tsx` ("one chip per key, the value defanged text and never a link", "ranks as given, labels archived cases and shows the kinds", "marks the keys carried by the visible IOC rows"); `lib/correlation.test.ts` ("maps the visible rows to their keys, by id only", "keeps generated texts neutral", "POSTs the key lookup with the value in the JSON body only") (9316433).
- [x] The query never reaches browser storage or logs. — `lib/search.test.ts` ("puts the query after # and never in a query string", "POSTs the query in the JSON body only, never in the URL or storage", "scans the search box, page and hooks"); `lib/correlation.test.ts` ("scans the correlation and search sources") (9316433). The server side is phase 4 (`test_a_timeout_is_isolated_per_type_and_nothing_logs_the_query`).
- [x] Web tests, typecheck and lint pass on the owned files. — `pnpm --filter web lint typecheck test` on the host (web lane), green before 9316433. The full `pnpm verify` re-run is pending gate.

## Risk Assessment
- **IOC tab components belong to M2–M4 code:** untouched by this phase; the phase-1 slot receives `{jobId, rows}` props, frozen in phase 1.
- **Large IOC tabs:** fetch the correlations once per tab and join in memory. No per-row request.

## Implementation Notes (2026-11-07)
- **Commit:** 9316433 (phases 2–10 together). The slots `search-box.tsx`, `ioc-seen-in.tsx` and `related-cases-card.tsx` were mounted in 980386a, so this phase edited only its owned files (RT16).
- **Web lane on the host:** `pnpm --filter web lint typecheck test`. No containers, and fetch is mocked against the phase-1 contracts plus the 9316433 gap fields.
- **Typed clients:**
  - `lib/search.ts` (+292): `checkQuery` (2–256 code points), `searchFragment` / `parseSearchFragment`, `searchBody`, `normalizeRanges` / `markSegments` / `snippetSegments`, `sectionStates`, `hitHref` and `slowDownText`;
  - `lib/use-search.ts` (+126): the page hook, per-type "load more" through the cursor, and 429 with `Retry-After`.
- **Search box** (`components/search/search-box.tsx`, `search-form.tsx`):
  - `/` outside a text field focuses the box;
  - Enter opens `/o/{org}/search#q=…`: the fragment never reaches a server or a log (RT13);
  - the page sends `POST /search` with the query in the body.
- **Search page** (`app/(app)/o/[orgId]/search/page.tsx`, `search-results.tsx`):
  - type chips with `aria-pressed` and sections with counts in an `aria-live="polite"` status;
  - a per-type timeout notice;
  - snippets are rendered from the server's `snippet_ranges` as `<mark>` segments, never as HTML, with the M6 `vis` rule;
  - a TLP badge and the case number on each hit;
  - deep links pass an internal-path check, which refuses external, scheme and other-org paths.
- **"Also seen in"** (`ioc-seen-in.tsx`, +106):
  - one `GET /analyses/{job}/correlations` per tab;
  - keys join the visible rows by the IOC row ids in `source_ids`, never by re-normalizing values in the browser (RT8);
  - a `common` badge;
  - clicking opens the key drawer.
- **Key drawer** (`key-drawer.tsx`, +146):
  - `POST /correlations/lookup`, the POST route from phase 4's security review, with the value in the JSON body;
  - jobs and cases with links, first and last seen;
  - the TI answer count, linked to the existing IOC history;
  - the collections holding the key;
  - neutral wording ("also observed in").
- **Related cases card** (`related-cases-card.tsx`):
  - ranked cases with shared-key counts;
  - `sample_keys` as defanged text, never links;
  - archived cases are labelled;
  - empty state "no shared observables".
- **Contract gap fields used:** search TLP and `snippet_ranges`, correlation `source_ids`, `sample_keys` and the TI count. The tests marked "(M7 follow-up)" cover them.
- **Tests** (9316433):
  - `lib/search.test.ts` and `lib/correlation.test.ts`;
  - `components/search/search-results.test.tsx` (7) and `components/correlation/correlation-parts.test.tsx` (6);
  - `apps/web/e2e/search-correlation.spec.ts`: header search, "also seen in" and related cases across two cases.
- **Pending gate:** the e2e spec (phase 11) and the `pnpm verify` re-run on the final tree.
- **Closure (2026-11-06):** `search-correlation.spec.ts` passed in the dev e2e (vp8) and the prod e2e; the gate passed in segments, not in one `pnpm verify:prod` run (see the plan's Closure).
