---
phase: 8
title: "AI analyst frontend views"
status: pending
priority: P1
effort: "11h"
dependencies: [2, 3, 4, 5, 6, 7]
---

# Phase 8: AI analyst frontend views (group C, 3a)

## Overview
The analyst-facing AI views:
- an "AI Analyst" tab on pcap and malware job pages;
- a per-row "Explain" drawer on findings and alerts;
- an incident card on the investigation page (summary, timeline, recommendations, per-job digests);
- the AI runs list replacing the M5 placeholder;
- citation chips that deep-link to the exact record (new `ref` support on every result tab);
- the server-side analyses-by-investigation filter adopted by `investigation-analyses.tsx`.

It starts after the group-B merge and the regenerated `packages/contracts`.

**Owns:**
- `apps/web/lib/ai.ts` (+ `ai.test.ts`), `lib/use-ai.ts`, `components/ai/**`;
- `lib/pcap-results.ts` (+ test), `lib/static-results.ts` (+ test), `lib/nav.ts`;
- `components/analysis/{analysis-results,findings-tab,alerts-tab,iocs-tab,records-tab,timeline-tab,investigation-analyses}.tsx`;
- `components/malware/{static-results,signature-tabs,strings-tab,structure-tabs}.tsx`;
- `app/(app)/o/[orgId]/ai-analyst/page.tsx` and `ai-analyst/[runId]/page.tsx`;
- `app/(app)/o/[orgId]/investigations/[invId]/page.tsx`;
- the `pcap/[jobId]` and `malware/[jobId]` pages only if the tab wiring needs it.

It never edits `components/ti/**`; it reuses `attack-chips.tsx` read-only.

## Requirements
- **Rendering rules** (security):
  - every model-derived string is rendered as React text: no `dangerouslySetInnerHTML`, no markdown renderer, no `<a href>` built from model text;
  - links exist only from the API's deep-link descriptors of **verified** citations, mapped by `lib/ai.ts` to internal routes (`/o/{org}/pcap/{job}?tab=findings&ref={id}` …); every path and query part is built with `encodeURIComponent` (a flow `ref` is an analyzer-written Zeek uid, RT16);
  - URLs in text stay defanged as delivered; a lint and test asserts that no `href` uses a field from the output body;
  - a banner on every AI view: "AI-generated interpretation of the cited evidence. Verify before acting. CyberLab never acts on AI output."
- **AI Analyst tab** (pcap: `RESULT_TABS` in `lib/pcap-results.ts`; static: `staticTabs()`):
  - **Task buttons:** pcap "Summarize capture", IOC correlation, ATT&CK mapping; static "Explain static findings", IOC correlation, ATT&CK mapping. Provider and model come from the org default with an override select.
  - **"What will be sent"** preview dialog (`POST …/ai/context-preview`):
    - per-kind counts included / total, the truncation note and pseudonymization counts;
    - the inclusion toggles in effect (read-only, linking to settings for admins);
    - the collapsible exact JSON as plain text.
  - **Run states:**

    | State | Shown as |
    |---|---|
    | queued / running | spinner with elapsed time |
    | waiting | "Provider rate-limited, retrying at {resume_at}" |
    | refused | "The provider declined this request (category: cyber). No retry is made." |
    | failed | a mapped message per code (`budget_exhausted`, `spend_limit`, `auth_failed`, `max_tokens`, `invalid_output`, `deadline`, `canary_leak` with "output withheld", `provider_unavailable`) |
    | deduplicated | "Showing the existing analysis of identical evidence", with a Regenerate button |
  - **Output view** (`components/ai/analysis-output.tsx`):
    - sections Observed / Interpretation / Hypotheses / Confidence / Next steps / Limitations / Possible ATT&CK techniques (name and tactic from the index chips, with the MITRE notice) / Timeline;
    - neutral confidence badges (no red/green, the M4 RT20 lesson), labelled "Confidence in this interpretation", never a maliciousness score (RT21);
  - supported claims read "backed by cited evidence", never "verified" or "true"; `weak_anchor` and `quote_too_short` have their own reason texts ("quote does not support this statement", "quote too short to check") (RT1, RT21);
    - **unsupported claims** collapsed behind "N statements hidden: not supported by verified evidence", expandable and greyed;
    - flags as notes: `verdict_language`, `command_like` ("CyberLab never runs commands"), `external_url`, stale citations.
  - **Citation chips** (`components/ai/citation-chip.tsx`):
    - **verified:** a label plus kind icon that links via the descriptor; a tooltip shows the field and quote;
    - **unverified / invalid:** grey, not a link, with the reason ("quote not found in record", "unknown reference", "outside this case") in the tooltip.
  - **Footer:**
    - provider, model, served model (if different), `prompt_version`, tokens, cost (`≈`, estimated flag), `context_sha256` (short), run time;
    - "View sent context" (`GET …/runs/{id}/context`, plain text, with a "show original names" toggle for `reveal`);
    - previous runs for this job (list, superseded marker).
- **Explain drawers:** a row action "Explain" on `findings-tab.tsx` and `alerts-tab.tsx` (pcap) and the static findings tab. It opens `ui/sheet.tsx` with the same output view for `explain_finding` / `explain_alert` (target id = row id) and reuses an existing completed run for the row if there is one.
- **Deep links (`ref`):** `findings`, `alerts`, `iocs`, `records`, `timeline` (pcap) and `signatures`, `capabilities`, `strings`, `imports` (static) read `?ref=<id>`. They call the list route with `ref=` (phase 4), show that row highlighted with a "Showing 1 cited record, clear filter" bar, and scroll it into view. Flows keep their existing `ref`.
- **Investigation page:**
  - `investigation-analyses.tsx` switches to `GET …/analyses?investigation_id=&latest_per_evidence=true`, dropping the newest-100 client filter;
  - new incident card (`components/ai/incident-card.tsx`): "Generate incident summary" (preview first) → parent status plus per-child digest progress (n of m);
  - the output shows the summary claims, the **timeline** (ts from records, ordered; each entry with its chips) and **recommendations** (`next_steps`);
  - per-job digests are collapsible, and a digest's flags (`verdict_language`, `external_url`) are shown on the parent too (RT23);
  - a partial run states which jobs failed.
- **AI runs list** `/o/{org}/ai-analyst`: a table (task, target link, provider/model, status, citation accuracy, unsupported count, tokens, cost, requested by, time), filters by task and status, paging; row → `/ai-analyst/{runId}` (full output view). `lib/nav.ts`: drop `plannedFor` from the AI item, and change the Integrations summary to "Threat intelligence and AI provider keys and settings" (phase 9 relies on this).
- **Hooks** (`lib/use-ai.ts`): TanStack Query polling at 2 s while active, with backoff while waiting until `resume_at`; stop when final.
- **Role awareness:** viewers see outputs but no run buttons (they lack `evidence.write`). If AI is disabled for the org, buttons are replaced by "AI is off for this organization" (admins get a link to Integrations).

## Implementation Steps
1. `lib/ai.ts`: types from contracts, the deep-link builder (an allowlist of routes and tabs), the error-code message map, citation and claim view helpers; unit tests (no external link is ever produced; a descriptor with an unknown route is dropped).
2. Output view, citation chip, preview dialog, run status, footer, context viewer.
3. AI tabs on pcap and static pages; Explain drawers; `ref` support on the result tabs (+ `pcap-results` / `static-results` tests).
4. Investigation page: the analyses filter and the incident card.
5. Runs list and run detail pages; nav.
6. Component tests (Vitest + Testing Library) with a hostile output fixture (`javascript:` text, markdown links, bidi, unsupported claims, invalid citations): no anchor except verified internal links, text rendered literally.

## Success Criteria
- [x] No `href` derives from model text; hostile-output component tests pass; unsupported claims are hidden by default. — `components/ai/analysis-output.test.tsx` ("renders no anchor except verified internal links", "renders model text literally (no HTML, no markdown)", "hides unsupported statements by default behind a counter"); the `lib/ai.test.ts` "AI view sources" scan: no `dangerouslySetInnerHTML`, `innerHTML`, markdown or `<a `, and every `href={…}` comes from `chip.href`, `target`, `back`, `orgPath(` or a literal `/o/` path (5e9b97e).
- [x] Each verified chip lands on the exact cited row (deep-link tests per tab). — `lib/ai.test.ts` `deepLinkHref` (internal routes only, URL-encoded flow ref RT16, unknown routes / tabs / non-uuid ids dropped, never absolute); `lib/pcap-results.test.ts` "reads ref on every citable PCAP tab", "queries just the cited row, ignoring the other filters and the page"; `lib/static-results.test.ts` "reads ref on every citable static tab"; server side `test_result_ref_filters.py::test_ref_returns_exactly_that_row` (5e9b97e, 83f24a1). The browser check is in `e2e/ai-analyst.spec.ts` (pending gate).
- [x] Every run state and error code has a message; viewers cannot start runs; a disabled org shows the off state. — `lib/ai.test.ts` "labels every status and maps every state to a message", "names unknown codes verbatim"; `components/ai/ai-access.tsx` (`canRun = can("evidence.write")`, the "AI is off for this organization" notice). There is no component test of that gate; the API refuses viewers (`test_ai_api_runs.py::test_viewer_reads_but_cannot_request`).
- [ ] `pnpm --filter web test`, lint and typecheck are green; the phase-11 e2e covers the flows. — **pending gate:** `pnpm verify:prod` is still running. `pnpm --filter web test` gives 316 passed at 6b52742. Lint, typecheck and the dev e2e (`apps/web/e2e/ai-analyst.spec.ts`) run inside that gate.

## Risk Assessment
- **Poll load** with many open tabs. Poll only active runs, with backoff, and stop on final.
- **Long outputs** (40 observed claims) hurt readability. Group by section, collapse after 10, and keep the counts visible.
- **Contract shape changes** from the group-B merge. This phase starts only after the contracts are regenerated; seams go to the parent.

## Implementation Notes (2026-11-06)
- **Commits:**
  - 5e9b97e: phases 8 and 9 together (49 files). `lib/ai.ts`, `lib/use-ai.ts`, `components/ai/**` (17 components), the runs list `/o/{org}/ai-analyst` and the run page `/ai-analyst/{runId}`, and `ref` on the pcap and static result tabs.
  - 6b52742: the context viewer's reveal toggle is hidden for viewers; the Playwright spec.
- **Rendering:**
  - Model text is rendered only as React text (`model-text.tsx`).
  - Links come only from the API descriptors of verified citations. `deepLinkHref` maps them over a route and tab allowlist, with `encodeURIComponent` and a cap on the ref length.
  - `ai-banner.tsx` shows the "verify before acting" banner on every AI view.
- **Wording (RT21):**
  - "backed by cited evidence", never "verified" or "true" ("says 'backed by cited evidence', never 'verified' or 'true' (RT21)");
  - "Confidence in this interpretation", with neutral badges;
  - the source scan forbids `malicious|benign|clean|safe|verdict|harmless` in the AI sources ("keeps fixed texts verdict-free").
- **Claims:** unsupported claims sit behind a counter; sections collapse after 10 items ("collapses long sections after 10 items").
- **Chips:**
  - verified chips link, with the field and quote in the tooltip;
  - unverified and invalid chips are grey and show their reason ("never links unverified or invalid citations, even if a descriptor is present").
- **Polling** (`use-ai.ts`): every 2 s while a run is active, until `resume_at` while it waits, never once final.
- **Context and footer:**
  - notes state the truncation and pseudonymization counts, make bidi controls visible, and show the cost as ≈;
  - `context-preview-dialog.tsx` and `context-viewer.tsx` ("Show original names" → `reveal`);
  - `run-footer.tsx`, and `run-history.tsx` with a superseded marker ("picks the newest run per task and marks superseded runs").
- **Explain drawers** (`explain-drawer.tsx`): on the pcap findings and alerts tabs and the static findings. They reuse an existing completed run for the row.
- **Incident card** (`incident-card.tsx`):
  - preview first, then the parent status with "n of m" digests, the timeline and the next steps;
  - child flags shown on the parent (RT23: "carries child flags to the incident parent (RT23) and counts digests").
- **Investigation analyses:** `investigation-analyses.tsx` uses the server filter `investigation_id` + `latest_per_evidence` instead of the newest-100 client filter.
- **Nav** (`lib/nav.ts`): `plannedFor` is dropped from the AI item, and the Integrations summary now mentions AI provider keys.
- **Deviations:**
  - Phases 8 and 9 shipped in one commit.
  - The viewer and AI-off gates have no component test. They are covered by the API RBAC tests and the dev e2e (pending gate).
