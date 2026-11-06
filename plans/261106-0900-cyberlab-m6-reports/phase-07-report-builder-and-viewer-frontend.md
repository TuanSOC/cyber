---
phase: 7
title: "Report builder and viewer frontend"
status: completed
priority: P1
effort: "12h"
dependencies: [1]
---

# Phase 7: Report builder and viewer frontend (group B, 2f, web only)

## Overview
The Reports module replaces the "Planned for Milestone 6" placeholder. It has:
- an org-wide reports list;
- a per-case reports panel (it fills the phase-1 `case-reports-panel.tsx` stub);
- a **draft builder** with analyst sections, selections, TLP, profile, distribution and an on-demand preview;
- finalize;
- a **version viewer** that renders the signed snapshot JSON as React text, with TLP banners, integrity status, citations and the appendix;
- render requests and downloads.

It builds against the phase-1 frozen contracts with mocked fetch.

**Owns:**
- `apps/web/lib/{reports,report-format}.ts` (+ tests) and `lib/use-reports.ts`;
- `components/reports/**` (after the phase-1 `case-reports-panel.tsx` stub);
- `app/(app)/o/[orgId]/reports/**`;
- `lib/nav.ts` (remove `plannedFor` from Reports).

## Requirements
- **Routes (pages):**
  - `/o/{org}/reports`: the list (case, title, TLP, latest version, updated, status), filterable by case (`?investigation=`), with a "New report" button that picks a case.
  - `/o/{org}/reports/{reportId}`: the builder (draft).
  - `/o/{org}/reports/{reportId}/v/{version}`: the version viewer.
- **Case reports panel:** the reports of the case, plus "New report" (`POST …/investigations/{inv}/reports`).
- **Builder:**
  - Title.
  - TLP select (the shared phase-1 `components/tlp/TlpSelect`, with its downgrade rule).
  - Profile (`internal` / `external`, with an explanation of what `external` removes and that pseudonymization is pattern-based and needs a human review, RT8).
  - Distribution, required for RED and AMBER+STRICT, with a counter.
  - **Analyst sections** (executive summary, scope, methodology, impact, root cause, actions taken, recommendations, lessons learned) as plain `<textarea>`s with counters. **No Markdown or rich text.**
  - **Selections:**
    - evidence and custody toggles;
    - jobs (`latest` or a pick list);
    - findings and alerts (minimum severity, max);
    - IOCs (case list toggle and collections);
    - TI toggle;
    - ATT&CK statuses;
    - timeline (kinds, range, max);
    - notes (pick list of `include_in_reports` notes);
    - AI runs: a pick list of completed case and job runs. Refused and canary-leak runs are absent. Flags and the model show for each run.
    - cited rows: added from row pickers or from "Add to report" actions.
  - **Autosave** is debounced and carries `revision`. On `409 stale_draft` the builder shows a conflict banner with "reload" (it never overwrites silently).
  - **Preview** (`POST …/preview`, rate limited, **on demand only**, never on keystrokes) renders the would-be snapshot in the same viewer component, with a "PREVIEW, not finalized" watermark, the section counts and truncation notes ("showing 500 of 3 412"), the size against the 8 MiB limit, and the render units against the budget, with per-section hints on what to narrow (RT1).
  - **Finalize** opens a confirm dialog with a summary: TLP, profile, distribution, counts, an optional change note (≤ 500, RT23), and "a signed, immutable version vN will be created".
    - For `external`, a required "I reviewed the preview for internal names" checkbox (`acknowledge_external_review`, RT8).
    - On `409 tlp_below_case`, the TLP downgrade confirm for `org.update` holders, or an explanation for others (RT7).
    - On `422 report_too_large_to_render`, the per-section units (RT1).

    It then navigates to the version viewer. Finalize queues the PDF only; other formats are rendered from the viewer (RT5).
- **Viewer** (`components/reports/report-view.tsx`; the same component renders preview and versions). A version's snapshot comes from `GET …/versions/{v}/content` (RT11); the audited snapshot download stays a separate button.
  - A TLP banner at the top and bottom, and sticky on scroll, with the FIRST definition of the label (RT23).
  - The document-control table (prior versions, change notes) under the cover facts (RT23).
  - An integrity strip: `snapshot_ok` and `signature_valid` (green check or red "integrity check failed", never hidden), kid, the full sha256 with a copy button, and a link to the signature JSON.
  - A table of contents and sections in snapshot order: cover facts, analyst sections, evidence inventory and custody, jobs and tool versions, findings, alerts, IOCs (defanged, TI attributed), ATT&CK matrix, timeline, notes, AI sections.
  - **AI sections** use a boxed disclaimer, confidence badges, labelled hypotheses, the omitted counts (unsupported, and flagged in `external`) and the flags inline per claim (RT15). They reuse the M5 `components/ai` presentational pieces where they accept plain props (import only).
  - **Citations:** `[C12]` superscripts are buttons that open the appendix entry. The entry shows kind, ids, `fields_sha256` and the copied fields, plus a deep link to the live record (internal route only, built from ids by `lib/report-format.ts`), labelled "open current record (may differ from the snapshot copy)".
  - **Text rendering:** every value is a text node. Defanged values come from the snapshot, and the viewer never defangs or refangs. Bidi and zero-width characters are made visible by the same `vis` rule as the renderer (`report-format.ts`, reading the materialized `vis-rules.json` and no runtime Unicode category, RT24). No `dangerouslySetInnerHTML`, no `href` from data, no `<img>`. `external` snapshots carry no paths, so their citation entries show no "open current record" link (RT8).
  - **Renders:** formats with status (queued, running, succeeded, failed with a typed reason and a hint), a "Render" button per format, and download buttons using the server filename. Polling stops on final states.
  - **Print:** a "Quick print" button (`window.print()` with print CSS, labelled "not the signed PDF").
- **"Add to report" entry points:** a small `AddToReportButton` (`components/reports/add-to-report.tsx`) that the case-page tabs can import after the merge. Until then it is used only in this phase's own pickers. Wiring it into phase-6 tabs is a phase-9 seam item.
- **Accessibility:**
  - landmarks and a heading hierarchy that matches the snapshot sections;
  - tables with `<th scope>`;
  - the integrity and TLP status conveyed in text;
  - focus management after finalize and on the conflict banner.

## Implementation Steps
1. `lib/reports.ts` (API wrappers, typed errors) and `lib/report-format.ts` (deep-link paths from ids, the `vis` rule, TLP labels, size formatting), with tests: hostile strings, path building only from UUID-shaped ids (otherwise no link), `vis` parity with the renderer through the phase-1 `apps/web/lib/vis-rules.json`.
2. Report list page, case reports panel, nav change.
3. Builder with autosave, the conflict handling and the selections. Component tests with mocked fetch: revision flow, distribution required, a role-disabled downgrade.
4. Viewer (shared with preview). Tests:
   - the golden snapshot renders every section;
   - **the hostile snapshot fixture produces no element, attribute or link from data** (DOM assertions on the rendered tree: no `img`, `script` or `style`, and every `a[href]` is in the internal allow-list);
   - an integrity failure is visible.
5. Renders and downloads.
6. Finalize flow and version navigation. Run `pnpm --filter web lint typecheck test` on the owned files.

## Success Criteria
- [x] An analyst builds a draft, previews it, finalizes it and lands on the version viewer. Stale drafts never overwrite silently. — the dev e2e `reports.spec.ts` covers report → draft + citations → finalize → viewer with a valid signature (e6e0665); `report-builder.test.tsx` "a conflict shows the banner with Reload, never a silent overwrite", "summarizes the version and allows finalize when nothing blocks"; `lib/reports.test.ts` "stops on 409 stale_draft and never overwrites: no further request until reset", "markConflict (a stale finalize) stops autosave" (319f04d). The prod e2e is pending gate.
- [x] The viewer renders every snapshot section as text, with TLP banners and integrity status. Citation chips open the appendix and the internal deep links. — `report-view.test.tsx` "renders every section in snapshot order with a matching heading hierarchy", "shows TLP banners at the top (sticky) and the bottom with the FIRST definition", "an integrity failure is visible as text and as an alert", "citations are buttons that open the appendix, which links to the live record by id"; `lib/report-format.test.ts` "builds job, evidence and note links from UUID ids", "never uses the snapshot path as the href" (319f04d).
- [x] The hostile snapshot renders inert: no data-derived elements, attributes or external links. — `report-view.test.tsx` "produces no element from data", "produces no attribute from data and no external link", "makes bidi and zero-width characters visible and keeps long values whole", "Markdown in text stays literal", "external snapshots carry no record links"; the fixtures are byte-identical copies of the API ones ("are byte-identical copies of the API fixtures") (319f04d).
- [x] Renders can be requested, their status is shown, and downloads use the server filename. — `report-builder.test.tsx` "render rows show typed failures with a hint, and downloads only when ready"; `lib/reports.test.ts` "polls only while a render is active", "latest render per format and typed failure text"; `lib/report-format.test.ts` "download filenames come from the server, sanitized, with a known extension"; the e2e checks that the PDF download's SHA-256 matches (e6e0665).
- [x] Reports is a live navigation entry. Lint, typecheck and tests are green on the owned files. — `lib/nav.ts` drops `plannedFor: "Milestone 6"` from the `reports` entry; the web lane (lint, typecheck, vitest on the owned files) was green (319f04d); web 446 passed at the phase-9 run.

## Risk Assessment
- **Viewer and renderer diverge** (different text rules or section order). The shared `vis` rule fixture and the snapshot-ordered sections keep them aligned, and phase 9 compares the viewer text to the extracted PDF text on the golden snapshot.
- **Large snapshots in the browser** (8 MiB JSON). Virtualize long tables (findings, IOCs, timeline, appendix) and lazy-render sections below the fold.
- **The builder grows large.** Split it into one component per selection group.

## Implementation Notes (2026-11-06)
- **Commit:** 319f04d (phases 2–8 together).
- **Web lane on the host:** lint, typecheck and vitest on the owned files, against the phase-1 contracts and mocked fetch. It shared the main tree with phase 6 because the worktrees were blocked by the permission system.
- **Pages:**
  - `app/(app)/o/[orgId]/reports/page.tsx` (the list, `?investigation=` filter, "New report" with a case picker);
  - `reports/[reportId]/page.tsx` (the builder);
  - `reports/[reportId]/v/[version]/page.tsx` (the viewer);
  - the case panel `components/reports/case-reports-panel.tsx`, the case page's Reports tab.
- **API layer:** `lib/reports.ts` (+811), `lib/use-reports.ts` (+306), `lib/report-format.ts` (+205).
- **Builder:**
  - Components: `report-builder.tsx` (+454) with one component per selection group (`selection-groups.tsx`, `selection-pickers.tsx`, `builder-fields.tsx`).
  - Analyst sections are plain `<textarea>`s with code-point counters.
  - Distribution is required for RED, AMBER+STRICT and external.
  - The `external` explanation (RT8) is shown.
  - The TLP downgrade is disabled without `org.update`.
  - AI runs: completed only, never refused or canary-leak, at most 10.
  - Cited rows are deduplicated and capped at 200.
- **Autosave:**
  - Debounced, carrying `revision`.
  - Edits made during an in-flight save go out with the new revision.
  - On `409 stale_draft` it stops: a conflict banner with Reload, and no further request until a reset.
  - "Add to report" (`appendCitedRow`) retries once from a fresh read on `stale_draft`, then gives up.
- **Preview and finalize:**
  - **Preview** (`preview-panel.tsx`) runs on demand only. It shows the watermark, size against 8 MiB, units against the budget, and per-section hints for `422 report_too_large_to_render` (RT1).
  - **Finalize** (`finalize-dialog.tsx`):
    - a summary and an optional change note (≤ 500);
    - the external-review checkbox (RT8);
    - for `409 tlp_below_case`, the acknowledgement for admins or an explanation for analysts (RT7);
    - it then navigates to the viewer. Finalize queues the PDF only (RT5).
- **Viewer** (`report-view.tsx`, `report-sections.tsx` +576, `report-parts.tsx`, `tlp-banner.tsx`, `integrity-strip.tsx`, `version-viewer.tsx`, `version-list.tsx`):
  - The snapshot comes from `GET …/versions/{v}/content`.
  - Sticky TLP banners at the top and bottom.
  - The document-control table.
  - The integrity strip: `snapshot_ok`, `signature_valid`, kid, the full sha256.
  - Sections in snapshot order.
  - `[Cn]` buttons open the appendix, whose "open current record" links are built only from UUIDs (none for `external`).
- **Text:** every value is a text node (`report-text.tsx`). The `vis` rule reads the materialized `lib/vis-rules.json`, including the review L7 extras. There is no `dangerouslySetInnerHTML`, `<img>` or data-derived `href`.
- **Renders** (`report-renders.tsx`):
  - a Render button per format, with typed failures and hints;
  - polling stops on final states;
  - downloads use the sanitized server filename;
  - "Quick print (not the signed PDF)" uses `window.print()`.
- **Tests:** `report-builder.test.tsx` (15), `report-view.test.tsx` (14), `lib/reports.test.ts` (19), `lib/report-format.test.ts` (8, including "follows the materialized range table at every boundary"). Fixtures: `components/reports/fixtures/{golden,hostile}_snapshot.json`.
- **Not done:**
  - Long tables (findings, IOCs, timeline, appendix) are neither virtualized nor lazy-rendered (a Risk Assessment mitigation).
  - The viewer-vs-PDF text comparison on the golden snapshot (planned for phase 9) was not written.
  - The web "Cited by" panel is deferred (ROADMAP).
  - The prod e2e is pending gate.
- **Closure (2026-11-06):** The prod e2e passed over TLS (349 s) in the prod phase with the fixed gate (7d2a8e8); the gate passed in segments, not in one `pnpm verify:prod` run (see the plan's Closure).
