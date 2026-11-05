---
phase: 7
title: "Report builder and viewer frontend"
status: pending
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
- [ ] An analyst builds a draft, previews it, finalizes it and lands on the version viewer. Stale drafts never overwrite silently.
- [ ] The viewer renders every snapshot section as text, with TLP banners and integrity status. Citation chips open the appendix and the internal deep links.
- [ ] The hostile snapshot renders inert: no data-derived elements, attributes or external links.
- [ ] Renders can be requested, their status is shown, and downloads use the server filename.
- [ ] Reports is a live navigation entry. Lint, typecheck and tests are green on the owned files.

## Risk Assessment
- **Viewer and renderer diverge** (different text rules or section order). The shared `vis` rule fixture and the snapshot-ordered sections keep them aligned, and phase 9 compares the viewer text to the extracted PDF text on the golden snapshot.
- **Large snapshots in the browser** (8 MiB JSON). Virtualize long tables (findings, IOCs, timeline, appendix) and lazy-render sections below the fold.
- **The builder grows large.** Split it into one component per selection group.
