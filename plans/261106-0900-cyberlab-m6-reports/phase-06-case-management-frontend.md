---
phase: 6
title: "Case management frontend"
status: completed
priority: P1
effort: "10h"
dependencies: [1]
---

# Phase 6: Case management frontend (group B, 2e, web only)

## Overview
The investigation page becomes a case workspace with tabs:
- **Overview:** status with reason, the history, TLP and the share policy;
- **Evidence** (with per-item share policy);
- **Notes** (versioned);
- **IOCs** (case-wide list and collections, with exports);
- **ATT&CK** (mappings, suggestions, matrix);
- **Timeline** (the existing view plus the new kinds and export);
- **AI** (the M5 incident card, plus the "blocked by policy" state);
- **Reports** (the phase-1 `case-reports-panel` stub, filled by phase 7).

The phase builds against the phase-1 frozen contracts (`packages/contracts/src/schema.d.ts`) with mocked fetch, because the API routes are still 501 in this lane.

**Owns:**
- `apps/web/lib/{case,notes,ioc-collections,case-attack}.ts` (+ `*.test.ts`) and `lib/use-case.ts` (React Query hooks);
- `components/investigations/**`, `components/notes/**`, `components/ioc-collections/**`, `components/case-attack/**`, `components/timeline/**`;
- `components/ai/policy-blocked.tsx` (new), imported by the existing AI views through the one-line edits listed below;
- `app/(app)/o/[orgId]/investigations/[invId]/**`;
- `app/(app)/o/[orgId]/evidence/[evidenceId]/page.tsx`.

## Requirements
- **TLP components:** `TlpBadge`, `TlpSelect` (with the downgrade confirm) and `lib/tlp.ts` come from phase 1 (shared with phase 7). This phase only uses them.
- **Overview tab:**
  - `StatusControl` is extended: close, reopen and archive open a reason dialog (required, ≤ 500 characters).
  - A status history list (`GET …/status-events`).
  - TLP badge and select.
  - **Share policy card:** "Do not send to AI" and "Do not send to threat-intel providers" toggles.
    - TLP:RED shows both as forced on, with an explanation.
    - Turning a toggle off is disabled for non-`integrations.manage` roles, with the reason shown.
    - A computed `share_policy.reasons` line.
- **Evidence:** the evidence page and the evidence table rows get a share-policy control (the same rules) and a badge when an item is excluded.
- **Policy-blocked state:** `components/ai/policy-blocked.tsx` renders `409 policy_blocked` responses with their reason, and links to the case policy card.
  - One-line imports are added in the M5 AI trigger components and in the TI "Enrich IOCs" button to show it instead of a generic error.
  - While `share_policy.ti_blocked` is set, the case and evidence pages hide the TI "Look up" entry points. Manual lookups carry no case scope, so the API cannot refuse them (RT20).
  - Those files belong to M5 and M4 and no group-B phase owns them, so this phase may make exactly those one-line edits; list them in the phase notes.
- **Notes tab:**
  - A list (pinned first) with author, time and an "edited (vN)" badge.
  - Create and edit in a plain `<textarea>` with a character counter, and refs added through a picker that searches the case's findings, alerts, IOCs and evidence.
  - Refs render as chips that deep-link to the row, using the existing M5 deep-link helpers.
  - The version history drawer shows each version's text as plain text.
  - Delete with confirm leaves a tombstone ("deleted by X at T"), and a "show deleted" toggle.
  - A stale edit (`409 stale_note`) shows a reload prompt with the newer text.
  - **All note text renders as text nodes: no Markdown, no `dangerouslySetInnerHTML`.**
- **IOCs tab:**
  - A case-wide table (type, value **defanged by default** with a reveal toggle, jobs, first/last seen, collections, TI chips reusing the M4 attributed chip), with filters and cursor paging.
  - Select → "Add to collection".
  - A collections list and detail: items, remove, manual add (type + value with client-side shape checks, while the server is authoritative), and the per-item `added / duplicate / invalid` results.
  - Export menu (CSV, JSON, STIX 2.1; the defang toggle only for `evidence.write`) through a download helper that uses the server filename. The TLP of the case shows next to the export button, with the note "exports are not redacted" (RT8).
- **ATT&CK tab:**
  - Mappings grouped by tactic in matrix form (a responsive grid, not a 14-column table on mobile).
  - Status chips (`confirmed`, `suspected`, `rejected`, styled neutrally) and a rationale editor.
  - A suggestions panel listing each source ("capa capability", "finding", "AI — verified citation") with deep links, and Confirm / Suspect / Reject actions.
  - An add-by-id field that validates against `GET /api/v1/attack/techniques?ids=`.
  - The MITRE notice and index version.
- **Timeline tab:**
  - The existing timeline component gains the `status` and `note` kinds (icons, text) and a kinds filter. Entries with a null `evidence_id` are shown as case events, without an evidence link (RT10).
  - An "Export" menu (CSV or JSON, with the current filters) that shows the TLP and the row cap.
- **Accessibility:**
  - The tabs are a `role="tablist"` with keyboard navigation, and the active tab is reflected in `?tab=` so deep links work.
  - Dialogs trap focus.
  - TLP colours are never the only signal: the label text is always present.
- **Permissions:** controls are hidden or disabled per role from the org membership (the existing `lib/roles.ts: can(role, permission)` helper, RT21), and every server 403 still renders a clear message.

## Implementation Steps
1. `lib/*.ts` API wrappers on `openapi-fetch` with typed errors, plus unit tests (`case.test.ts`: error mapping including `policy_blocked`).
2. The overview tab (status reason dialog, history, share-policy card); component tests with mocked fetch for the role matrix (viewer, analyst, admin).
3. Evidence share-policy control and the `policy-blocked` component with its one-line call sites.
4. Notes tab with a test that hostile note text (`<img src=x onerror=…>`, `javascript:` URLs, U+202E) renders as inert text.
5. IOCs tab and collections, including the add result list and the exports (download helper test: filename from `Content-Disposition`, no blob URL left behind).
6. ATT&CK tab.
7. Timeline kinds and export.
8. Investigation page with tabs and `?tab=` routing. Run `pnpm --filter web lint typecheck test` on the owned files.

## Success Criteria
- [x] Every case-management action of phases 2 and 5 is reachable from the case page, with role-correct controls and clear 403 / 409 / 422 messages. — the dev e2e `apps/web/e2e/reports.spec.ts` drives close / reopen with reasons → note → collection + CSV / STIX export → ATT&CK mapping from the case page (e6e0665); `lib/case.test.ts` "maps the stable codes, 403 and 404", "role matrix: viewer, analyst, admin"; `case-overview.test.tsx` role matrix (viewer / analyst / admin) (319f04d). The prod e2e is pending gate.
- [x] TLP is shown as label plus colour everywhere. Downgrades require the confirm and acknowledgement and are unavailable without `org.update`. — `case-overview.test.tsx` "always shows the label text next to the colour", "disables less restrictive labels without org.update"; `lib/tlp.test.ts` "labels and colours", "downgrades and distribution" (319f04d).
- [x] Note, IOC and rationale text renders only as text. Hostile fixtures produce no element, link or attribute from data. — `notes.test.tsx` "produces no element, link or attribute from the body", "makes bidi and zero-width characters visible", "links known refs internally and never links unknown ones"; `ioc-parts.test.tsx` "are defanged text by default and never links"; `case-overview.test.tsx` "renders reasons as text" (319f04d). The ATT&CK rationale renders as a text node (no `dangerouslySetInnerHTML` in `components/case-attack`), but it has no hostile-fixture test of its own.
- [x] `policy_blocked` responses from AI and TI show the reason and the link to the policy. — `components/ai/policy-blocked.test.tsx` (5) "shows the reason and links to the case share-policy card", "names the reason of an error from the shared unwrap (AI / TI wrappers)"; `lib/case.test.ts` "keeps the policy_blocked reason through unwrapCase" (319f04d).
- [x] Lint, typecheck and tests are green on the owned files against the frozen contracts. — the web lane (host `pnpm --filter web lint typecheck test` on the owned files) was green (319f04d). Web vitest: 446 passed at the phase-9 run (322 at phase 1).

## Risk Assessment
- **Contract drift** between the phase-1 stubs and the phase 2/5 implementations. The types come from the frozen OpenAPI, and the merge regenerates and typechecks.
- **Page complexity:** split each tab into its own component file under `components/…`, and keep the page file a thin shell (< 200 lines).
- **One-line edits in M4/M5 components** are the only files this phase touches outside its list. Record them, and the parent checks for conflicts at the merge.

## Implementation Notes (2026-11-06)
- **Commit:** 319f04d (phases 2–8 together).
- **Web lane on the host:** `pnpm --filter web test -- <own paths>`, `typecheck` and `lint`, against the phase-1 contracts and mocked fetch. It used no containers and no lane slot. The worktrees were blocked by the permission system, so this lane shared the main tree with phase 7 (file-disjoint).
- **Case page** (`components/investigations/case-workspace.tsx`):
  - Radix `Tabs` / `TabsList` (keyboard navigation, `aria-label="Case sections"`).
  - Tabs: Overview, Evidence, Notes, IOCs, ATT&CK, Timeline, AI, Reports (`CASE_TABS`).
  - `?tab=` is parsed by `lib/case.parseCaseTab`, with an Overview fallback.
- **Overview:**
  - `status-control.tsx` has the reason dialog for close, archive and reopen (≤ 500 characters).
  - `status-history.tsx`.
  - `case-tlp-card.tsx`, which uses the phase-1 `TlpSelect` with the downgrade confirm and the acknowledgement.
  - `share-policy-card.tsx`: TLP:RED forces both toggles on; turning a flag off is disabled without `integrations.manage`, with the reason shown; the card is the policy anchor.
- **Evidence:** `case-evidence-tab.tsx` and `evidence-share-policy.tsx` (the same rules, plus an excluded badge). The upload card moved to the Evidence tab.
  - **Phase-9 bug (e6e0665):** every e2e spec still uploaded on the Overview tab. The specs now open the Evidence tab, and the AI spec opens the AI tab for the incident card.
- **Policy-blocked** (`components/ai/policy-blocked.tsx`). Edits to M4 / M5 files:
  - `components/ai/context-preview-dialog.tsx`: an import plus the `PolicyBlocked` block, about 14 lines. **Deviation:** the plan allowed only one-line edits.
  - `components/ti/enrich-button.tsx`: +2.
  - `lib/ai.ts`: `AI_ERROR_TEXT.policy_blocked` and the preview text.
  - `lib/ti.ts`: the policy reason text.
  - While `ti_blocked` is set, `case-iocs-tab.tsx` and `collection-detail.tsx` hide the TI "Look up" entry points (RT20).
- **Notes** (`components/notes/{notes-tab,note-editor,note-parts,ref-picker}.tsx`, `lib/notes.ts`):
  - a plain `<textarea>` with a 20 000 code-point counter;
  - refs picked from the case's findings, alerts, IOCs and evidence, as chips through the allowlisted M5 deep links;
  - the version history as text;
  - tombstones, and a "show deleted" toggle;
  - a `409 stale_note` reload prompt.
- **IOCs** (`components/ioc-collections/*`, `lib/ioc-collections.ts`):
  - values are defanged text by default, with a reveal that is still text;
  - add-to-collection with per-item `added / duplicate / invalid`;
  - manual add with client-side shape checks;
  - the export menu: the defang toggle only for `evidence.write`, the TLP and "exports are not redacted" (RT8), and the server filename from `Content-Disposition` with the blob URL revoked.
- **ATT&CK** (`components/case-attack/{attack-tab,attack-parts}.tsx`, `lib/case-attack.ts`):
  - a responsive tactic grid with status chips and a rationale editor;
  - the suggestions panel with Confirm / Suspect / Reject;
  - add by id, validated against `/attack/techniques?ids=`;
  - only https MITRE links.
- **Timeline** (`components/timeline/{case-timeline,timeline-parts}.tsx`):
  - `status` / `note` entries are case events without an evidence link (RT10);
  - a kinds filter;
  - CSV / JSON export showing the TLP and the row cap.
- **Integration (319f04d):** `AddToReportButton` (phase 7) is wired into `notes-tab`, `attack-parts`, `collection-detail` and `timeline-parts`. The plan listed this as a phase-9 seam item.
- **Tests:**
  - `lib/case.test.ts` (17), `components/investigations/case-overview.test.tsx` (8), `notes.test.tsx` (5), `lib/notes.test.ts` (6);
  - `ioc-parts.test.tsx` (4), `lib/ioc-collections.test.ts` (7), `lib/case-attack.test.ts` (6), `timeline.test.tsx` (3);
  - `policy-blocked.test.tsx` (5), `lib/api.test.ts` (5).
  - Web total: 446 passed (phase 9). Dev e2e: all 7 specs pass. The prod e2e is pending gate.
- **Closure (2026-11-06):** The prod e2e passed over TLS (349 s) in the prod phase with the fixed gate (7d2a8e8); the gate passed in segments, not in one `pnpm verify:prod` run (see the plan's Closure).
