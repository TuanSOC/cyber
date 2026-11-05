---
phase: 6
title: "Case management frontend"
status: pending
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
- [ ] Every case-management action of phases 2 and 5 is reachable from the case page, with role-correct controls and clear 403 / 409 / 422 messages.
- [ ] TLP is shown as label plus colour everywhere. Downgrades require the confirm and acknowledgement and are unavailable without `org.update`.
- [ ] Note, IOC and rationale text renders only as text. Hostile fixtures produce no element, link or attribute from data.
- [ ] `policy_blocked` responses from AI and TI show the reason and the link to the policy.
- [ ] Lint, typecheck and tests are green on the owned files against the frozen contracts.

## Risk Assessment
- **Contract drift** between the phase-1 stubs and the phase 2/5 implementations. The types come from the frozen OpenAPI, and the merge regenerates and typechecks.
- **Page complexity:** split each tab into its own component file under `components/…`, and keep the page file a thin shell (< 200 lines).
- **One-line edits in M4/M5 components** are the only files this phase touches outside its list. Record them, and the parent checks for conflicts at the merge.
