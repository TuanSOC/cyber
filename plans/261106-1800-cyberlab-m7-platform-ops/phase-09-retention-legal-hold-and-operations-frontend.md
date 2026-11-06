---
phase: 9
title: "Retention legal hold and operations frontend"
status: completed
priority: P1
effort: "9h"
dependencies: [1]
---

# Phase 9: Retention, legal hold and operations frontend (group B, 2h, web only)

## Overview
The UI for the M7 governance and operations features:
- **Settings → Retention:** the policy with its pending lowered values, the enforce switch, the preview, the runs and items;
- **Legal holds:** an org list, a case hold card and a badge;
- **Settings → Operations:** the org's job metrics;
- **Evidence:** the purged state (410) and the type-mismatch badge.

It builds against the phase-1 contracts with mocked fetch. No containers.

**Owns:**
- `apps/web/lib/{retention,legal-holds,ops-metrics}.ts` (+ tests);
- `components/retention/**`, `components/legal-holds/**` and `components/ops/**`;
- `app/(app)/o/[orgId]/settings/{retention,operations}/**`;
- the phase-1 slots `components/evidence/evidence-integrity-strip.tsx` (the purged and mismatch states), `components/legal-holds/case-hold-card.tsx` and `components/investigations/legal-hold-badge.tsx`.

**Mount points:** none (RT16). Phase 1 mounted the slots (case overview, case workspace header, investigations list, evidence page) and wired `evidence-actions.tsx` to disable download and verify on `purged_at`.

## Requirements
- **Retention page** (`org.update` to edit, `org.read` to view):
  - three fields (days or "keep forever"), each showing current, pending and `effective_at` ("takes effect on …"), and the floors;
  - lowering shows a confirmation that names the delay;
  - **enforce switch:** off by default. Turning it on opens a dialog that requires typing the org name (compared after NFC normalization and trimming) and sends `acknowledge_destruction`. The dialog explains what is purged and what is never purged (the plan.md lists, verbatim), and that enforcement **starts after the delay** ("enforcement begins on …", RT1); the page shows the pending state until then.
  - **Preview button:** shows counts and bytes per category and the bounded sample (labels only), plus "includes pending values" as a toggle.
  - **Runs table:** mode, trigger, status, counts, started and finished; it opens the run items (paged, outcome filter).
- **Legal holds:**
  - org page section: active and released holds; place an org hold (reason required); release (reason required, confirmation that the data stays protected until `released_at + delay`, RT1);
  - case card: place or release a case hold, showing "object-store hold: pending" until `s3_synced_at` is set (the worker syncs it, RT5);
  - a badge "Legal hold" on the case header and in the case list;
  - only `org.update` sees the actions (`lib/roles.ts: can`).
- **Operations page** (`audit.read`):
  - a window selector (24 h / 7 d);
  - per analyzer: counts, failure rate, p50 / p95 run and queue latency, parse success;
  - the five most recent failures with error class and deep link;
  - the numbers are plain text and tables (no charting library added);
  - a note: "platform-wide metrics are served to operators at `/internal/metrics`".
- **Evidence page:**
  - when `purged_at` is set: an integrity strip "Bytes purged on … by retention run …; hashes and custody retained", the download and verify buttons disabled, and analysis triggers hidden. A 410 from any action shows the same message (`lib/http-errors.ts`).
  - when `type_mismatch` is set: a neutral badge "Declared type (.pdf) differs from detected type (PE)", with a tooltip that the file was accepted and analysis follows the detected type.
- **Tests:**
  - the policy form (floors, pending display, enforce dialog requires the typed name and shows the enforcement start date);
  - preview rendering;
  - the role gating of the actions;
  - the purged evidence state and the 410 handling;
  - the mismatch badge text;
  - operations numbers formatting;
  - hostile labels in samples and items render as text.

## Implementation Steps
1. The typed clients and hooks.
2. The retention page and its tests.
3. Legal holds (org section, case card, badge) and their tests.
4. The operations page and its tests.
5. The evidence purged and mismatch states, plus the mount lines.
6. `pnpm --filter web lint typecheck test` on the owned files.

## Success Criteria
- [x] Admins can view and edit the retention policy with pending values and floors shown, enable enforce only through the typed acknowledgement, preview candidates and browse runs and items. — `components/retention/retention.test.tsx` ("shows current, pending with its effective date, and the floor", "requires the typed org name before confirming", "states when enforcement begins and what is and is not purged", "renders counts and bytes per category and the bounded sample", "lists runs with mode, trigger, status, counts and a link to the items"); `lib/retention.test.ts` ("compares the typed org name after NFC normalization and trimming", "sends the acknowledgement only when turning enforcement on", "asks the API for one page of items, filtered by outcome") (9316433).
- [x] Holds can be placed and released with reasons, and badges show on cases. Non-admins see no actions. — `components/legal-holds/legal-holds.test.tsx` ("shows only on held cases", "offers place to org.update only", "offers release to org.update only…", "shows the object-store hold as pending until the worker syncs it", "names the protection delay before a release is confirmed (RT1)"); `lib/legal-holds.test.ts` ("requires a reason of at most 500 characters", "keeps a released hold protecting until the delay passed (RT1)") (9316433).
- [x] The operations page shows the org's metrics. — `components/ops/ops-metrics.test.tsx` ("renders the numbers as plain text", "shows active counts and the window selector", "lists recent failures with their class and a deep link"); `lib/ops-metrics.test.ts` (7) (9316433).
- [x] Purged evidence and type mismatches are shown clearly, and 410s are handled. — `components/evidence/evidence-integrity-strip.test.tsx` ("explains purged bytes with the date and the retained hashes and custody", "names the purging run, linked for audit readers only", "shows the same message after a 410 from an action", "disables download and verify on purged evidence", "shows the declared vs detected type badge with its tooltip"); `evidence-actions.test.tsx` ("explains a 410 evidence_purged instead of the raw server message"); `analysis/evidence-analyses-card.test.tsx` (the analysis triggers are hidden) (9316433).
- [x] Web tests, typecheck and lint pass on the owned files. — `pnpm --filter web lint typecheck test` on the host (web lane), green before 9316433. The full `pnpm verify` and `e2e/retention.spec.ts` are pending gate.

## Risk Assessment
- **Destructive UI:** the enforce dialog and the hold release are the only destructive affordances. Both require explicit confirmation and are audited server-side.
- **Wording:** "purge" and "legal hold" must not imply a legal opinion. The copy is reviewed in phase 11.

## Implementation Notes (2026-11-07)
- **Commit:** 9316433 (phases 2–10 together). The slots (`evidence-integrity-strip.tsx`, `case-hold-card.tsx`, `legal-hold-badge.tsx`), the settings tabs and the `purged_at` disable in `evidence-actions.tsx` come from 980386a.
- **Web lane on the host:** `pnpm --filter web lint typecheck test`. No containers, and fetch is mocked against the contracts plus the 9316433 gap fields.
- **Typed clients:**
  - `lib/retention.ts` (+371): floors, the "keep forever" / days format, `isLowering`, the pending reads, the enforce state, the typed-name compare after NFC normalization and trimming, the paged items with an outcome filter, and the label sanitizer (control and bidi characters stripped, length capped);
  - `lib/legal-holds.ts` (+111): reasons of 1–500 characters, protection until `released_at + delay` (RT1), and the S3 sync shown for case holds only (RT5);
  - `lib/ops-metrics.ts` (+132).
- **Settings → Retention** (`settings/retention/page.tsx`, `retention-policy-card.tsx` +371):
  - three fields, each with its current and pending value, `effective_at` and floor;
  - the lowering notice names the delay and its date;
  - viewers see values only.
- **Enforce dialog** (`enforce-acknowledgement.tsx`):
  - it needs the typed org name and sends `acknowledge_destruction` only when turning enforcement on;
  - it lists what is purged and what is never purged;
  - it states "enforcement begins on …" (RT1);
  - the page shows the pending state until then.
- **Preview, runs and items:**
  - `retention-preview.tsx`: counts and bytes per category, the bounded sample, and the pending-values toggle;
  - `retention-runs.tsx`: mode, trigger, status and counts;
  - `settings/retention/runs/[runId]` with `run-detail.tsx`: items paged by the API with an outcome filter (a contract gap field).
- **Legal holds** (`hold-actions.tsx`, `hold-list.tsx`, `org-legal-holds.tsx`, `case-hold-card.tsx`, `legal-hold-badge.tsx`):
  - the org section with active and released holds;
  - place and release with a reason; the release confirmation names the protection delay;
  - "object-store hold: pending" until `s3_synced_at` is set;
  - the badge on the case header and in the list;
  - the actions show only for `org.update`.
- **Settings → Operations** (`settings/operations/page.tsx`, `ops-metrics.tsx` +211):
  - a 24 h / 7 d selector;
  - per kind: counts, failure rate, p50 / p95 run and queue latency, and parse success;
  - active counts;
  - the five most recent failures with class and deep link (a gap field);
  - plain text and tables, no charting library;
  - the `/internal/metrics` operator note.
- **Evidence:**
  - `evidence-integrity-strip.tsx` (+160): the purged message with the date, the run (linked for `audit.read` only, through `purged_by_run_id`), and the retained hashes and custody;
  - the same text after a 410 (`lib/http-errors.ts`);
  - the declared vs detected type badge with its tooltip;
  - the evidence legal hold.
- **Deviation from "no mount points" (RT16), small:**
  - `components/analysis/evidence-analyses-card.tsx` (+9) hides the analysis triggers on purged evidence (`PURGED_NOTE`);
  - `components/evidence/evidence-actions.tsx` (+12) explains a 410 instead of the raw server message;
  - both have tests.
- **Tests** (9316433):
  - `lib/{retention,legal-holds,ops-metrics}.test.ts`: 17, 5 and 7;
  - `components/retention/retention.test.tsx`: 11;
  - `components/legal-holds/legal-holds.test.tsx`: 8;
  - `components/ops/ops-metrics.test.tsx`: 4;
  - `evidence-integrity-strip.test.tsx`: 8;
  - `evidence-actions.test.tsx`: 3;
  - `evidence-analyses-card.test.tsx`;
  - `apps/web/e2e/retention.spec.ts`: policy, preview, dry run, hold, purged evidence, viewer and operations.
- **Copy review:** the "purge" and "legal hold" wording has no legal opinion and is reviewed in phase 11 (risk 2).
- **Pending gate:** `e2e/retention.spec.ts` (phase 11) and the `pnpm verify` re-run on the final tree.
- **Closure (2026-11-06):** `retention.spec.ts` passed in the dev e2e (vp8) and the prod e2e (steps 4 and 5 skipped in prod by design); the gate passed in segments, not in one `pnpm verify:prod` run (see the plan's Closure).
