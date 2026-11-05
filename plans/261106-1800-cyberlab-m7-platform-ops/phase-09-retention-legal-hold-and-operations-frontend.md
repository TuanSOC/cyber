---
phase: 9
title: "Retention legal hold and operations frontend"
status: pending
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
- [ ] Admins can view and edit the retention policy with pending values and floors shown, enable enforce only through the typed acknowledgement, preview candidates and browse runs and items.
- [ ] Holds can be placed and released with reasons, and badges show on cases. Non-admins see no actions.
- [ ] The operations page shows the org's metrics.
- [ ] Purged evidence and type mismatches are shown clearly, and 410s are handled.
- [ ] Web tests, typecheck and lint pass on the owned files.

## Risk Assessment
- **Destructive UI:** the enforce dialog and the hold release are the only destructive affordances. Both require explicit confirmation and are audited server-side.
- **Wording:** "purge" and "legal hold" must not imply a legal opinion. The copy is reviewed in phase 11.
