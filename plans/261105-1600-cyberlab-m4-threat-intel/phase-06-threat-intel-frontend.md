---
phase: 6
title: "Threat intel frontend"
status: pending
priority: P1
effort: "10h"
dependencies: [4, 5]
---

# Phase 6: Threat intel frontend

## Overview
Three surfaces:
- the Integrations page in org settings;
- enrichment panels in the PCAP and Malware IOC tabs, with run controls on jobs;
- an IOC lookup page with a per-IOC history timeline.

ATT&CK chips label capa capabilities and findings. All wording is verdict-free and source-attributed.

## Requirements
- **Integrations page** `/o/{org}/settings/integrations`, linked from the settings nav.
  - **One card per provider** shows:
    - label, supported types, status badge (`not configured`, `unverified`, `valid`, `invalid`, `error`), `••••last4`, verified_at, last error code;
    - enabled toggle, limits (per minute / per day, capped by the ceilings shown), the `tos_note` and the `privacy_note`;
    - the first enable opens a dialog that states what the provider receives and links its terms; it sends `acknowledge_terms: true` only after an explicit checkbox, and the card then shows "terms acknowledged on <date>" (RT16).
  - **Key entry:**
    - a password-type input with `autocomplete="off"`;
    - it is cleared after submit and never pre-filled;
    - "Replace key" and "Remove key" (confirm dialog), plus "Verify" with polling until the status changes.
  - MISP adds a `base_url` field with inline syntax errors (`misp_url_invalid`); changing it requires re-entering the key (`key_required_for_url_change`); a host that resolves to a non-public address shows up after verify as `invalid · misp_url_not_public`.
  - **Permissions:** viewers and analysts see read-only cards (no inputs); the page hides edit controls without `integrations.manage` (the API still enforces it).
  - A privacy notice: "Enabled providers receive the indicators you enrich. Private IPs, internal names, URL query strings, emails (except MISP), file paths and registry keys are never sent."
  - A TI settings card: excluded suffixes, with a hint to add the org's own internal domains before enabling providers.
  - `mock` appears only when the catalog says `available` (dev/test), labelled "Test provider".
- **Enrichment in IOC tabs** (`components/analysis/iocs-tab.tsx`, used by PCAP and Malware):
  - an "Enrich IOCs" button (with `evidence.write`) opens a provider picker (enabled providers only) → `POST …/enrichments` → a run progress strip (status, per-provider counts, "waiting for rate limit until hh:mm", partial explanation);
  - the IOC list uses `include=enrichment`. Each row shows compact per-provider chips ("VT 12/71 engines", "AbuseIPDB confidence 87/100", "URLhaus listed", "OTX 3 pulses", "MISP 2 events", "not found", "stale"), each titled "reported by <provider> on <date>". Chips use one neutral style: no red/green or severity colouring by count or score (RT20);
  - expanding a row shows a panel with each provider's summary fields, a permalink (external link, `rel="noopener noreferrer"`, rendered only if it parses as `https:`), and "View history";
  - MISP results carrying TLP tags show them as a badge (TLP:RED / TLP:AMBER highlighted, text only);
  - ineligible IOCs show the skip reason ("private address — not sent"); URLs show "query removed before lookup" when applicable.
- **IOC lookup page** `/o/{org}/intel` (a new nav module, "Threat Intel"):
  - a textarea for up to 20 values (refanged display) → normalization report (eligible / skipped with reason / query removed) → run progress → a results table per value and provider from the run's items, cached results marked "cached, fetched <date>";
  - a recent-runs list.
- **History page** `/o/{org}/intel/ioc?type=&value=`: a timeline of every result for the IOC across providers (newest first, filter by provider). It shows status, key fields and fetched_at / expires_at; deltas such as "detections 3 → 12" between consecutive `ok` rows of one provider are computed client-side.
- **ATT&CK chips:**
  - in capa capabilities (`signature-tabs.tsx`), findings (`findings-tab.tsx`), OTX/MISP summaries and the static report view, ids are labelled through `/attack/techniques` (phase 4; batched, cached with React Query, `staleTime` infinity);
  - each chip shows "T1055 · Process Injection" with tactics in a tooltip and a link to the ATT&CK page;
  - revoked → "T1xxx (revoked → T1yyy)"; unknown → the raw id with "not in ATT&CK v<N>";
  - the MITRE notice and version (from the route's `meta`) sit in a footer on the TI pages and the static report.
- **Wording:**
  - TI UI strings never say "malicious", "benign", "clean", "safe" or "verdict" as our own label;
  - provider-native category names (VT `malicious` count) appear only inside attributed text ("71 engines: 12 report malicious") — decide the exact template here, and the test then allows that template only;
  - a vitest wording test scans the TI components, i18n strings and chip templates.
- **Untrusted text:** all provider strings (pulse names, tags, `Event.info`, labels) are rendered as text only, truncated with a title tooltip. External links only to the permalink built server-side, and only `https:`.
- **Data:** generated contract types; React Query with polling while a run is `queued`, `running` or `waiting` (back-off 2 s → 10 s), stopping at a final state.

## Implementation Steps
1. API hooks and types for integrations, settings, runs, results and attack; the shared `ProviderChip`, `ProviderSummary` (a discriminated union per provider), `RunProgress` and `AttackChip`.
2. The Integrations page (with the acknowledgement dialog) and TI settings card, with vitest: no key value re-rendered after save; read-only for analysts; enable blocked until the checkbox is ticked.
3. The IOC tab enrichment (PCAP + Malware).
4. The lookup page and the history timeline.
5. ATT&CK chips in capabilities, findings and the report, plus the notice footer.
6. Wording and untrusted-text tests; typecheck, eslint, prod build.

## Success Criteria
- [ ] An admin can acknowledge terms, configure, verify, replace and remove keys; no key value is ever rendered back (unit and e2e).
- [ ] IOC rows show source-attributed chips and a history link; ineligible IOCs explain why they were not sent.
- [ ] capa and finding ATT&CK ids show names and tactics with the MITRE notice; the wording test passes.
