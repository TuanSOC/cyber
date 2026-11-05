---
phase: 5
title: "ATT&CK case mapping and timeline export"
status: pending
priority: P1
effort: "8h"
dependencies: [1]
---

# Phase 5: ATT&CK case mapping and timeline export (group B, 2d, lane 5)

## Overview
The §10 ATT&CK mapping and timeline items at case level:
- **Mappings:** analyst-owned case mappings (`confirmed | suspected | rejected`, with rationale and source refs), and suggestions drawn from evidence-backed sources: capa capabilities, finding ATT&CK ids and **verified** AI `attack_techniques` of the case's runs. Nothing is ever confirmed automatically.
- **Matrix:** a tactic-grouped read.
- **Timeline:** the merged case timeline gains `note` and `status` entries, plus a streamed, formula-safe, audited CSV / JSON export.

**Owns:**
- `app/modules/case_attack/**` (after the phase-1 stubs and models);
- `app/modules/investigations/timeline.py`;
- `app/modules/case_timeline/**` (the export router and service);
- `tests/security/idor_cases_attack.py`;
- `tests/integration/test_case_attack.py`, `test_case_attack_suggestions.py`, `test_timeline_kinds.py` and `test_timeline_export.py`.

## Requirements
- **Routes** (under `/api/v1/orgs/{org_id}`; frozen in phase 1):

  | Method and path | Permission | Behaviour |
  |---|---|---|
  | `GET /investigations/{inv}/attack` | `investigation.read` | mappings with labels (name, tactics, url to MITRE as **text**, revoked or deprecated flag), status, rationale, sources (resolved to deep-link descriptors), `updated_by/at`; plus `matrix: [{tactic, techniques[]}]` in v20 tactic order, rejected mappings excluded; the MITRE notice and `INDEX_VERSION` |
  | `GET /investigations/{inv}/attack/suggestions` | `investigation.read` | `[{technique_id, label, sources: [{kind: capability|finding|ai_run, ref_id, job_id, run_id?, citation_status}], already_mapped}]`, deduplicated by technique; AI sources only from completed runs whose technique entry has ≥ 1 verified citation (the M5 rule, read from `ai_outputs.verification`) |
  | `POST /investigations/{inv}/attack` | `investigation.write` | `{technique_id, status, rationale?, sources?}`; the id must exist in the v20 index and not be revoked or deprecated → `422 invalid_technique`; a duplicate → `409 mapping_exists`; sources re-checked in the case scope → `422 ref_out_of_scope`; audit `case_attack.mapped` |
  | `PATCH /attack-mappings/{mid}` | `investigation.write` | `{status?, rationale?, sources?}`; audit `case_attack.updated` (from/to status) |
  | `GET /investigations/{inv}/timeline/export?format=csv\|json&kinds&from&to` | `evidence.read` | streamed attachment, ≤ `TIMELINE_EXPORT_MAX_ROWS` (a truncation marker row when capped); CSV header line `# TLP:<label> CASE-xxxxx exported <ts>`; RFC 4180 through `app/core/csv_safe.write_csv` (phase 1); JSON: `{tlp, case, exported_at, entries[]}`; `nosniff`, `no-store`, CSP sandbox; audit `investigation.timeline_exported` (format, count, filters) |

  Rationale ≤ 2 000 characters of plain text; `sources` ≤ 32.
- **Archived cases:** mappings are read-only → `409 investigation_archived`.
- **Timeline kinds** (`timeline.py`, keeping the phase-1 signature `page(..., kinds=None)` and the cursor format; RT10). The new entries carry `evidence_id = None` and `ref_kind` `status` / `note` (`RefKindName.STATUS` / `NOTE`, added by phase 1):
  - **`status`:** from `investigation_status_events` (`ts` = `occurred_at`, the text from/to, reason shown only to `investigation.read` holders; the timeline route already requires `evidence.read`);
  - **`note`:** notes with `include_in_reports=true` and not deleted, at the time of their first version, with the text truncated to 280 characters and `ref_id` = note id.
  - The sort key stays (`ts`, kind, `ref_id`). The kind literal was extended in phase 1.
  - `kinds` filter support: phase 1 added the parameter to `page()` and to the route in `investigations/router.py` (phase 2's file), and `page()` ignores it until this phase implements it. This phase touches neither the route nor the schema (RT10).
  - The note entry uses the first version's time on purpose: it marks when the note was written (RT32).
- **CSV safety:** `app/core/csv_safe.py` is implemented and frozen in phase 1, and is shared with phase 2.

## Implementation Steps
1. Suggestions (`suggest.py`):
   - capabilities with ATT&CK ids from the latest static jobs of the case;
   - finding ATT&CK ids from the latest pcap and static jobs;
   - AI `attack_techniques` from completed case and job runs with verified citations.

   Map them to labels, deduplicate, and mark `already_mapped`. `test_case_attack_suggestions.py`: an unverified AI technique is excluded, a revoked id is excluded, and another case's jobs are excluded.
2. Mapping routes and service; `test_case_attack.py`: validation, duplicate, status changes audited, matrix grouping and order, archived read-only, viewer 403 on writes.
3. Timeline kinds; `test_timeline_kinds.py`: status and note entries appear in order with `evidence_id` null, deleted or not-included notes are absent, the `kinds` filter works, cursor paging across the new kinds is stable, and the existing timeline tests and the M5 AI tests that read the timeline stay green.
4. Export; `test_timeline_export.py`: formula cells neutralized (leading whitespace and full-width `＝` included, RT19), the TLP header, the cap marker, headers, audit, a cross-org case → 404.
5. `idor_cases_attack.py`: cases for the attack, mapping and export routes, plus a victim extender (a mapping). Empty `PENDING_ROUTES`.

## Success Criteria
- [ ] Suggestions come only from evidence-backed sources (capa, findings, verified AI) in the case scope. Nothing is confirmed without an analyst request.
- [ ] Unknown, revoked or deprecated technique ids are refused, and the matrix groups confirmed and suspected techniques by v20 tactic.
- [ ] The timeline includes status and opted-in notes without breaking existing cursors or tests.
- [ ] Exports are TLP-headed, formula-safe, capped, audited and served as attachments with CSP sandbox.
- [ ] IDOR cases are complete, `PENDING_ROUTES` is empty, and the lane passes.

## Risk Assessment
- **Timeline query cost** grows with two more sources. Both are small tables with `(investigation_id, …)` indexes from 0012; re-measure the timeline p95 recorded in M5.
- **AI suggestions read as authority.** The UI labels them "suggested by: capa / finding / AI (verified citation)". The analyst must confirm, and rejected suggestions stay visible as rejected.
