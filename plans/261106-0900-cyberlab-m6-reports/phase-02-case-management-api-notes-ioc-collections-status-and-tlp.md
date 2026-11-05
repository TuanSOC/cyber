---
phase: 2
title: "Case management API notes IOC collections status and TLP"
status: pending
priority: P1
effort: "12h"
dependencies: [1]
---

# Phase 2: Case management API notes IOC collections status and TLP (group B, 2a, lane 2)

## Overview
This phase covers the remaining §10 case-management items as an org-scoped API:
- versioned analyst notes;
- IOC collections with normalized items and CSV / JSON / STIX 2.1 exports;
- a case-wide IOC read;
- status reasons and status history;
- case TLP with the downgrade rule;
- the case and evidence share-policy flags.

The enforcement function (`investigations/policy.py`) and its call sites already exist from phase 1. This phase builds the routes that set the flags, and the tests that prove that setting them blocks AI and TI.

**Owns:**
- `app/modules/investigations/{router,service,repository}.py` (route bodies; `schemas.py` is frozen);
- `app/modules/evidence/router.py` (the share-policy routes only), `evidence/share_policy.py`, and `evidence/{service,repository}.py` (the flags on `EvidenceOut` reads, RT11);
- `app/modules/notes/**` and `app/modules/ioc_collections/**` (after the phase-1 stubs and models), including `ioc_collections/case_iocs.py`, whose frozen signature the phase-3 snapshot builder calls (RT11);
- `tests/security/idor_cases_case.py`;
- `tests/integration/test_case_{status,tlp,policy_api,notes,ioc_collections,ioc_exports,case_iocs}.py`;
- `tests/unit/test_stix_export.py`. `csv_safe` itself is a phase-1 helper in `app/core/csv_safe.py`.

## Requirements
All paths are under `/api/v1/orgs/{org_id}`. Permissions follow `core/rbac.py`.
- **Investigations** (extends the existing routes):
  - `PATCH /investigations/{inv}` (`investigation.write`) now also takes `tlp`, `ai_excluded`, `ti_excluded`, `status_reason` and `acknowledge_tlp_downgrade`.
    - **Status reasons:** a change to `closed`, `archived`, or from `closed` back to `in_progress` (reopen) needs `status_reason` (1–500 characters, no NUL) → `422 status_reason_required`.
    - **Status history:** every status change inserts one `investigation_status_events` row in the same transaction as the update.
    - **TLP:** lowering the TLP (by `TLP_ORDER`) needs `org.update` (`403 tlp_downgrade_forbidden`) and `acknowledge_tlp_downgrade` (`422 tlp_downgrade_not_acknowledged`). Raising it needs only `investigation.write`.
    - **Exclusion flags:** turning `ai_excluded` or `ti_excluded` **off** needs `integrations.manage` (`403`); turning one **on** needs only `investigation.write`.
    - Archived cases stay read-only (the existing `409 investigation_archived`).
    - **Audit:** `investigation.updated` keeps its existing details and gains `tlp_from/to`, the flag changes and `status_from/to`. The reason text is never logged; only `has_reason`.
  - `GET /investigations/{inv}/status-events` (`investigation.read`): newest first, cursor-paged, with the actor display name.
  - `InvestigationOut` gains `tlp`, `ai_excluded`, `ti_excluded` and a computed `share_policy {ai_blocked, ti_blocked, reasons}` (frozen in phase 1).
- **Evidence share policy:**
  - `GET /evidence/{ev}/share-policy` (`evidence.read`).
  - `PUT /evidence/{ev}/share-policy` (`evidence.write`; turning a flag off needs `integrations.manage`): `{ai_excluded, ti_excluded}`.
    - It upserts `evidence_share_policies`, and the evidence row is never touched.
    - Audit `evidence.share_policy_updated`.
  - `EvidenceOut` reads include the flags.
- **Notes** (`notes/router.py`):
  - `GET /investigations/{inv}/notes?include_deleted&pinned&cursor` (`investigation.read`): the current version of each note, its author, `version`, `edited` and the `deleted` state. Deleted notes are listed only with `include_deleted`, and show their tombstone, not the body.
  - `POST /investigations/{inv}/notes` (`investigation.write`): `{body, refs?, pinned?, include_in_reports?}`.
    - Refs are typed `{kind: finding|alert|ioc|evidence|job|timeline|capability|signature, ref_id, job_id?}`, and each one is **re-checked in the org and the case scope** (the evidence or job belongs to the case) → `422 ref_out_of_scope`.
    - Audit `note.created` (ids, ref count; no body).
  - `GET /notes/{note}` (`investigation.read`): the current version and the full version list (body, author, time).
  - `PUT /notes/{note}` (author, or `org.update`; `investigation.write`): `{expected_version, body?, refs?, pinned?, include_in_reports?}`.
    - A body or ref change inserts a version and bumps `current_version`; flag-only changes update the flags.
    - A wrong `expected_version` → `409 stale_note`.
    - Audit `note.edited`.
  - `DELETE /notes/{note}` (author, or `org.update`) → 204. It sets `deleted_at/by` (the versions stay). Audit `note.deleted`.
  - A note on an archived case is read-only → `409 investigation_archived`.
- **IOC collections** (`ioc_collections/router.py`):
  - `GET /investigations/{inv}/ioc-collections` (`investigation.read`) and `POST` (`investigation.write`): `{name, description?}`. A duplicate name in the case → `409 collection_exists`.
  - `GET /ioc-collections/{cid}` (`investigation.read`) returns the counts per type. `PATCH /ioc-collections/{cid}` (`investigation.write`) takes `{name?, description?, archived?}`.
  - `GET /ioc-collections/{cid}/items?type&q&include_removed&cursor` (`investigation.read`): each item carries the TI enrichment summary from `ti_results` by `ioc_key` (latest per provider, attributed, never a verdict) and the source job link.
  - `POST /ioc-collections/{cid}/items` (`investigation.write`): `{items: [{ioc_id} | {type, value, note?}]}`, up to 500 per call.
    - Job IOCs must belong to a job of this case.
    - Values are normalized with the M4 TI normalizer (`threat_intel` normalization, the same function that builds `value_norm` / `ioc_key`).
    - Pcap-only types that the TI normalizer does not cover (ja3, ja3s, cert_sha256, registry_key, file_path) are stored with `ioc_type` = the job type and `ioc_key` = `sha256(type\0value)` (documented).
    - The answer gives per item `added | duplicate | invalid(reason)`. Duplicates are idempotent, and a removed duplicate is re-added as a new item.
    - Audit `ioc_collection.items_added` (counts).
  - `DELETE /ioc-collections/{cid}/items/{item}` → 204 (soft remove). Audit.
  - `GET /ioc-collections/{cid}/export?format=csv|json|stix21&defang=true` (`evidence.read`):
    - A streamed attachment with the RFC 5987 filename, `nosniff`, `no-store` and `Content-Security-Policy: sandbox`.
    - **CSV:** a header row naming the TLP, then one row per IOC. Every cell that starts with `= + - @ \t \r` is prefixed with `'` (`csv_safe`), and RFC 4180 quoting is used.
    - **JSON:** `{tlp, collection, exported_at, items[]}`.
    - **STIX 2.1 bundle:**
      - one `indicator` per item, with the pattern built from the escaped value (`[ipv4-addr:value = '…']` etc., with `'` and `\` escaped);
      - a deterministic `uuid5` from (org, collection, ioc_key);
      - `object_marking_refs` to the TLP 2.0 marking-definition of the case's TLP: the OASIS ids from `cyberlab_jobs.report.STIX_TLP_MARKINGS`, with the marking-definition object (extension `extension-definition--60a3c5c5-…`) included in the bundle (RT18);
      - `created_by_ref` an identity for the org name.
    - Exports are **never redacted** (internal IPs stay in clear), and the export response and UI say so; the `external` profile applies to reports only (RT8).
    - `defang=false` needs `evidence.write` and is the only clear-text form.
    - Audit `ioc_collection.exported` (format, count, defang).
- **Case-wide IOCs:**
  - `GET /investigations/{inv}/iocs?type&q&cursor&limit≤500` (`evidence.read`) aggregates `iocs` over the latest succeeded job per evidence (`timeline.latest_succeeded_jobs`).
  - It dedups by (type, value) and returns `count_jobs`, `first_seen`, `last_seen`, the source jobs (≤ 5), `in_collections` (ids) and `ioc_key`.
  - It is a server-side query with the existing per-job unique index, bounded by the case's job count.
  - The query lives in `ioc_collections/case_iocs.py: case_iocs(...)` (frozen signature). The route and the phase-3 snapshot builder both call it (RT11).
- **Errors** are stable strings: `status_reason_required`, `tlp_downgrade_forbidden`, `tlp_downgrade_not_acknowledged`, `stale_note`, `ref_out_of_scope`, `collection_exists`, `collection_archived`, `too_many_items`, `invalid_ioc`.

## Implementation Steps
1. Investigations service: status reason and history, TLP rule, flag rules, audit details; `test_case_status.py`, `test_case_tlp.py` (role matrix: an analyst raises, an admin lowers with ack, a viewer gets 403).
2. Evidence share policy routes. `test_case_policy_api.py`: set a flag through the API → the AI preview, the AI run and the TI enrichment are blocked (the phase-1 call sites), and turning the flag off needs `integrations.manage`.
3. Notes module: versions, refs in scope, author rule, soft delete, history; `test_case_notes.py` (including concurrency on `expected_version` and that an UPDATE of a version row fails in the DB).
4. IOC collections: normalization, dedupe, job-IOC scope, TI join, soft remove; `test_case_ioc_collections.py`.
5. Exports: the STIX builder unit tests (`test_stix_export.py`: formula cells including leading whitespace and full-width `＝`, quotes in values, deterministic ids, the five OASIS TLP marking ids, defang default); `test_case_ioc_exports.py` (headers, audit, permissions).
6. Case-wide IOC read; `test_case_case_iocs.py` (dedupe across two jobs, latest job per evidence only, other case's IOCs absent).
7. `idor_cases_case.py`: cases for every route above, plus victim extenders (a note, a collection with an item, an evidence policy). Empty this module's `PENDING_ROUTES`. Run `test_idor_routes.py -k case` in lane 2.

## Success Criteria
- [ ] Status changes need reasons where required, and each writes exactly one history row atomically. The history rows refuse UPDATE and DELETE.
- [ ] A TLP downgrade without `org.update` or the acknowledgement is refused. Exclusions can be turned off only by `integrations.manage`. Everything is audited without free text.
- [ ] A flag set through the API blocks the AI preview, the AI run and the TI enrichment for that case or evidence. The provider mocks see 0 calls.
- [ ] Notes keep every version, and a delete keeps the history. Out-of-scope refs are refused, and stale edits get 409.
- [ ] Collections normalize and deduplicate. Exports are formula-safe, defanged by default, TLP-marked (STIX marking-definition), audited, and served as attachments with CSP sandbox.
- [ ] Every route is in `idor_cases_case.py`, its `PENDING_ROUTES` is empty, and the lane passes.

## Risk Assessment
- **STIX pattern injection** through IOC values. Escape `'` and `\` per the STIX 2.1 pattern grammar, test with hostile values, and never build a pattern for unknown types (those get skipped with a count).
- **The TI normalizer refuses private IPs or internal names**, which an analyst may still want in a collection. Store them with `ti_eligible=false` (computed) rather than refusing them, and document it. Check this against the M4 normalizer before coding; it is a parent decision if the frozen schema needs a field.
- **The case-wide IOC read on large cases** (50 jobs × 10 000 IOCs). Use cursor paging and a statement timeout. Measure p95 on the dataset and note it for phase 9.
