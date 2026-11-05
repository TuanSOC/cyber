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
- [x] Status changes need reasons where required, and each writes exactly one history row atomically. The history rows refuse UPDATE and DELETE. — `integration/test_case_status.py::test_close_archive_and_reopen_need_a_reason`, `test_invalid_reasons_are_refused`, `test_a_reason_alone_is_not_an_update`, `test_no_status_change_writes_no_history`, `test_invalid_transition_writes_nothing`, `test_history_rows_refuse_update_and_delete`, `test_history_rows_refuse_mutation_by_the_owner_too` (319f04d).
- [x] A TLP downgrade without `org.update` or the acknowledgement is refused. Exclusions can be turned off only by `integrations.manage`. Everything is audited without free text. — `test_case_tlp.py::test_role_matrix_for_tlp`, `test_role_matrix_for_exclusion_flags`, `test_rejected_update_changes_nothing`, `test_audit_records_tlp_and_flags_without_free_text`; `test_case_status.py::test_audit_has_the_status_change_but_never_the_reason`; `test_case_policy_api.py::test_evidence_policy_role_rules_and_audit` (319f04d).
- [x] A flag set through the API blocks the AI preview, the AI run and the TI enrichment for that case or evidence. The provider mocks see 0 calls. — `test_case_policy_api.py::test_ai_flag_set_through_the_api_blocks_preview_and_run`, `test_ti_flag_set_through_the_api_blocks_enrichment` (`sent.runs == []`: nothing dispatched), `test_turning_a_flag_off_through_the_api_unblocks` (319f04d).
- [x] Notes keep every version, and a delete keeps the history. Out-of-scope refs are refused, and stale edits get 409. — `test_case_notes.py::test_edits_keep_every_version`, `test_delete_keeps_the_history_and_shows_a_tombstone`, `test_refs_out_of_scope_are_refused`, `test_stale_edit_is_409`, `test_concurrent_edits_on_one_version_one_wins`, `test_version_rows_refuse_update_in_the_db` (319f04d).
- [x] Collections normalize and deduplicate. Exports are formula-safe, defanged by default, TLP-marked (STIX marking-definition), audited, and served as attachments with CSP sandbox. — `test_case_ioc_collections.py::test_values_are_normalized`, `test_duplicates_are_idempotent_and_removed_items_are_readded`, `test_job_iocs_of_the_case_only`; `test_case_ioc_exports.py::test_download_headers`, `test_csv_is_tlp_marked_defanged_and_formula_safe`, `test_clear_text_export_needs_evidence_write`, `test_stix_export`, `test_exports_are_audited`; `unit/test_stix_export.py::test_the_five_oasis_tlp_marking_ids`, `test_bundle_shape_marking_and_identity`, `test_hostile_values_cannot_break_out_of_the_literal`, `test_formula_cells_are_quoted` (319f04d).
- [x] Every route is in `idor_cases_case.py`, its `PENDING_ROUTES` is empty, and the lane passes. — `security/idor_cases_case.py` `PENDING_ROUTES = frozenset()`; `test_m6_foundation.py::test_every_m6_route_is_in_the_schema_and_none_is_pending`; lane 2 green with ruff / format / mypy (319f04d).

## Risk Assessment
- **STIX pattern injection** through IOC values. Escape `'` and `\` per the STIX 2.1 pattern grammar, test with hostile values, and never build a pattern for unknown types (those get skipped with a count).
- **The TI normalizer refuses private IPs or internal names**, which an analyst may still want in a collection. Store them with `ti_eligible=false` (computed) rather than refusing them, and document it. Check this against the M4 normalizer before coding; it is a parent decision if the frozen schema needs a field.
- **The case-wide IOC read on large cases** (50 jobs × 10 000 IOCs). Use cursor paging and a statement timeout. Measure p95 on the dataset and note it for phase 9.

## Implementation Notes (2026-11-06)
- **Commit:** 319f04d (phases 2–8 together). The worktrees were blocked by the permission system, so there was no lane branch to commit on its own (phase-1 notes).
- **Lane 2 in the main tree:**
  - `scripts/lane-test.sh 2 uv run pytest -q -p no:cacheprovider <own files>`, plus ruff, format and mypy;
  - DB `cyberlab_b2_test`, under the 3-slot semaphore.
- **Investigations** (`investigations/service.py` +187, `repository.py`):
  - Close, archive and reopen need `status_reason` (1–500 characters, no NUL), else `422 status_reason_required`.
  - The status-event row is inserted in the same transaction as the update.
  - A reason without a status change is not an update.
  - The audit records `status_from/to` and `has_reason`, never the reason text.
  - A TLP downgrade needs `org.update` (`403 tlp_downgrade_forbidden`) and `acknowledge_tlp_downgrade` (`422 tlp_downgrade_not_acknowledged`).
  - Turning a flag off needs `integrations.manage`.
  - `GET …/status-events` is newest first, cursor-paged, with the actor's display name.
- **Evidence share policy** (`evidence/share_policy.py`):
  - `PUT` upserts `evidence_share_policies` and never touches the evidence row or its custody (`test_evidence_row_and_custody_are_untouched`).
  - Audit `evidence.share_policy_updated`.
  - Archived cases are read-only.
- **Notes** (`notes/{service,refs,paging}.py`):
  - A body or ref change inserts a version and bumps `current_version`; flag-only edits update in place.
  - `expected_version` is compared under a row lock, so of two concurrent edits on one version, one wins and the other gets `409 stale_note`.
  - Refs are re-checked in the org and case scope (`422 ref_out_of_scope`).
  - Only the author or `org.update` may change a note.
  - A delete sets `deleted_at/by` and the list shows a tombstone.
- **IOC collections** (`ioc_collections/{service,normalize}.py`):
  - Values go through the M4 TI normalizer.
  - The pcap-only types (`ja3`, `ja3s`, `cert_sha256`, `registry_key`, `file_path`) keep the job type and use a sha256 `ioc_key` over the type and value.
  - At most 500 items per call (`MAX_ITEMS_PER_CALL`).
  - Each item answers `added`, `duplicate` or `invalid`, and a removed item is re-added as a new row (the 0012 partial unique index).
  - Items carry the latest TI answer per provider, joined by `ioc_key`.
- **Exports** (`export.py`, `stix.py`):
  - **CSV:** `csv_safe.write_csv` with a `# TLP:… CASE-…` header comment (one quoted cell after review L1, look-alikes covered after L2).
  - **STIX 2.1:**
    - `'` and the backslash are escaped in the pattern literal;
    - deterministic `uuid5` ids over (org, collection, `ioc_key`);
    - the OASIS TLP 2.0 marking-definition is included;
    - the org identity is set in `created_by_ref`;
    - types without a STIX path are skipped and counted.
  - Values are defanged by default, and `defang=false` needs `evidence.write`. Exports are never redacted (RT8).
  - The response has an RFC 5987 filename, `nosniff`, `no-store` and `CSP: sandbox`.
- **Case IOCs:** `case_iocs.case_iocs(...)` (frozen signature, `MAX_PAGE = 500`) reads the latest succeeded job per evidence and dedups by (type, value). The route and the phase-3 snapshot builder both call it (`test_entry_point_matches_the_route_and_is_tenant_scoped`).
- **IDOR:** `idor_cases_case.py` has cases and victim extenders for a note, a collection with an item, and an evidence policy, and its `PENDING_ROUTES` is empty.
- **Tests:** `test_case_{status,tlp,policy_api,notes,ioc_collections,ioc_exports,case_iocs}.py` and `unit/test_stix_export.py`.
- **Full API suite** (phase-9 run): 4167 passed, plus 7 errors in `unit/test_signing.py` (the IDOR stand-in leak, fixed in e6e0665). The re-run after that fix is pending gate.
