---
phase: 3
title: "Report snapshot versioning citations and signing"
status: pending
priority: P1
effort: "15h"
dependencies: [1]
---

# Phase 3: Report snapshot versioning citations and signing (group B, 2b, lane 3)

## Overview
The report core, all built in the trusted API:
- drafts with optimistic concurrency;
- the **snapshot builder**, which turns a draft and the case data into `cyberlab.report.v1`;
- citation resolution with copied rows and `fields_sha256`;
- the redaction profiles;
- canonical bytes, sha256, MinIO storage with object lock, and the Ed25519 manifest signature;
- finalize into append-only versions;
- verification on read, "which outputs and report versions cite this row", and the offline verifier script.

This phase never renders. Finalize calls the frozen `dispatch.create_render` / `dispatch_render` (phase 4), and in this lane those are the stubs, monkeypatched in tests.

**Owns:**
- `app/modules/reports/{service,repository,snapshot,snapshot_sections,citations,cited_by,redact,signing,storage,router}.py` (after the stubs);
- `scripts/verify_report.py`;
- `tests/security/idor_cases_reports.py`;
- `tests/integration/test_report_{drafts,finalize,snapshot,citations,cited_by,redaction,signing,storage}.py`;
- `tests/unit/test_report_canonical.py` and `test_verify_report_script.py`.

## Requirements
- **Routes** (under `/api/v1/orgs/{org_id}`; frozen in phase 1):

  | Method and path | Permission | Behaviour |
  |---|---|---|
  | `GET /reports?investigation_id&status&cursor` | `investigation.read` | the org-wide list (latest version, TLP, updated) |
  | `GET /investigations/{inv}/reports` | `investigation.read` | the reports of one case |
  | `POST /investigations/{inv}/reports` | `investigation.write` | `{title, template: "incident_v1", tlp?, profile?}`; TLP defaults to the case TLP; below the case TLP the downgrade rule applies (`org.update` + ack); `409 investigation_archived` |
  | `GET /reports/{rid}` | `investigation.read` | the draft, `revision`, versions summary |
  | `PATCH /reports/{rid}` | `investigation.write` | `{revision, title?, tlp?, profile?, distribution?, draft?}` → `409 stale_draft`; validates the selections (AI runs completed and in the case scope, not `canary_leak` / refused; notes in the case; collections in the case; jobs in the case) → `422 selection_out_of_scope` |
  | `POST /reports/{rid}/discard` | `investigation.write` | only without versions → else `409 report_has_versions` |
  | `POST /reports/{rid}/preview` | `investigation.write`, 30 per user per 10 min | builds the snapshot in memory and returns it with section counts, the size and `render_units` against the budget (RT1); nothing is stored, nothing is audited |
  | `POST /reports/{rid}/finalize` | `investigation.write`, 10 per user per 10 min | `{revision, change_note?, acknowledge_tlp_downgrade?, acknowledge_external_review?}` → 201 with the version; queues the PDF only, and other formats are requested on demand (RT5); `422 report_too_large_to_render` (RT1), `409 tlp_below_case` (RT7), `422 external_review_required` (RT8) |
  | `GET /reports/{rid}/versions` | `investigation.read` | the version list |
  | `GET /reports/{rid}/versions/{v}` | `investigation.read` | the manifest, `signature_valid`, `snapshot_ok` (sha256 re-hashed from the stored object), section counts, renders |
  | `GET /reports/{rid}/versions/{v}/content` | `evidence.read` | the stored snapshot as `ReportSnapshot` JSON for the viewer (inline, `no-store`), re-hashed and refused with `409 integrity_failed` on mismatch; not audited per view (RT11) |
  | `GET /reports/{rid}/versions/{v}/snapshot` | `evidence.read` | the canonical JSON as stored; attachment; audited `report.snapshot_downloaded` |
  | `GET /reports/{rid}/versions/{v}/signature` | `investigation.read` | `{manifest, signature, kid, alg: "Ed25519"}` as `.sig.json` |
  | `GET /cited-by?kind&ref_id&job_id?` | `evidence.read` | the AI outputs (run, claim count; via `ai_citations`, verified only) and report versions (via `report_citations`) that cite the row |

- **Draft shape** (`reports.draft`, frozen schema `ReportDraft`):
  - `sections`: `executive_summary`, `scope`, `methodology`, `impact`, `root_cause`, `actions_taken`, `recommendations`, `lessons_learned`. Plain text, ≤ 20 000 characters each, no NUL. They are carried into the snapshot as `AnalystText` and never truncated (RT9). The whole draft is ≤ 1 MiB, checked by the request schema (422) before the DB check.
  - `include`:
    - `evidence`, `custody` (bool);
    - `jobs`: `"latest"` or ids;
    - `findings {min_severity, max ≤ 500}`, `alerts {min_severity, max ≤ 500}`;
    - `iocs {case_iocs: bool, collections: [ids], max ≤ 2000}`, `ti` (bool);
    - `attack {statuses: [confirmed, suspected]}`;
    - `timeline {kinds, from?, to?, max ≤ 1000}`;
    - `notes: [ids]`, `ai_runs: [ids ≤ 10]`, `cited_rows: [{kind, ref_id, job_id?}] ≤ 200`.
- **Snapshot builder** (`snapshot.py: build_snapshot`, in the requester's tenant session, inside **one read-only REPEATABLE READ transaction**, so every section sees the same instant, RT14):
  1. Re-read everything at finalize time: nothing is trusted from the draft except the ids and the text. Evidence-derived and AI text is **defanged here, once** (`ai/text.defang`); the renderers and the viewer apply only `vis` (RT24).
  2. **Case:**
     - case ref, title, description, status, severity, TLP;
     - the status history;
     - the distribution;
     - the report and version metadata (`generated_by` = the display name, or the role for `external`; `base_url` = `PUBLIC_BASE_URL`, which the renderer uses for appendix links, and is omitted for `external`, RT8);
     - document control: the prior versions (version, `finalized_at`, short sha256, `change_note`) and this version's `change_note` (RT23).
  3. **Evidence inventory** with trusted hashes (sha256 / sha1 / md5, size, mime, `uploaded_at`, verification state) and the custody events (action, actor, time; ip and user agent only for `internal`).
  4. **Jobs:** analyzer, tool, rule and AV DB versions, status, timing (from the analysis result metadata the static report already reads).
  5. **Findings, alerts and IOCs** filtered and capped by the draft; IOCs from `ioc_collections/case_iocs.case_iocs` (the frozen phase-2 entry point, monkeypatched with a fake in this lane, RT11) and the selected collections, with an attributed TI summary when `ti`.
  6. **ATT&CK** case mappings with labels from `attack/index.label` (name, tactics, revoked flag), status and rationale.
  7. **Timeline** from `timeline.page`, filtered, with entries capped.
  8. **Notes** selected and not deleted, at their current version.
  9. **AI sections** for each selected run, read through the M5 `service_outputs` read model:
     - supported observed and interpretation claims, hypotheses labelled, overall confidence, next steps (flagged `command_like` shown as text), limitations;
     - flags inline on each claim, plus the counts of omitted unsupported claims. For `external`, claims flagged `verdict_language` or `external_url` are also omitted and counted (RT15);
     - each run's pseudonyms reversed with its own map (both profiles; RT2);
     - model, provider, `prompt_version`, `context_sha256`;
     - the disclaimer.
  10. **Citations** (`citations.py`):
      - each distinct cited row (AI verified citations, `cited_rows`, note refs, ATT&CK sources) gets `C1…Cn` in first-use order;
      - the row is re-queried in scope; out-of-scope rows are dropped and counted, never shown;
      - a bounded field copy (the same allow-list per kind as the M5 context fields, defanged) and its `fields_sha256`;
      - the internal deep-link path (built like `ai/service_outputs.deep_link`, from ids only);
      - claims carry their `C` numbers.
  11. **Caps and totals** per section. Over `REPORT_MAX_SNAPSHOT_BYTES` → `422 report_too_large` with the counts. Over `REPORT_MAX_RENDER_UNITS` (`render_units` of the redacted snapshot) → `422 report_too_large_to_render` with the per-section units, so no unrenderable version is ever signed (RT1).
- **Redaction** (`redact.py`), applied to the built snapshot before hashing:
  - **Both profiles:** each AI run's pseudonyms are first reversed with that run's own map (whole tokens, as in M5), because separate run trees number independently (RT2).
  - **`external`** (RT2, RT8):
    - **One report-level map.** A single M5 `Pseudonymizer` (imported from `ai/context`, not modified), using `ai_org_settings.internal_cidrs/suffixes` or the defaults, covers the whole snapshot. A pseudonym therefore means the same value in every section and every AI run.
    - **Seeding.** The map is seeded first from the structured fields (hostname-typed and user-typed fields of pcap and static results, custody actors).
    - **Field walk.** The pseudonymizer runs over **every string field** except an explicit allow-list of enum, hash, UUID, count and timestamp fields. The walk includes case title and description, analyst sections, status reasons, distribution, evidence filenames, timeline titles, finding and alert text, IOC values, TI summaries, ATT&CK rationale, citation copies and AI text.
    - **Second pass.** A whole-token pass then replaces every original value already in the map wherever it occurs, which catches single-label hosts (`FIN-SRV-01`) and bare usernames in free text.
    - **Dropped:** notes, custody `ip` / `user_agent`, deep links and `base_url`. Actors and authors become role labels.
    - The map is **never** stored, in the snapshot or elsewhere (RT29).
    - Finalize requires `acknowledge_external_review` → `422 external_review_required`.
  - **`internal`:** real values after the reversal; nothing else changes.
  - TLP:RED and TLP:AMBER+STRICT need a non-empty `distribution` → `422 distribution_required`.
- **Finalize** (three steps; no transaction is held across the build, the put or the signing; RT14):
  1. **Read** (one `tenant_session(..., snapshot_read=True)` from phase 1):
     - check the `revision`, that the case is not archived, and the TLP rule against the **current** case TLP (RT7: below it needs `org.update` plus `acknowledge_tlp_downgrade`, otherwise `409 tlp_below_case`);
     - build, then redact;
     - check the render budget, then `canonical_json` and sha256.
     - Record the `revision` and `latest_version` that were read.
  2. **Outside any transaction:**
     - `storage.put_snapshot` puts the object in `reports/{org}/{rid}/{v}/snapshot.json`, with v = the recorded `latest_version + 1`;
     - set the per-object GOVERNANCE retention (`EVIDENCE_LOCK_DAYS`, RT6) on the exact version id;
     - build the `Manifest` and sign it with the active kid (`signing.py`, the only importer of the private-key loader).
  3. **Write** (one short tenant transaction under a per-report advisory lock):
     - re-check that `revision` and `latest_version` are unchanged (otherwise `409 stale_draft`, and the object is an orphan);
     - insert `report_versions` (with `change_note`) and `report_citations`;
     - update `reports.latest_version`;
     - `dispatch.create_render(…, "pdf")` (PDF only; RT5);
     - audit `report.finalized` (version, sha256, TLP, profile, counts, and `tlp_downgraded` / `external_review` booleans; no text);
     - commit, then `dispatch.dispatch_render`.

  If the object is stored but the write transaction fails or conflicts, an orphan object remains. It is logged, and the reconcile script lists it (the existing orphans pattern). A dispatch failure still answers 201, and the reaper recovers it (phase 4).
- **Read verification:**
  - Version reads re-hash the stored object (`hash_version`) and verify the signature with the public key of the version's `kid`.
  - A mismatch shows `snapshot_ok=false` / `signature_valid=false`. It is never hidden, and it is audited as `report.integrity_failed`.
- **`scripts/verify_report.py`** (stdlib + `cryptography` + `pypdf` if present, otherwise a minimal attachment reader):
  - Given a PDF or a snapshot plus `.sig.json`, and a public-keys JSON (from the unauthenticated `GET /api/v1/report-signing-keys` or DEPLOYMENT, RT22), it extracts the embedded attachments, recomputes the sha256, verifies the signature and checks the manifest fields.
  - Exit 0 on valid, 1 otherwise.

## Implementation Steps
1. Repository, drafts, list and read routes, selection validation; `test_report_drafts.py` (revision conflicts, discard rule, TLP rule, archived case, viewer 403 on writes).
2. Snapshot builder per section (`snapshot_sections.py`) on seeded pcap and static cases. `test_report_snapshot.py` covers:
   - caps and totals, trusted hashes, out-of-scope selections refused, the size limit;
   - the render budget (`report_too_large_to_render`), a 20 000-character Vietnamese executive summary kept whole, and the document-control table (RT1, RT9, RT23).
3. Citations; `test_report_citations.py`:
   - verified AI citations only;
   - `fields_sha256` equals a recomputation;
   - a row of another case or org is never resolved;
   - stable `C` numbering for the same draft.
4. Redaction; `test_report_redaction.py`:
   - in `external`, no internal IP, host, user, custody IP, note, deep link or `base_url` remains anywhere in the canonical bytes. The scan uses seeded sentinels, including a single-label host and a bare username in free text, the case title, a status reason and an evidence filename (RT8);
   - two AI runs whose maps number different hosts `INT_HOST_1` give one consistent report-level mapping (RT2);
   - `internal` reverses pseudonyms.
5. Storage and signing, finalize, and read verification:
   - `test_report_finalize.py`: atomic rows; v1 then v2; versions and citations refuse UPDATE and DELETE; the dispatch stub is called with pdf only; a publish failure → 201;
   - also in `test_report_finalize.py`: a draft edited between the read and write steps → `409 stale_draft` plus a logged orphan; a case TLP raised after the draft → `409 tlp_below_case` without the ack (RT7, RT14);
   - `test_report_signing.py`: a tampered object → `snapshot_ok=false`; a wrong kid → invalid;
   - `test_report_storage.py`: exact version, per-object retention set, in `reports-test`;
   - the `content` route returns the stored snapshot and refuses a tampered object with `409 integrity_failed` (RT11).
6. `cited_by` and its route; `test_report_cited_by.py`.
7. `scripts/verify_report.py`, `test_verify_report_script.py` (on a snapshot and its signature; the PDF path is tested in phase 9 with a real render), and `test_report_canonical.py` (re-serializing the stored snapshot gives identical bytes).
8. `idor_cases_reports.py`: every route plus the victim extenders (a report with a version). Empty `PENDING_ROUTES`.

## Success Criteria
- [x] Finalize writes the version, citations, render rows and audit atomically. Versions are immutable in the DB and the bucket (object lock), and v2 never alters v1. — `integration/test_report_finalize.py::test_finalize_writes_v1_then_v2`, `test_versions_and_citations_are_append_only`, `test_a_refused_render_never_undoes_the_version`, `test_a_publish_failure_still_answers_201`; `test_report_storage.py::test_finalize_stores_the_exact_version_with_retention` (319f04d).
- [x] The snapshot round-trips to identical canonical bytes, its sha256 matches the stored object, and the signature verifies in the API and offline. — `unit/test_report_canonical.py::test_stored_bytes_round_trip_identically`, `test_key_order_and_whitespace_do_not_change_the_bytes`; `test_report_signing.py::test_a_valid_version_verifies`; `unit/test_verify_report_script.py::test_a_signed_snapshot_verifies`, `test_a_tampered_snapshot_fails`, `test_a_pdf_with_embedded_files_verifies`, `test_the_canonical_form_matches_the_contract` (319f04d). The dev e2e viewer shows a valid signature (e6e0665). The real-renderer `test_report_pipeline.py` / `test_end_to_end_pdf` under `REPORT_E2E=1` are pending gate.
- [x] Every citation resolves to an in-scope row with a matching `fields_sha256`. AI sections contain only supported claims and labelled hypotheses, and never an unverified link. — `test_report_citations.py::test_only_verified_ai_citations_and_matching_field_hashes`, `test_rows_of_another_case_or_org_are_never_resolved`, `test_numbering_is_stable_and_written_at_finalize`; `test_report_snapshot.py::test_ai_sections_hold_supported_claims_and_labelled_hypotheses`; `test_report_drafts.py::test_canary_leak_runs_are_not_selectable` (319f04d).
- [x] `external` snapshots contain no seeded internal name (single-label ones included), custody IP, note text or deep link, and use one pseudonym map across all sections and runs. Distribution is required for RED and AMBER+STRICT. — `test_report_redaction.py::test_external_leaves_no_internal_value` (the timeline-note leak was found and fixed in e6e0665), `test_one_report_level_map_across_ai_runs`; `test_report_finalize.py::test_profile_rules` (`distribution_required` for external and RED; AMBER+STRICT shares the `STRICT_DISTRIBUTION` rule but has no test of its own).
- [x] Finalize never signs a version over the render budget, or below the current case TLP without the ack. It holds no transaction across the build, put and sign. — `test_report_finalize.py::test_the_render_budget_and_the_size_limit_refuse_before_signing`, `test_a_case_tlp_raised_after_the_draft_needs_the_acknowledgement`, `test_a_case_tlp_raised_during_the_build_is_rechecked_at_write`, `test_an_edit_between_read_and_write_is_stale_and_leaves_an_orphan`. The three steps are in `reports/service.py` (the build in its own `snapshot_read` session, RT14) (319f04d).
- [x] Integrity failures are visible and audited. `cited_by` returns both AI outputs and report versions. — `test_report_signing.py::test_a_tampered_object_is_shown_audited_and_refused`, `test_a_wrong_kid_is_invalid`; `test_report_storage.py::test_the_content_route_refuses_a_tampered_object`; `test_report_cited_by.py::test_cited_by_lists_ai_outputs_and_report_versions`, `test_unverified_citations_are_not_listed` (319f04d). The route only: the web "Cited by" panel is deferred (ROADMAP).
- [x] IDOR cases are complete, `PENDING_ROUTES` is empty, and the lane passes. — `security/idor_cases_reports.py` `PENDING_ROUTES = frozenset()`; lane 3 green (319f04d). Its victim stand-ins leaked into later tests in the full run (7 errors in `unit/test_signing.py`), fixed in e6e0665. The full re-run is pending gate.

## Risk Assessment
- **Building a large snapshot inside the request** holds a read transaction and memory: up to 8 MiB, against the 30 s statement timeout. The write transaction stays short (RT14). Measure p95 on the dataset. If it is too slow, move finalize into a trusted task (a parent decision; it would need a frozen-contract change).
- **Pattern-based redaction** stays a residual even with the second pass: a name that appears in no structured field and matches no rule passes (RT8). The preview and the external-review ack put the final check on the analyst.
- **Coupling to M5 read models** (`service_outputs`, the pseudonymizer). This phase imports them and never changes them. If their signatures prove insufficient, that is a parent change request.
- **Orphan objects** when the DB transaction fails after the put. Accepted: they are reported by the reconcile script, never served.

## Implementation Notes (2026-11-06)
- **Commits:**
  - 319f04d (phases 2–8 together; lane 3 in the main tree with `cyberlab_b3_test`).
  - e6e0665: the phase-9 fixes to `redact.py` and `signing.py`.
- **Modules:**
  - `reports/service.py` (+1092), `snapshot_sections.py` (+968), `citations.py` (+636), `redact.py` (+350), `repository.py`, `storage.py`, `cited_by.py`;
  - `scripts/verify_report.py` (+293).
- **Finalize, three steps** (`service.finalize`), with no transaction across them:
  1. Read the draft.
  2. Build in a `snapshot_read` repeatable-read session, run `canonical_json`, check the budget and size, put the object with GOVERNANCE retention, and sign the manifest.
  3. Write: re-check `revision`, `latest_version`, the archived state and the case TLP. Insert the version, the citations, the queued PDF render and the audit. Commit, then publish.
- **Finalize outcomes:**
  - A stale edit between the read and the write leaves an orphan snapshot, logged as "orphan report snapshot" and listed by `reconcile_orphans.py`.
  - A publish failure still answers 201; the reaper redispatches the queued render (RT5).
- **Refusals before signing:**
  - `422 report_too_large_to_render`, with the per-section units, against `REPORT_MAX_RENDER_UNITS`: 450 000 after the phase-4 calibration (750 000 in phase 1).
  - The 8 MiB size cap.
  - `409 tlp_below_case` without the acknowledgement.
  - `distribution_required` for RED, AMBER+STRICT and external.
  - `external_review_required` (RT8).
- **Rate limits** (per user, per 10 min): finalize 10, preview 30. Preview stores and audits nothing (`test_preview_stores_and_audits_nothing`).
- **Snapshot:**
  - Sections are capped with honest totals (`CAPS`).
  - Evidence text is defanged once; analyst text is not defanged.
  - A 20 000-character Vietnamese summary is kept whole.
  - `[Cn]` numbers follow document order.
  - The build is deterministic for the same draft (`test_build_is_deterministic_for_the_same_draft`).
- **Citations:**
  - Every cited row is re-queried in the case scope.
  - Only verified AI citations are used.
  - The row copies carry `fields_sha256`.
  - Numbering is written at finalize.
  - `cited_by` lists AI outputs and report versions.
- **Redaction** (`redact.py`):
  - One report-level pseudonym map across sections and AI runs.
  - A field walk with an allow-list, then a second whole-token pass.
  - `external` drops notes, custody `ip` / `user_agent`, deep links and `base_url`.
  - **Phase-9 bug (e6e0665):** the timeline's `note` entries kept the note body as their title. `external` now drops them (and corrects `total`) and empties a cited note's fields.
- **Signing:**
  - `reports/signing.py` is the only importer of the key loader.
  - The Ed25519 manifest uses `kid`.
  - The prod startup check `check_startup_keys` came from review L3.
  - `verify_report.py` verifies a snapshot plus its signature JSON, or a PDF with its embedded files, offline against the published keys.
- **Phase-9 bug (e6e0665):** `idor_cases_reports.py`'s victim extender replaced `report_signing._private_keys` and `dispatch.*` without restoring them. In the full API run (4167 passed) this caused 7 errors in `unit/test_signing.py`. The fix:
  - `test_idor_routes._no_publish` now registers the originals with monkeypatch;
  - `reset_cache` tolerates a stand-in without `cache_clear`.
- **Storage:**
  - Snapshots go to `reports` / `reports-test` with per-object GOVERNANCE retention.
  - The content and download routes re-hash the object before serving and refuse a mismatch with `409 integrity_failed` (audited).
- **Deferred:** the web "Cited by" panel (the route exists; REPORTS.md, ROADMAP). The real-renderer pipeline run under `REPORT_E2E=1` is pending gate.
