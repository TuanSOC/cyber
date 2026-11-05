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
- [ ] Finalize writes the version, citations, render rows and audit atomically. Versions are immutable in the DB and the bucket (object lock), and v2 never alters v1.
- [ ] The snapshot round-trips to identical canonical bytes, its sha256 matches the stored object, and the signature verifies in the API and offline.
- [ ] Every citation resolves to an in-scope row with a matching `fields_sha256`. AI sections contain only supported claims and labelled hypotheses, and never an unverified link.
- [ ] `external` snapshots contain no seeded internal name (single-label ones included), custody IP, note text or deep link, and use one pseudonym map across all sections and runs. Distribution is required for RED and AMBER+STRICT.
- [ ] Finalize never signs a version over the render budget, or below the current case TLP without the ack. It holds no transaction across the build, put and sign.
- [ ] Integrity failures are visible and audited. `cited_by` returns both AI outputs and report versions.
- [ ] IDOR cases are complete, `PENDING_ROUTES` is empty, and the lane passes.

## Risk Assessment
- **Building a large snapshot inside the request** holds a read transaction and memory: up to 8 MiB, against the 30 s statement timeout. The write transaction stays short (RT14). Measure p95 on the dataset. If it is too slow, move finalize into a trusted task (a parent decision; it would need a frozen-contract change).
- **Pattern-based redaction** stays a residual even with the second pass: a name that appears in no structured field and matches no rule passes (RT8). The preview and the external-review ack put the final check on the analyst.
- **Coupling to M5 read models** (`service_outputs`, the pseudonymizer). This phase imports them and never changes them. If their signatures prove insufficient, that is a parent change request.
- **Orphan objects** when the DB transaction fails after the put. Accepted: they are reported by the reconcile script, never served.
