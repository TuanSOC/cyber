# Reports and Case Management (Milestone 6)

M6 turns an investigation into a deliverable and adds the case management around it:

1. **Case management:** versioned analyst notes, IOC collections with CSV / JSON / STIX 2.1 exports, status changes with reasons and a history, analyst-confirmed ATT&CK mappings, and a timeline export.
2. **TLP 2.0 and the share policy:** every case carries a TLP label and "do not send to AI / TI" flags (also per evidence item). The AI analyst (M5) and threat intel (M4) refuse what the policy excludes, in the API and again in their workers.
3. **Reports:** a mutable draft is **finalized** into an immutable, signed version. The signed snapshot (canonical JSON, sha256, Ed25519 manifest) is the record of truth; every cited row is numbered `[Cn]` and listed in a citation appendix.
4. **Rendering:** an isolated, sandboxed WeasyPrint **report-worker** turns a signed snapshot into PDF/A-3a (with the snapshot, manifest and signature embedded), HTML and Markdown. It has no egress, no database, no secrets and fetches nothing.

Network and trust layout: [ARCHITECTURE.md](ARCHITECTURE.md#reports-and-case-management-m6); tables: [DATABASE.md](DATABASE.md); routes: [API.md](API.md#reports-and-case-management-m6); threats and residuals: [THREAT_MODEL.md](THREAT_MODEL.md#m6-reports-and-case-management); operations: [DEPLOYMENT.md](DEPLOYMENT.md#reports-m6).

## Case management

### Notes

- A note is a logical row (`analyst_notes`: case, creator, `current_version`, `pinned`, `include_in_reports`, soft delete) plus **append-only versions** (`analyst_note_versions`: plain-text body ≤ 20 000 characters, up to 20 typed refs `{kind, ref_id, job_id}`, author, time).
- A body or refs edit adds version n+1. It names the version it was based on (`expected_version`): a stale edit answers `409 stale_note`, and the note row is locked, so two concurrent edits on one version cannot both win. Flag-only edits (`pinned`, `include_in_reports`) change the note row.
- Refs are re-checked in the org **and the case** on every write (`422 ref_out_of_scope`).
- Only the author or an `org.update` holder edits or deletes. A delete sets `deleted_at/by` once (trigger); the versions stay and the list shows a tombstone (`include_deleted=true`). A deleted note's bodies (its whole history) are readable only by an `org.update` holder: for anyone else `GET /notes/{id}` returns the tombstone metadata with `versions: []`.
- Notes are plain text, never Markdown or HTML. Audit rows (`note.created`, `note.edited`, `note.deleted`) carry ids, versions and counts, never the body.
- Notes with `include_in_reports` appear on the case timeline as `note` entries, at the time the note was written; edits are in its history (RT32).

### IOC collections

- Per case: `ioc_collections` (name ≤ 120, unique per case case-insensitively, description ≤ 2 000, archivable) and `ioc_collection_items` (`ioc_type`, `value_norm`, `ioc_key`, source `job_ioc` with `job_id` + `ioc_id` or `manual`, note ≤ 500, soft remove).
- **Normalization** is the M4 TI normalizer, so `ioc_key` is the M4 `compute_ioc_key` and items join the `ti_results` history by `ioc_key` (the item list shows the latest answer per provider). Values the normalizer would refuse to *send* (private IPs, special-use or single-label names) are still kept, marked `ti_eligible=false` on read. The pcap-only types (`ja3`, `ja3s`, `cert_sha256`, `registry_key`, `file_path`) keep their type and get `sha256(type ‖ 0 ‖ value)` as key, in a type space no TI result uses. Anything that cannot be normalized is reported per item as `invalid(reason)`.
- Adding: up to 500 values per call, each answered `added`, `duplicate` or `invalid`; at most 10 000 active items per collection (`422 too_many_items`). A removed item can be added again. Job IOCs must belong to the case.
- **Case-wide IOCs:** `GET …/investigations/{id}/iocs` deduplicates by `ioc_key` across the latest succeeded job per evidence; the report builder uses the same function (`ioc_collections/case_iocs.py`).
- **Exports** (`GET …/ioc-collections/{id}/export?format=csv|json|stix21&defang=true`):
  - **TLP-marked:** the CSV's first line is `# TLP:<label> CASE-xxxxx exported <ts>`, the JSON has `tlp`, the STIX bundle carries the TLP 2.0 marking-definition.
  - **Formula-safe CSV:** every cell goes through `core/csv_safe.py`: a cell whose first non-whitespace character is `= + - @`, TAB, CR or a look-alike (full-width `＝ ＋ － ＠`, small `﹢ ﹣ ﹦ ﹫`, the minus sign `−`) is prefixed with `'` (RT19); NUL is removed; RFC 4180 quoting with CRLF. The TLP header comment (`# TLP:AMBER CASE-00012 …`) is one cell on one line (line breaks become spaces), quoted like any other cell, so user text in it (a collection name) cannot add columns.
  - **STIX 2.1:** one `indicator` per item with a pattern built from the escaped value (`'` and `\` escaped per the pattern grammar; `ja3`, `ja3s` and `file_path` have no STIX object path and are skipped with a count, never guessed). Deterministic uuid5 ids (an indicator from org + collection + `ioc_key`), an `identity` of the org as `created_by_ref`, and `object_marking_refs` to the OASIS TLP 2.0 marking-definition of the case TLP (extension `extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d`; the five ids are frozen in `cyberlab_jobs.report.STIX_TLP_MARKINGS`, RT18). A defanged bundle says so (`x_cyberlab_defanged`): it documents, it does not match.
  - **Defanged by default.** `defang=false` (the only clear-text form) needs `evidence.write`; a refused attempt is audited `ioc_collection.export_refused` (format, ids). TI summaries are raw provider JSON, never defanged: the defanged JSON export keeps each attributed answer (provider, status, found, score, time) but sets its `summary` to `null`; only the clear-text export carries it.
  - **Never redacted:** internal IPs and names stay in clear; the `external` profile applies to reports only (`X-Export-Redacted: false`, and the export menu says so).
  - Streamed attachments (`nosniff`, `no-store`, `CSP: sandbox`), audited `ioc_collection.exported` with format, count and defang.

### Status, reasons and history

- The M1 workflow is unchanged (`TRANSITIONS` in `investigations/service.py`, `allowed_transitions` on the case).
- Closing, archiving and reopening (`closed → in_progress`) need a `status_reason` (1 … 500 characters after surrounding whitespace is stripped, so a blank reason is `422`; `422 status_reason_required` without one); starting work takes an optional one. A reason without a status change is not an update.
- Every change writes an append-only `investigation_status_events` row (from, to, reason, actor, time) in the same transaction. The history is served newest first (`GET …/status-events`), appears as `status` entries on the case timeline and as the status history in the report. The audit row has the change but never the reason text.
- Archived cases are read-only for notes, collections, mappings, share policies and reports (`409 investigation_archived`).

### ATT&CK case mapping

- `case_attack_mappings`: one row per (case, technique), `status` `confirmed | suspected | rejected`, rationale ≤ 2 000, up to 32 source refs. The technique must exist in the pinned v20 index and be neither revoked nor deprecated (`422 invalid_technique`); duplicates are `409 mapping_exists`; source refs are re-checked in the case scope, and an `ai_run` source must be a `completed` run (`422 ref_out_of_scope`).
- **Suggestions** (never auto-confirmed): the ATT&CK ids of capa capabilities of the latest succeeded static job per evidence, finding ATT&CK ids of the latest pcap and static jobs, and the `attack_techniques` of completed AI runs of the case that the M5 verifier marked supported (at least one verified citation). One suggestion per technique with its sources; `already_mapped` keeps a rejected suggestion visible.
- The matrix read groups confirmed and suspected mappings by tactic in v20 order (rejected ones excluded), with the MITRE notice. Writes are audited `case_attack.mapped` / `case_attack.updated` (from / to status).

### Timeline and export

- The merged case timeline (M5) gains two case-event kinds without evidence: `note` (notes with `include_in_reports`) and `status`. `evidence_id` is nullable on those entries (RT10), and `kinds` filters by ref kind (`custody`, `job`, `timeline`, `alert`, `finding`, `note`, `status`). AI contexts select only the evidence-derived kinds: notes and status reasons never enter a prompt.
- **Export** `GET …/timeline/export?format=csv|json&kinds&from&to`: at most `TIMELINE_EXPORT_MAX_ROWS` (50 000) entries in timeline order; when capped, the CSV ends with a truncation marker row and the JSON says `truncated: true`. The CSV starts with the TLP line and is formula-safe (`csv_safe`). Streamed with `nosniff`, `no-store` and `CSP: sandbox`; audited `investigation.timeline_exported` (format, count, truncation, filters) before the first byte; `422 invalid_range` when `from` is after `to`.

## TLP 2.0

- **Labels and order:** `clear < green < amber < amber_strict < red` (`investigations.tlp`, default `amber`; existing cases were backfilled `amber`). Shown as `TLP:CLEAR` … `TLP:RED` in the FIRST colours on black (`#FFFFFF`, `#33FF00`, `#FFC000`, `#FFC000`, `#FF2B2B`; `cyberlab_jobs.report.TLP_COLOURS`).
- **Marking:** the header and footer of every PDF page, the HTML and Markdown artifacts (a TLP line opens and closes the Markdown), the download file name (`CASE-00012_v2_TLP-AMBER+STRICT.pdf`), the CSV / JSON / STIX exports, the viewer banner and the case badge. Every report cover prints the FIRST one-line definition of its label for the recipients (RT23).
- **Downgrade rule** (a report or a case made *less* restrictive than the case TLP):
  - Case: lowering the case TLP needs `org.update` (`403 tlp_downgrade_forbidden`) and `acknowledge_tlp_downgrade: true` (`422 tlp_downgrade_not_acknowledged`). Raising it needs only `investigation.write`.
  - Report: the TLP defaults to the case TLP. Below it, create, update and finalize answer `409 tlp_below_case` without `acknowledge_tlp_downgrade`, then `403 tlp_downgrade_forbidden` without `org.update`. An allowed downgrade is audited `report.tlp_downgraded`.
  - **Finalize re-checks the rule against the case TLP at that moment (RT7)**, when it reads the draft and again in its write transaction, so a case TLP raised after the draft was written (or during the build) needs the acknowledgement in the finalize body.
- **Distribution:** TLP:RED and TLP:AMBER+STRICT reports, and every `external` report, need a `distribution` statement (≤ 500 characters, printed on the cover; `422 distribution_required` at finalize).

## Share policy ("do not send to AI / TI")

- **Flags:** a case has `ai_excluded` and `ti_excluded`; an evidence item may have an `evidence_share_policies` row with the same two flags (a separate table, so the `evidence_immutable` trigger and the evidence row are never touched).
- **TLP:RED implies both** (computed, never stored).
- **One resolver:** `investigations/policy.py: load_policy(session, org_id, investigation_id=, job_ids=, evidence_ids=) → SharePolicy`. Jobs map to their evidence, evidence to their cases; any case flag or TLP:RED of those cases blocks, and the share-policy rows of the *targeted* evidence block too. For a case scope, excluded evidence is listed (`excluded_evidence_ids`) without blocking, so builders can skip it. Reasons, first applicable wins: `tlp_red`, `case_ai_excluded`, `case_ti_excluded`, `evidence_ai_excluded`, `evidence_ti_excluded`.
- **Enforcement points** (service choke points, never the routers, RT20):

  | Where | Effect |
  |---|---|
  | `ai/service_runs` (`POST /ai/runs`, `POST /ai/context-preview`) | `409 policy_blocked` with `reason` |
  | the AI incident / case context builder | skips AI-excluded evidence; the count is stored in `context_stats.policy_excluded` but **not rendered into the prompt**, so the pinned M5 prompt digests and `prompt_version` are unchanged |
  | `threat_intel/service_runs` (job-scope enrichments) | `409 policy_blocked` |
  | the **analyst-worker**, before **every** provider request, `count_tokens` included | a policy that changed after the request fails the run `failed / policy_blocked` without a provider call |
  | the **enrich-worker**, before each provider slice | the same: the items end `policy_blocked`, no call |

- **Not checked:** manual TI lookups (`POST /ti/lookups`) carry no case scope, so typed values cannot be matched to a case (residual). The case and evidence pages hide "Look up" / "Enrich" while TI is blocked, and the AI buttons show the policy reason. A provider call already in flight when a flag flips completes.
- **Who may change the flags:** turning an exclusion **on** needs `investigation.write` (case, through `PATCH` of the investigation) or `evidence.write` (evidence, `PUT …/evidence/{id}/share-policy`); turning one **off** also needs `integrations.manage`. Both are audited (`investigation.updated` with the flags, `evidence.share_policy_updated`), never with free text.
- These controls close the M4 RT26 and M5 "no TLP / do not send to AI" residuals ([THREAT_MODEL.md](THREAT_MODEL.md#m6-reports-and-case-management)).

## Reports

### Draft and versions

- A `reports` row is the mutable **draft**: title, TLP, profile (`internal` / `external`), template (`incident_v1`), distribution, the eight analyst sections (executive summary, scope, methodology, impact, root cause, actions taken, recommendations, lessons learned; plain text ≤ 20 000 characters each) and the selections: evidence, custody, jobs (`latest` or a list), findings and alerts by minimum severity, case IOCs and collections, TI, ATT&CK statuses, timeline kinds and range, notes, up to 10 AI runs and up to 200 cited rows. The draft JSON is ≤ 1 MiB (`422` at the schema, before the DB check, RT9).
- Every write carries the current integer `revision` (optimistic concurrency, `409 stale_draft`); the trigger makes `revision` grow by exactly one per write.
- Selections must belong to the case (`422 selection_out_of_scope`); AI runs must be completed (or partial) runs of this case's scope, never canary-leak or refused runs.
- **`POST …/finalize`** freezes the draft into `report_versions` v(n+1), append-only, and leaves the draft editable for the next edition. **Versions are never deleted.** A draft without versions can be discarded (`POST …/discard`; `409 report_has_versions` otherwise; the trigger enforces it, and a discarded report is final).
- **`POST …/preview`** builds the snapshot in memory and returns it with its size, the render units against the budget and the per-section counts; nothing is stored or audited.

### Finalize

Three steps, so no transaction is held across the build, the storage put or signing (RT14):

1. **Read:** one `REPEATABLE READ READ ONLY` tenant transaction (`tenant_session(..., snapshot_read=True)`) checks the revision, the archived state, the TLP rule (RT7) and the profile rules (distribution; `acknowledge_external_review` for `external`, `422 external_review_required`), builds the snapshot, applies the redaction profile and computes the canonical bytes, sha256 and render units. Above `REPORT_MAX_SNAPSHOT_BYTES` (8 MiB) → `422 report_too_large`; above `REPORT_MAX_RENDER_UNITS` → `422 report_too_large_to_render`. Both answers carry the per-section counts (and units), so the analyst knows what to narrow (RT1).
2. **Sign and store, outside any transaction:** the manifest is signed with the active kid (`503 signing_unavailable` without a usable key); the snapshot is put into the `reports` bucket at `{org}/{report}/{version}/snapshot.json`, and a GOVERNANCE retention of `EVIDENCE_LOCK_DAYS` is set on that exact object version.
3. **Write:** one short transaction takes the report's advisory lock, re-checks `revision`, `latest_version`, the archived state and the TLP rule against the current case TLP, then inserts the version (manifest, signature, kid, section counts, `change_note` ≤ 500, `finalized_by/at`), the `report_citations` rows, a `pdf` render (`queued`) and the audit row `report.finalized` (sha256, bytes, render units, TLP, profile). After the commit the PDF render is published. A refused render (`render_busy`) or a lost publish never undoes the signed version: the PDF can be requested again, and the reaper re-dispatches a lost publish.

A conflict at step 3 (another finalize or an edit in between) answers `409 stale_draft` and leaves the stored object as an orphan, logged by the API (never served; `apps/api/app/scripts/reconcile_orphans.py` lists it, with render artifacts no render recorded). Finalize is rate-limited to 10 per user per 10 minutes (preview 30).

### The snapshot `cyberlab.report.v1`

The Pydantic contract is `packages/py-jobs/src/cyberlab_jobs/report.py`, shared by the API and the renderer.

- **Sections:** `report` (ids, version, title, TLP, profile, distribution, `generated_by`, `finalized_at`, `base_url`, `change_note`, and the **document control** table of prior versions with their change notes, RT23), `case` (case ref, title, description, status, severity, TLP, status history), the analyst `sections`, then `evidence` (with the trusted hashes and the last verification), `custody`, `jobs` (with tool versions), `findings`, `alerts`, `iocs`, `ti` (attributed, latest per provider), `attack`, `timeline`, `notes`, `ai` and `citations`.
- **Caps** (each section keeps its `items` and the uncapped `total`): evidence 500, custody 2 000, jobs 200, findings 500, alerts 500, IOCs 2 000, TI 2 000, ATT&CK 500, timeline 1 000, notes 200, AI runs 10 (200 claims each), citations 2 000, status history 200, document control 100.
- **Text:** evidence-derived text is `BoundedText` (≤ 4 096 characters, longer values cut with `…[truncated n]`); analyst-authored text (sections, notes, rationale, case description) is `AnalystText` (≤ 20 000 characters, refused above, **never truncated**, RT9). Both refuse NUL and lone surrogates. The builder **defangs evidence-derived and AI text once**; renderers and the viewer only make bidi, zero-width, control and tag characters visible (`⟨U+202E⟩`) from the materialized `vis_rules.json` table (RT24). Analyst text is not defanged.
- **Canonical JSON:** sorted keys, UTF-8 (`ensure_ascii=False`), `(",", ":")` separators, **no floats** (scores are fixed-point strings), timestamps RFC 3339 UTC with microseconds and `Z`. Re-validating and re-serializing gives the same bytes. The sha256 of these bytes is the version id printed on every page.
- **Determinism:** the same draft over the same data numbers and serializes identically (`test_report_snapshot.py::test_build_is_deterministic_for_the_same_draft`).

### Citations

- **Sources:** verified AI citations only (as M5 `deep_link` does), rows the analyst selected (`cited_rows`), note refs and ATT&CK mapping sources.
- Every cited row is **re-queried in the requester's tenant session and in the case scope**; a row of another case or org is dropped and counted (`citations.dropped_out_of_scope`), never shown.
- Each resolved row becomes `[C<n>]` with kind, table, row id, job id, a **bounded copy of its fields** (the M5 per-kind allow-list, as strings, defanged once, ≤ 4 096 characters each, ≤ 32 fields), the `fields_sha256` of exactly that copy, and the internal deep-link path (`/o/{org}/pcap/{job}?tab=findings&ref={id}`, built from ids only). Internal PDFs prefix it with `PUBLIC_BASE_URL`.
- **Numbering** follows the first use in document order (evidence, jobs, findings, alerts, TI, ATT&CK, timeline, notes, AI claims), then the rows only the analyst selected, in draft order. The contract refuses a snapshot that cites a number missing from the appendix.
- **"Cited by":** `report_citations` (append-only, index `(org, kind, ref_id)`, next to the M5 `ai_citations` / `ai_context_refs` indexes) answers `GET …/cited-by?kind&ref_id&job_id` with the AI outputs (verified citations only) and the report versions that cite one row. The route is API-only in M6: the web app has no "Cited by" panel on rows yet (deferred; the viewer's citation appendix links each `[Cn]` back to its row).

### AI content

- Only completed (or partial) runs of the case scope that the analyst selected; never canary-leak or refused runs.
- Each run's pseudonyms are **reversed with that run's own map** in both profiles, because separate run trees number independently (RT2).
- Only `supported` claims and labelled hypotheses; unsupported claims are omitted with a count (`omitted_unsupported`). Flags (`verdict_language`, `external_url`, `command_like`, …) are shown inline on each claim. The `external` profile also omits claims flagged `verdict_language` or `external_url` (counted in `omitted_flagged`, RT15).
- The section and the appendix carry the disclaimer *"AI-generated interpretation: observations to verify before acting, not verdicts."* AI never drafts analyst sections in M6.

### Redaction profiles

- **`internal`:** real values and names, notes (when selected), custody IPs and user agents, and the citation deep links.
- **`external`** (RT2, RT8, RT29): **one report-level pseudonym map** (the M5 `Pseudonymizer` with the org's CIDRs and suffixes) over the whole snapshot, so a pseudonym means the same value in every section and every AI run:
  1. the map is seeded first from structured fields: hostname-typed pcap fields of the case (DNS query, HTTP host, TLS SNI / certificate CN), user paths in static strings, the org members' names, and **every original value of the included AI runs' own pseudonym maps** (the builder reverses them into the claims, so a single-label host such as `FIN-SRV-02` that only a finding attribute named still gets a report pseudonym);
  2. **every string field is walked**, except an explicit allow-list of enum, hash, UUID, count and timestamp fields; planted pseudonym-shaped text is neutralized first. That covers the case title and description, analyst sections, status reasons, distribution, evidence file names, timeline titles, finding and alert text, IOC values, TI summaries, ATT&CK rationale, citation copies and AI text;
  3. a **whole-token second pass** replaces every original value already in the map wherever it appears, so single-label hosts (`FIN-SRV-01`) and bare usernames in free text are replaced too;
  4. notes (their section, the timeline's `note` entries, whose title is the body, and every citation of an `analyst_notes` row, also through a `timeline` citation of a note entry, which the builder does not resolve in `external`), custody `ip` / `user_agent`, deep links and `base_url` are dropped; actors and authors become role labels; `finalized_by` in the manifest is a UUID, never a name;
  5. **`ioc_key` is opaque:** the internal key is an unsalted `sha256(type ‖ 0 ‖ value)`, so an internal value (an RFC 1918 address) could be recovered by brute force. In `external` every `ioc_key` (IOC and TI sections) is replaced by HMAC-SHA256 under a random key generated for the build and never stored: the TI rows still join their IOC inside the version, but the key matches nothing outside it (not even another version of the same report).
- Finalizing an `external` version needs a distribution statement and `acknowledge_external_review` (the builder shows the preview first).
- **Residuals:** pseudonymization is pattern-based (a name that matches no rule and no seed passes), and the report-level map is **not stored** (RT29): "which host is `INT_HOST_3`?" is answered by an `internal` version of the same report.

## Signing

- **Manifest** (`cyberlab.report.manifest.v1`, canonical JSON): `report_schema`, `report_id`, `version`, `org_id`, `snapshot_sha256`, `snapshot_bytes`, `tlp`, `profile`, `finalized_at`, `finalized_by` (a UUID), `kid`. The detached Ed25519 signature (base64, 64 bytes), the kid and the manifest are stored on `report_versions`.
- **Verify on read:** the API reads the exact stored object version and re-hashes it on every read. The version detail reports `snapshot_ok` and `signature_valid`; the content and snapshot routes serve the bytes only when the manifest signature verifies **and** the bytes match the sha256 and size the signed manifest names (and re-serialize canonically), else `409 integrity_failed` (audited `report.integrity_failed` with both flags); the rendition download re-hashes against the render's sha256.
- **Key custody:** the private keys are a JSON `{kid: base64 raw key}` file, the compose secret behind `REPORT_SIGNING_KEYS_FILE`, for the **api role only**: `Settings` refuses it for every other `PROCESS_ROLE`, so the ingest, enrich and analyst workers and the renderer never hold it. Only `app/modules/reports/signing.py` may import the loader (`tests/unit/test_report_import_guard.py`). Public keys come from `REPORT_SIGNING_PUBLIC_KEYS` and the active kid from `REPORT_SIGNING_ACTIVE_KID`.
- **Dev pair:** `infra/reports/dev-signing-private.json` (kid `dev-report-1`) is committed so a fresh clone starts. `ENV=prod` refuses any `dev-` kid and the committed public key, and requires the key file and an active kid that names a published key.
- **Public keys for recipients (RT22):** `GET /api/v1/report-signing-keys` is **unauthenticated** (an external recipient has no account), rate-limited to 60 per minute per client IP, cacheable for 5 minutes, and returns `{keys: [{kid, alg, public_key, active}]}`. Operators also publish the prod keys with their deployment notes ([DEPLOYMENT.md](DEPLOYMENT.md#reports-m6)).

### Key rotation (prod)

1. Add a key to the existing file: `docker run --rm -v "$PWD:/repo" -w /repo cyberlab/api:dev python scripts/gen_report_signing_keys.py --add --kid prod-report-YYYYMMDD` (the file stays mode 0400, owner uid 10001).
2. Merge the printed public key into `REPORT_PROD_SIGNING_PUBLIC_KEYS` **next to every older key**, and set `REPORT_PROD_SIGNING_ACTIVE_KID` to the new kid.
3. Recreate the api (`pnpm prod:up`), finalize a test version and check `kid` and `signature_valid` in the viewer.
4. **Never remove an old public key** while reports signed with it may still circulate: the public-key route and `verify_report.py` need it. Old private keys can leave the file once the new kid is active.

### Offline verification

`scripts/verify_report.py` needs Python with `cryptography`. PDFs are read by its own bounded reader of the embedded files (`pypdf`, when installed, is only a fallback):

```bash
# Pin the keys: get them from the operator out of band (or save the public route's output
# once over a channel you trust); the script never fetches anything itself.
python scripts/verify_report.py --pdf CASE-00012_v2_TLP-AMBER.pdf --public-keys keys.json
# VALID: report 6b1f… v2 (amber, internal) sha256 3f9a… signed by prod-report-20261106
# NOTE: the signature covers the embedded snapshot.json only, not the PDF's visible pages; …
python scripts/verify_report.py --snapshot snapshot.json --sig report-v2.sig.json --public-keys keys.json
```

**Scope: the signature covers the snapshot, not the pages.** A valid PDF result proves that the attached `snapshot.json` is the signed record; it does not prove what the pages show (the renderer is untrusted and signs nothing; a signed rendition attestation is deferred). Read the snapshot, or the version in CyberLab, as the authoritative content; the script prints this note with every valid PDF result.

It checks that the PDF is **one revision** (exactly one `%%EOF`, one cross-reference section, no `/Prev`, no object defined twice: an incremental update, which could add pages or attachments after rendering, is refused) and embeds exactly `snapshot.json`, `manifest.json` and `manifest.sig.json`, each once, and no other embedded file; every compressed stream inflates within a size bound (9 MiB per stream, 64 MiB per file); every JSON document is strict (no duplicate keys, no NaN / Infinity); the signature file names a pinned kid, and the **committed dev key (or any `dev-` kid) is refused unless `--allow-dev`**; the Ed25519 signature over the canonical manifest; the snapshot's sha256 and size against the manifest; that the snapshot re-serializes to the same canonical bytes; that report id, version, TLP, profile and schema match the manifest; and, for a PDF, that the embedded `manifest.json` equals the signed one. Exit 0 when every check passes, 1 otherwise, 2 on usage errors. `--public-keys` (alias `--keys`) takes the public route's JSON or a plain `{kid: base64}` map; `--quiet` prints nothing on success.

**Why not PAdES:** a PAdES signature (pyHanko) signs the PDF bytes, i.e. one rendition produced by the untrusted renderer. M6 signs the snapshot (the record of truth) in the trusted API and embeds the signature, so every rendition, and the snapshot on its own, verifies offline with one small script. PAdES, RFC 3161 timestamps and KMS / HSM custody are deferred.

## Renderer

### Why WeasyPrint

WeasyPrint 70 (`weasyprint>=70.0,<71`, `fonttools>=4.60.2`, `jinja2>=3.1.6`) has no JavaScript engine, sends every resource load through one choke point (`URLFetcher`, made deny-all), writes native PDF/A-3a (tagged, with attachments) and is reproducible with a fixed identifier and dates; it needs only Pango and HarfBuzz. Chromium-based renderers (Playwright, Gotenberg) need a user-namespace sandbox that conflicts with `cap_drop: [ALL]`, ship monthly V8 / Blink CVEs, weigh 1–2 GB and are not reproducible; `window.print` cannot be signed, archived or reliably TLP-marked (the M3 static print page stays as a convenience). 70.0 fixes CVE-2026-55073 (`stylesheets` / `xmp_metadata` bypassed the fetcher) and CVE-2026-106443 (EPS → Ghostscript RCE); 69.0 fixes CVE-2026-49452 (presentational hints → CSS injection); 68.0 CVE-2025-68616 (redirect SSRF); fonttools 4.60.2 CVE-2025-66034. A new major is a deliberate upgrade.

### Isolation

- **Image** `cyberlab/report-worker` (`apps/workers/report`): python 3.12-slim-trixie with Pango, HarfBuzz subset, libseccomp, fontconfig, `fonts-noto-core` and `fonts-noto-mono`. **No Ghostscript** (the build fails if `gs` exists). Fontconfig lists only the bundled Noto fonts; its cache is built at image build time and read-only at runtime. Templates and CSS are root-owned and read-only.
- **Container:** `init`, `read_only`, `cap_drop: [ALL]` plus the analyzers' `SETUID, SETGID, KILL, CHOWN, DAC_OVERRIDE, FOWNER`, `no-new-privileges`, `pids_limit: 128`, 1 GiB, 1 CPU, tmpfs `/tmp` (16 MiB) and a root-owned tmpfs `/work` (96 MiB, `0711`, `noexec`). Network **`analysis` only** (internal: the broker and MinIO, no default route). Env: `BROKER_URL` only (broker user `report`, confined to `report*` / `test.report*`, write-only to ingest). No database, JWT secret, MinIO credentials, signing key or app Redis.
- **Celery:** prefork `--concurrency 1 --max-tasks-per-child 1` (a fresh child per render), soft 90 s / hard 120 s time limits, without gossip, mingle or heartbeat. The render subprocess's own limits (wall 80 s, CPU 75 s) sit below the soft limit with 10 s left for the download, the checks and the upload, so a slow render is answered `timeout` by the sandbox and never cut mid-render by Celery (`test_sandbox.py::test_the_sandbox_times_out_before_the_celery_soft_limit`).
- **Input and output only through presigned URLs** in the message: a GET of the exact snapshot version and a POST for one key (`{org}/{report}/{version}/{render_id}.{ext}`, fixed content type, 1 … 32 MiB). The worker checks the snapshot's size and sha256 (`snapshot_mismatch` otherwise) and that the manifest names the same sha256, size and org.
- **Render subprocess** (`report_worker/sandbox.py`, worker-kit `run_tool`): uid 10004 (`CYBERLAB_TOOL_UID` in the image; the static worker's tools use 10003, and `RLIMIT_NPROC` counts per uid); `python -I -B -m report_worker.render` (isolated mode, no `.pyc` writes; not `-S`, which would drop the venv); environment `PATH`, `LANG`, `HOME` / `TMPDIR` in the job dir, `FONTCONFIG_FILE` and `MALLOC_ARENA_MAX=2`, never the broker URL; cwd the root-owned, read-only input dir; `RLIMIT_AS` 768 MiB, `RLIMIT_CPU` 75 s, `RLIMIT_FSIZE` 32 MiB, `RLIMIT_NOFILE` 64, `RLIMIT_NPROC` 16; wall timeout 80 s (the process group is killed). **Seccomp** is an allowlist: `socket()` / `socketpair()` of every family except `AF_UNIX`, and the io_uring syscalls, fail with `EACCES` (`IORING_OP_SOCKET` would bypass a `socket()` filter). Every uid-10004 process is killed and the job dir wiped before each render.
- **Deny-all fetcher** (`report_worker/fetch.py`): every `fetch` (http, https, file, data, `@import`, `@font-face url()`, `<img>`, `<link>`, SVG references, attachments given as names) raises a fatal `FetchBlocked`. The fetcher also counts attempts, so a block that WeasyPrint swallows still fails the render (`fetch_blocked`). The CSS is a trusted constant (`CSS(string=…)`, checked at import for `url(`, `@import`, `@font-face`), fonts come only from fontconfig, attachments are bytes, `base_url=None`.
- **Constant options:** `pdf_variant="pdf/a-3a"`, `presentational_hints=False`, `custom_metadata=False`, compressed, `pdf_identifier` = the first 16 bytes of the snapshot sha256; nothing is derived from data.
- **Templates:** `jinja2.sandbox.SandboxedEnvironment(autoescape=True, undefined=StrictUndefined)` without its escape hatches: the `safe`, `urlize` and `xmlattr` filters are removed and the `{% autoescape %}` statement is a syntax error (`render_html.ReportEnvironment`), so a template using one fails to compile (or to render, inside a conditional) even if it slipped past the lint. `tests/test_template_lint.py` also bans `|safe`, `Markup(`, `{% autoescape false %}`, resource references and data-built `style=` / `class=`; severity and TLP map to fixed classes; the only links are in-document anchors and, in internal reports, the platform paths behind `base_url`. AI and analyst text are plain paragraphs. The HTML artifact carries `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`, because a downloaded file opened from disk gets no header (RT19).
- **Output checks before upload:** the PDF starts with `%PDF-`, is ≤ 32 MiB and has 1 … 300 pages (checked after layout, before writing); HTML and Markdown are strict UTF-8 and ≤ 32 MiB; HTML must start with exactly the template's constant head (`cyberlab_jobs.report.HTML_HEAD`: doctype, `<html lang>`, charset and the CSP meta), byte for byte. Root reads the artifact only through `open_output` (one name, `O_NOFOLLOW`, regular file).
- **The trusted ingest re-checks** (`reports/render_ingest.py`): the org from `report_render_index`, the per-render token (an HMAC derived from the JWT secret; only its sha256 is stored), the render still `queued` / `running` and its index `deadline_at` (the token's lifetime) not passed (a late answer is dropped; the reaper fails the render `timeout`). The object at the re-derived key and the reported version is re-hashed and its size and magic checked (`%PDF-`; strict UTF-8; HTML starts with exactly `HTML_HEAD`, CSP meta included), never parsed (RT27); then GOVERNANCE retention on that version and `succeeded`. Any mismatch is `invalid_output`.
- **Errors are typed codes only** (`snapshot_mismatch`, `fetch_blocked`, `timeout`, `oom`, `too_large`, `too_many_pages`, `invalid_output`, `renderer_error`); no stderr, exception text or URL leaves the worker. The viewer shows a hint per code (narrow the selections for `oom`, `timeout`, `too_large` and `too_many_pages`; retry for `renderer_error`).

### Formats

| Format | Content type | Notes |
|---|---|---|
| `pdf` | `application/pdf` | PDF/A-3a (tagged, `lang="en"`, title, headings, table headers); TLP in the header and footer of every page, footer `CASE-00012 v2 sha256:0123456789ab…`; embeds `snapshot.json`, `manifest.json` and `manifest.sig.json` as attachments (relationship `Source`, dated `finalized_at`). Queued at finalize. |
| `html` | `text/html; charset=utf-8` | the same template with the constant CSS inlined and the meta CSP; never shown inside the app |
| `md` | `text/markdown; charset=utf-8` | CommonMark + GFM tables with our escaper: every ASCII punctuation character escaped, evidence values as code spans with a longer fence, `\|` escaped and newlines as `⏎` in table cells; the only links are `[Cn](#cn)` anchors |

HTML and Markdown are rendered on demand (`POST …/renders {format}`, deduplicated per version and format, `409 render_busy` above the caps). **DOCX is deferred** (RT12: python-docx writes zip members with the current time, which breaks the determinism gate).

**The app never shows renderer output.** The viewer (`/o/{org}/reports/{id}/v/{n}`) renders the snapshot JSON (`GET …/versions/{v}/content`) with React text nodes: TLP banners, the integrity strip (signature and hash status), the sections and the citation appendix with deep links. Downloads are streamed by the API from the exact object version, re-hashed while streaming, as attachments with the TLP in the file name, `nosniff`, `no-store` and `Content-Security-Policy: sandbox` (HTML: `sandbox; default-src 'none'; style-src 'unsafe-inline'`), and audited `report.downloaded`. No presigned URL is ever given to a user.

### Render budget and caps (RT1)

A signed version is immutable, so it must be renderable. `render_units(snapshot)` counts every character of every string value plus 40 units per list row and 60 more per citation. Finalize refuses a snapshot above `REPORT_MAX_RENDER_UNITS` (`422 report_too_large_to_render`), and the preview shows the units against the budget.

| Setting | Value | Why |
|---|---|---|
| `REPORT_MAX_RENDER_UNITS` | **450 000** | calibrated in the report-worker on worst-case shapes at the budget: peak **594 MiB RSS** of the 768 MiB `RLIMIT_AS`, at most **214 pages** (cap 300), CPU at most 60 s, inside the 75 s limit (`tests/test_render_budget.py`) |
| `REPORT_MAX_SNAPSHOT_BYTES` | 8 MiB | `422 report_too_large` |
| `REPORT_MAX_ARTIFACT_BYTES` / `REPORT_MAX_PAGES` | 32 MiB / 300 | `too_large` / `too_many_pages` |
| `REPORT_RENDER_DEADLINE_S` | 600 | the reaper fails a render past it with `timeout` and re-dispatches a lost publish (≤ 3 attempts) |
| `REPORT_ACTIVE_RENDERS_PER_ORG` / `_GLOBAL` | 2 / 4 | per renderer replica; `409 render_busy` |
| renders / finalize / preview per user | 20 / 10 / 30 per 10 min | `429 rate_limited` |

Recalibrate after changing the template, the CSS, the fonts or WeasyPrint: `scripts/lane-test.sh 4 --service report-worker-test sh -c "REPORT_CALIBRATE=1 pytest -q -s tests/test_render_budget.py -k calibrate"`, then change the API setting and `CALIBRATED_RENDER_UNITS` together.

### Reproducibility

The same snapshot gives byte-identical PDF, HTML and Markdown with the same image and `renderer_version` (`report-worker/<v>+weasyprint-<v>+template-incident_v1.<n>`, stored on each render): a fixed `pdf_identifier`, document and attachment dates from `finalized_at`, constant options, no "now" anywhere. Debian font or Pango updates in a rebuilt image change the bytes, so determinism is claimed per image (RT17). The signed snapshot, not a rendition, is the record of truth.

### Accessibility

PDF/A-3a gives a tagged structure tree; the template sets the document language and title, uses real headings and `<th>` table headers, and prints text, never images. veraPDF validation is a **local, recorded check**, not part of the gate; PDF/UA-1 is not claimed.

## Metrics

Recorded during the M6 build (report-worker image, local); phase 9 records the gate run in [TESTING.md](TESTING.md#m6-reports-and-case-management-suites).

| Metric | Value |
|---|---|
| Render at the 450 000-unit budget, worst shape | 594 MiB peak RSS (limit 768 MiB), ≤ 214 pages |
| PDF render latency, golden snapshot | p50 / p95 3.9 s |
| Deterministic re-render (same image) | byte-identical (`test_render_pdf.py::test_rendering_twice_gives_identical_bytes`) |
| Hostile fixture | every payload inert visible text, no fetch, no markup (`test_render_html.py::test_hostile_payloads_are_inert_visible_text`, `test_render_md.py::test_the_hostile_document_has_no_links_images_or_html`) |

## Limitations

- **DOCX** is deferred (RT12); Markdown covers editable text.
- **No PAdES, RFC 3161 timestamps or KMS / HSM:** the API holds the signing key (the same trust level as the DB writer).
- **CJK glyphs:** `fonts-noto-core` has no CJK coverage, so Chinese, Japanese and Korean text renders as missing-glyph boxes in PDFs (the snapshot, the viewer, HTML and Markdown keep the text). Vietnamese and other Latin, Greek and Cyrillic text renders.
- **veraPDF** is not in CI; only PDF/A-3a is claimed, PDF/UA-1 is not.
- **External redaction is pattern-based**, and the report-level map is not stored (RT29).
- **No images or charts** (the fetcher stays deny-all), no per-org templates, no rich text, no report approvals, comments or multi-signer reviews, no sharing outside the platform, no TAXII / MISP push, no org-wide IOC watchlists.
- **Retention (M7):** signed snapshots, versions, citations and notes are **never** purged; snapshot objects are GOVERNANCE-locked for `EVIDENCE_LOCK_DAYS`, and the purge MinIO user has an explicit Deny on `*/snapshot.json`. Renditions (PDF, HTML, Markdown) of cases closed longer than `closed_case_days` are purgeable: the render row is marked `purged` (hash and size kept), its object is deleted, and a new render can be requested from the signed snapshot. A case legal hold also sets the S3 legal hold on the case's report snapshots (retention worker).
- **RBAC is org-wide:** viewers (`evidence.read`) can download any report, TLP:RED included; every download is audited (RT31).
- **One render at a time per renderer replica**; the global cap counts per replica.
