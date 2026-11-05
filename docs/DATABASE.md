# Database

PostgreSQL 17. Schema owned by Alembic (`apps/api/alembic/versions`): `0001` is M1, `0002`–`0005` M2 (analysis jobs, pcap results), `0006`–`0008` M3 (static analyzer, malware results, storage quota), `0009`–`0010` M4 (threat intelligence), `0011` M5 (AI analyst), `0012` and `0013` M6 (reports and case management; `0013` adds same-org composite FKs, review L4).

## Roles

| Role | Used by | Rights |
|---|---|---|
| `postgres` | init script only | superuser |
| `cyberlab_owner` | `migrate` service, test setup/cleanup | owns `cyberlab` / `cyberlab_test` and every table |
| `cyberlab_app` | the API process and the trusted workers (ingest, enrich, analyst) | `NOSUPERUSER NOBYPASSRLS`, explicit per-table grants, `idle_in_transaction_session_timeout=60s`, `statement_timeout=30s` |

The API never receives owner credentials (`Settings` has no field for them; compose passes `MIGRATION_DATABASE_URL` only to `migrate` and `api-test`).

## Tables

```mermaid
erDiagram
  users ||--o{ organization_members : "member of"
  organizations ||--o{ organization_members : has
  users ||--o{ refresh_tokens : owns
  users ||--o{ auth_events : "logged for"
  organizations ||--o{ investigations : has
  investigations ||--o{ evidence : contains
  evidence ||--o{ evidence_hashes : "hashed as"
  evidence ||--o{ evidence_custody_events : "custody chain"
  organizations ||--o{ audit_logs : records
  users ||--o{ evidence : uploads
  evidence ||--o{ analysis_jobs : "analyzed by"
  analysis_jobs ||--|| analysis_job_index : "system lookup"
  analysis_jobs ||--o{ network_flows : produced
  analysis_jobs ||--o{ network_records : produced
  analysis_jobs ||--o{ network_alerts : produced
  analysis_jobs ||--o{ analysis_findings : produced
  analysis_jobs ||--o{ iocs : produced
  analysis_jobs ||--o{ analysis_timeline : produced
  analysis_jobs ||--o| malware_samples : produced
  analysis_jobs ||--o{ malware_sections : produced
  analysis_jobs ||--o{ malware_imports : produced
  analysis_jobs ||--o{ malware_strings : produced
  analysis_jobs ||--o{ malware_signature_matches : produced
  analysis_jobs ||--o{ malware_capabilities : produced
  organizations ||--o{ ti_provider_configs : "sealed keys"
  organizations ||--o| ti_org_settings : "TI settings"
  analysis_jobs ||--o{ ti_enrichment_runs : "enriched by"
  ti_enrichment_runs ||--|| ti_run_index : "system lookup"
  ti_enrichment_runs ||--o{ ti_run_items : "planned pairs"
  ti_enrichment_runs ||--o{ ti_results : "provider answers"
  ti_results ||--o{ ti_run_items : "answer or cache hit"
  organizations ||--o{ ai_provider_configs : "sealed AI keys"
  organizations ||--o| ai_org_settings : "AI settings"
  analysis_jobs ||--o{ ai_runs : "job scope"
  investigations ||--o{ ai_runs : "investigation scope"
  ai_runs ||--o{ ai_runs : "incident children / supersedes"
  ai_runs ||--|| ai_run_index : "system lookup"
  ai_runs ||--o{ ai_run_inputs : "frozen context (base, reduce)"
  ai_runs ||--o{ ai_context_refs : "label map"
  ai_runs ||--o| ai_outputs : "verified output"
  ai_outputs ||--o{ ai_citations : "checked citations"
  investigations ||--o{ investigation_status_events : "status history"
  evidence ||--o| evidence_share_policies : "share flags"
  investigations ||--o{ analyst_notes : notes
  analyst_notes ||--o{ analyst_note_versions : versions
  investigations ||--o{ ioc_collections : collections
  ioc_collections ||--o{ ioc_collection_items : items
  investigations ||--o{ case_attack_mappings : "ATT&CK mapping"
  investigations ||--o{ reports : "report drafts"
  reports ||--o{ report_versions : "signed versions"
  report_versions ||--o{ report_citations : "C1..Cn"
  report_versions ||--o{ report_renders : renditions
  report_renders ||--|| report_render_index : "system lookup"
```

(`malware_exports` and `malware_resources` hang off `analysis_jobs` the same way.)

| Table | Scope | Notes |
|---|---|---|
| `users` | global | `email` citext unique; argon2id `password_hash` |
| `auth_events` | global | append-only; register/login/logout/refresh-reuse; no read API in M1 |
| `refresh_tokens` | user | sha256 of opaque token, `family_id`, `revoked_reason` (rotated/logout/reuse) |
| `organizations` | tenant | `slug` unique, `next_case_number` counter; `storage_quota_bytes` (NULL = `DEFAULT_STORAGE_QUOTA_BYTES`, set by an operator only) |
| `organization_members` | tenant | unique (org, user); role owner/admin/analyst/viewer |
| `investigations` | tenant | unique (org, case_number); status open/in_progress/closed/archived; M6: `tlp` (`clear` / `green` / `amber` / `amber_strict` / `red`, default `amber`, existing rows backfilled), `ai_excluded`, `ti_excluded` (default false) |
| `evidence` | tenant | object `storage_bucket/key/version_id`; identity columns immutable |
| `evidence_hashes` | tenant | append-only; md5/sha1/sha256 per evidence |
| `evidence_custody_events` | tenant | append-only chain of custody |
| `audit_logs` | tenant | append-only; `organization_id` NOT NULL |
| `analysis_jobs` | tenant | one analyzer run (`pcap` / `static`) over one evidence version; `profile` `full` / `av` for static jobs, NULL otherwise; status machine enforced by trigger (final states and identity columns, incl. `profile`, immutable); `ingest_token_sha256`; `summary` jsonb (tool versions, engine errors, truncation flags, counts) |
| `analysis_job_index` | system lookup | job → org, analyzer, status, deadline for ingest/reaper and the global per-analyzer caps; RLS: sessions without org context see all rows, tenant sessions only their org; app may UPDATE only `status`, `deadline_at` |
| `network_flows` | tenant | Zeek conn records (largest `max_flows` by bytes); `total_bytes` indexed for sorting |
| `network_records` | tenant | `kind` dns/http/tls, `summary` text (searchable), `details` jsonb |
| `network_alerts` | tenant | Suricata alerts (sid, rev, signature, category, severity, community id) |
| `analysis_findings` | tenant | heuristic findings: type, severity, confidence, method@version, evidence refs, attributes |
| `iocs` | tenant | observables with first/last seen, count, source; unique (job, type, md5(value)) |
| `analysis_timeline` | tenant | capture start/end, findings, serious alerts, first contacts |
| `malware_samples` | tenant | one per static job (unique `job_id`): size, md5/sha1/sha256, ssdeep, libmagic type, mime, entropy, `file_format` pe/elf/other, `pe` / `elf` summary jsonb |
| `malware_sections` | tenant | index, name, virtual address (`numeric(20)`: unsigned 64-bit), sizes, entropy, flags |
| `malware_imports` / `malware_exports` | tenant | library + function or ordinal / name, ordinal, address |
| `malware_resources` | tenant | type, name, language, size, entropy, sha256 |
| `malware_strings` | tenant | capped; `encoding` ascii / utf16le / floss_decoded / floss_stack / floss_tight; offset |
| `malware_signature_matches` | tenant | `engine` clamav / yara, name, namespace, tags, meta |
| `malware_capabilities` | tenant | capa rule name, namespace, ATT&CK and MBC ids (jsonb), match count |
| `ti_provider_configs` | tenant | one row per (org, provider); provider check; `enabled`; MISP `base_url` (normalized, required iff `misp`); sealed key `key_kid`, `key_version`, `key_epk`, `key_nonce`, `key_ct`, `key_last4`; `verify_status` unverified/valid/invalid/error, `verified_at`, `last_error_code`; `limits` jsonb (org-lowered); `terms_ack_at`, `terms_ack_by` |
| `ti_org_settings` | tenant | one per org: `excluded_suffixes` (≤ 50 domain suffixes never sent) |
| `ti_enrichment_runs` | tenant | `scope` manual / job, `job_id` (composite FK to `analysis_jobs`), `requested_by`, `providers`, `status` (queued / running / waiting / completed / partial / failed), `summary` jsonb (≤ 16 KiB, counts only), `deadline_at`, `started_at`, `finished_at` |
| `ti_run_index` | system lookup | run → org, `status`, `resume_at`, `deadline_at`, `dispatched_at`, `lease_until`, `lease_owner` for the enrich worker, `ti.resume` and the reaper; same RLS pattern as `analysis_job_index`; index (status, resume_at) |
| `ti_run_items` | tenant | the frozen plan of a run: PK (run_id, provider, ioc_key), `seq`, `ioc_type`, `value_norm`, `state` pending / done / cached / abandoned, `result_id` (this run's answer or the cached one), `reason` rate_limited / quota_exhausted / deadline / auth_failed |
| `ai_provider_configs` | tenant | one row per (org, provider); provider `anthropic` / `gemini` / `mock`; `enabled`, `model` (pattern `^[a-z0-9][a-z0-9._-]{0,63}$`, allowlist in the app); sealed key `key_kid`, `key_version`, `key_epk` (32 bytes), `key_nonce` (12 bytes), `key_ct`, `key_last4` (all or none); `verify_status` unverified/valid/invalid/error, `verified_at`, `last_error_code`; `limits` jsonb object; `terms_ack_at/by`, `paid_tier_ack_at/by`. Checks: `enabled` needs `terms_ack_at`, and for `gemini` `paid_tier_ack_at` (RT5). A sealed key or the dev platform key is required by the app, not the DB |
| `ai_org_settings` | tenant | PK `organization_id`: `ai_enabled` (default false; true needs `privacy_ack_at`), `privacy_ack_at/by`, `default_provider`, `pseudonymize_internal` (true), `internal_cidrs` / `internal_suffixes` (jsonb arrays ≤ 50), `include_strings` (false), `include_ti` (true), `include_case_text` (false), `daily_token_budget` (1 000 000), `run_token_cap` (100 000), `incident_token_cap` (600 000), all > 0 |
| `ai_runs` | tenant | `task` (8 values incl. `job_digest`), `scope` job / investigation with `job_id` iff job and `investigation_id` iff investigation (composite FKs), `target_kind` finding / alert iff `target_id`, `parent_run_id` iff `job_digest` (composite self FK), `supersedes_run_id`, `provider`, `model`, `served_model`, `prompt_version`, `output_schema`, `status` (queued / running / waiting / completed / partial / failed / refused), `error_code`, `context_sha256` (64 hex), `context_stats` ≤ 16 KiB, `usage` ≤ 2 KiB, `metrics` ≤ 4 KiB, `cost_micros` ≥ 0, `price_version`, `requested_by`, `deadline_at`, `created_at`, `started_at`, `finished_at`; indexes (org, created_at), (org, context_sha256), (job_id, created_at), (investigation_id, created_at), (parent_run_id) |
| `ai_run_index` | system lookup | run → org, `status`, `resume_at`, `deadline_at`, `dispatched_at`, `lease_until`, `lease_owner`, `attempts` (529 backoff), `calls` (provider calls made, RT2); same RLS pattern as `ti_run_index`; index (status, resume_at) |
| `ai_run_inputs` | tenant, append-only | PK (run_id, stage `base` / `reduce`): `context` jsonb ≤ 512 KiB (the redacted payload exactly as sent), `context_sha256`, `pseudonym_map` jsonb object ≤ 64 KiB (never sent, never selected by the worker) |
| `ai_context_refs` | tenant, append-only | PK (run_id, label): `stage`, `label` (`^(J[0-9]{1,3}:)?[A-Z][0-9]{1,4}$`), `kind` (16 values), `ref_table`, `ref_id` (uuid text or a Zeek `flow_ref`), `job_id` (composite FK), `fields_sha256`; index (org, kind, ref_id) for M6 "which outputs cite this row" |
| `ai_outputs` | tenant, append-only | `run_id` unique: `body` jsonb ≤ 64 KiB (validated, sanitized `AnalysisOutput`; raw model text is never stored), `verification` ≤ 32 KiB (claim verdicts, citation counts, dropped refs, invalid ATT&CK, truncation, digest reuse), `flags` jsonb array |
| `ai_citations` | tenant, append-only | `output_id`, `run_id`, `claim_path`, `section`, `claim_id`, `claim_status` supported / unsupported / hypothesis, `label`, `kind`, `ref_id`, `job_id`, `status` verified / unverified / invalid, `reason`, `field`, `quote` ≤ 256, `stale`; indexes on `output_id` and (org, kind, ref_id) |
| `investigation_status_events` | tenant, append-only | M6: `investigation_id` (composite FK), `from_status` (NULL or a status), `to_status`, `reason` ≤ 500, `actor_id`, `occurred_at`; index (investigation_id, occurred_at) |
| `evidence_share_policies` | tenant | M6: PK `evidence_id` (composite FK), `ai_excluded`, `ti_excluded`, `updated_by`, `updated_at`; a separate table so the `evidence_immutable` trigger is untouched |
| `analyst_notes` | tenant | M6: `investigation_id`, `created_by`, `current_version` ≥ 1, `pinned`, `include_in_reports`, `deleted_at` / `deleted_by` (both or neither); index (investigation_id, created_at) |
| `analyst_note_versions` | tenant, append-only | M6: PK (note_id, version): `body` 1–20 000 characters, `refs` jsonb array ≤ 20 entries and ≤ 16 KiB, `author_id`, `created_at` |
| `ioc_collections` | tenant | M6: `investigation_id`, `name` 1–120 (unique per case on `lower(name)`), `description` ≤ 2 000, `archived_at` |
| `ioc_collection_items` | tenant | M6: `collection_id`, `ioc_type` (`^[a-z][a-z0-9_]{0,31}$`), `value_norm` 1–2 048, `ioc_key` (64 hex), `source` `job_ioc` / `manual` with `job_id` + `ioc_id` both or neither (and set iff `job_ioc`; `ioc_id` a composite same-org FK since `0013`), `note` ≤ 500, `added_by/at`, `removed_at/by` (both or neither); unique (collection, ioc_key) among items not removed; index (org, ioc_key) to join `ti_results` |
| `case_attack_mappings` | tenant | M6: `investigation_id`, `technique_id` (`^T\d{4}(\.\d{3})?$`), `status` confirmed / suspected / rejected, `rationale` ≤ 2 000, `sources` jsonb array ≤ 32 and ≤ 16 KiB, `created_by`, `updated_by`; unique (investigation, technique) |
| `reports` | tenant | M6: the draft: `investigation_id`, `template` `incident_v1`, `title` 1–200, `tlp`, `profile` internal / external, `draft` jsonb object ≤ 1 MiB, `distribution` ≤ 500, `status` draft / discarded, `revision` ≥ 1, `latest_version` ≥ 0, `created_by`; indexes (org, updated_at), (investigation_id, created_at) |
| `report_versions` | tenant, append-only | M6: unique (report, version): `schema_version` `cyberlab.report.v1`, `tlp`, `profile`, `snapshot_sha256`, `snapshot_bytes`, `object_key`, `object_version_id`, `manifest` jsonb ≤ 4 KiB, `signature` (base64 Ed25519, 88 characters), `kid`, `section_counts` ≤ 4 KiB, `change_note` ≤ 500, `finalized_by/at`; index (org, finalized_at) |
| `report_citations` | tenant, append-only | M6: `version_id`, `cite_no` > 0 (unique per version), `kind`, `ref_table`, `ref_id` (1–64, uuid text or a Zeek `flow_ref`), `job_id`, `fields_sha256`, `source` ai / selection / note / attack, `ai_citation_id` (composite same-org FK to `ai_citations` since `0013`); **index (org, kind, ref_id)** for "which report versions cite this row", next to the M5 `ai_context_refs` and `ai_citations` indexes |
| `report_renders` | tenant | M6: `version_id`, `format` pdf / html / md (DOCX deferred), `status` queued / running / succeeded / failed (failed needs `error_code`), `token_sha256`, `sha256`, `bytes`, `pages`, `object_version_id`, `renderer_version`, `requested_by`, `started_at`, `finished_at`; unique (version, format, renderer version) among non-failed renders; index (org, created_at) |
| `report_render_index` | system lookup | M6: PK `render_id` (composite FK, cascade) → org, `status`, `dispatched_at`, `deadline_at`, `attempts`; the `ai_run_index` RLS pattern; index (status, deadline_at) for the reaper |
| `ti_results` | tenant | append-only provider answers (history = cache): `provider`, `ioc_type`, `value_norm`, `ioc_key` (sha256 of type ‖ 0 ‖ value), `status` ok / not_found / error / auth_failed, `found` (only with ok), `detections`, `score` + `score_scale`, `tags`, `families`, `attack_ids`, `first_seen`, `last_seen`, `summary` (strict per-provider model, ≤ 16 KiB, never the raw body), `permalink` (`https://` only), `error_code`, `latency_ms`, `fetched_at`, `expires_at` (NULL for errors); unique (run_id, provider, ioc_key); index (org, ioc_key, provider, fetched_at DESC) |

All ids are UUIDs (client-generated `uuid4`, server default `gen_random_uuid()`); timestamps are `timestamptz`.
Child rows are pinned to their parent's tenant with composite foreign keys, e.g. `evidence(investigation_id, organization_id) → investigations(id, organization_id)`.

Analysis result tables (migrations 0004/0005):
- They are written only by the trusted ingest worker, in the same transaction that moves the job to `succeeded`; a stream is never partially written.
- The app role has SELECT and INSERT only.
- `flow_ref` is not a foreign key: a referenced flow may have been dropped by the flow cap.

Static results (migration 0007) follow the same rules:
- Every `malware_*` row points at its job with a composite FK `(job_id, organization_id) → analysis_jobs(id, organization_id)`, `ON DELETE CASCADE`.
- Findings and IOCs of static jobs go into the shared `analysis_findings` and `iocs`. The §11 `malware_findings` table is therefore `analysis_findings` of static jobs.
- The static JSON report is still built on demand per job; the persisted, signed case reports are the M6 `reports` tables below.

Threat intel (migrations 0009/0010; details in [THREAT_INTEL.md](THREAT_INTEL.md)):
- `iocs` is unchanged: results join on `ioc_key`, computed in Python.
- Rate-limited, quota and deadline outcomes are item states, never `ti_results` rows; the history shows only what a provider said.
- A cache hit is the newest unexpired `ok` / `not_found` row of the same org (DB clock).
- `ti_results` is never purged yet (no retention policy).

AI analyst (migration 0011; details in [AI_ANALYST.md](AI_ANALYST.md)):
- The API writes a run, its index row, its base input, its refs and the audit row in one transaction (incident children with them); the analyst-worker writes the output, the citations and the run's usage / cost / metrics in one transaction.
- `ai_runs.context_stats` never carries field names, titles or filenames (RT4); `ai_run_inputs.context` is exactly what was sent.
- Nothing in `ai_*` is ever purged yet (no retention policy, RT28).

Reports and case management (migration 0012; details in [REPORTS.md](REPORTS.md)):
- Finalize writes a version, its citations, the PDF render, its index row and the audit row in one short transaction, after the snapshot object was stored and locked outside any transaction; a version whose write fails leaves a logged orphan object, never a row without an object.
- The snapshot bytes live in MinIO (`reports` bucket, exact `object_version_id`); the row keeps their sha256, size, the signed manifest and the signature, so every read is verified.
- `ti_run_items.reason` gains `policy_blocked` (the share-policy outcome of the enrich-worker); `ai_runs.error_code` has no CHECK, so its `policy_blocked` needed no change.
- Notes, collections, mappings, reports and versions are never purged (no retention policy); versions and note versions are append-only, and a deleted note keeps its versions.

## Tenant isolation (RLS)

Every tenant table has `ENABLE` **and** `FORCE ROW LEVEL SECURITY` (`test_rls_coverage.py` fails if a table with `organization_id` lacks either).

The request context lives in two transaction-local settings, read through helper functions:

```sql
app_org_id()  = NULLIF(current_setting('app.org_id',  true), '')::uuid
app_user_id() = NULLIF(current_setting('app.user_id', true), '')::uuid
```

| Table | Command | Policy |
|---|---|---|
| investigations, evidence, evidence_hashes, evidence_custody_events, audit_logs, analysis_jobs, pcap result tables, `malware_*`, `ti_*` except `ti_run_index`, `ai_*` except `ai_run_index`, the M6 tables except `report_render_index` | ALL | `organization_id = app_org_id()` (USING + CHECK) |
| analysis_job_index, ti_run_index, ai_run_index, report_render_index | ALL | `app_org_id() IS NULL OR organization_id = app_org_id()`: trusted workers' system sessions see every row, tenant sessions only their org's |
| organization_members | SELECT | `organization_id = app_org_id() OR user_id = app_user_id()` |
| organization_members | INSERT / UPDATE / DELETE | `organization_id = app_org_id()` |
| organizations | SELECT | `id = app_org_id() OR id IN (memberships of app_user_id())` |
| organizations | INSERT / UPDATE (incl. `SELECT … FOR UPDATE`) | `id = app_org_id()` |

Reads and writes are split per command on purpose: a single ALL-command policy would let the "caller's own row" clause authorize **cross-tenant** UPDATE/DELETE of the caller's membership in another org (regression tests in `test_rls.py`).

The helper functions are schema-qualified (`pg_catalog.current_setting`, `pg_catalog.uuid`) and trigger functions pin `search_path = pg_catalog`; `TEMPORARY` on both databases is revoked from PUBLIC so temp objects cannot shadow names.

**RLS trusts `app.org_id`.** It does not check membership itself: any code that opens `tenant_session(org_id, …)` for an org taken from the request sees that org's rows. Only `require()` / `org_session()` (`app/core/rbac.py`) may open a tenant session for a request-supplied org, after verifying membership inside that same session; `tests/unit/test_tenant_session_guard.py` fails if `tenant_session(<org>…)` appears anywhere else besides the auth and org-creation services (which use org ids they just created).

With no context set, tenant tables return zero rows. `INSERT … RETURNING` also evaluates `USING`, so every tenant insert runs with a matching `app.org_id`.

### Setting the context

`app/core/tenancy.py::tenant_session(org_id, user_id)` opens one transaction and runs `set_config('app.user_id', …, true), set_config('app.org_id', …, true)` (`SET LOCAL` cannot take bind parameters). The values reset at commit/rollback, so they never leak to the next user of a pooled connection.

Rules:
- One `tenant_session` = one transaction. A flow needing several transactions opens a new one each time.
- Commit (leave the block) before sending the response; never rely on dependency teardown.
- Non-tenant tables (`users`, `refresh_tokens`, `auth_events`) are used via `tenant_session(None, None)` or `(None, user_id)`.

## Grants

| Table | `cyberlab_app` |
|---|---|
| users | SELECT, INSERT, UPDATE |
| refresh_tokens | SELECT, INSERT, UPDATE, DELETE |
| organizations | SELECT; INSERT on `id, name, slug, next_case_number, created_by, created_at, updated_at`; UPDATE on `name, next_case_number, updated_at` (0008: the app cannot write `storage_quota_bytes`) |
| investigations, evidence | SELECT, INSERT, UPDATE |
| organization_members | SELECT, INSERT, UPDATE, DELETE |
| auth_events, audit_logs, evidence_hashes, evidence_custody_events | SELECT, INSERT |
| pcap result tables, `malware_*` | SELECT, INSERT |
| `ti_provider_configs` | SELECT, INSERT; UPDATE on `enabled, base_url, key_kid, key_version, key_epk, key_nonce, key_ct, key_last4, verify_status, verified_at, last_error_code, limits, terms_ack_at, terms_ack_by, updated_at`; **no DELETE** (0010) |
| `ti_org_settings` | SELECT, INSERT; UPDATE on `excluded_suffixes, updated_by, updated_at` |
| `ti_enrichment_runs` | SELECT, INSERT; UPDATE on `status, summary, deadline_at, started_at, finished_at` |
| `ti_run_items` | SELECT, INSERT; UPDATE on `state, result_id, reason` |
| `ti_run_index` | SELECT, INSERT; UPDATE on `status, resume_at, deadline_at, dispatched_at, lease_until, lease_owner` |
| `ti_results` | SELECT, INSERT |
| `ai_provider_configs` | SELECT, INSERT; UPDATE on `enabled, model, key_kid, key_version, key_epk, key_nonce, key_ct, key_last4, verify_status, verified_at, last_error_code, limits, terms_ack_at, terms_ack_by, paid_tier_ack_at, paid_tier_ack_by, updated_at` (the sealed columns also for the analyst's lazy re-seal); **no DELETE** |
| `ai_org_settings` | SELECT, INSERT; UPDATE on `ai_enabled, privacy_ack_at, privacy_ack_by, default_provider, pseudonymize_internal, internal_cidrs, internal_suffixes, include_strings, include_ti, include_case_text, daily_token_budget, run_token_cap, incident_token_cap, updated_by, updated_at` |
| `ai_runs` | SELECT, INSERT; UPDATE on `status, error_code, served_model, usage, cost_micros, price_version, metrics, started_at, finished_at` |
| `ai_run_index` | SELECT, INSERT; UPDATE on `status, resume_at, deadline_at, dispatched_at, lease_until, lease_owner, attempts, calls` |
| `ai_run_inputs`, `ai_context_refs`, `ai_outputs`, `ai_citations` | SELECT, INSERT |
| `investigation_status_events`, `analyst_note_versions`, `report_versions`, `report_citations` | SELECT, INSERT (append-only) |
| `evidence_share_policies` | SELECT, INSERT; UPDATE on `ai_excluded, ti_excluded, updated_by, updated_at` |
| `analyst_notes` | SELECT, INSERT; UPDATE on `current_version, pinned, include_in_reports, deleted_at, deleted_by, updated_at` |
| `ioc_collections` | SELECT, INSERT; UPDATE on `name, description, archived_at, updated_at` |
| `ioc_collection_items` | SELECT, INSERT; UPDATE on `removed_at, removed_by, note` |
| `case_attack_mappings` | SELECT, INSERT; UPDATE on `status, rationale, sources, updated_by, updated_at` |
| `reports` | SELECT, INSERT; UPDATE on `title, tlp, profile, draft, distribution, status, revision, latest_version, updated_at` |
| `report_renders` | SELECT, INSERT; UPDATE on `status, error_code, sha256, bytes, pages, object_version_id, renderer_version, started_at, finished_at` |
| `report_render_index` | SELECT, INSERT; UPDATE on `status, dispatched_at, deadline_at, attempts` |

No M6 table has a DELETE grant. `investigations` keeps its table-wide UPDATE (M1), which covers the new `tlp`, `ai_excluded` and `ti_excluded` columns; the rules for them (downgrade, turning a flag off) are enforced by the API.

The enrich and analyst workers use the same `cyberlab_app` role as the API (no dedicated role yet; accepted residual, see THREAT_MODEL). The app role can never UPDATE `organization_id`, `provider`, `task` or `created_at` of an `ai_*` row.

## Triggers

- `forbid_mutation()` — `BEFORE UPDATE OR DELETE` on the four append-only tables, on `ti_results` (M4), on `ai_run_inputs`, `ai_context_refs`, `ai_outputs`, `ai_citations` (M5) and on `investigation_status_events`, `analyst_note_versions`, `report_versions`, `report_citations` (M6); it fires for the owner too.
- `analyst_note_guard()` (M6) — `BEFORE UPDATE` on `analyst_notes`: `current_version` never decreases, `deleted_at/by` are set once, identity columns (id, org, case, creator, `created_at`) are immutable.
- `ioc_collection_item_guard()` (M6) — `BEFORE UPDATE` on `ioc_collection_items`: the removal is set once; type, value, key, source, job, IOC, adder and `added_at` are immutable.
- `report_guard()` (M6) — `BEFORE UPDATE` on `reports`: a discarded report is final; `revision` increases by exactly one per update; `latest_version` never decreases; a report with versions cannot be discarded; identity columns (id, org, case, template, creator, `created_at`) are immutable.
- `report_render_transition()` (M6) — `BEFORE UPDATE` on `report_renders`: only `queued → running / failed` and `running → succeeded / failed`; final states never change; id, org, version, format, `token_sha256`, requester and `created_at` are immutable.
- `ti_run_transition()` — `BEFORE UPDATE` on `ti_enrichment_runs`: only `queued → running / partial / failed`, `running → waiting / completed / partial / failed`, `waiting → running / partial / failed`; final states never change; identity columns (`id`, org, `scope`, `job_id`, `requested_by`, `providers`, `created_at`) are immutable.
- `ti_key_version_guard()` — `BEFORE UPDATE` on `ti_provider_configs`: `key_version` never decreases; new sealed columns need a higher `key_version`, except a re-seal of the same key (same version and last4) under another kid. Clearing a key keeps the version, so an old ciphertext can never be put back (RT18).
- `ai_run_transition()` — `BEFORE UPDATE` on `ai_runs`: only `queued → running / failed`, `running → waiting / completed / partial / failed / refused`, `waiting → running / failed`; final states (`completed`, `partial`, `failed`, `refused`) never change; identity columns (id, org, task, scope, job, investigation, target, parent, provider, model, prompt and schema versions, `context_sha256`, `context_stats`, requester, `supersedes_run_id`, `deadline_at`, `created_at`) are immutable, even for the owner.
- `ai_key_version_guard()` — `BEFORE UPDATE` on `ai_provider_configs`: the same rules as `ti_key_version_guard()` (RT18).
- `evidence_immutable()` — `BEFORE UPDATE` on `evidence`; every column except `status` and `description` is immutable (incl. `id`, detected type, storage location/version, uploader, timestamps).

**Trust boundary:** grants + triggers stop the app role (and accidental owner `UPDATE`/`DELETE`). The table owner can still `TRUNCATE` or drop triggers; it is a trusted admin identity and its credentials never reach the API. Test cleanup relies on owner `TRUNCATE` against `cyberlab_test` only (the harness refuses any database not ending in `_test`).

## Migrations

```bash
docker compose run --rm migrate uv run alembic revision --autogenerate -m "..."   # then hand-review
docker compose run --rm migrate uv run alembic upgrade head
docker compose run --rm migrate uv run alembic check                                # models vs. migrations
```

M3 migrations:

| Revision | Changes |
|---|---|
| `0006` static analyzer | `ALTER TYPE analyzer ADD VALUE 'static'` inside `autocommit_block()`: `env.py` runs all pending migrations in one transaction, and Postgres cannot use an enum value added in a transaction that has not committed. Later SQL compares `analyzer::text`, never the `'static'` literal as an enum. Adds `analysis_jobs.profile` with checks `ck_analysis_jobs_profile_valid` (`full` / `av`) and `ck_analysis_jobs_profile_iff_static`, adds `profile` to the immutable identity columns of the job trigger, and adds `analysis_job_index.analyzer` (backfilled `pcap`) with index `(analyzer, status)`. Downgrade cannot remove the enum value. |
| `0007` static results | the eight `malware_*` tables, with RLS ENABLE + FORCE, `tenant_isolation` policy and SELECT/INSERT grants, as for the pcap tables |
| `0008` storage quota | `organizations.storage_quota_bytes` (nullable, check ≥ 0); replaces the app's table-wide INSERT/UPDATE on `organizations` with column grants, so the app cannot raise its own quota |

M4 migrations:

| Revision | Changes |
|---|---|
| `0009` threat intel | the six `ti_*` tables with checks (provider list, statuses, `permalink LIKE 'https://%'`, summary ≤ 16 KiB, 64-char `ioc_key`, `found` only with `ok`, sealed-column shapes), composite tenant FKs, RLS ENABLE + FORCE with `tenant_isolation` (and `run_index_scope` on `ti_run_index`), per-column UPDATE grants, the run-transition, key-version and append-only triggers |
| `0010` TI hardening | revokes the app's DELETE on `ti_provider_configs` (deleting a row reset the `key_version` floor); `ti_run_index.run_id` now references `(id, organization_id)` of the run, so an index row cannot name another org |

M5 migration:

| Revision | Changes |
|---|---|
| `0011` AI analyst | the eight `ai_*` tables with checks (provider and task lists, statuses, scope / target / parent shapes, model pattern, label grammar, hash shapes, jsonb size caps, sealed-column shapes, enable-needs-acknowledgement), composite tenant FKs (incl. the run self-references), RLS ENABLE + FORCE with `tenant_isolation` (and `run_index_scope` on `ai_run_index`), table grants without DELETE plus per-column UPDATE grants, the run-transition, key-version and append-only triggers |

M6 migration:

| Revision | Changes |
|---|---|
| `0012` reports and case management | `investigations` gains `tlp` (check, default `amber`, backfilled), `ai_excluded`, `ti_excluded`; `ti_run_items.reason` accepts `policy_blocked`; the eleven tenant tables `investigation_status_events`, `evidence_share_policies`, `analyst_notes`, `analyst_note_versions`, `ioc_collections`, `ioc_collection_items`, `case_attack_mappings`, `reports`, `report_versions`, `report_citations`, `report_renders` plus the system lookup `report_render_index`, with named checks (length caps with `char_length` / `octet_length`, jsonb shapes, hash and signature shapes), composite tenant FKs, RLS ENABLE + FORCE (`tenant_isolation`; the run-index pattern on `report_render_index`), SELECT / INSERT plus per-column UPDATE grants and no DELETE, the four guard triggers and `forbid_mutation()` on the four append-only tables. Indexes include `report_citations (organization_id, kind, ref_id)` and `ioc_collection_items (organization_id, ioc_key)`. `0012` stays frozen: later M6 schema fixes go into `0013` |
| `0013` same-org FKs (M6 review L4) | `iocs` and `ai_citations` gain the unique constraints `uq_iocs_id_organization_id` / `uq_ai_citations_id_organization_id` (the `id` is the primary key, so they always hold), and the two plain FKs of 0012 become composite `(column, organization_id)` FKs: `ioc_collection_items.ioc_id → iocs` and `report_citations.ai_citation_id → ai_citations`. MATCH SIMPLE leaves NULL references unchecked; creating the FKs validates existing rows, so a cross-org row (only writable past RLS) fails the upgrade |

asyncpg executes one statement per call, so raw SQL in migrations is issued statement by statement. `citext` is created by migration `0001` (trusted extension, created by the database owner); `gen_random_uuid()` is built in.

ORM notes: `Timestamps` models use `eager_defaults` so `updated_at` is fetched with `RETURNING` and stays loaded after the `tenant_session` block commits. `refresh_tokens.replaced_by` is a `DEFERRABLE INITIALLY DEFERRED` self-reference so rotation can mark the old token before inserting its successor.
