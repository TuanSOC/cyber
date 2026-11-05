# API (v1)

Base path `/api/v1`, served through the gateway. Interactive docs (dev only): `/api/docs`. Machine-readable contract: `/api/openapi.json` and `packages/contracts/openapi.json`.

## Conventions

**Authentication.** Cookie-based. Login/register/refresh set:

| Cookie | Scope | Notes |
|---|---|---|
| `cl_access` | `Path=/api`, HttpOnly, SameSite=Strict, 15 min | JWT (HS256) bound to its refresh family |
| `cl_refresh` | `Path=/api/v1/auth`, HttpOnly, SameSite=Strict, 7 days | opaque, rotated on every refresh; sessions last at most 30 days |
| `cl_csrf` | `Path=/`, readable by JS | double-submit token |

**CSRF.** Every `POST/PUT/PATCH/DELETE` under `/api/v1` (except login and register) must send `X-CSRF-Token` equal to the `cl_csrf` cookie, read at request time (it rotates on refresh).

**Errors.** Always `{"error": {"code": "...", "message": "...", "details"?: [...]}}`. Validation errors (`422`, `validation_error`) list `loc/msg/type` and never echo submitted values.

| Status | Codes |
|---|---|
| 400 | `bad_request`, `client_disconnected` (upload body ended early) |
| 401 | `unauthorized`, `invalid_token`, `invalid_credentials`, `invalid_refresh`, `stale_refresh` (another tab rotated: retry once), `refresh_reused` (session revoked) |
| 403 | `forbidden`, `csrf_failed`, `cannot_modify_self` |
| 404 | `not_found` (also for orgs you are not a member of), `user_not_found`, `results_not_available` (static job without stored results) |
| 409 | `conflict`, `registration_failed`, `already_member`, `last_owner`, `invalid_transition`, `investigation_archived`, `evidence_archived`, `evidence_content_missing`, `org_limit_reached` (user already owns `MAX_OWNED_ORGS_PER_USER` orgs); M7: `retention_run_active`, `legal_hold_released` |
| 405 | `method_not_allowed` |
| 410 | M7: `evidence_purged` (download, verify and new analyses of evidence whose bytes retention purged; `purged_at` and `run_id` in the body; hashes, custody and metadata stay readable) |
| 413 / 415 | `payload_too_large`, `storage_quota_exceeded` (upload would exceed the org quota), `unsupported_media_type` |
| 422 | `validation_error`; M7: `policy_floor` (`fields` lists the values below their floor), `retention_acknowledgement_required`, `hold_scope_invalid`, `search_query_invalid` |
| 429 | `rate_limited` (+ `Retry-After`): the route limits, and since M7 the global per-user limit (`RATE_LIMIT_USER_PER_MIN`, 600 / min on every authenticated request except `GET /auth/me`) |
| 500 | `internal_error` (details only in server logs) |
| 503 | `service_unavailable` (Redis down: the API fails closed) |

**Pagination.** Lists return `{"items": [...], "total": n}` with `limit` (1–100, default 25) and `offset` (≤ 10 000).

**Inputs.** Names reject control and invisible formatting characters; free text rejects NUL; unknown fields on investigation create/update are rejected. Email addresses on special-use domains (`.local`, `.test`) are rejected by the validator.

## Endpoints

| Method | Path | Permission |
|---|---|---|
| POST | `/auth/register` · `/auth/login` | public (rate limited) |
| POST | `/auth/refresh` · `/auth/logout` | session cookies |
| GET | `/auth/me` | signed in |
| GET | `/health` | public |
| GET / POST | `/orgs` | signed in (create: 10/hour; a user may own at most `MAX_OWNED_ORGS_PER_USER`, default 5) |
| GET / PATCH | `/orgs/{org_id}` | `org.read` / `org.update` |
| GET | `/orgs/{org_id}/storage` → `used_bytes`, `quota_bytes`, `evidence_count` | `org.read` |
| GET / POST | `/orgs/{org_id}/members` | `members.read` / `members.manage` (add: 30/10 min) |
| PATCH / DELETE | `/orgs/{org_id}/members/{member_id}` | `members.manage` (only owners touch the owner role) |
| GET | `/orgs/{org_id}/audit-logs?action&actor_id&from&to` | `audit.read` |
| GET / POST | `/orgs/{org_id}/investigations?q&status&severity&sort` | `investigation.read` / `investigation.write` |
| GET / PATCH | `/orgs/{org_id}/investigations/{investigation_id}` | `investigation.read` / `investigation.write` |
| GET | `/orgs/{org_id}/investigations/{investigation_id}/evidence` | `evidence.read` |
| GET | `/orgs/{org_id}/investigations/{investigation_id}/timeline?cursor&limit&kinds` (merged case timeline, M5; M6 adds the `note` and `status` kinds, without `evidence_id`) | `evidence.read` |
| POST | `/orgs/{org_id}/investigations/{investigation_id}/evidence?filename&description` | `evidence.write` |
| GET | `/orgs/{org_id}/evidence/{evidence_id}` · `/download` · `/custody` | `evidence.read` |
| POST | `/orgs/{org_id}/evidence/{evidence_id}/verify` · `/archive` | `evidence.write` |
| POST | `/orgs/{org_id}/evidence/{evidence_id}/analyses` `{"analyzer":"pcap"}` or `{"analyzer":"static","profile":"full"\|"av"}` | `evidence.write` (20 manual runs / 10 min) |
| GET | `/orgs/{org_id}/evidence/{evidence_id}/analyses` | `evidence.read` |
| GET | `/orgs/{org_id}/analyses?status&analyzer&profile&investigation_id&latest_per_evidence` · `/orgs/{org_id}/analyses/{job_id}` (incl. `profile`, `summary`) | `evidence.read` |
| GET | `/orgs/{org_id}/analyses/{job_id}/findings?severity&type` | `evidence.read` |
| GET | `/orgs/{org_id}/analyses/{job_id}/flows?ip&port&proto&sort=bytes\|ts` | `evidence.read` |
| GET | `/orgs/{org_id}/analyses/{job_id}/records?kind=dns\|http\|tls&q` | `evidence.read` |
| GET | `/orgs/{org_id}/analyses/{job_id}/alerts?severity` · `/iocs?type&q` · `/timeline` | `evidence.read` |
| GET | static jobs: `/orgs/{org_id}/analyses/{job_id}/sample` · `/sections` · `/imports?library&q` · `/exports?q` · `/resources` | `evidence.read` |
| GET | static jobs: `/orgs/{org_id}/analyses/{job_id}/strings?encoding&q` · `/signatures?engine=clamav\|yara` · `/capabilities?namespace&attack` | `evidence.read` |
| GET | `/orgs/{org_id}/analyses/{job_id}/report` (static jobs) | `evidence.read` (audited) |
| GET | `?ref=<row id>` on `/findings`, `/records`, `/alerts`, `/iocs`, `/timeline`, `/imports`, `/strings`, `/signatures`, `/capabilities`; `?ref=<flow_ref>` on `/flows` (M5: deep links to one cited row) | `evidence.read` |
| GET | `/orgs/{org_id}/analyses/{job_id}/iocs?include=enrichment` (latest answer per provider on each IOC, M4) | `evidence.read` |
| GET | `/orgs/{org_id}/integrations` (provider catalog + this org's status; never a key) · `/orgs/{org_id}/ti/settings` | `org.read` |
| PUT | `/orgs/{org_id}/integrations/{provider}` `{api_key?, enabled?, acknowledge_terms?, base_url?, limits?}` · `/orgs/{org_id}/ti/settings` `{excluded_suffixes}` | `integrations.manage` |
| DELETE | `/orgs/{org_id}/integrations/{provider}/key` | `integrations.manage` |
| POST | `/orgs/{org_id}/integrations/{provider}/verify` → 202 (10 per provider / 10 min) | `integrations.manage` |
| POST | `/orgs/{org_id}/analyses/{job_id}/enrichments` `{providers?}` · `/orgs/{org_id}/ti/lookups` `{values: [{value, type?}], providers?}` → 202 new run, 200 deduplicated / nothing eligible | `evidence.write` (30 / 10 min per user) |
| GET | `/orgs/{org_id}/ti/runs?job_id&status` · `/orgs/{org_id}/ti/runs/{run_id}?provider&state` (items with their results, `from_cache`) | `evidence.read` |
| GET | `/orgs/{org_id}/ti/results?value&type&provider` (history of one indicator, newest first) · `/orgs/{org_id}/ti/results/{result_id}` | `evidence.read` |
| GET | `/attack/techniques?ids=T1055,T1059.001` (labels + MITRE notice, ≤ 100 ids) | signed in |
| GET | `/orgs/{org_id}/ai/providers` (AI catalog + this org's status; never a key) · `/orgs/{org_id}/ai/settings` · `/orgs/{org_id}/ai/usage` | `org.read` |
| PUT | `/orgs/{org_id}/ai/providers/{provider}` `{api_key?, enabled?, acknowledge_terms?, acknowledge_paid_tier?, model?, limits?}` · `/orgs/{org_id}/ai/settings` (partial) | `integrations.manage` |
| DELETE | `/orgs/{org_id}/ai/providers/{provider}/key` → 204 | `integrations.manage` |
| POST | `/orgs/{org_id}/ai/providers/{provider}/verify` → 202 (10 per provider / 10 min) | `integrations.manage` |
| POST | `/orgs/{org_id}/ai/runs` `{task, job_id \| investigation_id, target_id?, provider?, model?, regenerate?}` → 202 new run, 200 deduplicated | `evidence.write` (10 / 10 min per user) |
| POST | `/orgs/{org_id}/ai/context-preview` (same body; nothing persisted) | `evidence.write` (30 / 10 min per user) |
| GET | `/orgs/{org_id}/ai/runs?job_id&investigation_id&task&status&target_id` · `/orgs/{org_id}/ai/runs/{run_id}?pseudonyms=keep` · `/orgs/{org_id}/ai/runs/{run_id}/context` | `evidence.read` |
| GET | `/orgs/{org_id}/ai/runs/{run_id}?pseudonyms=reverse` (original internal values; the default for these roles) | `evidence.write` (viewers: 403; their default is `keep`) |
| GET | `/orgs/{org_id}/ai/runs/{run_id}/context?reveal=true` (adds the pseudonym map; audited `ai.context_revealed`) | `evidence.write` (viewers: 403) |
| GET | `/report-signing-keys` (public Ed25519 keys `{keys: [{kid, alg, public_key, active}]}`, M6) | **public** (60 / min per IP, `Cache-Control: public, max-age=300`) |
| PATCH | `/orgs/{org_id}/investigations/{investigation_id}` with `tlp`, `ai_excluded`, `ti_excluded`, `status_reason`, `acknowledge_tlp_downgrade` (M6) | `investigation.write`; lowering the TLP also `org.update`; turning a flag off also `integrations.manage` |
| GET | `/orgs/{org_id}/investigations/{investigation_id}/status-events?cursor&limit` (newest first, M6) | `investigation.read` |
| GET | `/orgs/{org_id}/investigations/{investigation_id}/timeline/export?format=csv\|json&kinds&from&to` | `evidence.read` (audited) |
| GET / PUT | `/orgs/{org_id}/evidence/{evidence_id}/share-policy` `{ai_excluded, ti_excluded}` | `evidence.read` / `evidence.write`; turning a flag off also `integrations.manage` |
| GET / POST | `/orgs/{org_id}/investigations/{investigation_id}/notes?include_deleted&pinned&cursor&limit` | `investigation.read` / `investigation.write` |
| GET / PUT / DELETE | `/orgs/{org_id}/notes/{note_id}` (detail with every version; `PUT {expected_version, body?, refs?, pinned?, include_in_reports?}`; delete → 204) | `investigation.read` / `investigation.write` (edit and delete: the author or `org.update`) |
| GET / POST | `/orgs/{org_id}/investigations/{investigation_id}/ioc-collections` | `investigation.read` / `investigation.write` |
| GET / PATCH | `/orgs/{org_id}/ioc-collections/{collection_id}` (name, description, archived) | `investigation.read` / `investigation.write` |
| GET / POST | `/orgs/{org_id}/ioc-collections/{collection_id}/items?type&q&include_removed&cursor` (add ≤ 500 per call) | `investigation.read` / `investigation.write` |
| DELETE | `/orgs/{org_id}/ioc-collections/{collection_id}/items/{item_id}` (soft remove) → 204 | `investigation.write` |
| GET | `/orgs/{org_id}/ioc-collections/{collection_id}/export?format=csv\|json\|stix21&defang=true` | `evidence.read`; `defang=false` needs `evidence.write` (audited) |
| GET | `/orgs/{org_id}/investigations/{investigation_id}/iocs?type&q&cursor&limit` (case-wide, deduplicated by `ioc_key`) | `evidence.read` |
| GET / POST | `/orgs/{org_id}/investigations/{investigation_id}/attack` (mappings + tactic matrix / create) · `GET …/attack/suggestions` | `investigation.read` / `investigation.write` |
| PATCH | `/orgs/{org_id}/attack-mappings/{mapping_id}` (status, rationale, sources) | `investigation.write` |
| GET | `/orgs/{org_id}/reports?investigation_id&status&cursor` · `/orgs/{org_id}/investigations/{investigation_id}/reports` | `investigation.read` |
| POST | `/orgs/{org_id}/investigations/{investigation_id}/reports` `{title, tlp?, profile?, acknowledge_tlp_downgrade?}` → 201 | `investigation.write` |
| GET / PATCH | `/orgs/{org_id}/reports/{report_id}` (PATCH `{revision, title?, tlp?, profile?, distribution?, draft?, acknowledge_tlp_downgrade?}`) | `investigation.read` / `investigation.write` |
| POST | `/orgs/{org_id}/reports/{report_id}/discard` · `/preview` (30 / 10 min) · `/finalize` `{revision, change_note?, acknowledge_tlp_downgrade?, acknowledge_external_review?}` → 201 (10 / 10 min) | `investigation.write` |
| GET | `/orgs/{org_id}/reports/{report_id}/versions` · `/versions/{version}` (manifest, `signature_valid`, `snapshot_ok`, counts, renders) · `/versions/{version}/signature` (`.sig.json` attachment) | `investigation.read` |
| GET | `/orgs/{org_id}/reports/{report_id}/versions/{version}/content` (the verified snapshot JSON for the viewer, `no-store`, not audited per view) | `evidence.read` |
| GET | `/orgs/{org_id}/reports/{report_id}/versions/{version}/snapshot` (canonical JSON attachment, audited `report.snapshot_downloaded`) | `evidence.read` |
| POST | `/orgs/{org_id}/reports/{report_id}/versions/{version}/renders` `{format: pdf\|html\|md}` → 202 queued, 200 deduplicated (20 / 10 min) | `investigation.write` |
| GET | `/orgs/{org_id}/reports/{report_id}/versions/{version}/renders` · `/orgs/{org_id}/report-renders/{render_id}` | `investigation.read` |
| GET | `/orgs/{org_id}/report-renders/{render_id}/download` (streamed, re-hashed, audited `report.downloaded`) | `evidence.read` |
| GET | `/orgs/{org_id}/cited-by?kind&ref_id&job_id` (AI outputs and report versions citing one row) | `evidence.read` |
| GET / PUT | `/orgs/{org_id}/retention/policy` (M7; PUT replaces `{ti_results_days, ai_runs_days, closed_case_days, enforce, acknowledge_destruction?}`) | `org.read` / `org.update` |
| POST | `/orgs/{org_id}/retention/preview` `{ti_results_days?, ai_runs_days?, closed_case_days?}` (read-only candidates; recorded as a manual dry run) | `org.update` |
| GET | `/orgs/{org_id}/retention/runs` · `/orgs/{org_id}/retention/runs/{retention_run_id}` (counts, sample, items) | `audit.read` |
| POST | `/orgs/{org_id}/retention/runs` `{dry_run?}` → 202 (mode from the DB policy) | `org.update` |
| GET | `/orgs/{org_id}/legal-holds?investigation_id&active_only` | `investigation.read` |
| POST | `/orgs/{org_id}/legal-holds` `{scope: org\|investigation, investigation_id?, reason}` → 201 · `/orgs/{org_id}/legal-holds/{hold_id}/release` `{reason}` | `org.update` |
| GET | `/orgs/{org_id}/analyses/{job_id}/correlations` ("also seen in") · `/orgs/{org_id}/correlations?kind&value` (lookup) · `/orgs/{org_id}/investigations/{investigation_id}/related` | `investigation.read` |
| POST | `/orgs/{org_id}/search` `{q, types?, cursor?}` (30 / min per user; never logged) | `investigation.read` |
| GET | `/orgs/{org_id}/ops/metrics?window=1h\|24h\|7d` (the org's failure rate, latency, parse success) | `audit.read` |
| GET | `/internal/metrics` (**outside `/api/v1`, never routed by the gateway**; Prometheus text) | bearer `METRICS_TOKEN` (operators) |

Roles: **viewer** = all `*.read`; **analyst** = viewer + `investigation.write`, `evidence.write`; **admin** = analyst + `org.update`, `members.manage`, `audit.read`, `integrations.manage` (M4; also AI providers and settings, M5); **owner** = admin + owner-role management. So viewers read AI runs (pseudonyms kept), pseudonymized contexts and settings, analysts request runs, see outputs with original names and reveal pseudonym maps, and only admins and owners store AI keys or turn AI on. In M6, viewers read notes, collections, mappings and report versions and download reports and exports (defanged only); analysts write notes, collections, mappings and report drafts, finalize and request renders, and turn share-policy exclusions on; only admins and owners lower a TLP below the case or turn an exclusion off. RBAC stays org-wide: there is no per-case access control.

## Evidence upload

```bash
curl -X POST "https://host/api/v1/orgs/$ORG/investigations/$CASE/evidence?filename=capture.pcap" \
  -H "Content-Type: application/octet-stream" -H "X-CSRF-Token: $CSRF" \
  -b cookies.txt --data-binary @capture.pcap
```

The body is the raw file (no multipart). Max 2 GiB (`MAX_EVIDENCE_BYTES`); at most 2 concurrent uploads per user. Each org has a storage quota (`DEFAULT_STORAGE_QUOTA_BYTES`, 20 GiB, unless an operator set a per-org value); active and archived evidence both count. An upload that would exceed it gets `413 storage_quota_exceeded`: before the body is read when `Content-Length` is declared, otherwise after spooling (the stored version is then discarded). Response includes `hashes.md5/sha1/sha256`. Downloads are `application/octet-stream` attachments with `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox`, `Cache-Control: no-store`.

M7 additions to `EvidenceOut`: `declared_type` (the extension family) and `type_mismatch` (declared vs detected by magic; write-once, NULL on older rows). A mismatch is audited `evidence.type_mismatch` and **never rejects the upload**. `purged_at` is set once retention purged the bytes (then download, verify and new analyses answer `410 evidence_purged`), and `legal_hold` tells whether a hold covers the evidence. `GET /evidence/{id}` and `GET /evidence/{id}/custody` are audited (`evidence.viewed`, `evidence.custody_viewed`), at most once per user, evidence and action every 15 minutes. `InvestigationOut.legal_hold` is the case-level flag.

`investigations.allowed_transitions` lists the valid next statuses for the current one.

## Analyses

- **Automatic runs:** queued as a best effort after the upload commits (the upload never fails because of it; a refused auto-run is audited as `analysis.skipped`):
  - pcap/pcapng magic → `pcap`;
  - PE or non-core ELF → `static`, profile `full`;
  - any other non-empty file ≤ `STATIC_MAX_BYTES` → `static`, profile `av` (ClamAV + YARA).
- **Manual runs:** `analyzer` defaults to `pcap`. `profile` is only accepted for `static` and defaults to `full` there.
- **Job fields:** `status` is `queued`, `running`, `succeeded` or `failed`; `error_code` is set on failure; `profile` is set for static jobs only.
- **Results:** they appear only after the trusted ingest validated the whole result stream; see [PCAP_ANALYSIS.md](PCAP_ANALYSIS.md) and [MALWARE_ANALYSIS.md](MALWARE_ANALYSIS.md). Findings and IOCs of both analyzers are served by the shared `/findings` and `/iocs` routes.

Refusals when requesting a run:

| Status | Code |
|---|---|
| 409 | `analysis_active` (a run of this evidence by the same analyzer is queued/running), `evidence_archived`, `investigation_archived` |
| 413 | `capture_too_large` (> `PCAP_MAX_BYTES`), `sample_too_large` (> `STATIC_MAX_BYTES`, 64 MiB) |
| 429 | `analysis_queue_full` (5 active per org / 50 overall, counted per analyzer), `rate_limited` |

Static result routes answer `404` for jobs of another analyzer, and `404 results_not_available` from `/sample` when the job has no stored results.

**Report.** `GET .../analyses/{job_id}/report` returns `cyberlab.report.static.v1` JSON as an attachment (RFC 5987 filename, `nosniff`, `Content-Security-Policy: sandbox`, `Cache-Control: no-store`). Each download writes an `analysis.report_downloaded` audit row; the evidence custody chain is unchanged. It answers `409 report_unavailable` for non-static jobs and `409 analysis_not_succeeded` for jobs that have not succeeded. Contents: [MALWARE_ANALYSIS.md](MALWARE_ANALYSIS.md#report).

Job `error_code` values:
- **Evidence and input:**
  - `integrity_mismatch`: bytes differ from the evidence record.
  - `unsupported_capture_format`: not raw pcap/pcapng, incl. compressed.
  - `unparseable_capture`, `capture_too_large`, `url_expired`, `evidence_unavailable`.
- **Engines:** `zeek_failed`, `zeek_timeout`, `tool_timeout`, `timed_out`, `analyzer_error`.
- **Result transfer:** `result_too_large`, `result_upload_failed`.
- **Trusted side:**
  - `invalid_result`: the stream failed validation.
  - `ingest_error`.
  - `enqueue_failed`.
  - `never_started`: the queue TTL expired.
- **Static jobs** use the same input, transfer and trusted-side codes (`sample_too_large` instead of `capture_too_large`). A capped, skipped or incomplete engine does not fail the job: it is listed in the result's `engine_errors` (e.g. `av_not_fully_scanned`, `av_unavailable`, `capa_skipped`).

Result lists are paged like every list. Text filters are case-insensitive substring matches with `%`/`_` escaped.

## Threat intelligence (M4)

Details: [THREAT_INTEL.md](THREAT_INTEL.md).

- **Keys are write-only.** `api_key` is accepted on `PUT` only (8–256 printable ASCII characters) and never returned, logged or audited. The read model has `configured`, `key_last4`, `enabled`, `verify_status` (`unverified` / `valid` / `invalid` / `error`), `verified_at`, `last_error_code`, `terms_ack_at`, `base_url` (MISP), `limits`, the catalog defaults and ceilings, and `available` (false for `mock` in prod).
- **First enable** needs `acknowledge_terms: true` (audited `integration.terms_acknowledged`). A new key or MISP URL queues a check after the commit; `verify_queued` says whether it was (the save stands either way). Audit actions: `integration.key_set`, `integration.key_replaced`, `integration.key_removed`, `integration.updated`, `integration.verified` / `integration.verify_failed` (worker, no actor), `ti.settings_updated`, `ti.enrichment_requested`, `ti.run_deadline` (reaper).
- **Runs** answer `RunRequestOut`: the run (or none when nothing was eligible) plus, for lookups, a per-value normalization report (`skipped` reason, `query_removed` / `refanged` notes). Poll `GET .../ti/runs/{run_id}` until the status is final.
- **History** answers `400 invalid_ioc` for a value that cannot be normalized; `skipped` says why no provider would receive it.

| Status | Code |
|---|---|
| 400 | `invalid_ioc` |
| 404 | `not_found` (also an unknown job for an enrichment request) |
| 409 | `integration_not_configured` (no key to verify or remove), `job_not_ready` (job not succeeded), `no_provider_enabled`, `provider_not_enabled`, `enrichment_busy` (3 active runs per org / 20 overall) |
| 422 | `provider_unavailable` (TI disabled, or `mock` in prod), `terms_not_acknowledged`, `api_key_required`, `invalid_api_key`, `key_required_for_url_change` (a MISP URL change needs the key again), `misp_url_required`, `misp_url_invalid` (fixed reason, URL never echoed), `base_url_not_supported`, `limit_above_ceiling`, `too_many_values` (> `TI_MAX_LOOKUP_VALUES`, 20), `no_values`, `unknown_provider`, `invalid_attack_ids` |
| 429 | `rate_limited` (run requests, verify checks) |
| 503 | `seal_key_unavailable` (no usable active public key), `broker_unavailable` (verify could not be queued, `Retry-After: 5`) |

## AI analyst (M5)

Details: [AI_ANALYST.md](AI_ANALYST.md). The API builds and freezes the context and publishes the run; only the analyst-worker calls a provider.

- **Providers.** `provider` is `anthropic`, `gemini` or `mock` (dev/test only). The read model has the catalog (`models` with prices and `verified`, `default_model`, `price_version`, `tos_note`, `privacy_note`), `available` / `unavailable_reason` (`ai_disabled_platform`, `prod_mock`, `gemini_billing_required`), `platform_key` (the dev overlay covers it), `requires_paid_tier_ack`, and this org's `configured`, `key_last4`, `enabled`, `model`, `verify_status`, `verified_at`, `last_error_code`, `terms_ack_at`, `paid_tier_ack_at`, plus `default_limits` (catalog), `ceilings` (`AI_CEILINGS.per_minute` override, else the catalog ceiling) and `limits` (the org's own, or null). `limits: {per_minute}` sets the org's per-minute request limit, at most the ceiling (`422 limit_above_ceiling`); `{}` resets it to the catalog default; a change is audited in `integration.ai_updated` with `changed: ["limits"]`. Keys are write-only (8–256 printable ASCII). The first configuration needs `api_key` unless the platform key covers the provider; the first `enabled: true` needs `acknowledge_terms: true`, and for Gemini `acknowledge_paid_tier: true` (per key: a new Gemini key clears it, so an enabled Gemini config needs it again in the same request). A new key queues `ai.verify` after the commit (`verify_queued` in the answer); the save stands either way.
- **Settings.** `ai_enabled`, `default_provider`, `pseudonymize_internal`, `internal_cidrs` / `internal_suffixes` (≤ 50 each, validated), `include_strings`, `include_ti`, `include_case_text`, `daily_token_budget`, `run_token_cap`, `incident_token_cap`; the answer adds `ceilings`, `privacy_notice`, `privacy_ack_at/by` and `platform_ai_enabled`. Turning AI on, and later turning TI, strings or case text on, pseudonymization off, or removing internal CIDRs / suffixes, needs `acknowledge_privacy: true`.
- **Runs.** `task` is `explain_finding` / `explain_alert` (job + `target_id`), `summarize_pcap`, `explain_static` (job), `ioc_correlation`, `attack_mapping` (job or investigation) or `incident_summary` (investigation; queues one `job_digest` child per job). `provider` / `model` default to the org's default provider and the provider's configured or catalog model. The answer is `{run, deduplicated}`; poll `GET …/ai/runs/{run_id}` until the status is final (`completed`, `partial`, `failed` with `error_code`, `refused` with `refusal_category`; `waiting` carries `resume_at`). The list shows top-level runs; incident digests are `child_runs` of their parent.
- **Run detail.** `output` (when `completed` / `partial`) has every claim with `status` (`supported` / `unsupported` / `hypothesis`) and `reason`, every citation with `status`, `reason`, `stale` and, for verified ones only, a `link` `{route, job_id, tab, ref}` (never a URL); timeline entries carry the time of their first verified cited row. Display text has pseudonyms reversed for `evidence.write` members unless `pseudonyms=keep`; viewers always get them kept (`pseudonyms: "kept"`, `403 forbidden` on `pseudonyms=reverse`). A canary-leak output is never returned (`output_withheld: true`). `context_stats`, `metrics`, `flags`, `usage`, `cost_micros` (an estimate, `cost_estimated`), `price_version`, `served_model` and `prompt_version` are always there.
- **Context.** `GET …/runs/{run_id}/context` returns the frozen stage(s) exactly as sent (`base`, and `reduce` for an incident parent); `reveal=true` adds the pseudonym map; it needs `evidence.write` (viewers get `403 forbidden` and read only the pseudonymized context) and every reveal writes `ai.context_revealed`. `POST …/ai/context-preview` returns the items, stats, data `categories` and inclusions a run would send.
- **Audit:** `ai.enabled` / `ai.disabled`, `ai.settings_updated`, `integration.ai_terms_acknowledged`, `integration.ai_key_set`, `integration.ai_key_replaced`, `integration.ai_key_removed`, `integration.ai_updated`, `ai.provider_verified` / `ai.provider_verify_failed` (worker, no actor), `ai.run_requested` (no content), `ai.context_revealed` (run, actor and stages, never a name), `ai.run_deadline` (reaper). Key values never appear (last4, kid and version only).

| Status | Code |
|---|---|
| 403 | `forbidden` (also `context?reveal=true` without `evidence.write`) |
| 404 | `not_found` (also an unknown or foreign job, investigation or run) |
| 409 | `ai_disabled` (platform or org), `no_provider_enabled` (not enabled, terms or paid-tier attestation missing, or no key), `job_not_ready` (job not succeeded), `budget_exhausted` (today's usage already reaches the org budget), `ai_busy` (12 active runs per org / 40 overall, incident children included), `provider_not_configured` (no key to verify or remove) |
| 422 | `provider_unavailable` (AI off, `mock` in prod, Gemini without `GEMINI_BILLING_ENABLED`), `model_not_allowed`, `terms_not_acknowledged`, `paid_tier_not_acknowledged`, `api_key_required`, `invalid_api_key`, `privacy_not_acknowledged`, `budget_above_ceiling`, `limit_above_ceiling` (provider `limits.per_minute` above the ceiling), `target_not_found` (the finding or alert is not part of the job), `task_not_applicable` (wrong analyzer for the task), `context_empty` (nothing to analyze), `validation_error` (request shape: exactly one of `job_id` / `investigation_id`, `target_id` only for the explain tasks, `job_digest` not requestable) |
| 429 | `rate_limited` (run requests, previews, verify checks) |
| 503 | `seal_key_unavailable`, `broker_unavailable` (verify could not be queued, `Retry-After: 5`) |

Run `error_code` values (`deadline`, `ai_disabled`, `provider_disabled`, `provider_unavailable`, `auth_failed`, `spend_limit`, `overloaded`, `max_tokens`, `invalid_output`, `context_too_large`, `budget_exhausted`, `provider_error`, `canary_leak`, `no_digest`, `refused`) are listed with their causes in [AI_ANALYST.md](AI_ANALYST.md#run-lifecycle).

**Investigation reads (M5).** `GET …/analyses?investigation_id=` lists only that case's jobs (404 for an unknown or foreign case); `latest_per_evidence=true` keeps the newest job per evidence and kind of run. `GET …/investigations/{id}/timeline` merges custody events, job lifecycle, the latest pcap job's timeline and alerts per evidence, and static findings at analysis time (`ts_source: analysis_time`), sorted by (ts, kind, ref_id), cursor-paged.

## Reports and case management (M6)

Details: [REPORTS.md](REPORTS.md). Cursor-paged lists (`next_cursor`) replace limit/offset on the M6 routes; a bad cursor is `400 invalid_cursor`.

- **Downloads and exports** (report renders, snapshots, signatures, IOC collection and timeline exports) are attachments with an RFC 5987 file name, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` and `Content-Security-Policy: sandbox` (HTML renders: `sandbox; default-src 'none'; style-src 'unsafe-inline'`). Report downloads are streamed by the API from the exact stored object version and re-hashed while streaming; the file name carries the case, version and TLP (`CASE-00012_v2_TLP-AMBER.pdf`). No presigned URL is ever returned to a client. IOC exports add `X-Export-Count`, `X-Export-Skipped`, `X-Export-Defanged` and `X-Export-Redacted: false` (exports are never redacted).
- **Share policy refusals** on the M4 / M5 routes: `POST /ai/runs`, `POST /ai/context-preview` and `POST …/analyses/{job_id}/enrichments` answer `409 policy_blocked` with `reason` (`tlp_red`, `case_ai_excluded`, `case_ti_excluded`, `evidence_ai_excluded`, `evidence_ti_excluded`). The case and evidence reads carry the effective `share_policy` (`ai_blocked`, `ti_blocked`, reasons). A policy changed after a request is caught by the workers without a provider call: an AI run fails `failed / policy_blocked`, a TI run ends with its pending items abandoned as `policy_blocked`. `POST /ti/lookups` is not checked (no case scope).
- **Render error codes** on `report_renders.error_code`: `snapshot_mismatch`, `fetch_blocked`, `timeout`, `oom`, `too_large`, `too_many_pages`, `invalid_output`, `renderer_error` ([REPORTS.md](REPORTS.md#isolation)).
- **Audit:** `investigation.updated` (status, TLP and flags; never the status reason), `evidence.share_policy_updated`, `investigation.timeline_exported`, `note.created` / `note.edited` / `note.deleted`, `ioc_collection.created` / `.updated` / `.items_added` / `.item_removed` / `.exported`, `case_attack.mapped` / `.updated`, `report.created`, `report.updated`, `report.discarded`, `report.finalized`, `report.tlp_downgraded`, `report.snapshot_downloaded`, `report.render_requested`, `report.rendered` / `report.render_failed` (ingest, no actor), `report.downloaded`, `report.integrity_failed`. Details carry ids, counts, formats and TLP, never note bodies or reasons.

| Status | Code |
|---|---|
| 400 | `invalid_cursor` |
| 403 | `forbidden` (also turning a share-policy flag off without `integrations.manage`, editing another author's note without `org.update`, `defang=false` without `evidence.write`), `tlp_downgrade_forbidden` (a case or report TLP below the case without `org.update`) |
| 404 | `not_found` (also another org's or case's note, collection, mapping, report, version or render) |
| 409 | `investigation_archived`, `invalid_transition`, `stale_note`, `note_deleted`, `collection_exists`, `collection_archived`, `mapping_exists`, `stale_draft` (with the current `revision`), `report_discarded`, `report_has_versions`, `tlp_below_case` (a report TLP below the case without `acknowledge_tlp_downgrade`, also at finalize, RT7), `render_busy` (2 active renders per org / 4 per renderer replica), `render_not_ready`, `integrity_failed` (stored snapshot or rendition differs from its recorded hash), `policy_blocked` |
| 422 | `validation_error` (also a draft over 1 MiB, an analyst section over 20 000 characters), `status_reason_required`, `tlp_downgrade_not_acknowledged` (case TLP), `ref_out_of_scope` (note refs, mapping sources), `too_many_items` (10 000 active items per collection), `invalid_technique` (unknown, revoked or deprecated), `selection_out_of_scope`, `distribution_required` (TLP:RED, AMBER+STRICT or `external`), `external_review_required`, `report_too_large` (snapshot > 8 MiB), `report_too_large_to_render` (render units > `REPORT_MAX_RENDER_UNITS`; with `render_units`, `section_units`, `section_counts`), `invalid_range` (timeline export) |
| 429 | `rate_limited` (preview, finalize, renders, the public signing keys) |
| 503 | `signing_unavailable` (no usable signing key at finalize) |

## Platform operations (M7)

Design: [ARCHITECTURE.md](ARCHITECTURE.md#platform-operations-m7). Every route below is in the IDOR enumerator (`security/idor_cases_{retention,correlation,ops}.py`) and RLS-bound.

**Retention policy.** `GET /retention/policy` answers the effective values, the `pending_*` values with `effective_at`, `enforce`, `pending_enforce` with `enforce_effective_at`, `delay_days` and the `floors`; with no row every value is null (keep forever) and `enforce` is off. `PUT` replaces the whole policy (every value is required; null = keep forever):
- a **raised** value (or null) applies at once; a **lowered** one is stored as `pending_*` and applies after `RETENTION_POLICY_DELAY_DAYS` (7);
- turning `enforce` on needs `acknowledge_destruction: true` (`422 retention_acknowledgement_required`) and is stored as `pending_enforce` until the delay passes; turning it off applies at once;
- floors: 30 days for TI and AI, closed cases at least `max(30, EVIDENCE_LOCK_DAYS)` (`422 policy_floor`);
- audited `retention.policy_changed` / `retention.enforce_changed`.

**Preview and runs.** `POST /retention/preview` computes what a run would select now (counts per category with rows, bytes, `kept_cited`, `skipped_hold`, `skipped_locked`, a bounded sample, `truncated`, `holds_active`) through the same selector as the worker. It deletes nothing, accepts trial values (an omitted value previews the effective one), and is recorded as a manual dry run (audited `retention.previewed`). `POST /retention/runs` queues a manual run: its mode comes from the effective DB policy, never from the request (`dry_run: true` forces a dry run); `409 retention_run_active` while a run of the org is queued or running; audited `retention.run_requested`. Run reads (`audit.read`) list status, counts and timings; the detail adds the sample and the run items with their `outcome` (`purged`, `skipped_hold`, `skipped_locked`, `object_delete_failed`, `kept_cited`).

**Legal holds.** `POST /legal-holds` places an org hold (no `investigation_id`) or a case hold (`investigation_id` required; `422 hold_scope_invalid` otherwise, `404` for another org's case); audited `legal_hold.placed`. The answer has `s3_sync: pending` until the retention worker mirrored a case hold as S3 legal holds (`synced`, `s3_synced_at`). `POST /legal-holds/{id}/release` needs a reason, works once (`409 legal_hold_released`), is audited `legal_hold.released`, and the hold keeps protecting until `protects_until` (release + the delay); `active` is false from the release.

**Correlation** (`investigation.read`; deterministic, counts only, never across orgs):
- `GET /analyses/{job_id}/correlations`: the job's keys shared with other jobs of the org, each with `other_jobs`, `other_cases`, first / last seen, `common` and the top cases; `indexed: false` until the indexer reached the job; `truncated` when the job hit `CORRELATION_MAX_KEYS_PER_JOB`.
- `GET /correlations?kind&value`: where one observable was seen (the server normalizes `value`, `422 search_query_invalid` without echo when it cannot; `kind` ∈ ipv4, ipv6, domain, url, email, md5, sha1, sha256, ja3, ja3s, cert_sha256).
- `GET /investigations/{id}/related`: cases sharing at least one non-common key, ranked by shared keys with a count per kind; `common_keys_excluded` counts the keys left out.

**Search.** `POST /search` `{q, types?, cursor?}`; `q` is stripped and must be 2–256 characters without control characters (`422 search_query_invalid`); `types` ⊆ observable, case, evidence, finding, alert, note (default all); `cursor` continues one type. The answer groups hits per type (at most 20 each, plain-text `title` and `snippet`, `match` exact / fts / trigram, the ids needed for the deep link and a relative `href`) and sets `partial` when a type hit the 3 s statement timeout. 30 searches / min per user (`429`). The query travels only in the body and is **never logged or audited**; errors never echo it.

**Operations metrics.** `GET /ops/metrics?window=1h|24h|7d` (`audit.read`): per kind (pcap, static, ti, ai, report) and subkind, the totals, `failure_ratio`, `parse_success_ratio` (analyzers), queue and run latency quantiles and the failures per error class, plus the active counts, computed from the org's own tenant tables.

**`GET /internal/metrics`** (operators only). Mounted on the root app, not under `/api/v1`, so the gateway never forwards it; call it from the `backend` network. `404` while no `METRICS_TOKEN_FILE` is configured (the route is off), 60 requests / min per peer, `401 invalid_token` without `Authorization: Bearer <token>`, `403 proxied_request` when `X-Forwarded-For` or `Forwarded` is present. The body is Prometheus text 0.0.4 with no tenant data; `Cache-Control: no-store`.

**Global rate limit.** Every request authenticated by the access cookie counts once against `RATE_LIMIT_USER_PER_MIN` (600 / min per user) after the token check; `GET /auth/me` is exempt. `429 rate_limited` + `Retry-After`; a Redis failure answers `503` (fail closed). Unauthenticated routes keep their own per-IP limits; there is no anonymous global limit.

**New audit actions:** `retention.policy_changed`, `retention.enforce_changed`, `retention.previewed`, `retention.run_requested`, `legal_hold.placed`, `legal_hold.released`, `evidence.purged`, `retention.run_completed` and `retention.run_downgraded` (an enforce run whose enforce is no longer effective runs as a dry run; all three by the retention worker), `evidence.viewed`, `evidence.custody_viewed`, `evidence.type_mismatch`. The custody chain gains the action `purged` (actor: the system user `retention@system.invalid`).
