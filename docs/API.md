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
| 409 | `conflict`, `registration_failed`, `already_member`, `last_owner`, `invalid_transition`, `investigation_archived`, `evidence_archived`, `evidence_content_missing`, `org_limit_reached` (user already owns `MAX_OWNED_ORGS_PER_USER` orgs) |
| 405 | `method_not_allowed` |
| 413 / 415 | `payload_too_large`, `storage_quota_exceeded` (upload would exceed the org quota), `unsupported_media_type` |
| 429 | `rate_limited` (+ `Retry-After`) |
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
| POST | `/orgs/{org_id}/investigations/{investigation_id}/evidence?filename&description` | `evidence.write` |
| GET | `/orgs/{org_id}/evidence/{evidence_id}` · `/download` · `/custody` | `evidence.read` |
| POST | `/orgs/{org_id}/evidence/{evidence_id}/verify` · `/archive` | `evidence.write` |
| POST | `/orgs/{org_id}/evidence/{evidence_id}/analyses` `{"analyzer":"pcap"}` or `{"analyzer":"static","profile":"full"\|"av"}` | `evidence.write` (20 manual runs / 10 min) |
| GET | `/orgs/{org_id}/evidence/{evidence_id}/analyses` | `evidence.read` |
| GET | `/orgs/{org_id}/analyses?status&analyzer&profile` · `/orgs/{org_id}/analyses/{job_id}` (incl. `profile`, `summary`) | `evidence.read` |
| GET | `/orgs/{org_id}/analyses/{job_id}/findings?severity&type` | `evidence.read` |
| GET | `/orgs/{org_id}/analyses/{job_id}/flows?ip&port&proto&sort=bytes\|ts` | `evidence.read` |
| GET | `/orgs/{org_id}/analyses/{job_id}/records?kind=dns\|http\|tls&q` | `evidence.read` |
| GET | `/orgs/{org_id}/analyses/{job_id}/alerts?severity` · `/iocs?type&q` · `/timeline` | `evidence.read` |
| GET | static jobs: `/orgs/{org_id}/analyses/{job_id}/sample` · `/sections` · `/imports?library&q` · `/exports?q` · `/resources` | `evidence.read` |
| GET | static jobs: `/orgs/{org_id}/analyses/{job_id}/strings?encoding&q` · `/signatures?engine=clamav\|yara` · `/capabilities?namespace&attack` | `evidence.read` |
| GET | `/orgs/{org_id}/analyses/{job_id}/report` (static jobs) | `evidence.read` (audited) |
| GET | `/orgs/{org_id}/analyses/{job_id}/iocs?include=enrichment` (latest answer per provider on each IOC, M4) | `evidence.read` |
| GET | `/orgs/{org_id}/integrations` (provider catalog + this org's status; never a key) · `/orgs/{org_id}/ti/settings` | `org.read` |
| PUT | `/orgs/{org_id}/integrations/{provider}` `{api_key?, enabled?, acknowledge_terms?, base_url?, limits?}` · `/orgs/{org_id}/ti/settings` `{excluded_suffixes}` | `integrations.manage` |
| DELETE | `/orgs/{org_id}/integrations/{provider}/key` | `integrations.manage` |
| POST | `/orgs/{org_id}/integrations/{provider}/verify` → 202 (10 per provider / 10 min) | `integrations.manage` |
| POST | `/orgs/{org_id}/analyses/{job_id}/enrichments` `{providers?}` · `/orgs/{org_id}/ti/lookups` `{values: [{value, type?}], providers?}` → 202 new run, 200 deduplicated / nothing eligible | `evidence.write` (30 / 10 min per user) |
| GET | `/orgs/{org_id}/ti/runs?job_id&status` · `/orgs/{org_id}/ti/runs/{run_id}?provider&state` (items with their results, `from_cache`) | `evidence.read` |
| GET | `/orgs/{org_id}/ti/results?value&type&provider` (history of one indicator, newest first) · `/orgs/{org_id}/ti/results/{result_id}` | `evidence.read` |
| GET | `/attack/techniques?ids=T1055,T1059.001` (labels + MITRE notice, ≤ 100 ids) | signed in |

Roles: **viewer** = all `*.read`; **analyst** = viewer + `investigation.write`, `evidence.write`; **admin** = analyst + `org.update`, `members.manage`, `audit.read`, `integrations.manage` (M4); **owner** = admin + owner-role management.

## Evidence upload

```bash
curl -X POST "https://host/api/v1/orgs/$ORG/investigations/$CASE/evidence?filename=capture.pcap" \
  -H "Content-Type: application/octet-stream" -H "X-CSRF-Token: $CSRF" \
  -b cookies.txt --data-binary @capture.pcap
```

The body is the raw file (no multipart). Max 2 GiB (`MAX_EVIDENCE_BYTES`); at most 2 concurrent uploads per user. Each org has a storage quota (`DEFAULT_STORAGE_QUOTA_BYTES`, 20 GiB, unless an operator set a per-org value); active and archived evidence both count. An upload that would exceed it gets `413 storage_quota_exceeded`: before the body is read when `Content-Length` is declared, otherwise after spooling (the stored version is then discarded). Response includes `hashes.md5/sha1/sha256`. Downloads are `application/octet-stream` attachments with `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox`, `Cache-Control: no-store`.

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
