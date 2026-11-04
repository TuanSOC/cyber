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

Roles: **viewer** = all `*.read`; **analyst** = viewer + `investigation.write`, `evidence.write`; **admin** = analyst + `org.update`, `members.manage`, `audit.read`; **owner** = admin + owner-role management.

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
