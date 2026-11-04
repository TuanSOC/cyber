---
phase: 5
title: "Integrations enrichment and lookup API"
status: pending
priority: P1
effort: "9h"
dependencies: [2]
---

# Phase 5: Integrations enrichment and lookup API

## Overview
The org-scoped HTTP surface. It covers integrations (terms acknowledgement, write-only keys,
verify, TI settings), enrichment runs (job and manual lookup), results (latest per provider on
IOC lists, history per IOC), and the audit trail. The API only normalizes, seals, records and
publishes; it never contacts a provider and never resolves an external name.

Files: `threat_intel/router_*.py` (filling the phase-1 router stubs), `threat_intel/service_*.py`
and repositories, the `include=enrichment` addition to the existing IOC list route, tests.
It does not edit `providers/`, `summaries.py`, `catalog.py`, `runs.py`, `ssrf.py` or `app/main.py`.

## Requirements
- **Integrations** (`threat_intel/router_integrations.py`):
  - `GET /orgs/{org}/integrations` (`org.read`): the provider catalog (from `catalog.py`). Each entry has:
    - `name`, `label`, `supported_types`, `tos_note`, `privacy_note`, `default_limits`, `ceilings`;
    - `available` (false for `mock` in prod, false for everything if `TI_ENABLED=false`);
    - and, if configured: `enabled`, `configured`, `key_last4`, `verify_status`, `verified_at`, `last_error_code`, `terms_ack_at`, `base_url` (MISP), `limits`.

    Never `key_*` ciphertext columns.
  - `PUT /orgs/{org}/integrations/{provider}` (`integrations.manage`): body `{api_key?: SecretStr (1–256 printable ASCII, stripped), enabled?: bool, acknowledge_terms?: bool, base_url?: str (MISP only), limits?: {per_minute?, per_day?}}`.
    - The first configuration requires `api_key`.
    - The first `enabled=true` requires `acknowledge_terms: true` → `terms_ack_at`, `terms_ack_by`; otherwise `422 terms_not_acknowledged` (RT16).
    - A new key → `key_version += 1`, sealed under the active kid (with `base_url_norm` for MISP), `verify_status=unverified`, a verify task is queued.
    - MISP `base_url` goes through the syntactic `ssrf.validate_base_url` only (no DNS, RT5) → `422 misp_url_invalid`. A changed `base_url` without a new `api_key` → `422 key_required_for_url_change`, because the stored key is bound to the old URL (RT1). Every save queues `ti.verify`, which resolves the host in the worker and reports `misp_url_not_public` through `verify_status` / `last_error_code`.
    - Limits above the ceilings → `422 limit_above_ceiling`.
    - An unavailable provider → `422 provider_unavailable`.
    - The org row is locked `FOR NO KEY UPDATE` while writing (serializes concurrent PUTs).
    - Audit `integration.terms_acknowledged`, `integration.key_set` / `integration.key_replaced` (provider, last4, kid, key_version) or `integration.updated` (changed fields, no values for the key).
  - `DELETE /orgs/{org}/integrations/{provider}/key` (`integrations.manage`): clears the sealed columns and sets `enabled=false`. Audit `integration.key_removed`.
  - `POST /orgs/{org}/integrations/{provider}/verify` (`integrations.manage`): queues `ti.verify` (rate limited 10 per 10 min per org and provider) → 202.
  - `GET` / `PUT /orgs/{org}/ti/settings` (read `org.read`, write `integrations.manage`): `excluded_suffixes` (≤ 50, validated as domain suffixes). Audit `ti.settings_updated`.
- **Runs** (`threat_intel/router_runs.py`; `evidence.write`; per-user limit 30 runs per 10 min; per-org 3 active runs → `409 enrichment_busy`; global 20). Creation goes through phase 2's `runs.create_run` and `runs.dispatch`:
  - `POST /orgs/{org}/analyses/{job_id}/enrichments` `{providers?: [...]}`. The job must be `succeeded` (otherwise `409 job_not_ready`), and `providers` defaults to every enabled provider.
  - `POST /orgs/{org}/ti/lookups` `{values: [{value, type?}] (1–20, each ≤ 2048 characters), providers?}`. The response contains the run plus a per-value normalization report (`ioc_type`, `value_norm`, `ioc_key`, `notes` such as `query_removed`, or `skipped: reason`), so the UI can explain skips at once. When nothing is eligible, no run is created and the response is 200 with the report only.
  - The same job with an active run returns the existing run (200, `deduplicated: true`) instead of creating another.
  - The run, its index row, its items and the audit row (`ti.enrichment_requested`: scope, target id, providers, counts; no values) are committed in one transaction. `send_task` is called after the commit. A publish failure is logged, and the response is still 202, because `ti.resume` picks the run up.
  - No enabled provider → `409 no_provider_enabled`.
  - `GET /orgs/{org}/ti/runs?job_id&status` (paged) and `GET /orgs/{org}/ti/runs/{run_id}` (`evidence.read`): status, summary, deadline, `resume_at`, providers, requested_by, and the run's items (paged, filter by provider or state), each with its result (this run's row, or the cached row marked `from_cache: true`) (RT10).
- **Results** (`evidence.read`):
  - `GET /orgs/{org}/analyses/{job_id}/iocs?include=enrichment`: the existing route gains an optional per-row `enrichment: [{provider, status, found, score, score_scale, detections, tags, families, attack_ids, fetched_at, expires_at, stale, permalink, result_id}]`. It holds the latest row per provider (`DISTINCT ON (ioc_key, provider) … ORDER BY fetched_at DESC`) for the page's normalized keys, computed in Python. Ineligible IOCs carry `enrichment_skip: reason`.
  - `GET /orgs/{org}/ti/results?value=&type=` (history): normalizes the input, then returns every row for that `ioc_key` (all providers, newest first, paged, filter by provider), with each row's `summary`. `400 invalid_ioc` if it cannot be normalized; a skip reason is returned for ineligible values.
  - `GET /orgs/{org}/ti/results/{result_id}`: one row with its full summary.
- **Schemas:**
  - every provider summary is a typed union in OpenAPI built from the frozen `summaries.py`, so the contracts carry per-provider types;
  - the `api_key` field is write-only (`SecretStr`, excluded from every response model); custom validators never put the submitted value in their message;
  - the error envelope never echoes the key or `base_url` userinfo.
- **Contracts:** the parent runs `pnpm gen:contracts` after the routes freeze.
- **Read indexes:** if `EXPLAIN` shows sequential scans for the IOC page join, the run-items page or the history query, migration **0010** adds the indexes (parent-assigned).

## Implementation Steps
1. Service and repository for configs (seal through `seal.py` with the public key only), with the catalog read from `catalog.py` (no adapter imports).
2. Integration routes with tests:
   - RBAC (analyst or viewer `PUT` → 403; viewer `GET` → 200 without secrets);
   - enabling without `acknowledge_terms` → 422; acknowledgement audited;
   - a sentinel key absent from every response, audit row and log (caplog plus a scan of captured stdout), including 422 responses for an over-long or non-ASCII key;
   - replace bumps the version; remove;
   - MISP: syntactic errors → 422; URL change without a key → 422; save queues verify;
   - the prod catalog marks `mock` unavailable;
   - concurrent PUTs.
3. Settings routes and tests.
4. Run routes: creation, dedupe, caps, rate limits and publish failure, with tests (a fake broker for the publish failure; a real broker in the pipeline test).
5. Result routes:
   - `include=enrichment` on the IOC list, history, run detail with cached items;
   - tests for org B seeing nothing of org A's results, runs, items or configs (IDOR enumerator plus explicit tests);
   - `ti_results` append-only through the API role;
   - stale flags.
6. The OpenAPI typed unions; contracts regenerated.

## Success Criteria
- [ ] The IDOR and RLS enumerators cover every new route and table, and they pass.
- [ ] No response, audit detail, error or log line contains the sentinel key or its ciphertext.
- [ ] A job enrichment request gives 202 → the worker runs it → `include=enrichment` shows per-provider results, history lists them, and a repeat run shows the cached items.
- [ ] A MISP `base_url` change cannot reuse the stored key.
