---
phase: 3
title: "Public provider adapters and fixtures"
status: pending
priority: P1
effort: "8h"
dependencies: [2]
---

# Phase 3: Public provider adapters and fixtures

## Overview
Lookup-only adapters for VirusTotal v3, AbuseIPDB v2, URLhaus, MalwareBazaar and AlienVault
OTX on the phase-2 client. Each is about 60–100 lines of httpx with the frozen summary model from
`summaries.py` and a path allowlist, plus a fixture set covering every failure mode. Endpoints, fields and quotas
come from `plans/reports/researcher-261105-m4-providers.md`.

## Requirements
- **One module per provider** under `threat_intel/providers/`: `virustotal.py`, `abuseipdb.py`, `abusech.py` (URLhaus and MalwareBazaar as two providers sharing helpers), `otx.py`. Each one has:
  - **`allowed_paths`:** exact (method, host, path pattern). Only GET for VT, AbuseIPDB and OTX; only POST to `/v1/url/`, `/v1/host/`, `/v1/payload/` and `/api/v1/` with `query=get_info` for abuse.ch.
    - VT `POST /files`, `POST /urls` and `/analyse`, the URLhaus `download` route, and MalwareBazaar `get_file` and uploads can never match. A test enumerates the forbidden routes against every allowlist.
  - **Auth:** the key goes only in a header (`x-apikey`, `Key`, `Auth-Key`, `X-OTX-API-KEY`), attached per request through phase 2's `KeyAuth`, never in a query string, path, body or `client.headers` (RT11).
  - **Not-found mapping:**
    - VT and OTX: 404;
    - OTX: also 200 with `pulse_info.count == 0` and no reputation;
    - URLhaus: `query_status == "no_results"`;
    - MalwareBazaar: `hash_not_found`;
    - AbuseIPDB: never returns not-found. A score of 0 with 0 reports is `found=false`, and the summary still keeps `usageType`, `isp`, `isTor` and `isWhitelisted`.
  - **Error mapping:**
    - abuse.ch `invalid_*`, `illegal_hash` and `http_post_expected` → `error` (kind `bad_request`);
    - an abuse.ch bad key → `auth`;
    - AbuseIPDB 422 → `error` (kind `invalid_input`);
    - VT `QuotaExceededError` → `ProviderError(quota_exhausted)` when it is the daily quota, else `ProviderError(rate_limited)` until the next minute boundary. Rate-limit and quota outcomes become item states in the worker, never `ti_results` rows;
    - error bodies are mapped to a code and dropped: never copied into `summary`, exceptions or logs (RT11).
  - **Summary model** (frozen in phase 1's `summaries.py`; adapters only fill it, copying and coercing values, never the raw body). If a field below proves wrong, the parent changes `summaries.py`. Fields:
    - VT: `last_analysis_stats`, `reputation`, `total_votes`, `tags`, `last_analysis_date`, `first_submission_date` / `last_submission_date`, `suggested_threat_label`, `meaningful_name`, `type_tag`, `as_owner`, `country`;
    - AbuseIPDB: `abuseConfidenceScore`, `totalReports`, `numDistinctUsers`, `lastReportedAt`, `isWhitelisted`, `isTor`, `usageType`, `isp`, `countryCode`, `categories`;
    - URLhaus: `url_status`, `threat`, `tags`, `date_added`, `last_online`, `blacklists`, `url_count`, `firstseen` / `lastseen`, `signature`;
    - MalwareBazaar: `first_seen`, `last_seen`, `signature`, `tags`, `file_type`, `imphash`, `ssdeep`, `tlsh`, and capped `vendor_intel` names;
    - OTX: `pulse_count`, top 10 pulses (`name`, `tags`, `malware_families`, `attack_ids`, `modified`), `reputation`, `validation`.
  - **`score`, `detections` and `permalink`:**
    - `score` is provider-native, with a `score_scale` label (VT `reputation`, AbuseIPDB 0–100);
    - `detections` = {malicious, suspicious, total} from VT only. The field names are VT's own and are shown attributed;
    - `permalink` is built from constants and the normalized value, always `https:`. A provider-supplied URL (`urlhaus_reference`) is accepted only if it is `https:` and its host is the provider's own (RT19).
  - **`attack_ids`:** taken from OTX pulses and validated against the T-id pattern.
  - **`verify(client)`:**
    - VT: a lookup of a constant public hash (never `/users/{id}`, whose id may be the key itself, RT11);
    - AbuseIPDB `check` of `8.8.8.8` (documented to cost 1 check);
    - abuse.ch `get_info` of a constant hash;
    - OTX `GET /api/v1/user/me`.

    Confirm each choice against the docs.
  - **URL id for VT:** base64url of the normalized URL without padding.
- **Fixtures** under `apps/api/tests/fixtures/ti/{virustotal,abuseipdb,urlhaus,malwarebazaar,otx}/`:
  - `hit.json` and `not_found.json`;
  - 429 with and without `Retry-After`;
  - 401 / 403;
  - timeout (the handler raises `httpx.ReadTimeout`);
  - `bad_json`;
  - oversize (a 2 MiB body) and a deeply nested body;
  - 5xx;
  - per-provider oddities: abuse.ch 200-with-error, the OTX 200 "quiet" case, the VT daily quota error, an error body that echoes the key;
  - hostile strings: bidi/control characters and `javascript:` URLs in tags and references.

  Fixtures are handcrafted from the docs or captured once and scrubbed. They contain no real keys and use only documentation IPs and `example` domains, mapped to public test values in the handler.
- **Live tests:** `@pytest.mark.live`, skipped unless `CYBERLAB_LIVE_TI=1` and the provider's key is in the environment. One lookup per provider of a well-known public value; never in CI or the verify gate.
- **ToS and limits:** `tos_note`, `privacy_note` and `default_limits` live in the frozen `catalog.py` (phase 1), not on the adapter classes (RT14); report corrections to the parent. Verify and record the free-tier numbers, the abuse.ch bad-key response and the OTX 429 behaviour in THREAT_INTEL.md during this phase. A provider never checked live is marked "unverified against the live API" there.

## Implementation Steps
1. A shared adapter test harness: a parametrized suite that runs every adapter against its fixture set and asserts `ProviderResult.status` (or the raised `ProviderError` kind), `found`, the summary model validity and the size cap. It also asserts that every request matched the allowlist and carried the key only in the expected header.
2. VirusTotal, then AbuseIPDB, URLhaus, MalwareBazaar and OTX, each with its fixtures.
3. A forbidden-route test (upload, scan and download endpoints) for every allowlist.
4. A key-placement test: a sentinel key appears only in the auth header of outbound requests, never in the URL, body, `ProviderResult`, exception text, `repr` of client / request / auth, or captured logs (including the key-echo fixture).
5. Live smoke tests (opt-in). Then report verified numbers to the parent, who updates `catalog.py` and the plan's provider table if they differ.

## Success Criteria
- [ ] Every adapter passes hit, not-found, 429 (both forms), 401, timeout, bad JSON, deep nesting, oversize and 5xx with the right status; hostile strings are sanitized.
- [ ] No adapter can reach an upload, scan or download endpoint (allowlist test).
- [ ] The sentinel key appears nowhere but the outbound auth header.
