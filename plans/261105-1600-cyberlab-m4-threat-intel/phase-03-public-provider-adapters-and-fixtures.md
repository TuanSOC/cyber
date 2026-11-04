---
phase: 3
title: Public provider adapters and fixtures
status: completed
priority: P1
effort: 8h
dependencies:
  - 2
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
- [x] Every adapter passes hit, not-found, 429 (both forms), 401, timeout, bad JSON, deep nesting, oversize and 5xx with the right status; hostile strings are sanitized. — `test_ti_provider_fixtures.py::test_manifest_case` (238 cases), `test_every_public_provider_case_is_covered`; `test_ti_provider_adapters.py::test_virustotal_hostile_values_are_dropped_or_cleaned`, `test_unexpected_shapes` (8f5e23b).
- [x] No adapter can reach an upload, scan or download endpoint (allowlist test). — `test_forbidden_routes_match_no_allowlist`, `test_forbidden_routes_are_never_sent`, `test_allowlists_are_lookup_only`, `test_malwarebazaar_sends_only_get_info` (8f5e23b).
- [x] The sentinel key appears nowhere but the outbound auth header. — `test_manifest_case` via `assert_key_only_in_header` (URL, body, headers, reprs, result, exception, caplog, key-echo fixtures); `test_ti_http.py::test_key_only_in_the_auth_header_and_never_in_reprs` (8f5e23b).

## Implementation Notes (2026-11-05)
- **Commits:** b83d6f2 committed the fixtures for all six providers early, together with the ATT&CK index; 8f5e23b holds the adapters (`virustotal.py`, `abuseipdb.py`, `abusech.py` for URLhaus + MalwareBazaar, `otx.py`). The registry loads them lazily (`test_registry_builds_every_public_adapter`).
- **Allowlists (lookup only):**

  | Provider | Allowed requests |
  |---|---|
  | VirusTotal | `GET /api/v3/{ip_addresses,domains,urls,files}/{id}` |
  | AbuseIPDB | `GET /api/v2/check` (`maxAgeInDays=90`) |
  | URLhaus | `POST /v1/{url,host,payload}/` |
  | MalwareBazaar | `POST /api/v1/` with the `get_info` form only (`MALWAREBAZAAR_QUERIES`; anything else raises `PathNotAllowed`) |
  | OTX | `GET /api/v1/indicators/{IPv4,IPv6,domain,url,file}/{value}/general` |

  Tests: `test_forbidden_routes_match_no_allowlist`, `test_forbidden_routes_are_never_sent`, `test_allowlists_are_lookup_only`, `test_malwarebazaar_sends_only_get_info`.
- **Fixtures** (`tests/fixtures/ti/manifest.json`):
  - 238 public cases (VT 63, AbuseIPDB 17, URLhaus 68, MalwareBazaar 24, OTX 66) plus 42 MISP cases.
  - Handcrafted, with documentation IPs, `example` domains and only the sentinel key.
  - They cover: found, not found, sanitized, capped; auth, including key-echo bodies; 429 with and without `Retry-After`; 5xx; bad JSON and deep nesting; timeout (`httpx.ReadTimeout`); oversize (2 MiB); abuse.ch `bad_request`; AbuseIPDB 422 `invalid_input`.
- **`test_manifest_case`** (one test per case, `unit/test_ti_provider_fixtures.py`) asserts:
  - the exact request, on the allowlist;
  - the key only in the auth header, via `assert_key_only_in_header`: not in the URL, the body, other headers, the request/client/auth reprs, the result, the exception or caplog (with httpx/httpcore at DEBUG);
  - the expected status or error kind;
  - a sanitized summary under 16 KiB.

  `test_every_public_provider_case_is_covered` checks that every case runs.
- **VirusTotal 429 (deviation):** VT's daily-quota 429 body is identical to the per-minute one.
  - The adapter always raises `rate_limited` with no `Retry-After`, so the worker cools down to the next minute. The 4 `quota_exhausted` VT manifest cases expect `RATE_LIMITED`.
  - The worker's own daily counter, or 3 consecutive 429s (`QUOTA_STRIKES`, 913023d), turns this into `quota_exhausted` until 00:00 UTC.
- **abuse.ch:**
  - A bad key is handled both ways: HTTP 401/403, or 200 with `query_status` `no_api_key` / `unknown_auth_key`.
  - `invalid_*`, `illegal_hash`, `no_hash_provided` and `http_post_expected` map to `bad_request`.
  - The status string is compared, never stored or logged.
- **AbuseIPDB:** never answers "not found". A score of 0 with 0 reports becomes `not_found` and keeps `usageType`, `isp`, `isTor` and `isWhitelisted` (`test_abuseipdb_hit_and_not_found`, `test_abuseipdb_hostile_categories`).
- **OTX:**
  - A 404 or a quiet 200 (`pulse_info.count == 0`, no reputation) is `not_found`. Only the top 10 pulses are kept, and `attack_ids` are checked against the T-id pattern (`test_otx_hit_quiet_and_attack_ids`, `test_otx_huge_keeps_the_top_ten_pulses`).
  - URLs with dot segments are refused before sending (`test_otx_url_dot_segments_are_refused_before_sending`).
- **Permalinks:**
  - Built from constants and the normalized value, `https:` only (ASCII-only after review).
  - URLhaus' `urlhaus_reference` is used only on `https://urlhaus.abuse.ch/` (`test_provider_links_only_on_their_own_https_host`, the `url_spoofed_reference` fixture).
  - The VT URL id is unpadded base64url (`test_virustotal_url_id_is_unpadded_base64url`).
- **Verify (`test_verify`):**
  - VT: a lookup of the EICAR sha256 (never `/users/{id}`, RT11);
  - AbuseIPDB: a check of `8.8.8.8` (costs 1 check);
  - URLhaus: a payload lookup of the EICAR sha256;
  - MalwareBazaar: `get_info`;
  - OTX: `/api/v1/user/me`.
- **Other refusals:** unsupported types never leave (`test_unsupported_types_never_leave`), and unexpected response shapes become `bad_json` (`test_unexpected_shapes`). Hostile strings are cleaned (`test_virustotal_hostile_values_are_dropped_or_cleaned`).
- **Live tests:** `unit/test_ti_provider_live.py` (`CYBERLAB_LIVE_TI=1` + `CYBERLAB_TI_KEY_<PROVIDER>`), never in the gate.
- **Deviation: no live run was made.** The free-tier numbers, the real abuse.ch bad-key answer and the OTX 429 behaviour are unverified. THREAT_INTEL.md marks the quotas "unverified against the live API", and the catalog defaults are unchanged.
- **Accepted residual (ToS):** the VT public tier and the abuse.ch free tier are non-commercial. Bring-your-own-key, plus a ToS note and a privacy note on each card.
