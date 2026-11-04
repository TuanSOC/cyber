# M4 Threat Intel Provider Research (2026-11-05)

Scope: lookup-only adapters for IOC reputation enrichment. Confidence tags: [doc] means confirmed in vendor docs fetched today; [~] means from memory or community sources, so verify during implementation.

## Cross-cutting rules
- **Lookup only.** Never call VT `POST /files`, `POST /urls` or `/analyse`, URLhaus `/v1/download/`, or MalwareBazaar `get_file`/upload. Each adapter enforces a path allowlist.
- **Egress guard.** Drop RFC1918, loopback, link-local and internal-suffix IOCs. Never send TLP:RED or TLP:AMBER IOCs (including ones from MISP) to external providers.
- **Bring your own key.** VT public and abuse.ch free tiers are non-commercial only, which is fine for learning/portfolio use. Each provider is optional and disabled when it has no key.
- **Cache not-found** with a shorter TTL (for example 6h, versus 24h for a hit).

## VirusTotal v3
| Item | Value |
|---|---|
| Auth | `x-apikey` header [doc] |
| IP / domain | `GET /api/v3/ip_addresses/{ip}`, `GET /api/v3/domains/{d}` |
| URL | `GET /api/v3/urls/{id}`, where id = base64url(url) with no `=` padding, or the sha256 of the canonical URL [doc]. Never POST |
| Hash | `GET /api/v3/files/{md5\|sha1\|sha256}` [doc] |
| Email | not supported |
| Quota (public) | 4 req/min, 500/day [doc] (~15.5k/month [~]). Daily quota resets 00:00 UTC |
| 429 | `QuotaExceededError` / `TooManyRequestsError`. No documented Retry-After or X-RateLimit headers, so back off to the next minute boundary. For the daily quota, park the provider until 00:00 UTC |
| Not found | HTTP 404 `NotFoundError` |
| Fields | `last_analysis_stats` (malicious/suspicious/harmless/undetected/timeout), `reputation`, `total_votes`, `tags`, `last_analysis_date`. File: `first_submission_date`, `last_submission_date`, `popular_threat_classification.suggested_threat_label`, `meaningful_name`, `type_tag`. IP: `as_owner`, `country` |
| Permalink | `https://www.virustotal.com/gui/{file\|ip-address\|domain\|url}/{id}` |
| ToS | Public API must not be used in commercial products or workflows. Multiple accounts are banned [doc] |

## AbuseIPDB v2 (IP only)
| Item | Value |
|---|---|
| Auth | `Key` header plus `Accept: application/json` [doc] |
| Endpoint | `GET https://api.abuseipdb.com/api/v2/check?ipAddress=&maxAgeInDays=90[&verbose]`. URL-encode IPv6 [doc] |
| Quota (free) | 1,000 checks/day [doc] |
| 429 | Returns `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` (epoch) and `Retry-After` (seconds) [doc] |
| Not found | Never 404: returns `abuseConfidenceScore: 0`, `totalReports: 0`. Invalid IP returns 422 [~] |
| Fields | `abuseConfidenceScore` (0-100), `totalReports`, `numDistinctUsers`, `lastReportedAt`, `isWhitelisted`, `isTor`, `usageType`, `isp`, `countryCode`, plus report `categories` when verbose |
| Permalink | `https://www.abuseipdb.com/check/{ip}` |

## URLhaus (abuse.ch)
| Item | Value |
|---|---|
| Auth | `Auth-Key` header, **mandatory on every request** [doc]. One free key from auth.abuse.ch covers URLhaus, MalwareBazaar and ThreatFox |
| URL | `POST https://urlhaus-api.abuse.ch/v1/url/` form `url=` |
| Domain/IP | `POST /v1/host/` form `host=` |
| Hash | `POST /v1/payload/` form `md5_hash=` or `sha256_hash=` (no SHA1) |
| Quota | Fair use, with no published numbers. Expect 401/403 on a bad key [~] |
| Not found | HTTP 200 with `query_status: "no_results"`. Errors also return 200 with `invalid_url` or `http_post_expected`, so check `query_status`, not only the HTTP status |
| Fields | `url_status` (online/offline/unknown), `threat`, `tags`, `date_added`, `last_online`, `blacklists` (spamhaus_dbl, surbl), `payloads[].signature`; host: `firstseen`, `url_count`; payload: `firstseen`, `lastseen`, `signature`, `virustotal` |
| Permalink | `urlhaus_reference` field |

## MalwareBazaar (abuse.ch, hash only)
| Item | Value |
|---|---|
| Auth | `Auth-Key` header, required [doc] |
| Endpoint | `POST https://mb-api.abuse.ch/api/v1/` form `query=get_info&hash=<md5\|sha1\|sha256>` [doc] |
| Not found | HTTP 200 with `query_status: "hash_not_found"`. Also `illegal_hash` and `no_hash_provided` |
| Fields | `data[0]`: `sha256_hash`, `first_seen`, `last_seen`, `signature` (family), `tags`, `file_type`, `file_name`, `imphash`, `ssdeep`, `tlsh`, `vendor_intel.*`, `intelligence.clamav` |
| Permalink | `https://bazaar.abuse.ch/sample/{sha256}/` |

**abuse.ch ToS (confirmed):** Auth-Key mandatory since 2025. Free access is for authenticated, not-for-profit users within query volume limits. Commercial use needs a Spamhaus subscription, and redistribution or derivative works need consent. A per-user private cache shown with attribution is low risk. Do not republish feeds.

## AlienVault OTX (DirectConnect API v1)
| Item | Value |
|---|---|
| Auth | `X-OTX-API-KEY` header |
| Endpoints | `GET https://otx.alienvault.com/api/v1/indicators/{IPv4\|IPv6\|domain\|hostname\|url\|file}/{value}/{section}`. Use `general`, plus `reputation` for IPs and `analysis` for files [doc] |
| Email | not supported |
| Quota | No published hard limit; the community describes "reasonable use" [~]. Handle a 429 with exponential backoff |
| Not found | 404 with a JSON body [doc]. Some known-but-quiet indicators return 200 with `pulse_info.count: 0`. Treat both as not found |
| Fields | `pulse_info.count`, `pulse_info.pulses[].{name,tags,malware_families,attack_ids,created,modified}`, `reputation`, `validation[]` (allowlist hints), `base_indicator` |
| Permalink | `https://otx.alienvault.com/indicator/{ip\|domain\|hostname\|url\|file}/{value}` |
| Notes | "v2" is the SDK name, not a REST version. Now branded LevelBlue OTX, same host |

## MISP (self-hosted)
| Item | Value |
|---|---|
| Auth | `Authorization: <authkey>` (raw key, no "Bearer"), plus `Accept: application/json` and `Content-Type: application/json` |
| Endpoint | `POST {base}/attributes/restSearch` with body `{"returnFormat":"json","value":"<ioc>","limit":50,"page":1,"includeEventTags":true,"includeContext":false,"deleted":false,"enforceWarninglist":true}`. Optionally add `type`, `to_ids`, `published` |
| Types | All IOC types, including `email-src`/`email-dst`, `md5`, `sha1`, `sha256`, `ip-src`/`ip-dst`, `domain`, `hostname`, `url` |
| Not found | 200 with `{"response":{"Attribute":[]}}` |
| Fields | `Attribute[].{type,category,to_ids,first_seen,last_seen,timestamp,event_id,Event.info,Event.uuid,Tag[].name}`. Tags carry TLP and galaxy clusters (families, ATT&CK) |
| Permalink | `{base}/events/view/{event_id}` |
| TLS | Settings `MISP_VERIFY_TLS` (bool) and `MISP_CA_BUNDLE` (path). Build an `ssl.create_default_context(cafile=...)` and pass it to `httpx.AsyncClient(verify=ctx)`, because httpx 0.28 deprecated string paths for `verify`. Allow `verify=False` only with a loud startup warning |
| Rate | Not applicable. Self-imposed concurrency limit of 4 |

## MITRE ATT&CK (offline)
- **Source:** `mitre-attack/attack-stix-data` (STIX 2.1, collections, versioned files `enterprise-attack/enterprise-attack-<ver>.json`, plus `index.json`). It is preferred over `mitre/cti`, which is STIX 2.0 legacy.
- **Version:** latest is v20.0 (2026-10-13) per `index.md` [doc, verify]. v19 (2026-04-28) **split Defense Evasion into "Stealth" and "Defense Impairment"**, so capa/heuristic tactic strings may be stale. Map by T-id only and take tactics from the bundle.
- **Size:** the full bundle is about 40-50 MB [~], too big to ship. Write a build-time script (`scripts/build_attack_index.py`) that downloads a pinned version, checks its sha256, and emits a compact `attack_enterprise_v20.json` (~300 KB). Fields: `T-id -> {name, tactics[] (kill_chain_phases), is_subtechnique, parent, deprecated, revoked_by, url}`. Commit that file with the version recorded in it, and resolve revoked T-ids via `revoked-by` relationships.
- **License:** ATT&CK Terms of Use give a royalty-free license to use and redistribute. Include the MITRE copyright notice in the UI or about page.
- **Libraries:** none needed at runtime; plain `json` is enough. `mitreattack-python` is acceptable in the build script only, but it is heavy.

## Libraries vs httpx
Use plain httpx: one `httpx.AsyncClient` per provider inside our own `BaseProvider` (timeouts, retries, rate limits, normalization). The libraries are worse fits: `vt-py` adds aiohttp as a second HTTP stack, `pymisp` is heavy and sync-centric, and `OTXv2` is sync and barely maintained. Each adapter is about 60 lines of httpx. Retries: honor `Retry-After`, otherwise use exponential backoff with jitter. Rate limits: a Redis token bucket per provider (VT 4/min plus a daily counter; AbuseIPDB a daily counter).

## Normalized result (verdict-free)
`{provider, ioc_type, ioc, found: bool, score: float|None (provider-native, with scale noted), detections: {malicious, suspicious, total}|None, tags[], families[], attack_ids[], first_seen, last_seen, permalink, raw_ref (cached raw JSON id), fetched_at, error: None|"rate_limited"|"auth"|"unavailable"}`

## Test strategy
- **Mocks:** `respx` mocks for every adapter. Fixtures live in `tests/fixtures/providers/<name>/{hit,not_found,rate_limited}.json`. They are handcrafted from the docs or captured once locally and scrubbed, never with real keys.
- **Required cases:** hit; not found (VT/OTX 404, abuse.ch `no_results`/`hash_not_found`, MISP empty, AbuseIPDB score 0); 429 with and without Retry-After; 401; timeout; malformed JSON; MISP TLS verify off/on.
- **Path guard:** assert that only allowlisted paths are hit, using `respx` with `assert_all_mocked=True`, so no upload endpoint can slip in.
- **Live smoke tests:** mark them `@pytest.mark.live`. They are skipped unless `CYBERLAB_LIVE_TI=1` and keys are present, and excluded from CI. Configure CI with dummy keys.
- If VCR is used, `filter_headers=["x-apikey","Key","Auth-Key","X-OTX-API-KEY","Authorization"]`.

## Open questions
- OTX real rate limit (undocumented).
- Exact v19 tactic IDs for Stealth and Defense Impairment.
- Whether abuse.ch returns 401 or a 200 with an error `query_status` for a bad key. Confirm with one manual call.
