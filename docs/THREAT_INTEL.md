# Threat Intelligence (Milestone 4)

M4 looks up IOCs at external reputation providers and shows what each provider said, attributed and never restated as our own verdict. It is **lookup only**: nothing is ever submitted, uploaded or downloaded.

1. The API normalizes the values, drops everything that must not leave the host, and plans the run (the eligible (IOC, provider) pairs) in one transaction. It never calls a provider and never resolves an external name.
2. The trusted **enrich-worker**, the only service with internet egress, opens the org's sealed key and calls the provider in short time slices, under per-org rate limits.
3. Every real answer is stored in an append-only, per-org history (`ti_results`), which is also the cache.
4. The UI shows source-attributed chips and panels on IOC tabs, a manual lookup page and a per-IOC history.

ATT&CK technique labels come from an offline, pinned index (no provider). Network and trust layout: [ARCHITECTURE.md](ARCHITECTURE.md#threat-intelligence-m4); threats and residuals: [THREAT_MODEL.md](THREAT_MODEL.md#m4-threat-intelligence).

## Providers

Every provider is **bring your own key**, opt-in per org, and disabled until an admin stores a key and acknowledges its terms. Metadata (types, limits, ToS and privacy notes) is data in `app/modules/threat_intel/catalog.py`; adapters live in `threat_intel/providers/`. Plain httpx, no vendor SDKs. Each adapter has a path allowlist: any other request (submission, upload, download, `/users/{id}`) raises `PathNotAllowed` before it is sent.

| Provider | IOC types | Requests (the only ones allowed) | Key header | Default limit = ceiling | Permalink |
|---|---|---|---|---|---|
| VirusTotal v3 | ip, domain, url, md5, sha1, sha256 | `GET https://www.virustotal.com/api/v3/{ip_addresses,domains,urls,files}/{id}` (URL id = unpadded base64url of the URL); verify = lookup of the EICAR sha256 | `x-apikey` | 4/min, 500/day | `https://www.virustotal.com/gui/{ip-address,domain,file}/{value}`; URLs `…/gui/url/{VT's sha256 id}` |
| AbuseIPDB v2 | ipv4, ipv6 | `GET https://api.abuseipdb.com/api/v2/check` (`maxAgeInDays=90`); verify = check of `8.8.8.8` (costs one check) | `Key` | 30/min, 1000/day | `https://www.abuseipdb.com/check/{ip}` |
| URLhaus (abuse.ch) | ip, domain, url, md5, sha256 | `POST https://urlhaus-api.abuse.ch/v1/{url,host,payload}/`; verify = payload lookup of the EICAR sha256 | `Auth-Key` | 30/min, 2000/day | the response's `urlhaus_reference` only if it is `https://urlhaus.abuse.ch/…`; hosts `https://urlhaus.abuse.ch/host/{value}/`; payloads `…/browse.php?search={hash}` |
| MalwareBazaar (abuse.ch) | md5, sha1, sha256 | `POST https://mb-api.abuse.ch/api/v1/` with `query=get_info` only (never `get_file` or an upload) | `Auth-Key` (the abuse.ch key, stored per provider) | 30/min, 2000/day | `https://bazaar.abuse.ch/sample/{sha256}/` |
| AlienVault OTX | ip, domain, url, md5, sha1, sha256 | `GET https://otx.alienvault.com/api/v1/indicators/{IPv4,IPv6,domain,url,file}/{value}/general`; verify = `GET /api/v1/user/me` | `X-OTX-API-KEY` | 30/min, 5000/day | `https://otx.alienvault.com/indicator/{ip,domain,url,file}/{value}` |
| MISP (your own) | ip, domain, url, hashes, **email** | `POST {base_url}/attributes/restSearch`; verify = `GET {base_url}/servers/getVersion` | `Authorization` (raw key, MISP convention) | 120/min, no daily cap | `{base_url}/events/view/{numeric event id}` |
| `mock` (dev/test) | all | `GET {TI_MOCK_BASE_URL}/v1/lookup/{type}/{value}`, `/v1/verify` | `X-Mock-Key` | 6000/min | none |

- **Concurrency:** at most 4 requests per provider and 16 in total inside one worker slice.
- **Limits are self-imposed.** An org may lower `per_minute` / `per_day` on the Integrations page, never raise them above the ceiling (`422 limit_above_ceiling`). An operator with a paid tier raises a ceiling with `TI_CEILINGS` (JSON `{provider: {per_minute, per_day, concurrency}}`). Set `per_day` explicitly there: an override without it means no daily cap.
- **Quotas are unverified against the live API.** The numbers above come from the providers' documentation (VT public: 4/min, 500/day, reset 00:00 UTC; AbuseIPDB free: 1,000 checks/day) or are conservative guesses where nothing is published (abuse.ch "fair use", OTX). No live run has been recorded yet. Opt-in live smoke tests exist (`tests/unit/test_ti_provider_live.py`, `CYBERLAB_LIVE_TI=1`, never in the gate). The abuse.ch bad-key answer is handled both ways (HTTP 401/403 or a 200 with `query_status` such as `unknown_auth_key`).
- **The `mock` provider** exists only when `ENV` is not `prod` and `TI_MOCK_ENABLED=true`. It talks to `ti-mock` (`infra/ti-mock/server.py`, test and e2e profiles, on `egress` only), which answers deterministically by IOC value (hit, not found, 429 with or without `Retry-After`, 401 for a wrong key, 500, slow, oversize, redirect, malformed). In prod the catalog shows it unavailable and `PUT` answers `422 provider_unavailable`.

### Terms of service

| Provider | Note shown on its card |
|---|---|
| VirusTotal | The public API must not be used in commercial products or workflows; one person may hold only one account. Commercial use needs a premium key. |
| AbuseIPDB | Free plan: 1,000 checks per day. Results are community reports, quoted with attribution. |
| URLhaus, MalwareBazaar | abuse.ch free access is for not-for-profit use within fair-use volumes; commercial use needs a Spamhaus subscription, and redistribution needs consent. MalwareBazaar receives hashes only, never files. |
| OTX | LevelBlue (AlienVault) OTX terms apply; no published hard limit, so CyberLab keeps a conservative one. |
| MISP | Your own instance: its sharing rules and the TLP markings of its events apply. |

**A commercial deployment needs paid tiers** for VirusTotal and abuse.ch. Mitigations in M4: each org brings its own key; the first `enabled=true` requires `acknowledge_terms: true` (stored as `terms_ack_at` / `terms_ack_by`, audited `integration.terms_acknowledged`); there is no cross-org cache and nothing is republished.

## Normalization and eligibility

`threat_intel/normalize.py` is pure (no DNS, sockets or clock) and shared by the API and the worker. Each value becomes a normalized indicator or a `Skip(reason)`; skipped values never leave the host and are listed in the lookup page's normalization report.

| Input | Rule | Skip reason |
|---|---|---|
| any | at most 2048 characters; refang `hxxp`/`fxp`, `[.]`, `(.)`, `{.}`, `[dot]`, `(dot)`, `[:]`, `[@]`, `(@)`, `[at]` (note `refanged`) | `too_long`, `invalid` |
| IP | strict parse (no decimal/octal/short forms, no zone id); IPv4-mapped unwrapped; must be global after also checking addresses embedded in 6to4 (`2002::/16`), NAT64 (`64:ff9b::/96`), Teredo and IPv4-compatible (`::/96`) forms. No private, loopback, link-local, CGNAT, documentation, multicast, reserved, site-local or NAT64 local-use (`64:ff9b:1::/48`) addresses | `not_global_ip` |
| domain | lowercase, IDNA punycode, ≤ 253 characters, ≥ 2 labels, no numeric last label; never a special-use or internal name: the TLDs `local`, `localhost`, `internal`, `lan`, `home`, `corp`, `private`, `intranet`, `localdomain`, `test`, `example`, `invalid`, `onion`, `alt`, **everything under `arpa`** (PTR names encode private IPs), and `example.com/net/org` | `special_use_name`, `single_label` |
| URL | `http`/`https` only, no userinfo, the host passes the IP or domain rule, default port dropped; **query string and fragment removed** before anything is keyed or sent (note `query_removed`: they carry session tokens, reset links and personal data) | `bad_scheme`, `has_userinfo` |
| hash | lowercase hex of 32 / 40 / 64 characters | `invalid` |
| email | valid local part and domain (domain rule above) | — |
| `ja3`, `ja3s`, `cert_sha256`, `registry_key`, `file_path` | never sent anywhere | `unsupported_type` |

Per provider (`eligible()`):
- the org's **excluded suffixes** (Integrations → settings card, ≤ 50) apply to domains, URL hosts and email domains (`excluded_suffix`). Internal hosts under the org's own public domain are only protected once an admin adds the suffix;
- the provider's supported types apply (`unsupported_type`);
- **emails go to MISP (and `mock`) only**;
- only `mock` accepts special-use names, and only under `example.com` (its behaviour names).

A sample is sent only as its trusted hashes. The IOC key is `sha256(type ‖ 0x00 ‖ value_norm)`, computed in Python; `iocs` is unchanged.

## Runs

| Trigger | Limits |
|---|---|
| "Enrich IOCs" on a succeeded analysis job (`POST /orgs/{org}/analyses/{job}/enrichments`) | ≤ `TI_MAX_IOCS_PER_RUN` (200) values; order: sample hashes first, then IOCs by occurrence count; an active run of the same job is returned instead of a new one (200) |
| Manual lookup (`POST /orgs/{org}/ti/lookups`) | ≤ `TI_MAX_LOOKUP_VALUES` (20) values |

Both: 30 requests per user per 10 minutes; 3 active runs per org and 20 overall (`409 enrichment_busy`); providers default to every enabled one. Auto-enrichment after ingest and investigation-wide runs are deferred (RT15).

- **Plan frozen at creation.** One `ti_run_items` row per eligible pair, written with the run in one transaction; nothing ineligible is ever planned.
- **States.** Run: `queued` → `running` ⇄ `waiting` → `completed` / `partial` / `failed` (`queued` / `waiting` may also end directly). Item: `pending` → `done` / `cached` / `abandoned` (reason `rate_limited`, `quota_exhausted`, `deadline` or `auth_failed`).
- **Outcome.** `completed` when every item was answered `ok` / `not_found` or came from the cache; `failed` when no item reached a provider or the cache; `partial` otherwise. The summary keeps honest counts.
- **Time slices (RT6).** One `ti.enrich` message = one slice of at most `TI_SLICE_S` (20 s, enforced with asyncio because the solo pool ignores Celery time limits). Work left → re-published to the tail of the queue (if a token is ready within 2 s) or `waiting` with `resume_at`. A long run never blocks another org's lookup.
- **Lease (RT8).** A slice starts only if it takes the DB lease (`lease_until = now() + 60 s`, renewed every 20 s); a duplicate message exits.
- **Resume.** `ingest-beat` sends `ti.resume` every 30 s. It re-sends `waiting` runs whose `resume_at` has passed, and `queued` / `running` runs with an expired lease that were dispatched more than 2 minutes ago (no Celery ETA anywhere).
- **Deadline.** `TI_RUN_DEADLINE_S` (30 min). The worker checks it at every slice: pending items become `abandoned/deadline` and the run is finalized. If the worker is down, the ingest reaper finalizes runs 10 minutes past their deadline with an expired lease (audited `ti.run_deadline`); it writes no result rows.
- **Free tiers make big runs partial.** 200 IOCs at VirusTotal's 4/min need 50 minutes; the run ends `partial` at the deadline, and the UI says so.

## Cache and TTLs

History is the cache. A hit is the newest `ok` / `not_found` row for (org, provider, IOC key) with `expires_at > now()` (DB clock). It is never shared across orgs. The item records the hit's `result_id`, so a run view shows cached answers too (marked cached).

| Type | `ok` | `not_found` |
|---|---|---|
| hash | 72 h | 6 h |
| IP | 12 h (AbuseIPDB 6 h) | 3 h (AbuseIPDB 1.5 h) |
| domain | 24 h | 6 h |
| URL | 12 h | 3 h |
| MISP, any type | 1 h | 15 min |

`error` and `auth_failed` rows have no `expires_at` and are never served. 429, quota and deadline outcomes are item states, never rows, so the history timeline shows only what a provider actually said. AbuseIPDB never answers "not found": zero reports with confidence 0 is stored as `not_found`. Results are kept forever (no retention policy yet).

## Rate limits, waiting and quotas

The limiter lives on the broker under the enrich worker's own ACL prefix (it has no app Redis, RT2):

| Key | Purpose |
|---|---|
| `enrich.ti:rl:{provider}:{org}` | per-minute token bucket (atomic Lua) |
| `enrich.ti:day:{provider}:{org}:{yyyymmdd}` | UTC daily counter (48 h TTL) |
| `enrich.ti:cool:{provider}:{org}` | cooldown after a 429 or a spent quota (only ever extended) |
| `enrich.ti:strikes:{provider}:{org}` | consecutive 429s (15 min TTL; a real answer clears it) |
| `enrich.ti:verify:{org}:{provider}:{key_version}` | `ti.verify` dedupe (60 s) |

- **Effective limits** = the org's own, capped by the ceiling.
- **No token yet** → wait in the slice, or `waiting` until the token.
- **429** → `Retry-After` (seconds or an HTTP date, clamped to 1–3600 s), else the next minute boundary (VirusTotal sends none). The provider cools down; the run goes `waiting` with `resume_at`. If the cooldown ends after the deadline, that provider's pending items become `abandoned/rate_limited`.
- **Daily cap reached** → that provider's pending items `abandoned/quota_exhausted`, cooldown until 00:00 UTC.
- **VirusTotal quota escalation.** VT's daily-quota 429 looks exactly like its per-minute one. Three consecutive 429s (a burst of in-flight requests counts once) are treated as a spent daily quota, as above.
- **Broker unreachable** → fail closed: no provider call, the run waits 30 s.
- **5xx, timeouts, transport errors** → 3 attempts with full-jitter backoff (0.5 s base, 4 s cap), then an `error` row.
- **401 / 403** → the worker runs the provider's verify once inline (VT answers 403 for some resources with a valid key, RT23). Only a failed verify sets `verify_status=invalid`. The pair gets an `auth_failed` row and the provider's remaining items `abandoned/auth_failed`.

## HTTP client

One `httpx.AsyncClient` per provider and slice (`threat_intel/http.py`):
- `trust_env=False`, `follow_redirects=False`, `verify=True`, fixed `User-Agent`;
- timeouts 3 s connect, 10 s read, 20 s for the whole exchange;
- https on port 443 only (MISP: its base URL's port; `ti-mock`: dev/test only);
- `Accept-Encoding: identity`; a server that compresses anyway is inflated incrementally with the cap applied to the inflated size (compression bombs stop at the cap); other codings are refused;
- body cap 1 MiB (MISP 2 MiB), streamed; error bodies are never read;
- strict JSON: nesting depth ≤ 64, integers ≤ 40 digits, no `NaN` / `Infinity`; any failure is `bad_json` (RT19);
- the key is attached per request by `KeyAuth` (redacted `repr`), never as a client default header: httpx masks only `Authorization` in reprs (RT11). Errors carry no cause chain that could quote a header.

Adapters copy selected fields into strict per-provider summary models (`summaries.py`, ≤ 16 KiB, never the raw body). Strings are stripped of control, bidi and zero-width characters and truncated; permalinks are `https:` only (DB check).

## Keys: sealing and rotation

**Format.** One sealed box per key: ephemeral X25519 → HKDF-SHA256 (salt = epk ‖ recipient public key, info `cyberlab.ti.v1`) → AES-256-GCM with a random 96-bit nonce. AAD = `cyberlab.ti.v1|{org_id}|{provider}|{kid}|{key_version}|{base_url_norm}`; `base_url_norm` is empty except for MISP, so **a MISP key only opens for the URL it was stored with** (RT1). Columns: `key_kid`, `key_version`, `key_epk`, `key_nonce`, `key_ct`, `key_last4`.

| Holder | Holds | Can |
|---|---|---|
| API (`seal.py`) | `TI_SEAL_PUBLIC_KEYS`, `TI_SEAL_ACTIVE_KID` | seal only |
| enrich-worker (`unseal.py`) | the private key file (compose secret `ti_seal_private`) | open, and re-seal under the active kid |
| everything else | nothing | `Settings` refuses `TI_SEAL_PRIVATE_KEYS_FILE` unless `PROCESS_ROLE=enrich`; an AST guard test refuses imports of `unseal`, `http`, the registry and adapters outside `app/workers/enrich*.py` |

- **Write-only.** Keys are 8–256 printable ASCII characters after trimming (422 otherwise, without echoing the value), never echoed, logged or audited; the UI sees `configured`, `key_last4`, `verify_status`, `verified_at`, `last_error_code`. Audit details drop any `*key*`, `authorization`, `token`… field except `key_last4`, `key_kid`, `key_version`, `ioc_key`.
- **Monotonic version (RT18).** A trigger requires a higher `key_version` for a new key; only a re-seal of the same key (same version and last4) under another kid keeps it. Removing a key clears the sealed columns and keeps the version; the app role cannot DELETE a config row (0010).
- **Dev keys.** A fresh clone uses the committed dev pair (kid `dev-1`, `infra/ti/dev-seal-private.json`). `ENV=prod` refuses any `dev-` kid and the dev public key. Prod keys: [DEPLOYMENT.md](DEPLOYMENT.md#prod-like-stack).

### Replace or remove a provider key

1. If the old key may be exposed, revoke it at the provider first.
2. Admin: org settings → Integrations → the provider's card → enter the new key → Save (`PUT /orgs/{org}/integrations/{provider}` with `api_key`). The key is sealed under the active kid with `key_version + 1`, `verify_status` resets to `unverified`, a check is queued (`verify_queued`), and the change is audited `integration.key_replaced` (last4, kid, version only).
3. **MISP URL change:** send the new `base_url` **and** the key together; a URL change alone is refused (`422 key_required_for_url_change`), because the old key is bound to the old URL.
4. Remove: `DELETE /orgs/{org}/integrations/{provider}/key` clears the key and disables the provider (`integration.key_removed`).

### Rotate the sealing key (prod)

The examples use `P="docker compose -f docker-compose.yml -f docker-compose.prod.yml"`.

1. **Add a key to the same file** (keeps the old private key):
   `docker run --rm -v "$PWD:/repo" -w /repo cyberlab/api:dev python scripts/gen_ti_seal_keys.py --add --kid prod-YYYYMMDD`
   It rewrites `.secrets/ti_seal_private.json` (0400, uid 10001) and prints the new public key.
2. **Update `.env`:** merge both public keys into `TI_PROD_SEAL_PUBLIC_KEYS='{"<old>":"…","<new>":"…"}'` and set `TI_PROD_SEAL_ACTIVE_KID=<new>`.
3. **Check it with a one-off enrich-worker container** (same image, env and secret as the service; no DB access needed):
   `$P run --rm --no-deps enrich-worker python -c "from app.core.config import get_settings; from app.workers.enrich import check_startup; check_startup(get_settings()); print('seal keys ok')"`
   It fails with a clear message if the file is unreadable, lacks the active kid, or does not match the published public key.
4. **Recreate** the services that read these settings: `$P up -d --force-recreate api ingest-worker ingest-beat enrich-worker`. New keys are now sealed under the new kid.
5. **Re-seal.** The worker re-seals an old-kid key under the active kid (same `key_version`) the next time it opens it, for a lookup or a verify. To do it now, an admin presses **Verify** on each configured provider (`POST …/integrations/{provider}/verify`, 10 per provider per 10 minutes).
6. **Check what is left** (superuser, which bypasses RLS):
   `$P exec postgres psql -U postgres -d cyberlab -c "SELECT key_kid, count(*) FROM ti_provider_configs WHERE key_ct IS NOT NULL GROUP BY key_kid"`
7. **Drop the old kid** once no row uses it: remove its entry from the private file (as root, keeping mode 0400 and owner 10001) and from `TI_PROD_SEAL_PUBLIC_KEYS`, then repeat steps 3–4. A key still sealed under a dropped kid can no longer be opened (`last_error_code=unknown_kid`, its items `abandoned/auth_failed`): the org re-enters it.

If the private key file itself leaked, treat every stored provider key as exposed: rotate the sealing key **and** have every org replace its provider keys at the providers.

The plan's batch re-seal script (`scripts/reseal_ti_keys.py`, run with the owner DB URL) was not built; re-sealing is lazy (step 5).

## MISP and SSRF

The org supplies the MISP URL, so it is checked twice.

**On save (API, syntax only, no DNS: the API has no egress, RT5)** — `ssrf.validate_base_url`, `422 misp_url_invalid` with a fixed reason, never the URL:
- `https` only; no userinfo, query or fragment; ≤ 512 characters;
- port 443 or one of `TI_MISP_ALLOWED_PORTS` (default 443, 8443);
- host: an IDNA name that is not special-use (the domain rules above) and not IPv4-like (`10.0.0.0x1`, `misp.123`), or a global IP literal;
- a path prefix of ≤ 256 characters of `[A-Za-z0-9._~-]` segments;
- the normalized form (`base_url_norm`) is stored and bound into the seal AAD. A save with a new key or URL queues a verify.

**Before every request (worker)** — `ssrf.PinnedTransport`:
- the host is resolved (a pool of 4 resolver threads, 2 s timeout; if all are busy, `dns_busy` instead of queueing), and **every** answer must be global, otherwise `misp_url_not_public` (shown as the integration's `last_error_code` after a verify);
- the request goes to the first validated address with `Host` and TLS SNI set to the hostname, so the certificate is still verified against the name (no DNS rebinding between check and connect);
- no redirects; only `restSearch` and `getVersion`; 2 MiB body cap;
- optional private CA bundle: `TI_MISP_CA_FILE`.

**Dev-only flags** (refused by `_prod_guards` when `ENV=prod`): `TI_MISP_ALLOW_PRIVATE` (private ranges allowed; loopback, link-local/metadata and unspecified never) and `TI_MISP_INSECURE_TLS`. Compose does not pass either; set them on the enrich-worker (and the API for the save check) explicitly.

MISP summaries keep up to 20 attributes, the TLP markings seen (most restrictive first, so RED and AMBER are never cut by the cap of 4), and ATT&CK galaxy tags as `attack_ids`. TLP is shown, not enforced. MISP answers never become IOC sources and are never forwarded to another provider.

## ATT&CK index

- **Source:** the pinned Enterprise bundle of `mitre-attack/attack-stix-data` (v20.0, sha256 `81113ba9…4352`), compacted to `apps/api/app/modules/attack/data/attack_enterprise_v20.0.json` (T-id → name, tactics, sub-technique / parent, deprecated, revoked_by, url). Committed; validated when the API starts.
- **Use:** labels by T-id only, for capa capabilities, findings, OTX `attack_ids` and MISP galaxy tags. A revoked id resolves to its replacement; deprecated ids are flagged. Tactics come from the bundle only, never from capa strings (since v19, Defense Evasion is split into "Stealth" and "Defense Impairment").
- **Route:** `GET /api/v1/attack/techniques?ids=T1055,T1059.001` (signed in; ≤ 100 ids, `422 invalid_attack_ids`) returns `meta` (version, spec, build time, notice), `techniques` and `unknown`.
- **Notice** (in `meta`, shown under every list of labels): "© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."

**Update** (a maintainer, on a host with internet; stdlib only):
1. Pick the newest Enterprise entry in `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json`, download it and compute its sha256.
2. `python scripts/build_attack_index.py --version <X.Y> --sha256 <hex>` (`--input <file>` builds from the downloaded bundle). It aborts on a sha256 mismatch; the same input always gives the same bytes.
3. Record the new pin (`DEFAULT_VERSION`, `DEFAULT_SHA256`) in the script, delete the old index file, set `INDEX_VERSION` in `app/modules/attack/index.py`, run the API tests, commit, rebuild the API image.

## Presentation policy (verdict-free)

- **Attributed.** "Reported by VirusTotal on 2026-11-05: 71 engines: 12 report malicious"; "AbuseIPDB confidence 87/100"; "URLhaus listed"; "OTX 3 pulses"; "MISP 2 events"; "… · stale" past `expires_at`. Provider labels and scores are quoted with their scale, never restated as ours.
- **Neutral styling.** Chips are not coloured red/green by count or score (RT20); a wording test covers the templates.
- **No verdicts.** TI never creates findings or changes severity in M4. Reputation is never sole evidence; M5 must follow the same rule.
- **Untrusted text.** Provider strings are sanitized, rendered as text only, and links are only server-built `https:` permalinks. M5 must treat provider text as prompt-injection input.
- **Privacy notice.** Each card says what the provider will learn ("Every enabled lookup tells {provider} which indicators your organization is investigating …"); the lookup page repeats it.

## Metric: IOC enrichment success

Resilience under synthetic faults, not provider quality (RT24): 600 lookups over the six real adapters' fixture handlers, seeded fault mix (10% 5xx, 5% 429, 2% malformed JSON, 1% timeout), virtual clock. Success = (`ok` + `not_found`) / items that reached a provider; skipped and cached items are reported separately. Floors: ≥ 0.95 per provider and 0 ineligible values sent. Harness: `apps/api/tests/ti/test_enrichment_metric.py` and `scripts/ti_eval.py`.

| Provider | Lookups | Success | Errors |
|---|---|---|---|
| VirusTotal | 100 | 1.000 | 0 |
| AbuseIPDB | 100 | 0.970 | 3 |
| URLhaus | 100 | 0.970 | 3 |
| MalwareBazaar | 100 | 0.990 | 1 |
| OTX | 100 | 0.970 | 3 |
| MISP | 100 | 0.970 | 3 |
| **All** | **600** | **0.978** | **13** |

- **Eligibility:** 245 ineligible values were submitted and skipped; 0 reached a provider.
- **Abandoned:** none (0 rate_limited, 0 quota_exhausted, 0 deadline).
- **Latency:** 729 requests; virtual p95 per request 1.08 s, p95 time to answer ~59 s (429 cooldowns). The pass took 29.5 virtual minutes, paced by VirusTotal's 4/min.
- **Cache (2nd pass):** 587 of 600 served from cache (0.978), i.e. every `ok` / `not_found` answer.
- Counts are identical from run to run (a retry that would cross a slice's end waits for the next slice instead of becoming an error); only slice counts and time to answer move with task timing. Full report: `plans/reports/ti-metric-261105.md`.

## Share policy and IOC collections (M6)

- **Enrichment refused by policy.** A case with `ti_excluded`, an evidence item with its own `ti_excluded` flag, or a case at **TLP:RED** (which implies both exclusions) refuses job-scope enrichments: `POST …/analyses/{job_id}/enrichments` answers `409 policy_blocked` with `reason` (`tlp_red`, `case_ti_excluded`, `evidence_ti_excluded`). The enrich-worker re-checks before each provider slice; a flag set after the request ends the run without a further provider call (its pending items are abandoned with the new `ti_run_items.reason` `policy_blocked`). Turning a flag off needs `integrations.manage` and is audited. Details: [REPORTS.md](REPORTS.md#share-policy-do-not-send-to-ai--ti).
- **Manual lookups are not checked** (`POST /ti/lookups` carries no case scope; residual). The case and evidence pages hide "Look up" and "Enrich" while the case or evidence blocks TI.
- **IOC collections** normalize items with the same normalizer and `compute_ioc_key`, so a collection item joins its `ti_results` history by `ioc_key` (the item list shows the latest answer per provider, attributed as everywhere). Values that are never sent (private IPs, internal names) stay in a collection with `ti_eligible=false`. Reports embed the latest TI answer per provider for the selected IOCs, attributed and verdict-free.

## Limitations

- **Unverified quotas and behaviour.** No provider has been checked with a live call yet; adapters are tested against handcrafted fixtures.
- **Free tiers.** Non-commercial terms (VT, abuse.ch) and small quotas; big job runs end `partial`.
- **One enrich-worker replica** (solo pool). Fairness comes from time slices, not parallelism; no scale-out.
- **Egress.** The enrich-worker has unrestricted internet (no proxy or hostname allowlist) and the full app DB role. Accepted residuals: [THREAT_MODEL.md](THREAT_MODEL.md#m4-threat-intelligence).
- **Disclosure.** Every lookup tells a third party what the org investigates (hash lookups reveal the org holds a file). There are no TLP labels on evidence or cases; the per-provider acknowledgement is the only consent record.
- **Not in M4:** auto-enrichment after ingest, investigation-scope runs, submission or download, feeds (TAXII, MISP sync, OTX pulses), other providers, a cross-org cache, scheduled re-enrichment, `ti_results` retention, a dedicated enrich DB role, the batch re-seal script, ICS/Mobile ATT&CK.
