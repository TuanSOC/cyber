# M4 Threat Intelligence — architecture research

## Findings from the codebase

- **The `backend` network is not internal.** Today the api, the ingest worker, Postgres and both Redis instances all have outbound internet access. "Only enrich has egress" requires setting `backend: internal: true`.
- **`audit.sanitize()` lets API keys through.** It only drops keys matching `password|token|secret`, so `api_key` and `authorization` are kept. Widen the pattern first.
- **IOC values are not safe to send as they are:**
  - static IPv4 IOCs keep RFC1918 and CGNAT addresses;
  - pcap domains include `.local` and `.internal` queries;
  - `iocs` is append-only, stored per job and not normalized.

  So the trusted side must normalize and filter before anything is sent out.
- **Dependencies:** `cryptography` is missing. `httpx` is dev-only and must become a runtime dependency. `httpx.MockTransport` is enough for tests, so `respx` is not needed.
- **Org lookup:** `test_tenant_session_guard.py` allowlists org-scoped sessions. A worker must resolve the org from a system index, as with `analysis_job_index`.

## 1. API key storage

**Recommendation: a sealed box. The API only encrypts; only the enrich-worker can decrypt.**
- **Scheme:** an ephemeral X25519 key, HKDF-SHA256, then AES-256-GCM, all from `cryptography`.
- **Columns:** `key_kid`, `key_epk`, `key_nonce`, `key_ct`, `key_last4`.
- **AAD:** `cyberlab.ti.v1|{org_id}|{provider}|{kid}`.
- **Key placement:**
  - the API holds only the public keys (`TI_SEAL_PUBLIC_KEYS`, `TI_SEAL_ACTIVE_KID`);
  - the worker gets `TI_SEAL_PRIVATE_KEYS_FILE` as a Docker secret.
- **Why:** if the API is compromised, the stored keys still cannot be decrypted.
- **Fallback:** a symmetric AES-GCM key-encryption key (KEK) in both processes.

**Never returned to the browser.** The read model is `configured`, `last4`, `enabled`, `verified_at`, `verify_status`, `last_error_code` and the MISP `base_url`. The key itself is write-only on `PUT` (`SecretStr`, at most 256 characters) and is never echoed or logged.

**Who can do what:**

| Action | Permission | Roles |
|---|---|---|
| Set or remove keys | new `Permission.INTEGRATIONS_MANAGE` in `_ADMIN` | owner, admin |
| Read integration status | `ORG_READ` | all |
| Request an enrichment | `EVIDENCE_WRITE` | analyst and up |
| Read results | `EVIDENCE_READ` | all |

**Audit events:**
- `integration.key_set`, `integration.key_replaced` (provider, last4, kid);
- `integration.key_removed`, `integration.updated`;
- `integration.verified`, `integration.verify_failed` (actor NULL);
- `ti.enrichment_requested`.

**Rotating the sealing key:**
1. Deploy `kid2`: its public key to the API, both private keys to the worker.
2. Make `kid2` the active kid.
3. The worker re-seals `kid1` rows lazily, each time it decrypts one.
4. `scripts/reseal_ti_keys.py` re-seals the rest. It uses the owner role through an owner-only policy, because FORCE RLS also binds the owner.
5. Drop `kid1`.

A provider's own key is rotated with a new `PUT`, audited as `key_replaced`.

**Why not pgcrypto:**
- the master key travels in SQL parameters, which can show up in `pg_stat_activity` and logs;
- the key and the ciphertext live in the same place;
- there is no AAD binding;
- rotation happens in SQL.

## 2. Where enrichment runs

- **Queue and worker:** a new `enrich` queue on the existing redis-broker. A trusted `enrich-worker` (api image, `-Q enrich --pool solo`) consumes it and reuses the `run()` loop.
- **Publishing:** the API never calls providers. It commits a run, then calls `send_task("ti.enrich", {run_id, org_id})` with the same timeout and limiter as `dispatch.send()`.
- **Org lookup:** a `ti_run_index` system table (like `analysis_job_index`) gives the worker the run's org, and the message's org must match it. Allowlist `workers/enrich.py` in the guard test.

**Compose:**
- add an `egress` bridge network that only enrich-worker joins, besides `backend`; it never joins `analysis`;
- set `backend: internal: true` (the gateway still publishes through `frontend`);
- run enrich-worker `read_only`, with `cap_drop: [ALL]` and `no-new-privileges`.

**Broker ACL:**
- New user: `user enrich … resetkeys ~enrich* ~test.enrich* ~trusted.* ~test.trusted.* ~_kombu.binding.*enrich* … ${DENY} ${READ_DENY}`. It has no access to the ingest, pcap or static queues.
- `api` and `ingest` (`~*`) can publish to `enrich`, which gives beat its housekeeping path.
- The analyzer users cannot reach `enrich*`. Add a test for it.

## 3. Cache

- **Where:** Postgres `ti_results` is both the history and the cache. A hit is the newest `ok` or `not_found` row with `expires_at > now()`.
- **Redis role:** buckets, cooldowns and in-flight dedupe (`SET NX … EX 60`) only, never cached results. It is not persistent, it is flushed per test, and it is shared.
- **Key:** `(organization_id, provider, ioc_type, value_norm)`, with `ioc_key = sha256(type‖0‖value_norm)` and an index on `(org, ioc_key, provider, fetched_at DESC)`.

**TTL:**

| Lookup | TTL |
|---|---|
| hash | 72 h |
| IP | 12 h (AbuseIPDB 6 h) |
| domain | 24 h |
| URL | 12 h |
| MISP | 1 h |
| `not_found` | ¼ of the TTL above (hashes at most 6 h) |
| errors, 429 | never cached |

**Cache per org, not shared.**
- **Why:** a shared cache tells org B that someone looked up a rare IOC at time T. It would also spend another org's quota and break provider terms of use.
- **MISP:** always per org.
- **ATT&CK:** not a lookup. Load a pinned STIX bundle into a global `attack_techniques` table and use it to label capa's ATT&CK ids.

## 4. Rate limiting

- **Per provider and org:** a Lua token bucket in the app Redis (`ti:rl:{provider}:{org}`).
  - Defaults follow the free tiers: VT 4/min and 500/day, AbuseIPDB 1000/day.
  - An org may lower the limits, but not raise them above a settings ceiling.
  - A daily counter gives `quota_exhausted`.

**Provider responses:**

| Response | Handling |
|---|---|
| 429 | Parse `Retry-After` (seconds or a date, clamped to 1–3600 s). Set the cooldown key `ti:cool:{provider}:{org}`, mark the remaining lookups `rate_limited`, and `self.retry(countdown=…)` until the deadline. |
| 401 / 403 | `verify_status=invalid`; stop that provider. |
| 5xx / timeout | 3 attempts with full-jitter backoff. |

**Concurrency:** one `anyio.Semaphore` per provider (at most 4) plus a global one (at most 16). ZSET leases, as in `upload_slots.py`, cover multiple replicas.

**Partial results:** every (IOC, provider) pair gets its own status. A run ends `completed` or `partial`, with its counts in `summary`.

## 5. Data model (migrations 0009–0010)

| Table | Scope / grants | Columns |
|---|---|---|
| `ti_provider_configs` | tenant RLS; S/I/U/D | `provider` (check), `enabled`, `base_url` (NOT NULL iff misp), sealed-key columns, `key_last4`, `verify_status`, `verified_at`, `last_error_code`, `limits`; unique (org, provider) |
| `ti_enrichment_runs` | tenant; S/I/U + status trigger | `requested_by`, `job_id` (composite FK to `analysis_jobs`), `scope`, `status`, `providers`, `summary`, `deadline_at` |
| `ti_run_index` | system lookup | run → org, status, deadline (reaper) |
| `ti_results` | tenant, append-only (S/I + `forbid_mutation`) | `run_id`, `provider`, `ioc_type`, `value_norm`, `ioc_key`, `status` (ok / not_found / error / rate_limited / quota_exhausted / skipped_*), `detections`, `score`, `summary` (strict per-provider model, at most 16 KiB, no raw body), `permalink`, `fetched_at`, `expires_at` |

**Linking to IOCs: `iocs` stays unchanged.**
- **IOC list:** the API normalizes the page (at most 100 values) in Python, then reads results with `DISTINCT ON (ioc_key, provider)`.
- **Job runs:** take the distinct pairs from `iocs`, capped by `TI_MAX_IOCS_PER_RUN`.

**`normalize.py`** (pure) returns `Normalized | Skip(reason)`:

| Input | Rule |
|---|---|
| refanging | `hxxp`, `[.]`, `(.)`, `[dot]`, `[:]`, `[@]` |
| IP | must be `is_global` after unwrapping IPv4-mapped addresses (excludes private, loopback, link-local, CGNAT, documentation and reserved ranges); stored compressed |
| domain | lowercase, IDNA to punycode, at most 253 characters; skip single labels, special-use TLDs (`local`, `localhost`, `internal`, `lan`, `home.arpa`, `corp`, `test`, `example`, `invalid`, `onion`) and per-org excluded suffixes |
| URL | `http(s)` only; host must pass the IP / domain rules; skip if it has userinfo |
| hash | lowercase hex; length must match the type |
| email, registry key, path, JA3, cert | never sent |

## 6. SSRF and egress safety

- **Fixed providers** use constant hostnames.
- **MISP `base_url`** is validated on save and again before every request:
  - `https` only, no userinfo, port 443 or an allowlisted port;
  - resolve the host and reject it if any address is not global;
  - connect to the pinned IP with `Host` and the `sni_hostname` extension, so TLS still verifies the name.
- **Self-hosted MISP in dev:** `TI_MISP_ALLOW_PRIVATE` is false by default. When true, it allows private addresses and `TI_MISP_CA_FILE`. `_prod_guards` refuses it in prod.
- **HTTP client:**
  - `trust_env=False`, `follow_redirects=False`, `verify=True`;
  - timeouts of 3 s connect, 10 s read and 20 s total;
  - streamed bodies capped at 1 MiB (2 MiB for MISP), then parsed into strict models.
- **What leaves the host:** lookups only. No file uploads and no URL scan submissions. A sample is sent only as hashes from `malware_samples`.
- **Provider text is untrusted:**
  - render it as text;
  - M5 must treat it as prompt-injection input;
  - reputation is shown with its source and timestamp, never as a verdict or a severity.

## 7. Testing and the success metric

- **Mocking:** inject the transport with `get_ti_http(transport=None)` and use `httpx.MockTransport`. CI makes no real egress calls.
- **Unit tests:**
  - normalize: refang cases, `100.64.0.1`, `::ffff:10.0.0.1`, `2001:db8::1`, `.local`, IDN;
  - seal: round trip; another org's or provider's AAD, a wrong kid or a flipped byte must fail;
  - `Retry-After` parsing;
  - SSRF: a fake resolver returning private and rebinding answers, redirects, oversized bodies.
- **Integration tests:**
  - the secret is absent from responses, audit details, errors and logs;
  - RBAC: an analyst `PUT` gets 403;
  - org B cannot see org A's results;
  - `ti_results` is append-only;
  - the IDOR, RLS-coverage and guard tests auto-enumerate the new routes and tables;
  - the token bucket runs against Redis db 1;
  - fault injection: 429 gives `rate_limited` and a requeue; 401 gives `invalid`; 5xx gives `error`; the run ends `partial`.
- **Isolation tests:**
  - the `enrich` broker ACL is confined to its own keys;
  - the analyzers cannot write to `enrich*`;
  - the api has no egress.
- **Metric: "IOC enrichment success"** = (`ok` + `not_found`) / eligible lookups attempted, per provider, excluding `skipped_*`.
  - Report it next to cache hit rate, the share of rate-limited lookups and p95 latency.
  - Evaluate it under a seeded fault mix: 10 % 5xx, 5 % 429, 2 % malformed.
  - Record it in TESTING.md and in each run's `summary`.

## Unresolved questions

- Auto-enrichment after ingest: recommend off by default, opt-in per org (it burns quota).
- ATT&CK labelling: M4 or M6?
- Verify current abuse.ch Auth-Key/quota terms.
