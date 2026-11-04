---
title: CyberLab M4 Threat Intelligence
description: >-
  Lookup-only IOC enrichment from VirusTotal, AbuseIPDB, URLhaus, MalwareBazaar,
  AlienVault OTX and MISP via a trusted, least-privilege enrich-worker that
  alone has egress; offline MITRE ATT&CK index; sealed per-org API keys (API
  encrypts only, MISP keys bound to their URL); per-org append-only result
  history used as the cache; broker-side token buckets; time-sliced runs;
  verdict-free, source-attributed UI (Integrations page, enrichment panels, IOC
  lookup).
status: completed
priority: P1
effort: 73h
branch: feat/m4-threat-intel
tags:
  - feature
  - threat-intel
  - security
blockedBy:
  - 261105-0900-cyberlab-m3-malware-static
blocks: []
created: '2026-11-04T15:44:33.764Z'
createdBy: 'ck:plan'
source: skill
---

# CyberLab M4 Threat Intelligence

## Overview

`requirement.txt` §8 asks for provider interfaces for VirusTotal, AbuseIPDB, URLhaus, AlienVault OTX, MalwareBazaar, MISP and MITRE ATT&CK, with:
- IOC lookup and reputation enrichment;
- source attribution;
- a cache and rate-limit handling;
- API key management, with keys encrypted and never exposed to the browser;
- historical enrichment results.

§14 adds the metric "IOC enrichment success". The plan builds on M3 (e3468ff).

Inputs: `plans/reports/researcher-261105-m4-providers.md` (provider endpoints, quotas, fields) and `plans/reports/researcher-261105-m4-architecture.md` (key sealing, worker, cache, SSRF). This plan follows the architecture report except where it says otherwise below; the differences are marked **(deviation)**. The red-team pass (RT1–RT28, table below) changed the plan in place.

## Architecture (decided)

    trigger (manual IOC lookup | analysis job IOC set)
      -> API: normalize + eligibility; in ONE transaction insert ti_enrichment_runs,
         ti_run_index and the planned ti_run_items (eligible (IOC, provider) pairs), commit
      -> send_task ti.enrich {run_id, org_id} -> broker queue `enrich`
      -> enrich-worker (TRUSTED, api image, `backend` + `egress` networks, least-privilege env)
         -> org from ti_run_index (must match the message); take the run lease; tenant_session(org)
         -> one time slice (<= TI_SLICE_S, 20 s) over pending items:
            cache check (ti_results, unexpired ok/not_found) -> item `cached`
            else token bucket + daily cap (broker Redis, enrich-prefixed keys)
              -> unseal key -> provider adapter (httpx) -> strict summary model
              -> INSERT ti_results (append-only) -> item `done`
         -> work left: re-publish ti.enrich to the queue tail (tokens ready) or `waiting` + resume_at
         -> nothing left: run ends completed | partial | failed, counts in summary
      -> UI polls the run; IOC tabs and the lookup page read the latest result per provider

**Trust and network**
- **The API never calls a provider and never resolves external names.**
  - Provider adapter, registry, HTTP-client and unseal modules may only be imported from `app/workers/enrich*.py` (AST guard test on module imports, like the tenancy guard); the shared `providers/base.py` types are exempt.
  - The API container has no egress at all: `backend` becomes `internal: true`. MISP URLs are checked syntactically by the API and resolved only by the worker (RT5).
- **`enrich-worker`** (api image) is the only service on a new non-internal `egress` network; it also joins `backend`, never `analysis`.
  - Command: `celery -A app.workers.enrich_app worker -Q enrich --pool solo --without-gossip --without-mingle --without-heartbeat`; remote control and task events off (RT7).
  - Hardening: `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, tmpfs `/tmp`.
  - **Least-privilege env (RT2):** its own `x-enrich-env` anchor, never `*api-env`. It gets `ENV`, `PROCESS_ROLE=enrich`, `DATABASE_URL` (app role), its broker URL, `QUEUE_PREFIX` and the `TI_*` settings. It has **no** `JWT_SECRET`, **no** MinIO credentials and **no** app `REDIS_URL` (`Settings` refuses them when `PROCESS_ROLE=enrich`). It holds the sealing private keys (a compose secret file).
  - **Prod override (RT3):** `docker-compose.prod.yml` lists `enrich-worker` with the prod image, `ENV: prod`, `volumes: !reset []` and the prod secret file, like every other service. `.env` says `ENV=dev`, so without this entry the worker would run in dev mode in prod.
- **Own Celery app (deviation).** `app.workers.enrich_app` uses its own unacked keys (`{prefix}enrich.unacked*`), so the broker ACL user `enrich` is confined to `~enrich* ~test.enrich*` plus its own kombu bindings. It never touches `trusted.*`, which holds ingest messages with per-job tokens.
  - The worker publishes only to its own queue (slice re-publish); it never writes `ingest*`.
  - Its rate-limit, cooldown and daily keys live on the broker under `{prefix}enrich.ti:*`, inside its ACL, so it needs no app Redis (RT2).
  - The `api` and `ingest` users (`~*`) can publish to `enrich`.
  - The `pcap` and `static` users cannot touch `enrich*` (test).
- **Making `backend` internal: runtime egress check** (verified against the compose files; phase 1 records the result in DEPLOYMENT.md):
  - Postgres, Redis, redis-broker, MinIO, minio-init, migrate, api, ingest-worker, ingest-beat and api-test need no internet at runtime (healthchecks and `mc` are local; the api dev image already has `UV_FROZEN=1`).
  - Image builds (apt, uv, pnpm, freshclam, capa rules) run on the build network, not at runtime.
  - Gateway and web stay on the non-internal `frontend` network (dev `next/font` fetches and any future ACME are unaffected). Prod uses Caddy `tls internal`.
  - Two items must be fixed in phase 1:
    - the dev MinIO console port `127.0.0.1:9001` cannot be published once MinIO sits only on internal networks, so it is dropped (prod already resets it);
    - `uv run` in `migrate` / `api-test` may try to sync dependencies, so `UV_NO_SYNC=1` and `UV_OFFLINE=1` are set; dependency changes then need an image rebuild.
  - Whether Docker's embedded DNS still forwards external names for containers on internal networks depends on the engine version; the egress suite asserts api-test cannot resolve a public name, or records it as a residual (RT22).

**Keys**
- **Sealed box per key:**
  - ephemeral X25519 → HKDF-SHA256 (info `cyberlab.ti.v1`, salt = epk ‖ recipient pk) → AES-256-GCM with a random 96-bit nonce (the derived key is unique per seal, so nonce reuse cannot occur);
  - AAD = `cyberlab.ti.v1|{org_id}|{provider}|{kid}|{key_version}|{base_url_norm}` (`base_url_norm` is empty except for MISP) **(deviation, RT1)**. A MISP key only opens for the URL it was stored with, so a compromised API or a DB writer cannot redirect it to another host; changing a MISP `base_url` requires re-entering the key.
  - A DB trigger makes `key_version` monotonic: new sealed columns need a higher `key_version`, except a re-seal under another kid at the same version (RT18).
- **Columns:** `key_kid`, `key_version`, `key_epk`, `key_nonce`, `key_ct`, `key_last4`.
- **Who holds what:**
  - the API holds only `TI_SEAL_PUBLIC_KEYS` (kid → public key) and `TI_SEAL_ACTIVE_KID`, and only imports `seal.py` (seal only);
  - only the enrich-worker reads `TI_SEAL_PRIVATE_KEYS_FILE` and imports `unseal.py` (RT21);
  - dev ships a committed dev-only key pair (kid `dev-1`, `infra/ti/dev-seal-private.json`) so a fresh clone starts; `_prod_guards` refuses any active kid starting with `dev-`, and prod mounts `.secrets/ti_seal_private.json` from `scripts/gen_ti_seal_keys.py` (mode 0400, owned by uid 10001) (RT13).
- **Write-only in the UI.** The read model is `configured`, `last4`, `enabled`, `verified_at`, `verify_status`, `last_error_code`, `terms_ack_at`, the MISP `base_url` and `limits`.
  - Keys are `SecretStr`, at most 256 printable ASCII characters, never echoed or logged.
  - The key is attached per request by an `httpx.Auth` object with a redacted `repr`, never set as client default headers: httpx only masks `Authorization` in header reprs, not `x-apikey`, `Key`, `Auth-Key` or `X-OTX-API-KEY` (RT11). Provider error bodies are never logged or stored, only mapped error codes.
- **Permissions:**
  - new `Permission.INTEGRATIONS_MANAGE` (owner/admin) to set or remove keys, acknowledge terms and change TI settings;
  - `ORG_READ` to read integration status;
  - `EVIDENCE_WRITE` to request enrichment;
  - `EVIDENCE_READ` to read results.
- **Audit sanitize** also drops `api_key`, `apikey`, `authorization`, `auth_key`, `x-apikey` and any key ending in `_key`, in nested dicts and lists of dicts. Allowlisted exceptions: `key_last4`, `key_kid`, `key_version`, `ioc_key`.
- **Rotation:**
  - sealing key: add kid2 → make it active → the worker re-seals lazily on decrypt → `scripts/reseal_ti_keys.py` re-seals the rest, run as a one-off `enrich-worker` container (it needs the private keys) with the owner DB URL passed only to that invocation → drop kid1;
  - provider key: a new `PUT`, audited as `integration.key_replaced`.

**Providers** (plain httpx, no vendor SDKs; lookup paths only; every adapter has a path allowlist; metadata in the frozen `threat_intel/catalog.py`)

| Provider | IOC types | Auth | Self-imposed default limits (ceiling) |
|---|---|---|---|
| VirusTotal v3 | ip, domain, url, md5/sha1/sha256 | `x-apikey` | 4/min, 500/day (public tier) |
| AbuseIPDB v2 | ip | `Key` | 30/min, 1000/day |
| URLhaus | url, domain, ip (host), md5/sha256 | `Auth-Key` | 30/min, 2000/day (fair use) |
| MalwareBazaar | md5/sha1/sha256 | `Auth-Key` (shared abuse.ch key, stored per provider) | 30/min, 2000/day |
| AlienVault OTX | ip, domain, url, hashes | `X-OTX-API-KEY` | 30/min, 5000/day |
| MISP | all types, including email | `Authorization` (raw key) | 120/min, concurrency 4; per-org `base_url`, SSRF-hardened |
| `mock` (dev/test only) | all | `X-Mock-Key` | no limit; refused when `ENV=prod` |
| MITRE ATT&CK | T-ids | none (offline) | committed compact index |

**Shared HTTP client.** One `httpx.AsyncClient` per provider and slice:
- `trust_env=False`, `follow_redirects=False`, `verify=True`;
- timeouts 3 s connect, 10 s read, 20 s total;
- bodies streamed and capped at 1 MiB (2 MiB for MISP);
- JSON parsing failures of any kind (`RecursionError` from deep nesting, the int-digit limit, `NaN`/`Infinity`) map to `bad_json` (RT19);
- transport injectable (`httpx.MockTransport` in tests).

**MISP** `base_url`:
- `https` only, no userinfo, port 443 or allowlisted;
- syntax checked by the API on save; **resolved only by the worker** (verify is queued automatically after every save, and the check repeats before every request); any non-global address → `verify_status=invalid`, `last_error_code=misp_url_not_public` (RT5);
- `TI_MISP_ALLOW_PRIVATE` (dev only, refused in prod);
- the request connects to the pinned IP with Host and SNI set to the hostname, so TLS still verifies the name;
- optional CA bundle (`ssl.create_default_context(cafile=…)`).

**ATT&CK**
- `scripts/build_attack_index.py` downloads a pinned `mitre-attack/attack-stix-data` enterprise bundle, checks its sha256 and emits a compact `attack_enterprise_v<N>.json` (T-id → name, tactics, sub-technique/parent, deprecated, revoked_by, url). The output is committed.
- Labels come from it by T-id only, for capa capabilities, findings, OTX `attack_ids` and MISP galaxy tags.
- The MITRE notice travels in the route's `meta` and is shown wherever labels appear.

**Data model** (migration **0009**; 0010 is reserved for read indexes if phase 5 needs them)

| Table | Scope / grants | Notes |
|---|---|---|
| `ti_provider_configs` | tenant RLS; S/I/U/D | unique (org, provider); provider check; sealed columns + monotonic `key_version` trigger; `base_url` NOT NULL iff misp; `limits` jsonb; verify fields; `terms_ack_at`, `terms_ack_by` (RT16) |
| `ti_org_settings` | tenant; S/I/U | `excluded_suffixes` (≤ 50) |
| `ti_enrichment_runs` | tenant; S/I/U + status-transition trigger | `scope` (`manual` / `job`), `job_id` (composite FK), `requested_by`, `providers`, `status` (`queued` → `running` ⇄ `waiting` → `completed` / `partial` / `failed`; `queued`/`waiting` may also go straight to `partial`/`failed`), `summary`, `deadline_at` |
| `ti_run_items` | tenant; S/I + UPDATE (`state`, `result_id`, `reason`) only | the frozen plan of a run (RT9): `run_id`, `seq`, `provider`, `ioc_type`, `value_norm`, `ioc_key`, `state` (`pending` / `done` / `cached` / `abandoned`), `result_id` (this run's row or the cached row), `reason` (`rate_limited` / `quota_exhausted` / `deadline` / `auth_failed`); PK (run_id, provider, ioc_key) |
| `ti_run_index` | system lookup, same pattern as `analysis_job_index`: RLS `app_org_id() IS NULL OR organization_id = app_org_id()`, column-level UPDATE grants (RT25) | run → org, `status`, `resume_at`, `deadline_at`, `dispatched_at`, `lease_until`, `lease_owner`; index (status, resume_at) |
| `ti_results` | tenant, append-only (S/I + `forbid_mutation`) | real provider outcomes only: `run_id`, `provider`, `ioc_type`, `value_norm`, `ioc_key` = sha256(type ‖ 0 ‖ value_norm), `status` (`ok` / `not_found` / `error` / `auth_failed`), `found`, `detections`, `score`, `score_scale`, `tags`, `families`, `attack_ids`, `first_seen`, `last_seen`, `summary` (strict per-provider model, ≤ 16 KiB, never the raw body), `permalink`, `fetched_at`, `expires_at` (NULL for error statuses); unique (run_id, provider, ioc_key); index (org, ioc_key, provider, fetched_at DESC) |

- `iocs` stays unchanged. Results join on `ioc_key`, computed in Python.
- Rate-limited, quota-exhausted and deadline outcomes are item states, not history rows, so the history timeline shows only what a provider actually said.

**Cache = history**
- A hit is the newest `ok` / `not_found` row for (org, provider, ioc_key) with `expires_at > now()` (DB clock). It is never shared across orgs. The item records the hit's `result_id`, so run views show cached values too (RT10).
- **TTLs:**
  - hash 72 h; IP 12 h (AbuseIPDB 6 h); domain 24 h; URL 12 h; MISP 1 h;
  - `not_found` gets ¼ of the TTL above (hashes at most 6 h);
  - errors and 429s are never cached.

**Rate limits**
- Lua token bucket `{prefix}enrich.ti:rl:{provider}:{org}` (per-minute) plus a daily counter `{prefix}enrich.ti:day:{provider}:{org}:{yyyymmdd}` (UTC), on the broker. A daily cap reached abandons that provider's remaining items in the run as `quota_exhausted` and sets a cooldown until 00:00 UTC; nothing parks past the run deadline.
- If the broker is unreachable the limiter fails closed: no provider call, the run goes `waiting`.
- An org may lower limits but never raise them above the settings ceilings.
- **429:**
  - parse `Retry-After` (seconds or a date, clamped to 1–3600 s), or with no header back off to the next minute boundary (VT);
  - set cooldown `{prefix}enrich.ti:cool:{provider}:{org}`;
  - the run goes to `waiting` with `resume_at` **(deviation: no Celery countdown/ETA)**. `ingest-beat` sends `ti.resume` every 30 s to the `enrich` queue.
- **Other errors:**
  - 5xx and timeouts: 3 attempts with full-jitter backoff, then an `error` row;
  - 401/403: the worker runs the provider's `verify` once inline; only a failed verify sets `verify_status=invalid` (RT23). The provider stops for the run (`auth_failed` row, remaining items abandoned `auth_failed`).
- **Fairness and concurrency (RT6):** a single solo-pool replica serves all orgs, so each `ti.enrich` invocation is a time slice of at most `TI_SLICE_S` (20 s, enforced with asyncio timeouts because the solo pool ignores Celery time limits). Unfinished runs go to the back of the queue, so a 50-minute VT run never blocks another org's manual lookup. Inside a slice: semaphores ≤ 4 per provider, ≤ 16 global.
- **Lease and dispatch (RT8):** a slice starts only after `UPDATE ti_run_index SET lease_until = now() + 60 s … WHERE lease_until IS NULL OR lease_until < now()` succeeds; duplicates exit. `ti.resume` re-sends only runs that are `waiting` with `resume_at <= now()`, or `queued`/`running` with an expired lease and `dispatched_at` older than 2 minutes, and it bumps `dispatched_at`, so a busy worker never accumulates duplicate messages in the 256 MB non-persistent broker.
- **Deadline and caps (RT9):**
  - the run deadline defaults to 30 min. The worker enforces it at the start of every slice: pending items become `abandoned/deadline` and the run ends `partial` (or `failed` if nothing was attempted);
  - the ingest-worker reaper is only a fallback for runs whose lease expired more than 10 min after `deadline_at` (worker down). It finalizes under `FOR UPDATE` on the run with the same rules; a worker that finds the run already final does nothing;
  - at most 200 IOCs per job run (`TI_MAX_IOCS_PER_RUN`) and 20 values per manual lookup;
  - order (`seq`): sample hashes first, then IOCs by occurrence count.

**Normalization and eligibility** (pure `normalize.py`, used by the API and the worker)
- **Refang:** `hxxp`, `[.]`, `(.)`, `[dot]`, `[:]`, `[@]`.
- **IP:** global only, after unwrapping IPv4-mapped, 6to4 (`2002::/16`), NAT64 (`64:ff9b::/96`) and Teredo addresses (no private, loopback, link-local, CGNAT, documentation or reserved ranges) (RT13).
- **Domain:**
  - lowercase, IDNA to punycode, at most 253 characters, at least 2 labels;
  - special-use and internal names are never sent: the TLDs `local`, `localhost`, `internal`, `lan`, `home`, `home.arpa`, `corp`, `private`, `intranet`, `localdomain`, `test`, `example`, `invalid`, `onion`, and **everything under `arpa`** (PTR names encode private IPs) (RT13), nor the org's excluded suffixes.
- **URL:** http(s) only, no userinfo; the host must pass the IP or domain rule; **the query string and fragment are removed before anything is sent or keyed** (they carry session tokens, reset links and personal data), and the normalization report says `query_removed` (RT4).
- **Hash:** lowercase hex of the right length.
- **Never sent to any external provider:** email, file path, registry key, JA3 and certificate values. MISP may receive emails. A sample is sent only as its trusted hashes from `malware_samples` / `evidence_hashes`.
- `Skip(reason)` values are returned to the UI. No skipped value leaves the host.

**Triggers** (RT15: auto-enrich after ingest and investigation-scope runs are deferred)
- Manual lookup (≤ 20 values).
- An analysis job's IOC set.

**Consent** (RT16)
- The first `enabled=true` on a provider requires `acknowledge_terms: true`: the admin confirms that the provider will receive the indicators the org enriches and that the provider's terms (shown on the card) fit the org's use. `terms_ack_at` / `terms_ack_by` are stored and audited.

**Presentation** (verdict-free)
- Each result is attributed: "Reported by VirusTotal on 2026-11-05: 12 of 71 engines report a detection".
- Provider-native labels and scores are quoted and attributed ("AbuseIPDB confidence 87/100"), never restated as our own. Chips use neutral styling: no red/green colouring by count or score (RT20).
- TI never creates findings or changes severity in M4. Reputation is never sole evidence; the docs state this for M5.
- Provider text is untrusted: control and bidi characters are stripped in the summary models, it is rendered as text only, links are only server-built `https:` permalinks, and M5 must treat it as prompt-injection input.

**`mock` provider and `ti-mock` sink**
- `ti-mock` is a stdlib Python HTTP server in `infra/ti-mock/` (test and e2e profiles) that sits only on the `egress` network.
- It returns deterministic responses keyed by the IOC value: hit, not found, 429 with or without Retry-After, 401 when `X-Mock-Key` ≠ `TI_MOCK_EXPECTED_KEY`, 500, slow, oversize, redirect, malformed.
- The `mock` adapter is available only when `ENV` is not `prod` and `TI_MOCK_ENABLED=true`. `_prod_guards` refuses `TI_MOCK_ENABLED`, `TI_MISP_ALLOW_PRIVATE` and `TI_MISP_INSECURE_TLS` in prod, and the API answers `422 provider_unavailable` there.
- It drives the e2e and the pipeline tests through the real seal → worker → httpx → egress path without real keys.

## Red-team changes (2026-11-04)

Four hostile reviewers (security, reliability, product/legal, scope) checked the plan against the codebase (`core/config.py`, `rbac.py`, `tenancy.py`, `audit/service.py`, `rate_limit.py`, `workers/*`, `infra/redis-broker/entrypoint.sh`, both compose files, `THREAT_MODEL.md`). 28 findings: 0 Critical, 6 High, 11 Medium, 11 Low; 24 accepted and applied, 4 rejected.

| ID | Finding (failure scenario) | Severity | Disposition |
|---|---|---|---|
| RT1 | MISP `base_url` was not bound to the sealed key: a compromised API (or any app-role DB writer) sets `base_url` to `https://evil.example` and the worker unseals the org's MISP key and sends it there, defeating the "API encrypts only" design. | High | Accepted → AAD includes `base_url_norm`; a URL change requires a new key (plan Keys; phase 1 seal; phase 5 PUT `key_required_for_url_change`). |
| RT2 | Reusing `*api-env` gives the internet-facing worker `JWT_SECRET` (forge any session), MinIO credentials and the app Redis (flush the token denylist); `Settings` even requires them. | High | Accepted → `x-enrich-env`, `PROCESS_ROLE=enrich` refuses JWT/MinIO/app-Redis settings; limiter keys moved to the broker under `enrich.ti:*` (plan Trust; phases 1, 2). |
| RT3 | `.env` sets `ENV=dev`; `docker-compose.prod.yml` overrides ENV per service, so an `enrich-worker` missing there runs the dev image in dev mode in prod (mock, allow-private and insecure-TLS guards off). | High | Accepted → prod override entry + a verify:prod check (phases 1, 7). |
| RT4 | Full URLs from pcaps carry session tokens, password-reset links and personal data in query strings; sending them to VT/URLhaus/OTX discloses customer secrets. | High | Accepted → query and fragment removed before sending or keying, reported as `query_removed` (plan Normalization; phase 2). |
| RT5 | Save-time DNS resolution of the MISP host runs in the API, which has no egress on an `internal` network: depending on the engine it either always fails (`misp_url_not_public` for every real MISP) or leaks lookups. | High | Accepted → API checks syntax only; resolution in the worker via auto-queued verify and before each request (plan MISP; phases 4, 5). |
| RT6 | One solo-pool worker: a 200-IOC job at VT 4/min holds it ~50 min, starving every other org's manual lookup; the solo pool ignores Celery time limits. | High | Accepted → 20 s time slices with re-queue to the tail, asyncio-enforced (plan Rate limits; phase 2). |
| RT7 | Celery gossip, mingle, heartbeat, remote control and events use `celery.pidbox` / `celeryev` keys and channels outside the `enrich` ACL: NOPERM at startup. | Medium | Accepted → `--without-gossip --without-mingle --without-heartbeat`, remote control and events off (phase 1). |
| RT8 | `ti.resume` re-sent `queued` runs every 30 s while their message merely waited behind a busy worker → unbounded duplicates in a 256 MB noeviction broker and double provider calls; limiter behaviour on broker outage undefined. | Medium | Accepted → DB lease (`lease_until`), `dispatched_at` throttle, limiter fails closed (plan Rate limits; phases 1, 2). |
| RT9 | The ingest reaper wrote per-pair `deadline` rows while the worker was still inserting, and the pair set was recomputed each resume (unstable for growing scopes). | Medium | Accepted → `ti_run_items` planned by the API at creation; worker owns the deadline; reaper is a locked fallback that writes no result rows (data model; phases 1, 2, 5). |
| RT10 | Cache hits wrote nothing, so a manual lookup of a value enriched an hour ago showed an empty result table. | Medium | Accepted → items record the cached `result_id`; run detail returns it with `from_cache` (phases 2, 5, 6). |
| RT11 | httpx masks only `Authorization` in header reprs: `x-apikey`, `Key`, `Auth-Key`, `X-OTX-API-KEY` appear in any logged `repr(request)`; some providers echo the key in error bodies; VT `GET /users/{id}` puts the key in the path. | Medium | Accepted → per-request `httpx.Auth` with redacted repr; error bodies never logged/stored; VT verify by constant-hash lookup; leak suite checks reprs (phases 2, 3, 7). |
| RT12 | Compose (non-swarm) secrets are bind mounts that ignore uid/mode: a mode-600 host file is unreadable by uid 10001 in prod; a missing file breaks `pnpm dev` and CI for every fresh clone after phase 1. | Medium | Accepted → committed `dev-` key pair refused in prod; keygen writes 0400 owned by 10001; startup readability check; `.secrets/` in `.gitignore` and `.dockerignore` (plan Keys; phase 1). |
| RT13 | `.arpa` PTR names (e.g. `5.1.168.192.in-addr.arpa`), `home`, `private`, `intranet`, `localdomain`, and 6to4/NAT64/Teredo-embedded private IPv4 slipped through eligibility. | Medium | Accepted → extended rules and table tests (plan Normalization; phase 2). |
| RT14 | Phases 3, 4, 5 were not file-disjoint: summary models needed by phase 5's OpenAPI unions were written in 3/4; provider metadata lived both on adapters and in `catalog.py`; `main.py` router registration by 4 and 5; phase 6 used phase 4's route but depended only on 5. | Medium | Accepted → phase 1 freezes `summaries.py`, `catalog.py` and registers empty routers; phase 2 owns the run service and the syntactic MISP URL check; phase 6 depends on 4 and 5 (Dependencies). |
| RT15 | 70 h was tight (phase 1 alone covers migration, crypto, compose, ACL and a full egress re-test). Auto-enrich after ingest discloses IOCs to third parties with no human decision and burns quotas; investigation runs duplicate per-job runs. | Medium | Accepted → both deferred (Out of scope); `/attack/about` folded into `meta`; effort 73 h. |
| RT16 | Enabling a provider had no explicit consent record although it discloses the org's investigations to a third party under that provider's terms. | Medium | Accepted → `acknowledge_terms` on first enable, `terms_ack_at/by`, audited (phases 1, 5, 6). |
| RT17 | The enrich-worker uses the app DB role, so an exploited worker can read every tenant. | Medium | Rejected → a dedicated role needs bootstrapping on existing volumes; the worker parses only strict pydantic models; documented residual in THREAT_MODEL. |
| RT18 | "key_version blocks rollback" was false: `key_version` was a plain writable column. | Low | Accepted → monotonic trigger (phase 1). |
| RT19 | Hostile JSON within 1 MiB (deep nesting → `RecursionError`, 5 000-digit ints, `NaN`), bidi/control characters in tags, non-https permalinks. | Low | Accepted → all map to `bad_json`; strings sanitized in summary models; https-only permalinks (phases 2, 3, 6). |
| RT20 | Bare numbers ("AbuseIPDB 87") and red/green chips read as our verdict. | Low | Accepted → attributed templates, neutral chip styling, wording test covers templates (phase 6). |
| RT21 | The import guard on the name `open_sealed` is bypassed by `import …seal as s; s.open_sealed`. | Low | Accepted → `seal.py` / `unseal.py` split, guard on module imports (phase 1). |
| RT22 | An API on an internal network may still resolve external names through Docker's embedded DNS (DNS exfiltration channel). | Low | Accepted → egress suite asserts it, else documented residual (phase 7). |
| RT23 | VT returns 403 for some resources with a valid key; flipping `verify_status=invalid` on any 401/403 disables a working key. | Low | Accepted → inline verify before marking invalid (phase 2). |
| RT24 | The ≥ 0.95 metric under synthetic faults is nearly guaranteed by retries; the e2e accepted "partial or completed". | Low | Accepted → metric labelled "resilience under synthetic faults", live-run numbers recorded when keys exist; e2e asserts an exact final state (phase 7). |
| RT25 | The plan claimed `analysis_job_index` uses SECURITY DEFINER functions; it actually uses RLS `app_org_id() IS NULL OR …` plus column grants. | Low | Accepted → `ti_run_index` follows the real pattern (data model; phase 1). |
| RT26 | No TLP / "do not share externally" flag on evidence or cases. | Low | Rejected → no TLP model exists yet; every external disclosure is a manual, per-provider-acknowledged action in M4; revisit with M6 cases. |
| RT27 | Viewers can see the MISP `base_url`. | Low | Rejected → org members only, not a secret; the key stays write-only. |
| RT28 | Hash lookups reveal to a provider that the org holds a file. | Low | Rejected → inherent to lookup; covered by the per-provider privacy acknowledgement and notice. |

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Contracts data model crypto and network hardening](./phase-01-contracts-data-model-crypto-and-network-hardening.md) | Completed |
| 2 | [Enrich worker broker limiter and normalization](./phase-02-enrich-worker-broker-limiter-and-normalization.md) | Completed |
| 3 | [Public provider adapters and fixtures](./phase-03-public-provider-adapters-and-fixtures.md) | Completed |
| 4 | [MISP SSRF client and ATT&CK index](./phase-04-misp-ssrf-client-and-att-ck-index.md) | Completed |
| 5 | [Integrations enrichment and lookup API](./phase-05-integrations-enrichment-and-lookup-api.md) | Completed |
| 6 | [Threat intel frontend](./phase-06-threat-intel-frontend.md) | Completed |
| 7 | [Hardening metrics e2e and docs](./phase-07-hardening-metrics-e2e-and-docs.md) | Completed |

## Dependencies and parallelism

- **Phase 1 goes first.** It freezes, and only the parent changes afterwards:
  - migration 0009;
  - `ProviderResult`, the `Provider` protocol, every per-provider summary model (`threat_intel/summaries.py`) and the provider metadata (`threat_intel/catalog.py`);
  - the seal format (including the MISP URL in the AAD);
  - `Queues.enrich` and the task names;
  - empty `threat_intel` and `attack` routers already registered in `app/main.py`.
- **Phase 2 next.** It delivers the worker loop, the HTTP client, the limiter, normalization, the run-creation service (`threat_intel/runs.py`), the syntactic MISP URL check (`threat_intel/ssrf.py: validate_base_url`) and the `mock` provider.
- **After phase 2, in parallel** (subagents, disjoint files):
  - phase 3: `threat_intel/providers/{virustotal,abuseipdb,abusech,otx}.py`, `tests/fixtures/ti/{virustotal,abuseipdb,urlhaus,malwarebazaar,otx}/`, their tests;
  - phase 4: `providers/misp.py`, the resolution and pinning half of `threat_intel/ssrf.py` (phase 2's `validate_base_url` stays as is), `modules/attack/` (filling its stub router), `scripts/build_attack_index.py`, their tests;
  - phase 5: `threat_intel/router_*.py`, `threat_intel/service_*.py` / repositories, the `include=enrichment` addition in the existing IOC list route, their tests. Never `providers/`, `summaries.py` or `catalog.py`.
- **Phase 6** starts once phases 4 and 5 have their routes in `packages/contracts`. The parent regenerates contracts.
- **Phase 7** comes last: hardening, the metric, e2e, docs and the gate.
- One commit per phase. The stack stays deployable after each one:
  - TI is dark until phase 5 exposes the routes;
  - `backend: internal`, the dev seal key and the prod override land in phase 1 together with their fixes.

## Definition of done

- An admin acknowledges a provider's terms and stores a key per provider; it is shown only as configured / last4 / verified. An analyst cannot set keys (403).
  - The plaintext key never appears in an API response, an audit row, a log line, a Celery message or an object `repr` (sentinel-key tests).
  - A MISP key cannot be used against a `base_url` other than the one it was stored with.
- "Enrich IOCs" on a pcap or static job, or a manual lookup, produces per-provider, source-attributed results.
  - A repeat inside the TTL is served from the per-org cache and still shown (marked cached).
  - 429 and quota exhaustion end the run `partial` with honest counts.
  - A long run does not block another org's manual lookup (time slices).
  - The history timeline shows every past provider result for an IOC.
- Private IPs (including embedded ones), internal, special-use and `.arpa` names, URL query strings, emails (except to MISP), paths and registry keys are never sent anywhere (tests on the outbound requests).
- Network isolation:
  - api, ingest and the analyzers have no default route and cannot reach `ti-mock`;
  - enrich-worker can reach it, and holds no JWT secret, MinIO credentials or app Redis URL;
  - the MISP SSRF suite passes;
  - analyzer broker users cannot touch `enrich*`.
- ATT&CK ids on capa capabilities and findings show technique names and tactics from the pinned index, with the MITRE notice.
- "IOC enrichment success" (per provider) under the seeded fault mix is ≥ 0.95, and is recorded in TESTING.md as resilience under synthetic faults, with the cache hit rate, the rate-limited share and p95 latency.
- `pnpm verify:prod` green:
  - the dev e2e runs the TI flow against `mock`;
  - the prod e2e asserts that `mock` is refused and the enrich-worker runs with `ENV=prod`.
- Docs: new `docs/THREAT_INTEL.md`, and ARCHITECTURE, DATABASE, API, THREAT_MODEL, TESTING, DEPLOYMENT, ROADMAP, README and `.env.example` updated.

## Out of scope

- Submitting files or URLs to any provider (VT upload/scan, URLhaus/MalwareBazaar submission), or downloading samples from providers.
- Feed ingestion (TAXII/STIX, MISP event sync, OTX pulse subscriptions), pushing or sharing to MISP, and ThreatFox.
- Other providers (Shodan, GreyNoise, Censys, Hybrid Analysis…).
- TI-derived findings, severity changes or scores of our own; AI correlation (M5); case-level ATT&CK mapping and reports (M6).
- **Auto-enrichment after ingest and investigation-scope runs** (RT15; revisit in M5/M6 with the consent model).
- IOC collections and watchlists; scheduled re-enrichment; retention or purge of `ti_results`; a cross-org shared cache.
- KMS/HSM key custody, per-user keys, several keys per provider, a dedicated enrich DB role (RT17), and an egress proxy with a hostname allowlist (documented residuals).
- TLP labels on evidence or cases (RT26).
- enrich-worker scale-out (cross-replica concurrency leases); ICS and Mobile ATT&CK matrices.

## Open risks

- **Terms of service.**
  - The VirusTotal public API must not be used in commercial products or workflows, and one person may hold only one account.
  - abuse.ch (URLhaus, MalwareBazaar) free access is for not-for-profit use; commercial use needs a Spamhaus subscription, and redistribution needs consent.
  - Mitigations: bring-your-own-key per org; a ToS note on each provider card and an explicit acknowledgement on first enable; no cross-org cache; no republishing.
  - A commercial deployment needs paid tiers. This goes into THREAT_INTEL.md and the README.
- **Free-tier numbers to verify in phase 3:** VT 4/min and 500/day; AbuseIPDB 1000/day; OTX has no published limit; abuse.ch is "fair use". Also confirm what abuse.ch returns for a bad key (401, or 200 with an error `query_status`) and the OTX 429 behaviour. The defaults above are conservative.
- **ATT&CK version:** v20 (2026-10-13) per the research report, to verify. Since v19, Defense Evasion is split into "Stealth" and "Defense Impairment", so tactics come only from the bundle, never from capa strings.
- **Privacy:** every lookup tells a third party what the org is investigating. Providers are opt-in per org with an acknowledgement; the Integrations page and the lookup page say so; emails, internal names, private IPs and URL query strings are never sent. Internal hostnames under the org's own public domain are only excluded once an admin adds the suffix, so the settings card prompts for it.
- **The enrich-worker has unrestricted internet** (no hostname allowlist) and the app DB role. It runs trusted code with constant hostnames, but a compromise would have egress and tenant-wide DB access. Documented residual; an egress proxy and a dedicated role come later.
- **Free-tier quotas make big runs partial.** 200 IOCs against VT at 4/min need 50 minutes, so the 30-minute deadline ends the run `partial`. The UI states this.
- **Making `backend` internal** may break dev habits (the MinIO console, `uv` syncing at runtime). Phase 1 verifies and documents this.
- **Provider text is untrusted** and may contain injection payloads aimed at M5. M4 only renders it as text.
- **Fixtures vs reality:** adapters are tested against handcrafted fixtures; any provider not checked with a live call is marked "unverified against the live API" in THREAT_INTEL.md.
