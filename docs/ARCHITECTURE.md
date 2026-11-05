# Architecture

## Components

```mermaid
flowchart LR
  B[Browser] -->|:8080 dev / :8443 prod| G[Caddy gateway<br/>on both networks]
  subgraph frontend [frontend network]
    W[Web - Next.js 16]
  end
  subgraph backend [backend network]
    A[API - FastAPI]
    P[(PostgreSQL 17)]
    R[(Redis 7)]
    M[(MinIO - object lock)]
  end
  G -->|everything else| W
  G -->|/api/*| A
  A --> P
  A --> R
  A --> M
```

- **One origin.** The gateway serves both the app and `/api`, so session cookies are first-party and `SameSite=Strict`.
- **Networks.** `web` cannot reach `api` directly; only the gateway (and data services) share the api's network. uvicorn trusts `X-Forwarded-For` from its peers, which is safe only because of this isolation. Since M4 `backend` is `internal` (no egress); only the enrich-worker and (M5) the analyst-worker have a route out ([Networks](#networks-m4-m5-m6)).
- **Gateway duties.** 1 MiB body cap everywhere except the evidence upload route; early 413 on oversize `Content-Length` (JSON error envelope); security headers; TLS + HSTS in prod.
- **CSP (M3).** The upstreams own it. The web app sets a per-request nonce policy on HTML (`apps/web/proxy.ts`, `lib/csp.ts`): `script-src 'self' 'nonce-…' 'strict-dynamic'`, no `'unsafe-inline'` for scripts; styles keep `'unsafe-inline'` (Radix/sonner inline styles). The root layout awaits `connection()`, so every page renders dynamically with a fresh nonce. API downloads send `CSP: sandbox`. Caddy's `csp_fallback` (`infra/caddy/common.caddy`) adds `default-src 'none'` only to responses that carry no CSP.

## API: modular monolith

```
apps/api/app/
  core/        config, db engine, tenancy (tenant_session), rbac (require/org_session),
               security (argon2, JWT), csrf, rate_limit, errors, storage, hashing, upload_slots
  modules/
    auth/            register, login, sessions (refresh rotation, logout), events (auth_events)
    users/           identity (models + repository only; `/auth/me` serves the profile)
    organizations/   orgs (service.py), memberships (members.py), storage quota (storage.py)
    investigations/  cases, case numbers, status lifecycle (M6: reasons + history, TLP), merged
                     timeline, policy.py (the TLP / share-policy resolver, M6)
    evidence/        uploads.py, locking.py, transfer.py (download/verify), service.py (custody, archive),
                     share_policy.py (M6: per-evidence "do not send to AI / TI" flags)
    audit/           audit writer + read API
    analysis/        analysis jobs: request (manual / auto on upload), dispatch per analyzer, lifecycle
    pcap_analysis/   pcap.v1 validation, ingest into tenant tables, read API (also findings / IOCs of every analyzer)
    static_analysis/ static.v1 validation, ingest, read API, JSON report
    threat_intel/    (M4) catalog, normalization, sealing (seal.py: API; unseal.py: enrich worker only),
                     runs, cache, limiter, SSRF checks, provider adapters + HTTP client (enrich worker only),
                     integrations / runs / results API
    attack/          (M4) offline ATT&CK index and label route
    ai/              (M5) contracts, catalog, output schema, labels, text, sealing (seal.py: API;
                     unseal.py: analyst worker only), context/ (builder, selectors, field
                     allowlists, pseudonymization, reduce), prompt + prompts/, verify,
                     postprocess, budget, ratelimit, lifecycle, providers/ + http (analyst
                     worker only), runs / providers / settings API
    notes/           (M6) analyst notes with append-only versions, typed refs re-checked in scope
    ioc_collections/ (M6) case IOC collections, normalization (M4 normalizer), case-wide IOCs,
                     CSV / JSON / STIX 2.1 exports
    case_attack/     (M6) analyst ATT&CK mappings, suggestions (capa, findings, verified AI), matrix
    case_timeline/   (M6) timeline export (CSV / JSON, formula-safe, TLP-headed)
    reports/         (M6) drafts, snapshot builder + sections, citations, cited-by, redaction,
                     signing wrapper (the only importer of the private-key loader), storage,
                     render dispatch, render ingest, public signing keys
  workers/     celery app, ingest + reaper tasks (trusted side of the analysis pipeline; M6:
               `report.rendered` ingest and the render reaper);
               enrich_app / enrich_tasks / enrich (M4: the internet-facing enrich worker);
               analyst_app / analyst_tasks / analyst (M5: the internet-facing AI analyst worker)
  scripts/     dump_openapi (contracts), reconcile_orphans (report-only)
```

Modules follow `models / schemas / repository / service / router`, keeping only the layers they need.

### Request lifecycle (org-scoped route)

1. Caddy enforces body limits and forwards with `X-Forwarded-For`.
2. `CSRFMiddleware` checks the double-submit token on mutating requests.
3. `current_user` validates the access JWT (signature, `typ`, expiry), the jti / refresh-family denylist in Redis, and that the user is active.
4. `require(permission)` opens **one** `tenant_session(org_id, user_id)` — a transaction with `app.org_id` / `app.user_id` set via `set_config(..., true)` — and checks membership **inside** it (404 for non-members, 403 for missing permission).
5. The handler works in that session; mutations write the audit row in the same transaction and commit before the response is built. The dependency uses `scope="function"`, so the session closes before the response is sent.

Postgres row-level security (forced on every tenant table) is the second line of defence: even a missing `WHERE organization_id = …` cannot leak another tenant's rows.

### Evidence flow

```mermaid
sequenceDiagram
  participant C as Client
  participant A as API
  participant D as Postgres
  participant S as MinIO
  C->>A: POST .../evidence (raw bytes)
  A->>D: short session: authorize + case not archived
  A->>A: spool to temp file, MD5/SHA1/SHA256 (worker thread)
  A->>S: put file -> version_id
  A->>D: short session: re-authorize, insert evidence + hashes + custody + audit, commit
  A->>S: set GOVERNANCE retention on that version
  A-->>C: 201 evidence + hashes
```

- No DB connection is held while bytes move; every write re-authorizes.
- Failure before commit deletes exactly the stored version; after commit nothing changes the response (retention/lock failure is logged and audited).
- Download and verify always read the **stored version id**, so overwriting the key in MinIO cannot change what is served or verified.
- Per-user slots (Redis ZSET leases) bound concurrent uploads/verifies; storage and hashing run on a dedicated thread limiter.
- **Storage quota (M3).** The declared `Content-Length` is checked against the org quota before the body is read. The actual size is checked again in the insert transaction, under a `FOR NO KEY UPDATE` lock on the org row, so concurrent uploads of one org cannot overshoot it (`413 storage_quota_exceeded`). Usage counts active and archived evidence.

## Web

Next.js 16 App Router, client-rendered signed-in area:

- `AuthGate` (client) calls `/auth/me`; the access cookie is scoped to `/api`, so the Next server never sees it.
- Typed API client (`openapi-fetch` + generated `@cyberlab/contracts`) adds the CSRF header and does single-flight token refresh (ok / expired / unavailable).
- Evidence upload uses XHR (progress) and a sequential client queue.

## Contracts

`pnpm gen:contracts` dumps the OpenAPI schema offline from the API image and regenerates `packages/contracts/src/schema.d.ts`. `pnpm verify` fails on drift.

## Analysis workers (M2)

Analysis runs outside the API process. Details are in [PCAP_ANALYSIS.md](PCAP_ANALYSIS.md).

```mermaid
flowchart LR
  A[API] -->|send_task pcap.analyze| RB[(redis-broker<br/>ACL users)]
  RB --> PW[pcap-worker<br/>UNTRUSTED]
  PW -->|presigned GET / POST| M[(MinIO)]
  PW -->|ingest.event| RB
  RB --> IW[ingest-worker<br/>trusted]
  IB[ingest-beat<br/>reaper schedule] --> RB
  IW --> P[(PostgreSQL)]
  IW --> M
  subgraph analysis [analysis network: internal, no egress]
    PW
  end
```

- **Untrusted side** (`apps/workers/pcap`):
  - The worker holds a broker URL only.
  - Its tools run as uid 10003 with seccomp, rlimits and kill-by-uid cleanup.
  - Output is a versioned `pcap.v1` stream (`packages/py-jobs`).
- **Trusted side** (`apps/api/app/workers`, api image):
  - It authenticates every message (per-job token, org from the job index).
  - It validates the whole result before opening one transaction.
  - It applies only state-valid transitions.
- **Shared contracts**: the `cyberlab_jobs` package is a path dependency of both the API and the worker. It holds the job message, ingest message, limits, result line models and capture magic detection.
- **Separate broker**: the analyzer can never reach the app Redis (token denylist, rate limits).
- **Reaper**: `ingest-beat` schedules it every 60 s. It fails jobs past their queue or run deadline.

## Static analysis (M3)

A second untrusted worker on the same pipeline. Details are in [MALWARE_ANALYSIS.md](MALWARE_ANALYSIS.md).

```mermaid
flowchart LR
  A[API] -->|static.analyze / pcap.analyze| RB[(redis-broker)]
  RB -->|queue static| SW[static-worker<br/>UNTRUSTED]
  RB -->|queue pcap| PW[pcap-worker<br/>UNTRUSTED]
  SW -->|presigned GET / POST| M[(MinIO)]
  SW -->|ingest.event| RB
  RB --> IW[ingest-worker<br/>trusted]
  IW -->|static.v1 / pcap.v1| P[(PostgreSQL)]
  subgraph analysis [analysis network: internal, no egress]
    SW
    PW
  end
```

- **Auto-run on upload** (from the first bytes, after the upload commits):
  - pcap / pcapng → pcap analyzer;
  - PE (`MZ` + in-bounds `PE\0\0`) or ELF (not a core dump) → static, profile `full`;
  - any other non-empty file ≤ `STATIC_MAX_BYTES` (64 MiB) → static, profile `av` (ClamAV + YARA).
- **Per analyzer:** each analyzer has its own Celery task, queue and broker ACL user (`static`, confined like `pcap`). The active-job caps (per org and global) count each analyzer separately, so a full pcap queue never blocks static runs.
- **Engine order:** ClamAV → YARA → facts → PE/ELF → strings → capa → FLOSS. The emulators (capa, FLOSS) run last, so a compromised emulator cannot hide an earlier signature match. The `av` profile stops after facts.
- **Untrusted side** (`apps/workers/static`): built on the shared worker kit (`packages/py-worker-kit`: sandbox, transfer, result writer, bounded readers), the same one the pcap worker uses. Every engine, including the Python probes (pefile, pyelftools, yara-python), runs as uid 10003 under seccomp and `RLIMIT_AS`; root never parses sample bytes.
- **Trusted side:** the ingest worker dispatches by schema version. A `static.v1` stream is validated as a whole (header, caps, trailer hash, and sample hashes that must match the evidence record), then written in one transaction into the `malware_*` tables plus the shared `analysis_findings` and `iocs`.
- **Web:** the Malware Lab (`/o/{org}/malware`, `/malware/{job}`, `/malware/{job}/report`) lists static jobs and shows sample facts, structure, strings, signatures, capabilities, findings and IOCs. It downloads the JSON report and renders a printable one.

## Threat intelligence (M4)

IOC lookups at external providers. Details: [THREAT_INTEL.md](THREAT_INTEL.md).

```mermaid
flowchart LR
  B[Browser] --> G[gateway]
  G --> A[API<br/>seals keys, plans runs]
  A -->|send_task ti.enrich / ti.verify| RB[(redis-broker)]
  IB[ingest-beat] -->|ti.resume every 30 s| RB
  RB -->|queue enrich| EW[enrich-worker<br/>TRUSTED, internet-facing]
  A --> P[(PostgreSQL)]
  EW --> P
  EW -->|limiter keys enrich.ti:*| RB
  EW -->|https, path allowlist| I((provider APIs<br/>/ org MISP))
  subgraph backend [backend: internal]
    A
    IB
    R[(Redis)]
    M[(MinIO)]
  end
  subgraph enrich [enrich: internal]
    P
    RB
  end
  subgraph egress [egress: the only network with a route out]
    EW
    TM[ti-mock<br/>test / e2e]
  end
```

- **The API never calls a provider** and never resolves an external name. It normalizes values, plans the run (`ti_enrichment_runs`, `ti_run_index`, `ti_run_items`) in one transaction and publishes `ti.enrich` after the commit. It holds only the sealing **public** key.
- **enrich-worker** (api image, uid 10001, read-only rootfs, `cap_drop: ALL`, no-new-privileges): `celery -A app.workers.enrich_app worker -Q enrich --pool solo --without-gossip --without-mingle --without-heartbeat`, remote control and events off. It runs one time slice (≤ 20 s) per message, behind a DB lease, and re-queues unfinished runs at the tail.
- **Least-privilege env** (`x-enrich-env`, never `*api-env`): `PROCESS_ROLE=enrich`, the app DB role, its own broker user and the `TI_*` settings. `Settings` refuses a JWT secret, MinIO credentials or an app Redis URL in that role. The sealing private keys come from the compose secret `ti_seal_private`.
- **Own Celery app and broker user.** `enrich` may touch only `enrich*` / `test.enrich*` keys (queue, unacked bookkeeping, limiter keys), never `trusted.*` or `ingest*`. The `api` and `ingest` users publish to it; the analyzer users cannot.
- **Import guard.** Adapters, the registry, the HTTP client and `unseal` may only be imported from `app/workers/enrich*.py` (AST test).
- **Lifecycle shared with ingest.** `threat_intel/lifecycle.py` finalizes runs for the worker and for the ingest reaper's fallback (runs 10 min past their deadline with no live lease).

### Networks (M4, M5, M6)

| Network | Internal | Members | Why |
|---|---|---|---|
| `frontend` | no | web, gateway, e2e | browser-facing |
| `backend` | **yes** since M4 | postgres, redis, redis-broker, minio, minio-init, migrate, api, ingest-worker, ingest-beat, gateway, api-test | no service here has a route out; the API cannot reach the internet even if compromised |
| `enrich` | yes | postgres, redis-broker, enrich-worker(-test), analyst-worker(-test) | the trusted internet-facing workers' way to their data, and nothing else (no app Redis, MinIO, API or gateway) |
| `egress` | no | enrich-worker(-test), analyst-worker(-test), ti-mock, ai-mock | the only route out |
| `analysis` | yes | pcap-worker(-test), static-worker(-test), report-worker(-test) (M6), redis-broker, minio | the untrusted parsers and the renderer: the broker and presigned MinIO URLs only |

Runtime egress per service and the operational consequences (no MinIO console port, `UV_NO_SYNC`): [DEPLOYMENT.md](DEPLOYMENT.md#networks-and-egress-m4-m5-m6).

- **Web:** org settings → Integrations (`/o/{org}/settings/integrations`: provider cards, write-only keys, terms acknowledgement, limits, excluded suffixes), Threat Intel (`/o/{org}/intel`: manual lookup with a normalization report, recent runs) and the IOC history (`/o/{org}/intel/ioc`). IOC tabs of pcap and static jobs get an "Enrich IOCs" button and attributed chips (`GET …/iocs?include=enrichment`); ATT&CK ids on capabilities and findings show names and tactics with the MITRE notice.

## AI analyst (M5)

Evidence-cited LLM explanations of normalized findings. Details: [AI_ANALYST.md](AI_ANALYST.md).

```mermaid
flowchart LR
  B[Browser] --> G[gateway]
  G --> A[API<br/>builds + freezes context,<br/>seals keys]
  A -->|send_task ai.run / ai.verify| RB[(redis-broker)]
  IB[ingest-beat] -->|ai.resume every 30 s| RB
  RB -->|queue analyst| AW[analyst-worker<br/>TRUSTED, internet-facing,<br/>no tools for the model]
  A --> P[(PostgreSQL)]
  AW --> P
  AW -->|limiter + budget keys analyst.ai:*| RB
  AW -->|https, path allowlist| L((Anthropic / Gemini))
  subgraph backend [backend: internal]
    A
    IB
    R[(Redis)]
    M[(MinIO)]
  end
  subgraph enrich [enrich: internal]
    P
    RB
  end
  subgraph egress [egress: route out]
    AW
    AM[ai-mock<br/>test / e2e]
  end
```

- **The API never calls a provider.** In the requester's RLS session it selects rows deterministically, sanitizes, pseudonymizes internal names, defangs, assigns short labels and hashes the context (`ai/context/`), then writes the run, its index, the frozen input, the label map and the audit row in one transaction and publishes `ai.run` after the commit. It holds only the AI sealing **public** key.
- **analyst-worker** (api image, uid 10001, read-only rootfs, tmpfs `/tmp`, `cap_drop: ALL`, no-new-privileges): `celery -A app.workers.analyst_app worker -Q analyst --pool solo --without-gossip --without-mingle --without-heartbeat`, remote control and task events off, `task_acks_late`, prefetch 1. **One message = at most one provider call** (≤ 3 per run), behind a DB lease; no DB session is open during the call. Two replicas in prod. It never shares the enrich-worker.
- **Least-privilege env** (`x-analyst-env`, never `*api-env` or `*enrich-env`): `PROCESS_ROLE=analyst`, the app DB role, its own broker user and the `AI_*` settings. `Settings` refuses a JWT secret, MinIO credentials, an app Redis URL and the TI private key file in that role, and refuses the AI private and platform key files in every other role. The AI private keys come from the compose secret `ai_seal_private`.
- **Own Celery app and broker user.** `analyst` may touch only `analyst*` / `test.analyst*` keys (queue, unacked bookkeeping, limiter and budget keys), never `enrich*`, `ingest*` or `trusted.*`. The `api` and `ingest` users publish to it; `pcap`, `static` and `enrich` cannot.
- **Import guard** (`tests/unit/test_ai_import_guard.py`): `ai.unseal`, the provider adapters, the registry, `ai.http` and the vendor SDKs (`anthropic`, `google.genai`, `httpx2`) only from `app/workers/analyst*.py` and the adapter modules; `core.sealbox_open` only from the TI and AI unseal wrappers, so no process role can open both domains.
- **Lifecycle shared with ingest.** `ai/lifecycle.py` changes run statuses for the worker and for the ingest reaper's fallback (`reap_ai_runs`: runs 10 min past their deadline with no live lease).
- **New server reads** (also used by M6): `GET /orgs/{org}/analyses?investigation_id=&latest_per_evidence=`, the merged case timeline `GET /orgs/{org}/investigations/{inv}/timeline`, and `ref=` filters on the pcap and static result lists, so citation chips deep-link to exactly the cited row.
- **Web** (phases 8–9; wording finalized in phase 11): an AI Analyst tab on pcap and malware job pages, a per-row "Explain" drawer on findings and alerts, an incident card on the investigation page, the AI runs list at `/o/{org}/ai-analyst`, and AI provider and privacy cards on the Integrations page. Run views show the context preview, truncation and pseudonymization banners, model, prompt version, tokens and cost, typed statuses, neutral confidence badges, an "AI-generated, verify before acting" banner and citation chips; model text is rendered as plain text only.

## Reports and case management (M6)

Signed, evidence-cited investigation reports, rendered by an isolated worker, plus notes, IOC collections, status history, TLP and the share policy. Details: [REPORTS.md](REPORTS.md).

```mermaid
flowchart LR
  B[Browser] --> G[gateway]
  G --> A[API<br/>snapshot builder, redaction,<br/>Ed25519 signing]
  A -->|put snapshot, retention| M[(MinIO<br/>reports bucket, object lock)]
  A -->|send_task report.render| RB[(redis-broker)]
  RB -->|queue report| RW[report-worker<br/>UNTRUSTED, WeasyPrint,<br/>sandboxed render subprocess]
  RW -->|presigned GET snapshot / POST artifact| M
  RW -->|report.rendered| RB
  RB -->|queue ingest| IW[ingest-worker<br/>trusted: token, re-hash, retention]
  IW --> P[(PostgreSQL)]
  IW --> M
  A --> P
  subgraph analysis [analysis network: internal, no egress]
    RW
  end
```

- **Case management** lives in the API only (`notes`, `ioc_collections`, `case_attack`, `case_timeline`, and `investigations` for TLP, status reasons and the status history). Every write is audited in its transaction; exports are streamed attachments.
- **Share policy:** `investigations/policy.py: load_policy` resolves TLP:RED and the case and evidence flags. It is called at the service choke points of the M4 and M5 modules (AI run and preview, the case context builder, job-scope enrichment) and again by the analyst-worker before every provider request and the enrich-worker before each slice.
- **Finalize** (the API, in the requester's session; RT14): (1) one `REPEATABLE READ READ ONLY` transaction builds the snapshot, redacts it and checks the size and the render budget; (2) outside any transaction the API signs the manifest and puts the snapshot into the object-locked `reports` bucket with a per-object retention; (3) one short write transaction re-checks the revision and the TLP rule, writes the version, citations, the PDF render and the audit row, then publishes `report.render`.
- **report-worker** (`apps/workers/report`, own image; analyzer-class): `analysis` network only, env `BROKER_URL` only (broker user `report`), root Celery process with the analyzers' capabilities, prefork with one task per child. It downloads the snapshot through a presigned GET, checks its sha256, and runs WeasyPrint in a uid-10004 subprocess (its own tool uid, not the static worker's 10003) with seccomp (AF_UNIX sockets only, no io_uring), rlimits, an empty environment and a deny-all URL fetcher. It uploads one artifact through a presigned POST and answers `report.rendered`.
- **Trusted ingest:** `reports/render_ingest.py` takes the org from `report_render_index`, checks the per-render token, re-hashes the stored object (never parses it), sets its retention and marks the render `succeeded`. `workers/reaper.py: reap_report_renders` fails renders past their deadline and re-dispatches lost publishes.
- **Reads:** the viewer gets the verified snapshot JSON (`GET …/versions/{v}/content`) and renders it as React text; renderer HTML is never shown in the app. Downloads are streamed by the API from the exact object version, re-hashed, audited, as sandboxed attachments.
- **Signing keys:** the private key file is a compose secret of the api role only; public keys are published unauthenticated at `GET /api/v1/report-signing-keys` for offline verification (`scripts/verify_report.py`).
- **Web:** the case workspace (`/o/{org}/investigations/{id}`) gains Notes, IOCs (case IOCs and collections), ATT&CK, Timeline (kinds filter, export) and Reports tabs, the TLP badge and card, the share-policy card, the status control with reasons and history; evidence pages get the evidence share policy. Reports: the org list (`/o/{org}/reports`), the builder (`/o/{org}/reports/{id}`: sections, selections, preview with the render budget, finalize dialog with the acknowledgements and change note) and the version viewer (`/o/{org}/reports/{id}/v/{n}`: TLP banners, integrity strip, renders and downloads).
