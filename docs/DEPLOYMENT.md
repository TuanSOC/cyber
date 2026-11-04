# Deployment

## Development (Windows, macOS, Linux)

Prerequisites: Docker Desktop (Compose ≥ 2.24), Node 22 + pnpm 10 (workspace scripts only). No host Python is needed.

```bash
cp .env.example .env      # replace every change-me value
pnpm dev                  # docker compose up --build --renew-anon-volumes
pnpm verify               # full gate (see TESTING.md)
```

- Windows: bind mounts do not forward file events, so dev uses polling (`WATCHFILES_FORCE_POLLING`, `NEXT_WATCH_POLL_MS`). Cloning inside WSL2 is faster.
- Init scripts (`infra/postgres/init`, MinIO buckets) run only on empty volumes. After changing them: `docker compose down -v`.
- Dependency changes need a rebuild: `pnpm dev` already passes `--build --renew-anon-volumes`. Since M4 the `backend` network has no egress and `UV_NO_SYNC=1` / `UV_OFFLINE=1` are set, so `uv run` never syncs at runtime: after editing `pyproject.toml`, relock with `docker compose run --rm --no-deps -e UV_FROZEN= api uv lock` while the network is up, then `docker compose build api`.
- MinIO console: not published (MinIO sits only on internal networks, which cannot publish ports). Use the client inside the container, e.g. `docker compose exec minio mc ls local/` after `docker compose exec minio mc alias set local http://localhost:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD"`.
- Upgrading an existing checkout to M4: `docker compose --profile test --profile e2e down` once (the `backend` network must be recreated as `internal`), add `BROKER_ENRICH_PASSWORD`, the `TI_*` lines and `TI_MOCK_EXPECTED_KEY` from `.env.example` to `.env`, then `pnpm dev`.

## Prod-like stack

```bash
pnpm prod:up              # built images, no bind mounts, TLS (Caddy internal CA) on :8443
pnpm verify:prod          # dev gate + prod health, headers, HSTS
pnpm prod:down
```

Differences from dev: API `prod` target (non-root, no reload, `ENV=prod` refuses insecure cookies and `change-me` secrets), Next.js standalone server, Swagger UI disabled, MinIO console not published, HSTS + COOP headers, nonce CSP without `'unsafe-eval'` (dev adds it, and `ws:` for HMR), prod worker images (no test tooling).

**Threat-intel seal keys (M4).** `ENV=prod` refuses the committed dev seal key (`dev-` kids). Before the first prod start, generate a key pair from the repo root:

```bash
docker run --rm -v "$PWD:/repo" -w /repo cyberlab/api:dev python scripts/gen_ti_seal_keys.py
```

It writes `.secrets/ti_seal_private.json` (mode 0400, owned by uid 10001 so the prod image user can read the compose secret; git- and docker-ignored) and prints `TI_PROD_SEAL_ACTIVE_KID` / `TI_PROD_SEAL_PUBLIC_KEYS` for `.env`. Only the `enrich-worker` mounts the private file; the API gets the public key only. Compose (non-swarm) secrets are bind mounts that keep the file's owner and mode, so keep it owned by 10001 when you edit it. Rotation (`--add --kid <new>`, both public keys, switch the active kid, check with a one-off enrich-worker container, lazy re-seal, drop the old kid): see the runbook in [THREAT_INTEL.md](THREAT_INTEL.md#rotate-the-sealing-key-prod).

**The prod enrich-worker override (RT3).** `.env` says `ENV=dev`, so `docker-compose.prod.yml` lists `enrich-worker` explicitly: `cyberlab/api:prod`, `ENV: prod`, the prod seal settings (`x-prod-ti`: `TI_MOCK_ENABLED=false`, `TI_PROD_SEAL_*`), `volumes: !reset []`, and the secret `ti_seal_private` from `.secrets/ti_seal_private.json`. `pnpm verify:prod` checks it twice: `scripts/check-enrich-env.mjs` compares the rendered prod environment with the fixture `test_config.py` builds `Settings` from (no JWT, MinIO or app Redis variable), and the gate requires the prod worker to be running with zero restarts after 15 s. `ti-mock` is not part of the prod stack.

The prod override also serves the site as `gateway:8443` so the e2e container can test it over the compose network; drop that for a real deployment. For a real deployment replace `tls internal` with a public certificate (set `SITE_ADDRESS` to the domain), use a maintained MinIO/S3 service, and put secrets in a secret manager rather than `.env`.

## Environment variables

| Variable | Used by | Notes |
|---|---|---|
| `ENV` | api | `dev` / `test` / `prod` |
| `COOKIE_SECURE` | api | must be `true` in prod (enforced) |
| `POSTGRES_PASSWORD`, `POSTGRES_OWNER_PASSWORD`, `POSTGRES_APP_PASSWORD` | postgres init | superuser / table owner / RLS-bound app role |
| `DATABASE_URL` | api | app role only |
| `MIGRATION_DATABASE_URL` | migrate | owner role; never given to the api |
| `REDIS_URL` | api | db 0 in dev; tests use db 1 |
| `JWT_SECRET` | api | ≥ 32 chars; rotating it signs everyone out |
| `MINIO_ENDPOINT` | api, api-test | `host:port` of MinIO |
| `MINIO_SECURE` | api (settings field; not passed by compose) | `true` for TLS to an external MinIO/S3; default `false` |
| `MINIO_BUCKET` | api, minio-init | created with object lock + versioning |
| `MINIO_TEST_BUCKET` | minio-init, api-test (as its `MINIO_BUCKET`) | test bucket, purged by the test harness |
| `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY` | api, minio-init (creates the user) | scoped user, no governance bypass |
| `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD` | minio, minio-init (and test profile) | never given to the api |
| `MAX_EVIDENCE_BYTES` | api | default 2 GiB |
| `CADDY_EVIDENCE_MAX` | gateway | `MAX_EVIDENCE_BYTES` + 1 MiB |
| `EVIDENCE_LOCK_DAYS` | api | GOVERNANCE retention per evidence version (0 disables) |
| `UPLOAD_TMP_DIR` | api | spool directory (volume) |
| `MAX_CONCURRENT_UPLOADS_PER_USER` | api | also bounds concurrent verifies |
| `RATE_LIMIT_LOGIN_PER_IP_PER_MIN`, `RATE_LIMIT_LOGIN_FAILURES_PER_15MIN`, `RATE_LIMIT_REGISTER_PER_IP_PER_10MIN` | api | |
| `TEST_DATABASE_URL`, `TEST_MIGRATION_DATABASE_URL`, `TEST_REDIS_URL` | api-test | must point at `*_test` DB and a non-zero Redis db (enforced) |
| `SITE_ADDRESS` | prod gateway | e.g. `localhost:8443` |
| `BROKER_API_PASSWORD`, `BROKER_INGEST_PASSWORD`, `BROKER_PCAP_PASSWORD`, `BROKER_STATIC_PASSWORD` | redis-broker (ACL users), api / ingest-* / pcap-worker / static-worker (in their `BROKER_URL`) | URL-safe; each component gets only its own |
| `RESULTS_BUCKET`, `RESULTS_TEST_BUCKET` | minio-init, api, ingest-worker | versioned, no object lock (derived data) |
| `PCAP_MAX_BYTES` | api | largest capture accepted for analysis (default 512 MiB) |
| `ANALYSIS_TIMEOUT_S`, `ANALYSIS_TOOL_TIMEOUT_S` | api (sent to the worker in every job) | 900 / 600 s |
| `MAX_ACTIVE_ANALYSES_PER_ORG` | api | queued + running jobs per org and analyzer (default 5; 50 overall per analyzer) |
| `STATIC_MAX_BYTES` | api | largest file analyzed statically (default 64 MiB); every other upload up to this size gets an `av` scan |
| `DEFAULT_STORAGE_QUOTA_BYTES` | api | per-org evidence quota when the org has no override (default 20 GiB; archived evidence counts). Per-org overrides: `organizations.storage_quota_bytes`, set by the DB owner |
| `MAX_OWNED_ORGS_PER_USER` | api | orgs one user may own (default 5) |
| `INGEST_TMP_DIR` | ingest-worker | disk-backed volume for result validation (results up to 256 MiB compressed, 1 GiB inflated) |
| `SURICATA_RULES` | pcap-worker-test only | small local rule file instead of the ET Open snapshot |
| `STATIC_CLAMAV_DB`, `STATIC_YARA_TEST_RULES`, `STATIC_CAPA_RULES`, `STATIC_CAPA`, `STATIC_FLOSS` | static-worker-test only | test DB / rules and engine switches; prod uses the baked defaults |
| `PROCESS_ROLE` | api (`api`), ingest-* (`ingest`), enrich-* (`enrich`) | `enrich` refuses `JWT_SECRET`, `MINIO_*` credentials and `REDIS_URL`; only `enrich` accepts `TI_SEAL_PRIVATE_KEYS_FILE` |
| `BROKER_ENRICH_PASSWORD` | redis-broker (ACL user `enrich`), enrich-worker | confined to `enrich*` / `test.enrich*` keys |
| `TI_ENABLED` | api, ingest-*, enrich-worker | default `true`; `false` hides every provider (`provider_unavailable`) |
| `TI_SEAL_ACTIVE_KID`, `TI_SEAL_PUBLIC_KEYS` | api, ingest-*, enrich-worker | kid and `{kid: base64 X25519 public key}` JSON; dev: the committed `dev-1` pair. Prod takes them from `TI_PROD_SEAL_ACTIVE_KID` / `TI_PROD_SEAL_PUBLIC_KEYS` (a `dev-` kid is refused) |
| `TI_SEAL_PRIVATE_KEYS_FILE` | enrich-worker only (compose secret `ti_seal_private`) | dev: `infra/ti/dev-seal-private.json`; prod: `.secrets/ti_seal_private.json` |
| `TI_MOCK_ENABLED`, `TI_MOCK_BASE_URL` | api, enrich-worker | `mock` provider → `ti-mock`; refused in prod |
| `TI_MOCK_EXPECTED_KEY` | ti-mock (test/e2e) | the key the mock accepts |
| `TI_MISP_ALLOW_PRIVATE`, `TI_MISP_INSECURE_TLS` | enrich-worker (and api for the save-time check) | dev only, refused in prod. Settings fields only: compose does not pass them |
| `TI_MISP_ALLOWED_PORTS`, `TI_MISP_CA_FILE`, `TI_MAX_IOCS_PER_RUN`, `TI_MAX_LOOKUP_VALUES`, `TI_RUN_DEADLINE_S`, `TI_SLICE_S`, `TI_CEILINGS` | api, enrich-worker | settings fields with defaults `[443, 8443]`, none, 200, 20, 1800, 20, catalog ceilings; compose does not pass them, so add them to both services' environment to change one. `TI_CEILINGS` is JSON `{provider: {per_minute, per_day, concurrency}}` for a paid tier; leaving out `per_day` removes the daily cap |
| `UV_NO_SYNC`, `UV_OFFLINE` | migrate, api, api-test, ingest-*, enrich-* | `uv run` never syncs (no egress on `backend`) |

## Capacity notes

- Each active upload needs temp disk up to its size plus ~32 MiB of RAM (16 MiB parts × 2). Size `UPLOAD_TMP_DIR` for `MAX_EVIDENCE_BYTES × MAX_CONCURRENT_UPLOADS_PER_USER × concurrent uploaders`.
- Measured locally: 1 GiB upload ≈ 15 s, API RSS peak ≈ 225 MiB, other requests unaffected.
- Stale spool files (> 1 h) are removed at API startup.
- Analysis runs one job at a time per pcap-worker. Measured on the synthetic dataset:
  - ET Open loading takes ≈ 40 s per job and peaks at ≈ 605 MiB (container limit 2 GiB).
  - The `pcap_work` volume needs room for the capture plus tool logs.
  - Scale by running more pcap-worker replicas; each takes jobs from the same queue.
- The static-worker also runs one job at a time. Measured on 40–231 KB samples (prod image):
  - clamscan with the full DB takes 14–20 s and peaks at ≈ 1.1 GiB (DB load); capa ≈ 20 s and FLOSS 35–42 s, each ≈ 1 GiB.
  - Engines run one after another, so the 3 GiB container limit covers the largest tool (`RLIMIT_AS` up to 2 GiB) plus the worker.
  - A `full` run with every engine took up to 42.7 s on the synthetic set; the `av` profile skips capa and FLOSS.
  - Images: prod ≈ 0.95 GB, dev ≈ 2.6 GB (mingw for test samples).

## Analysis services

| Service | Image | Trust | Notes |
|---|---|---|---|
| `redis-broker` | redis 7.4 | — | separate from the app Redis; ACL users `api`, `ingest`, `pcap`, `static`, `enrich` (+ `healthcheck`), no persistence, `maxmemory 256mb noeviction` |
| `pcap-worker` | `cyberlab/pcap-worker` (Zeek 8 base + tshark + suricata) | untrusted | `analysis` network only, read-only rootfs, `cap_drop: ALL` + 6 caps, tini init, `restart: unless-stopped` (fails closed), 2 GiB / 2 CPUs |
| `static-worker` | `cyberlab/static-worker` (python 3.12-slim-trixie + ClamAV, yara-python, pefile, pyelftools, capa, FLOSS) | untrusted | same isolation as pcap-worker (`analysis` network, read-only rootfs, caps, tini, fail-closed restart), 3 GiB / 2 CPUs |
| `ingest-worker` | `cyberlab/api` | trusted | `celery worker --pool solo`, app DB role + scoped MinIO user |
| `ingest-beat` | `cyberlab/api` | trusted | Celery beat: enqueues the reaper every 60 s |
| `enrich-worker` | `cyberlab/api` | trusted, internet-facing | threat-intel lookups (M4); `celery -A app.workers.enrich_app worker -Q enrich --pool solo` without gossip/mingle/heartbeat; `enrich` + `egress` (never `backend` or `analysis`), uid 10001, read-only rootfs, `cap_drop: ALL`, no-new-privileges; least-privilege env (no JWT secret, MinIO credentials or app Redis); seal private keys as a compose secret |
| `ti-mock` | python 3.12-alpine (stdlib server) | test / e2e only | deterministic provider sink on `egress` only |

## Networks and egress (M4)

| Network | Internal | Members |
|---|---|---|
| `backend` | yes (no egress) | postgres, redis, redis-broker, minio, minio-init, migrate, api, ingest-worker, ingest-beat, gateway, api-test |
| `enrich` | yes | postgres, redis-broker, enrich-worker(-test): the worker's data path, without the app Redis, MinIO, the API or the gateway |
| `frontend` | no | web, gateway, e2e |
| `analysis` | yes | pcap-worker(-test), static-worker(-test), redis-broker, minio |
| `egress` | no | enrich-worker(-test), ti-mock |

Runtime egress per service (checked 2026-11-05 on Docker Desktop 4.x / WSL2: `/proc/net/route`, a TCP connect to 1.1.1.1:443 and a lookup of `example.org` in each container; `tests/container/test_egress.py` pins it for api-test):

| Service | Needs internet at runtime? | Default route | Notes |
|---|---|---|---|
| postgres, redis, redis-broker | no | none | local healthchecks only |
| minio, minio-init | no | none | `mc` talks to `minio:9000`; dev console port dropped |
| migrate, api, api-test | no | none | `UV_NO_SYNC` / `UV_OFFLINE`; the API never calls a provider or resolves an external name (MISP URLs are checked syntactically) |
| ingest-worker, ingest-beat | no | none | broker, Postgres, MinIO only |
| pcap-worker, static-worker | no | none | `analysis` (unchanged); rules and AV DB are baked at build time |
| enrich-worker(-test) | **yes** (provider APIs) | via `egress` | the only one; on `enrich` + `egress`, never `backend` or `analysis` (`tests/container/test_enrich_network.py`, run by the gate inside `enrich-worker-test`) |
| gateway, web | dev `next/font` and future ACME only | via `frontend` | prod uses Caddy `tls internal` |
| ti-mock | no | via `egress` | test/e2e sink |

- External DNS: containers on `backend` only cannot resolve public names on this engine (`example.org` → `gaierror` from api and ingest-worker), so Docker's embedded DNS is not a lookup channel here (RT22; phase 7 asserts it in the egress suite).
- Image builds (apt, uv, pnpm, freshclam, capa rules) use the build network, not these.

- **Code reload:** Celery workers do not hot-reload. After changing worker code in dev, run `docker compose restart pcap-worker static-worker ingest-worker enrich-worker` (and `pcap-worker-test` / `static-worker-test` / `enrich-worker-test` for tests).
- **Rules:** the ET Open snapshot is baked into the pcap-worker image at build time. Rebuild the image to update rules and parsers.
- **Static worker freshness:** the ClamAV DB (freshclam in a cached build stage) and capa rules (pinned tag, sha256-checked) are baked into the image. The DB is only re-downloaded when `CLAMAV_DB_REFRESH` changes, e.g. `docker compose build --build-arg CLAMAV_DB_REFRESH=$(date +%F) static-worker`; if freshclam fails (e.g. CDN rate limit), the image ships without a DB and every scan reports `av_unavailable`, never "clean". New capa rules need a new pin in `apps/workers/static/docker/fetch_capa_assets.py`. The AV DB date is shown in the Malware Lab. Rebuilding also updates ClamAV, libmagic and the Python parsers.

## Operations

- Orphan check (report-only): see `apps/api/app/scripts/reconcile_orphans.py` (runs as the Postgres superuser).
- Per-org storage quota: as the DB owner, `UPDATE organizations SET storage_quota_bytes = <bytes> WHERE id = '<org>'` (NULL returns to `DEFAULT_STORAGE_QUOTA_BYTES`). The app role cannot write this column. Usage is shown in the org settings page (`GET /orgs/{org}/storage`).
- Governance-locked evidence can only be removed by the MinIO root user with bypass — an administrative, audited-outside-the-app action.
