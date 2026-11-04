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
- Dependency changes need a rebuild: `pnpm dev` already passes `--build --renew-anon-volumes`.

## Prod-like stack

```bash
pnpm prod:up              # built images, no bind mounts, TLS (Caddy internal CA) on :8443
pnpm verify:prod          # dev gate + prod health, headers, HSTS
pnpm prod:down
```

Differences from dev: API `prod` target (non-root, no reload, `ENV=prod` refuses insecure cookies and `change-me` secrets), Next.js standalone server, Swagger UI disabled, MinIO console not published, HSTS + COOP headers, nonce CSP without `'unsafe-eval'` (dev adds it, and `ws:` for HMR), prod worker images (no test tooling).

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
| `redis-broker` | redis 7.4 | — | separate from the app Redis; ACL users `api`, `ingest`, `pcap`, `static` (+ `healthcheck`), no persistence, `maxmemory 256mb noeviction` |
| `pcap-worker` | `cyberlab/pcap-worker` (Zeek 8 base + tshark + suricata) | untrusted | `analysis` network only, read-only rootfs, `cap_drop: ALL` + 6 caps, tini init, `restart: unless-stopped` (fails closed), 2 GiB / 2 CPUs |
| `static-worker` | `cyberlab/static-worker` (python 3.12-slim-trixie + ClamAV, yara-python, pefile, pyelftools, capa, FLOSS) | untrusted | same isolation as pcap-worker (`analysis` network, read-only rootfs, caps, tini, fail-closed restart), 3 GiB / 2 CPUs |
| `ingest-worker` | `cyberlab/api` | trusted | `celery worker --pool solo`, app DB role + scoped MinIO user |
| `ingest-beat` | `cyberlab/api` | trusted | Celery beat: enqueues the reaper every 60 s |

- **Code reload:** Celery workers do not hot-reload. After changing worker code in dev, run `docker compose restart pcap-worker static-worker ingest-worker` (and `pcap-worker-test` / `static-worker-test` for tests).
- **Rules:** the ET Open snapshot is baked into the pcap-worker image at build time. Rebuild the image to update rules and parsers.
- **Static worker freshness:** the ClamAV DB (freshclam in a cached build stage) and capa rules (pinned tag, sha256-checked) are baked into the image. The DB is only re-downloaded when `CLAMAV_DB_REFRESH` changes, e.g. `docker compose build --build-arg CLAMAV_DB_REFRESH=$(date +%F) static-worker`; if freshclam fails (e.g. CDN rate limit), the image ships without a DB and every scan reports `av_unavailable`, never "clean". New capa rules need a new pin in `apps/workers/static/docker/fetch_capa_assets.py`. The AV DB date is shown in the Malware Lab. Rebuilding also updates ClamAV, libmagic and the Python parsers.

## Operations

- Orphan check (report-only): see `apps/api/app/scripts/reconcile_orphans.py` (runs as the Postgres superuser).
- Per-org storage quota: as the DB owner, `UPDATE organizations SET storage_quota_bytes = <bytes> WHERE id = '<org>'` (NULL returns to `DEFAULT_STORAGE_QUOTA_BYTES`). The app role cannot write this column. Usage is shown in the org settings page (`GET /orgs/{org}/storage`).
- Governance-locked evidence can only be removed by the MinIO root user with bypass — an administrative, audited-outside-the-app action.
