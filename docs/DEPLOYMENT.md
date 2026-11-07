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
- Upgrading an existing checkout to M7: **take a backup first** if the data matters (below). Add the M7 block of `.env.example` to `.env` (`POSTGRES_RETENTION_PASSWORD`, `BROKER_RETENTION_PASSWORD`, `MINIO_PURGE_ACCESS_KEY` / `MINIO_PURGE_SECRET_KEY`, `RETENTION_POLICY_DELAY_DAYS`, `RATE_LIMIT_USER_PER_MIN`; the dev compose file falls back to `change-me` values), restart `redis-broker` (ACL user `retention`), recreate `minio` (it now starts with the KMS key; the dev key is `infra/minio/dev-kms-key`) and `minio-init` (SSE-S3 bucket defaults, the purge user), and run `db-bootstrap` then the migrations (`0014` refuses to run without the `cyberlab_retention` role): `docker compose up -d` does all of it in order. Enabling the KMS key on an existing volume makes MinIO encrypt its IAM and config with it from then on: keep that key (see [SSE-S3 and the KMS key](#sse-s3-and-the-kms-key)).
- Upgrading an existing checkout to M6: add `BROKER_REPORT_PASSWORD`, `REPORTS_BUCKET`, `REPORTS_TEST_BUCKET`, the `REPORT_SIGNING_*` lines and (optionally) `PUBLIC_BASE_URL` from `.env.example` to `.env` (the dev compose file falls back to a `change-me` broker password and the dev signing pair), restart `redis-broker` (new ACL user `report`) and `minio-init` (creates the object-locked `reports` / `reports-test` buckets and the new policy), build the `cyberlab/report-worker` image (`docker compose build report-worker`) and run the migrations (`0012`, `0013`).
- Upgrading an existing checkout to M5: add `BROKER_ANALYST_PASSWORD`, the `AI_*` lines and `AI_MOCK_EXPECTED_KEY` from `.env.example` to `.env` (the dev compose file falls back to a `change-me` broker password for an older `.env`, RT25), rebuild the api image (new dependencies `anthropic`, `google-genai`) and run the migrations (`0011`).
- Upgrading an existing checkout to M4: `docker compose --profile test --profile e2e down` once (the `backend` network must be recreated as `internal`), add `BROKER_ENRICH_PASSWORD`, the `TI_*` lines and `TI_MOCK_EXPECTED_KEY` from `.env.example` to `.env`, then `pnpm dev`.

## Prod-like stack

```bash
pnpm prod:up              # built images, no bind mounts, TLS (Caddy internal CA) on :8443
pnpm verify:prod          # dev gate + prod health, headers, HSTS
pnpm prod:down
```

Differences from dev: API `prod` target (non-root, no reload, `ENV=prod` refuses insecure cookies and `change-me` secrets), Next.js standalone server, Swagger UI disabled, MinIO console not published, HSTS + COOP headers, nonce CSP without `'unsafe-eval'` (dev adds it, and `ws:` for HMR), prod worker images (no test tooling).

**M7 prod secrets.** The prod overlay requires `POSTGRES_RETENTION_PASSWORD`, `BROKER_RETENTION_PASSWORD` and `MINIO_PURGE_SECRET_KEY` (no `change-me` fallback) and reads `.secrets/minio_kms_key` ([SSE-S3 and the KMS key](#sse-s3-and-the-kms-key)) and `.secrets/metrics_token` ([Runtime metrics](#runtime-metrics)). The prod retention-worker runs `cyberlab/api:prod` with `ENV=prod` and still no JWT secret, app Redis, api MinIO user or key material. `pnpm verify:prod` runs the prod stack in its own compose project (`<dev project>-prod`), so the dev volume's KMS key never meets the prod one (see the volume note).

**Threat-intel seal keys (M4).** `ENV=prod` refuses the committed dev seal key (`dev-` kids). Before the first prod start, generate a key pair from the repo root:

```bash
docker run --rm -v "$PWD:/repo" -w /repo cyberlab/api:dev python scripts/gen_ti_seal_keys.py
```

It writes `.secrets/ti_seal_private.json` (mode 0400, owned by uid 10001 so the prod image user can read the compose secret; git- and docker-ignored) and prints `TI_PROD_SEAL_ACTIVE_KID` / `TI_PROD_SEAL_PUBLIC_KEYS` for `.env`. Only the `enrich-worker` mounts the private file; the API gets the public key only. Compose (non-swarm) secrets are bind mounts that keep the file's owner and mode, so keep it owned by 10001 when you edit it. Rotation (`--add --kid <new>`, both public keys, switch the active kid, check with a one-off enrich-worker container, lazy re-seal, drop the old kid): see the runbook in [THREAT_INTEL.md](THREAT_INTEL.md#rotate-the-sealing-key-prod).

**The prod enrich-worker override (RT3).** `.env` says `ENV=dev`, so `docker-compose.prod.yml` lists `enrich-worker` explicitly: `cyberlab/api:prod`, `ENV: prod`, the prod seal settings (`x-prod-ti`: `TI_MOCK_ENABLED=false`, `TI_PROD_SEAL_*`), `volumes: !reset []`, and the secret `ti_seal_private` from `.secrets/ti_seal_private.json`. `pnpm verify:prod` checks it twice: `scripts/check-enrich-env.mjs` compares the rendered prod environment with the fixture `test_config.py` builds `Settings` from (no JWT, MinIO or app Redis variable), and the gate requires the prod worker to be running with zero restarts after 15 s. `ti-mock` is not part of the prod stack.

The prod override also serves the site as `gateway:8443` so the e2e container can test it over the compose network; drop that for a real deployment. For a real deployment replace `tls internal` with a public certificate (set `SITE_ADDRESS` to the domain), use a maintained MinIO/S3 service, and put secrets in a secret manager rather than `.env`.

## AI analyst (M5)

**AI seal keys.** As for TI: `ENV=prod` refuses `dev-` kids and the committed dev public key in every role. Before the first prod start:

```bash
docker run --rm -v "$PWD:/repo" -w /repo cyberlab/api:dev python scripts/gen_ai_seal_keys.py
```

It writes `.secrets/ai_seal_private.json` (mode 0400, chowned to uid 10001 when run as root, else it prints the `chown 10001` command) and prints `AI_PROD_SEAL_ACTIVE_KID` / `AI_PROD_SEAL_PUBLIC_KEYS` for `.env`. Only the `analyst-worker` mounts the private file (compose secret `ai_seal_private`); the API, ingest and the analyst get the public keys. Rotation (`--add --kid <new>`, both public keys, switch the active kid, one-off check, lazy re-seal, drop the old kid): [AI_ANALYST.md](AI_ANALYST.md#rotate-the-ai-sealing-key-prod).

**The prod analyst-worker override.** `docker-compose.prod.yml` lists `analyst-worker` explicitly: `cyberlab/api:prod`, `ENV: prod`, `x-prod-ai` (`AI_MOCK_ENABLED=false`, `AI_PLATFORM_PROVIDER=""`, `AI_PROD_SEAL_*`), `BROKER_URL` with `BROKER_ANALYST_PASSWORD` required (`:?`), `volumes: !reset []`, **two replicas** (the DB lease keeps them safe), and the secret from `.secrets/ai_seal_private.json`. `redis-broker` requires `BROKER_ANALYST_PASSWORD` in prod too. `ai-mock` is not part of the prod stack. The gate's env and running checks for it come with phase 11 (`scripts/check-analyst-env.mjs`).

**Gemini.** Off unless the operator sets `GEMINI_BILLING_ENABLED=true` on the api and the analyst-worker (both read it), and only for paid-tier keys: each org's admin must also attest it per key.

**Platform dev key (dev only).** For trying the analyst with the operator's own key on a dev stack:

```bash
printf '%s' "$KEY" > .secrets/ai_platform_key          # gitignored
AI_PLATFORM_PROVIDER=anthropic docker compose -f docker-compose.yml \
  -f docker-compose.ai-platform.yml up -d analyst-worker api
```

The overlay mounts the key as a compose secret into the analyst-worker only and tells the API which provider it covers (`platform_key` on the catalog). It is used only for orgs without their own key for that provider, after they enabled AI and acknowledged the terms, and is capped globally at `AI_PLATFORM_DAILY_TOKENS` (200 000 per UTC day). `ENV=prod` refuses it; it is never part of the gate.

**ai-mock profiles.** `ai-mock` runs in the `test` and `e2e` profiles only, on `egress`, and accepts `AI_MOCK_EXPECTED_KEY`. With the dev default `AI_MOCK_ENABLED=true`, the "Test analyst (mock)" provider appears on the Integrations page; start a stack with the `e2e` (or `test`) profile so `ai-mock` runs, and enter that key there.

## Reports (M6)

Details: [REPORTS.md](REPORTS.md).

**Buckets.** `minio-init` creates `reports` and `reports-test` with `mc mb --with-lock` (object lock, versioned) and **no bucket default retention**: a default retention would make MinIO demand `Content-MD5` on the renderer's presigned POST. Retention is set per object (GOVERNANCE, `EVIDENCE_LOCK_DAYS`) by the API on each snapshot and by the ingest worker on each artifact after its re-hash. An existing bucket without object lock is refused (recreate it with `docker compose down -v`). `reports-test` gets the test lifecycle rule (noncurrent versions expire); `reports` gets none, so a signed report is never auto-deleted. The api / ingest MinIO user (`infra/minio/api-policy.template.json`) may get, version-get, put and get / put retention on both report buckets, and has **no** `DeleteObject` / `DeleteObjectVersion` there. api-test uses `REPORTS_BUCKET=${REPORTS_TEST_BUCKET}`.

**report-worker.** Image `cyberlab/report-worker` (`apps/workers/report`, targets `dev` and `prod`; build contexts `jobs` and `worker_kit`): python 3.12-slim-trixie, Pango, HarfBuzz, libseccomp, Noto core and mono fonts, WeasyPrint 70, no Ghostscript. `init`, read-only rootfs, `cap_drop: ALL` plus the analyzers' six capabilities, no-new-privileges, `pids_limit: 128`, 1 GiB, 1 CPU, tmpfs `/tmp` 16 MiB and `/work` 96 MiB (`noexec`), `analysis` network only, env `BROKER_URL` only (user `report`). It needs no database, MinIO credentials, JWT secret or signing key. The prod overlay uses `cyberlab/report-worker:prod`, `ENV: prod`, `volumes: !reset []` and requires `BROKER_REPORT_PASSWORD`. **Scaling:** one replica renders one report at a time (prefork, concurrency 1); `REPORT_ACTIVE_RENDERS_GLOBAL` (4) is sized for one replica, so raise it with the replica count. `report-worker-test` (test profile) is not an api-test dependency; the end-to-end render test starts it.

**Signing keys (prod).** `ENV=prod` refuses `dev-` kids and the committed dev public key, and the api requires `REPORT_SIGNING_KEYS_FILE`. The prod api also checks the keys **at startup** (`reports/signing.check_startup_keys`, review L3): the private key file is loaded then (a missing or unreadable file fails the start, not the first finalize), the active kid must be in it, its public half must equal the published `REPORT_SIGNING_PUBLIC_KEYS` entry, and a private key whose public half is the committed dev key is refused (`dev_signing_key`). `scripts/check-report-worker-env.mjs` (in `pnpm verify:prod`) checks the rendered compose files: the report-worker holds only `BROKER_URL` (+ `ENV=prod`), the private key is mounted on `api` only, and the prod kid and public keys hold no dev key. Before the first prod start:

```bash
docker run --rm -v "$PWD:/repo" -w /repo cyberlab/api:dev python scripts/gen_report_signing_keys.py
```

It writes `.secrets/report_signing_private.json` (mode 0400, chowned to uid 10001 when run as root, else it prints the `chown 10001` command) and prints `REPORT_PROD_SIGNING_ACTIVE_KID` / `REPORT_PROD_SIGNING_PUBLIC_KEYS` for `.env`. Only the **api** mounts the private file (compose secret `report_signing_private`, `REPORT_SIGNING_KEYS_FILE=/run/secrets/report_signing_private`); ingest, enrich, analyst and the report-worker never get it, and `Settings` refuses it in any role but `api`. Rotation: `--add --kid <new>`, keep every old public key in `REPORT_PROD_SIGNING_PUBLIC_KEYS`, switch the active kid ([REPORTS.md](REPORTS.md#key-rotation-prod)).

**Published public keys.** External recipients verify reports with `GET /api/v1/report-signing-keys` (unauthenticated) or a key list the operator publishes with the deployment. Record every kid ever used here, for example:

| kid | Ed25519 public key (base64) | Status |
|---|---|---|
| `dev-report-1` | `zS2iP9napZDeshJwfCiTwYl8amzPuWJEJwHK8CpnF2k=` | dev only, refused in prod (its private half is committed) |
| `prod-report-YYYYMMDD` | from `REPORT_PROD_SIGNING_PUBLIC_KEYS` | fill in per deployment; never delete a row |

**`PUBLIC_BASE_URL`** (api): the origin printed in front of the citation paths of internal reports (e.g. `https://cyberlab.example`). Empty: paths only. Prod requires `https` (plain `http` only for localhost); `external` reports never carry it.

**Backups.** A report is a DB row (`report_versions`: sha256, manifest, signature, object version id) plus the locked objects in `reports`, so the database and the MinIO volume must be backed up **together**, with their version ids: since M7 `pnpm backup` does exactly that ([Backup and restore](#backup-and-restore-m7)), and `restore_verify --objects` re-hashes every snapshot and checks its signature. A snapshot object without its row is an orphan, and a row without its object answers `409 integrity_failed`. `apps/api/app/scripts/reconcile_orphans.py` lists object versions without a row in both buckets: evidence, and in `reports` the snapshots without a `report_versions` row (a finalize that failed after the put, also logged by the API as "orphan report snapshot" with its key and version id) and the render artifacts no render recorded (an upload ingest refused, or a render still running).

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
| `CADDY_EVIDENCE_MAX` | gateway | max(`MAX_EVIDENCE_BYTES`, `MEMORY_MAX_BYTES`, `DISK_MAX_UPLOAD_BYTES`) + 1 MiB on the upload route (M8 / M9: `.env.example` ships `8590983168`, 8 GiB + 1 MiB; for 16 GiB images or segments use `17180917760`) |
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
| `POSTGRES_RETENTION_PASSWORD` | postgres init (`02-m7-roles.sh`), db-bootstrap, retention-worker (in its `DATABASE_URL`), api-test (`RETENTION_TEST_DATABASE_URL`) | M7: password of `cyberlab_retention`; required in prod |
| `BROKER_RETENTION_PASSWORD` | redis-broker (ACL user `retention`), retention-worker | M7: confined to `retention*` / `test.retention*` keys; required in prod |
| `MINIO_PURGE_ACCESS_KEY`, `MINIO_PURGE_SECRET_KEY` | minio-init (creates the user), retention-worker only (test profile: `TEST_MINIO_PURGE_*`) | M7: the purge user (version delete, legal hold, no `PutObject`, no bypass, Deny on report snapshots); refused by every other `PROCESS_ROLE`; the secret is required in prod |
| `RETENTION_POLICY_DELAY_DAYS` | api, retention-worker | M7: delay of a lowered value, of turning `enforce` on and of a hold release (default 7) |
| `RATE_LIMIT_USER_PER_MIN` | api | M7: global per-user request limit (default 600; the test profile raises it) |
| `BROKER_MEMORY_PASSWORD` | redis-broker (ACL user `memory`), memory-worker(-test), api-test (`TEST_BROKER_MEMORY_URL`) | M8: the memory analyzer, confined to `memory*` / `test.memory*`, write-only to ingest; dev default `change-me-broker-memory`, required in prod |
| `MEMORY_MAX_BYTES` | api | M8: largest memory image (default 8 GiB, refused above 16 GiB); `CADDY_EVIDENCE_MAX` must cover it. Enforced on requests now, on `kind=memory` uploads from phase 6 |
| `ANALYSIS_MEMORY_TIMEOUT_S`, `ANALYSIS_MEMORY_PLUGIN_TIMEOUT_S`, `ANALYSIS_MEMORY_IDENTIFY_TIMEOUT_S` | api (sent in every memory job) | M8: 5 400 / 1 200 / 600 s (job ≤ 21 600) |
| `MEMORY_MAX_ACTIVE_PER_ORG`, `MEMORY_MAX_ACTIVE_TOTAL` | api | M8: active memory jobs per org / platform-wide (1 / 2; the test profile raises them) |
| `MEMORY_MAX_RESULT_BYTES`, `MEMORY_MAX_RESULT_DECOMPRESSED_BYTES`, `MEMORY_MAX_{PROCESSES,CONNECTIONS,INJECTIONS,ARTIFACTS,FINDINGS,IOCS,TIMELINE}`, `MEMORY_TREE_MAX_NODES` | api | M8 settings with defaults 256 MiB, 1 GiB, 20 000, 50 000, 5 000, 50 000, 5 000, 20 000, 5 000, 5 000; compose does not pass them |
| `MEMORY_SYMBOLS_DIR`, `MEMORY_ENGINE`, `MEMORY_PLUGIN_RLIMIT_AS` | memory-worker | M8: `/symbols`, `volatility3` (`replay` only with `TEST_PROFILE=1`), 2.5 GiB; image defaults |
| `BROKER_DISK_PASSWORD`, `DISK_*`, `ANALYSIS_DISK_TIMEOUT_S` | redis-broker, api, disk-worker(-test) | M9 (in progress): see [Disk forensics (M9)](#disk-forensics-m9), Settings |
| `MINIO_KMS_SECRET_KEY_FILE` (compose secret `minio_kms_key`) | minio, minio-init (name check only) | M7: SSE-S3 key `<name>:<base64 32 bytes>`; dev: `infra/minio/dev-kms-key` (name `cyberlab-dev-kms`, refused in prod); prod: `.secrets/minio_kms_key`. Refused by every app `PROCESS_ROLE` |
| `MINIO_SSE_ENABLED` | minio-init | M7: `true` (default) sets the SSE-S3 bucket default on every bucket |
| `MINIO_IMAGE`, `MC_IMAGE`, `MINIO_DATA_DIR`, `MINIO_READ_ONLY` | minio, minio-init, backup / restore | M7: object-store image (defaults since the switch: `localhost/cyberlab/silo:RELEASE.2026-10-26T00-00-00Z`, built from `infra/minio/silo/Dockerfile`; `bitnamilegacy/minio-client:2025.5.21`; `/data`; `true`). The bitnami rollback sets `bitnamilegacy/minio:2025.5.24`, `/bitnami/minio/data`, `false` |
| `METRICS_TOKEN_FILE` (compose secret `metrics_token`; dev override `METRICS_TOKEN_SECRET_FILE`) | api only | M7: bearer token of `/internal/metrics`; empty or unset = the route is off (dev default: an empty file) |
| `BACKUP_DIR` | `pnpm backup` | M7: default `./backups/` (gitignored); never a path git tracks or `.secrets/` |
| `RETENTION_BATCH_ROWS`, `RETENTION_BATCH_OBJECTS`, `RETENTION_RUN_SLICE_S`, `RETENTION_SAMPLE_LIMIT`, `RETENTION_JOB_OUTCOMES_DAYS`, `CORRELATION_COMMON_KEY_JOBS`, `CORRELATION_MAX_KEYS_PER_JOB`, `CORRELATION_INDEX_BUDGET_S`, `CORRELATION_INDEX_BATCH_JOBS`, `SEARCH_MIN_QUERY_CHARS`, `SEARCH_MAX_QUERY_CHARS`, `SEARCH_HITS_PER_TYPE`, `SEARCH_STATEMENT_TIMEOUT_S`, `SEARCH_PER_USER_PER_MIN`, `EVIDENCE_VIEW_AUDIT_DEDUPE_S` | api / workers | M7 settings with defaults 5 000, 200, 120 s, 50, 90 days, 50, 20 000, 10 s, 5, 2, 256, 20, 3 s, 30, 900 s; compose does not pass them |
| `PROCESS_ROLE` | api (`api`), ingest-* (`ingest`), enrich-* (`enrich`), analyst-* (`analyst`), retention-worker (`retention`, M7: refuses `JWT_SECRET`, `REDIS_URL`, the api MinIO user, every seal / signing / platform key file and the metrics token, and requires the `cyberlab_retention` DB URL and the purge keys) | `enrich` and `analyst` refuse `JWT_SECRET`, `MINIO_*` credentials and `REDIS_URL`; only `enrich` accepts `TI_SEAL_PRIVATE_KEYS_FILE`; only `analyst` accepts `AI_SEAL_PRIVATE_KEYS_FILE` and `AI_PLATFORM_KEY_FILE` |
| `BROKER_ENRICH_PASSWORD` | redis-broker (ACL user `enrich`), enrich-worker | confined to `enrich*` / `test.enrich*` keys |
| `TI_ENABLED` | api, ingest-*, enrich-worker | default `true`; `false` hides every provider (`provider_unavailable`) |
| `TI_SEAL_ACTIVE_KID`, `TI_SEAL_PUBLIC_KEYS` | api, ingest-*, enrich-worker | kid and `{kid: base64 X25519 public key}` JSON; dev: the committed `dev-1` pair. Prod takes them from `TI_PROD_SEAL_ACTIVE_KID` / `TI_PROD_SEAL_PUBLIC_KEYS` (a `dev-` kid is refused) |
| `TI_SEAL_PRIVATE_KEYS_FILE` | enrich-worker only (compose secret `ti_seal_private`) | dev: `infra/ti/dev-seal-private.json`; prod: `.secrets/ti_seal_private.json` |
| `TI_MOCK_ENABLED`, `TI_MOCK_BASE_URL` | api, enrich-worker | `mock` provider → `ti-mock`; refused in prod |
| `TI_MOCK_EXPECTED_KEY` | ti-mock (test/e2e) | the key the mock accepts |
| `TI_MISP_ALLOW_PRIVATE`, `TI_MISP_INSECURE_TLS` | enrich-worker (and api for the save-time check) | dev only, refused in prod. Settings fields only: compose does not pass them |
| `TI_MISP_ALLOWED_PORTS`, `TI_MISP_CA_FILE`, `TI_MAX_IOCS_PER_RUN`, `TI_MAX_LOOKUP_VALUES`, `TI_RUN_DEADLINE_S`, `TI_SLICE_S`, `TI_CEILINGS` | api, enrich-worker | settings fields with defaults `[443, 8443]`, none, 200, 20, 1800, 20, catalog ceilings; compose does not pass them, so add them to both services' environment to change one. `TI_CEILINGS` is JSON `{provider: {per_minute, per_day, concurrency}}` for a paid tier; leaving out `per_day` removes the daily cap |
| `BROKER_ANALYST_PASSWORD` | redis-broker (ACL user `analyst`), analyst-worker | confined to `analyst*` / `test.analyst*` keys; dev default `change-me-broker-analyst`, required in prod |
| `AI_ENABLED` | api, ingest-*, analyst-worker | default `true`; `false` makes every AI provider unavailable |
| `AI_SEAL_ACTIVE_KID`, `AI_SEAL_PUBLIC_KEYS` | api, ingest-*, analyst-worker | dev: the committed `dev-ai-1` pair; prod from `AI_PROD_SEAL_ACTIVE_KID` / `AI_PROD_SEAL_PUBLIC_KEYS` |
| `AI_SEAL_PRIVATE_KEYS_FILE` | analyst-worker only (compose secret `ai_seal_private`) | dev: `infra/ai/dev-seal-private.json`; prod: `.secrets/ai_seal_private.json` |
| `AI_MOCK_ENABLED`, `AI_MOCK_BASE_URL` | api, analyst-worker | `mock` provider → `ai-mock`; refused in prod |
| `AI_MOCK_EXPECTED_KEY` | ai-mock (test/e2e) | the key the mock accepts |
| `GEMINI_BILLING_ENABLED` | api, analyst-worker | default `false`: Gemini unavailable |
| `AI_PLATFORM_PROVIDER`, `AI_PLATFORM_KEY_FILE` | api (provider only), analyst-worker | dev-only overlay `docker-compose.ai-platform.yml`; refused in prod |
| `AI_ANTHROPIC_EFFORT` | analyst-worker | `low` / `medium` (default) / `high` / `xhigh` / `max` |
| `AI_DEFAULT_PROVIDER`, `AI_MAX_INPUT_TOKENS`, `AI_MAX_OUTPUT_TOKENS`, `AI_CALL_TIMEOUT_S`, `AI_CALL_IDLE_TIMEOUT_S`, `AI_MAX_CALLS_PER_RUN`, `AI_RUN_DEADLINE_S`, `AI_INCIDENT_DEADLINE_S`, `AI_MAX_JOBS_PER_INCIDENT`, `AI_CEILINGS`, `AI_PLATFORM_DAILY_TOKENS`, `AI_RUNS_PER_USER_10MIN`, `AI_ACTIVE_RUNS_PER_ORG`, `AI_ACTIVE_RUNS_GLOBAL` | api, analyst-worker | settings fields with defaults `anthropic`, 60 000, 16 000, 300, 60, 3, 1200, 3600, 10, catalog ceilings, 200 000, 10, 12, 40; compose does not pass them. `AI_CEILINGS` is JSON `{daily_token_budget, run_token_cap, incident_token_cap, per_minute: {provider: n}}` |
| `AI_ANTHROPIC_BASE_URL`, `AI_GEMINI_BASE_URL` | analyst-worker (tests) | replay endpoints; refused in prod |
| `UV_NO_SYNC`, `UV_OFFLINE` | migrate, api, api-test, ingest-*, enrich-*, analyst-* | `uv run` never syncs (no egress on `backend`) |
| `BROKER_REPORT_PASSWORD` | redis-broker (ACL user `report`), report-worker(-test) | confined to `report*` / `test.report*`, write-only to ingest; dev default `change-me-broker-report`, required in prod |
| `REPORTS_BUCKET`, `REPORTS_TEST_BUCKET` | minio-init, api, ingest-* (api-test uses the test bucket as its `REPORTS_BUCKET`) | object lock, versioned, no default retention; per-object GOVERNANCE retention (`EVIDENCE_LOCK_DAYS`) |
| `PUBLIC_BASE_URL` | api | origin in front of internal citation paths; https in prod (localhost excepted); empty: none |
| `REPORT_SIGNING_ACTIVE_KID`, `REPORT_SIGNING_PUBLIC_KEYS` | api only | kid and `{kid: base64 Ed25519 public key}` JSON; dev: the committed `dev-report-1` pair; prod from `REPORT_PROD_SIGNING_ACTIVE_KID` / `REPORT_PROD_SIGNING_PUBLIC_KEYS` (a `dev-` kid or the dev key is refused) |
| `REPORT_SIGNING_KEYS_FILE` | api only (compose secret `report_signing_private`) | dev: `infra/reports/dev-signing-private.json`; prod: `.secrets/report_signing_private.json`; refused for every other `PROCESS_ROLE` |
| `REPORT_MAX_SNAPSHOT_BYTES`, `REPORT_MAX_ARTIFACT_BYTES`, `REPORT_MAX_RENDER_UNITS`, `REPORT_MAX_PAGES`, `REPORT_RENDER_DEADLINE_S`, `REPORT_RENDER_TIMEOUT_S`, `REPORT_RENDERS_PER_USER_10MIN`, `REPORT_FINALIZE_PER_USER_10MIN`, `REPORT_PREVIEW_PER_USER_10MIN`, `REPORT_ACTIVE_RENDERS_PER_ORG`, `REPORT_ACTIVE_RENDERS_GLOBAL`, `TIMELINE_EXPORT_MAX_ROWS` | api | settings fields with defaults 8 MiB, 32 MiB, 450 000 (calibrated, RT1), 300, 600, 120, 20, 10, 30, 2, 4 (per renderer replica), 50 000; compose does not pass them. The snapshot, artifact and page settings can only be lowered: the contract values are their ceilings, and the renderer enforces the contract values |

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
| `redis-broker` | redis 7.4 | — | separate from the app Redis; ACL users `api`, `ingest`, `pcap`, `static`, `enrich`, `analyst`, `report`, `retention` (M7), `memory` (M8), `disk` (M9), `reverse` (M10) (+ `healthcheck`), no persistence, `maxmemory 256mb noeviction` |
| `db-bootstrap` | postgres 17.11-alpine | operator (superuser), one-shot | M7: creates / updates `cyberlab_retention` (`infra/postgres/bootstrap.sh`, idempotent) before `migrate`; `backend` only |
| `retention-worker` | `cyberlab/api` | trusted, destructive | M7: `celery -A app.workers.retention_app worker -Q retention --pool solo` without gossip/mingle/heartbeat; `backend` only, uid 10001, read-only rootfs, tmpfs `/tmp`, `cap_drop: ALL`, no-new-privileges, 384 MiB; least-privilege env (`x-retention-env`, never `*api-env`); dry run unless the DB policy says `enforce` is effective |
| `pcap-worker` | `cyberlab/pcap-worker` (Zeek 8 base + tshark + suricata) | untrusted | `analysis` network only, read-only rootfs, `cap_drop: ALL` + 6 caps, tini init, `restart: unless-stopped` (fails closed), 2 GiB / 2 CPUs |
| `static-worker` | `cyberlab/static-worker` (python 3.12-slim-trixie + ClamAV, yara-python, pefile, pyelftools, capa, FLOSS) | untrusted | same isolation as pcap-worker (`analysis` network, read-only rootfs, caps, tini, fail-closed restart), 3 GiB / 2 CPUs |
| `memory-worker` | `cyberlab/memory-worker` (python 3.12-slim-trixie + volatility3 2.28.2, pefile, capstone, jsonschema; no symbols) | untrusted | M8 (in progress; phase 1 fails every job `not_implemented`): same isolation as static-worker (`analysis` only, env `BROKER_URL` only, read-only rootfs, caps, tini, fail-closed restart), 3 GiB / 2 CPUs, `pids_limit 256`, `/work` on the named volume `memory_work`, `memory_symbols` read-only at `/symbols`; tool uid 10006 |
| `memory-symbols`, `memory-symbols-test` | `cyberlab/memory-worker` | trusted operator tool | M8 (CLI pending phase 5): profile `tools` (never part of `up`), uid 10005, read-only rootfs, `cap_drop: ALL`, 2 GiB, network `symbols_egress` only, no secrets; the target store rw at `/symbols` (`memory_symbols`, or `memory_symbols_test` for `--store test`) and `./.memory-import` read-only at `/import`. `memory-symbols-init` (one-shot, no network) chowns both volumes to 10005 |
| `disk-worker`, `disk-ingest-worker`, `disk-hashsets(-test)`, `disk-hashsets-init` | `cyberlab/disk-worker`, `cyberlab/api` | untrusted / trusted / operator tool | M9 (in progress, untested): see [Disk forensics (M9)](#disk-forensics-m9) |
| `re-worker`, `re-worker-test` | `cyberlab/re-worker` | untrusted | M10 (in progress, untested): see [Reverse engineering (M10)](#reverse-engineering-m10) |
| `ingest-worker` | `cyberlab/api` | trusted | `celery worker --pool solo`, app DB role + scoped MinIO user |
| `ingest-beat` | `cyberlab/api` | trusted | Celery beat: enqueues the reaper every 60 s |
| `enrich-worker` | `cyberlab/api` | trusted, internet-facing | threat-intel lookups (M4); `celery -A app.workers.enrich_app worker -Q enrich --pool solo` without gossip/mingle/heartbeat; `enrich` + `egress` (never `backend` or `analysis`), uid 10001, read-only rootfs, `cap_drop: ALL`, no-new-privileges; least-privilege env (no JWT secret, MinIO credentials or app Redis); seal private keys as a compose secret |
| `ti-mock` | python 3.12-alpine (stdlib server) | test / e2e only | deterministic provider sink on `egress` only |
| `analyst-worker` | `cyberlab/api` | trusted, internet-facing | AI analyst (M5); `celery -A app.workers.analyst_app worker -Q analyst --pool solo` without gossip/mingle/heartbeat; `enrich` + `egress`, uid 10001, read-only rootfs, tmpfs `/tmp`, `cap_drop: ALL`, no-new-privileges; least-privilege env (no JWT secret, MinIO, app Redis or TI key); AI seal private keys as a compose secret; 2 replicas in prod |
| `ai-mock` | python 3.12-alpine (stdlib server) | test / e2e only | deterministic LLM sink on `egress` only (uid 65534, read-only) |
| `report-worker` | `cyberlab/report-worker` (python 3.12-slim-trixie + WeasyPrint 70, Pango, Noto fonts; no Ghostscript) | untrusted | report renderer (M6): `analysis` network only, read-only rootfs, `cap_drop: ALL` + 6 caps, tini init, prefork concurrency 1 with one task per child, 1 GiB / 1 CPU, `/work` tmpfs 96 MiB; env `BROKER_URL` only; renders in a uid-10004 sandboxed subprocess (its own tool uid, not the static worker's 10003) |

## Networks and egress (M4, M5, M6)

| Network | Internal | Members |
|---|---|---|
| `backend` | yes (no egress) | postgres, redis, redis-broker, minio, minio-init, db-bootstrap (M7), migrate, api, ingest-worker, ingest-beat, retention-worker(-test) (M7), gateway, api-test |
| `enrich` | yes | postgres, redis-broker, enrich-worker(-test), analyst-worker(-test): the workers' data path, without the app Redis, MinIO, the API or the gateway |
| `frontend` | no | web, gateway, e2e |
| `analysis` | yes | pcap-worker(-test), static-worker(-test), report-worker(-test), memory-worker(-test) (M8), redis-broker, minio |
| `egress` | no | enrich-worker(-test), analyst-worker(-test), ti-mock, ai-mock |
| `symbols_egress` | no | memory-symbols, memory-symbols-test (M8, profile `tools`): their own bridge, shared with nothing |

Runtime egress per service (checked 2026-11-05 on Docker Desktop 4.x / WSL2: `/proc/net/route`, a TCP connect to 1.1.1.1:443 and a lookup of `example.org` in each container; `tests/container/test_egress.py` pins it for api-test):

| Service | Needs internet at runtime? | Default route | Notes |
|---|---|---|---|
| postgres, redis, redis-broker | no | none | local healthchecks only |
| minio, minio-init | no | none | `mc` talks to `minio:9000`; dev console port dropped |
| migrate, api, api-test | no | none | `UV_NO_SYNC` / `UV_OFFLINE`; the API never calls a provider or resolves an external name (MISP URLs are checked syntactically) |
| ingest-worker, ingest-beat | no | none | broker, Postgres, MinIO only |
| retention-worker(-test), db-bootstrap | no | none | M7: `backend` only (Postgres, the broker, MinIO) |
| pcap-worker, static-worker | no | none | `analysis` (unchanged); rules and AV DB are baked at build time |
| memory-worker(-test) | no | none | M8: `analysis`; symbols come only from the read-only store; Volatility is set offline and its tools may open AF_UNIX sockets only (checks pending phases 2, 11) |
| memory-symbols(-test) | **yes, on operator request** (`fetch-windows` only) | via `symbols_egress` | M8: HTTPS to `msdl.microsoft.com` and its symbol CDN only, by policy in the tool (suffix allow-list), not by the network; run by hand, never by `up`, a test or the gate |
| report-worker(-test) | no | none | `analysis`; fonts and templates baked into the image; the render subprocess cannot open inet sockets at all (`apps/workers/report/tests/test_isolation.py`, `test_sandbox.py`) |
| enrich-worker(-test) | **yes** (provider APIs) | via `egress` | one of two (with the analyst-worker); on `enrich` + `egress`, never `backend` or `analysis` (`tests/container/test_enrich_network.py`, run by the gate inside `enrich-worker-test`) |
| analyst-worker(-test) | **yes** (Anthropic / Gemini APIs) | via `egress` | on `enrich` + `egress`, never `backend` or `analysis` (`tests/container/test_analyst_network.py`, run inside `analyst-worker-test`) |
| gateway, web | dev `next/font` and future ACME only | via `frontend` | prod uses Caddy `tls internal` |
| ti-mock, ai-mock | no | via `egress` | test/e2e sinks |

- External DNS: containers on `backend` only cannot resolve public names on this engine (`example.org` → `gaierror` from api and ingest-worker), so Docker's embedded DNS is not a lookup channel here (RT22; phase 7 asserts it in the egress suite).
- Image builds (apt, uv, pnpm, freshclam, capa rules) use the build network, not these.

- **Code reload:** Celery workers do not hot-reload. After changing worker code in dev, run `docker compose restart pcap-worker static-worker ingest-worker enrich-worker analyst-worker report-worker` (and `memory-worker`, M8) (and `pcap-worker-test` / `static-worker-test` / `enrich-worker-test` / `analyst-worker-test` / `report-worker-test` for tests). A template, CSS, font or WeasyPrint change needs an image rebuild and a render-budget recalibration ([REPORTS.md](REPORTS.md#render-budget-and-caps-rt1)).
- **Rules:** the ET Open snapshot is baked into the pcap-worker image at build time. Rebuild the image to update rules and parsers.
- **Static worker freshness:** the ClamAV DB (freshclam in a cached build stage) and capa rules (pinned tag, sha256-checked) are baked into the image. The DB is only re-downloaded when `CLAMAV_DB_REFRESH` changes, e.g. `docker compose build --build-arg CLAMAV_DB_REFRESH=$(date +%F) static-worker`; if freshclam fails (e.g. CDN rate limit), the image ships without a DB and every scan reports `av_unavailable`, never "clean". New capa rules need a new pin in `apps/workers/static/docker/fetch_capa_assets.py`. The AV DB date is shown in the Malware Lab. Rebuilding also updates ClamAV, libmagic and the Python parsers.

## Operations

- Orphan check (report-only): see `apps/api/app/scripts/reconcile_orphans.py` (runs as the Postgres superuser). Since M7 it also reports `purged_pending_delete` (a tombstoned version still stored; the next retention run retries the delete) and `missing_unexplained` (a pinned version gone **without** a tombstone: a deletion outside retention, e.g. by the api's cleanup grant after the lock expired; investigate it).
- Correlation backfill for a large install (outside the ingest worker): `docker compose run --rm --no-deps ingest-worker uv run python -m app.scripts.backfill_correlation [--batch 20]` (idempotent, may run next to the beat task, which also backfills at most 5 jobs per minute).
- Per-org storage quota: as the DB owner, `UPDATE organizations SET storage_quota_bytes = <bytes> WHERE id = '<org>'` (NULL returns to `DEFAULT_STORAGE_QUOTA_BYTES`). The app role cannot write this column. Usage is shown in the org settings page (`GET /orgs/{org}/storage`).
- Governance-locked evidence can only be removed by the MinIO root user with bypass — an administrative, audited-outside-the-app action.
- Retention, legal holds and the M7 operations: see the sections below.

## Backup and restore (M7)

Offline, quiesced, single node: the whole stack is one maintenance window of a few minutes at this scale (it grows with the MinIO volume: a 20 GiB tar takes minutes). Design and rationale: [ARCHITECTURE.md](ARCHITECTURE.md#backup-and-restore). Online backup (Postgres PITR, MinIO site replication) needs a second site and is not provided.

### What a backup is (TLP:RED)

`backups/<UTC timestamp>/` (or `--out <dir>`; `BACKUP_DIR` changes the parent) holds `postgres.dump` (`pg_dump -Fc` as the superuser), `globals.sql` (roles without passwords, for reference), `security.json` (RLS flags, policies, grants, triggers, role attributes), `tables.json` (exact row counts), `objects.json` (every object version with size, etag, retention and legal hold), `minio-data.tar` (the MinIO data volume, relative to `MINIO_DATA_DIR`) and `manifest.json` (sha256 and size of every file, alembic head, image ids, `MINIO_IMAGE`, `MINIO_DATA_DIR`, `EVIDENCE_LOCK_DAYS`, the KMS key name and sha256 fingerprint, never the key).

It contains **every org's evidence** (malware samples included; objects written before SSE-S3 are plaintext in the tar), notes, reports, TI and AI results, the argon2 password hashes, the refresh-token hashes, the sealed provider keys and MinIO's IAM store. It holds no plaintext secret, but it is the prime exfiltration target:
- store it on an encrypted target **excluded from host antivirus** (AV quarantines evidence bytes, as it does the e2e samples, and can lock `minio-data.tar` mid-write);
- encrypt it offline, e.g. `tar -C backups/<ts> -cf - . | age -r <recipient> -o cyberlab-<ts>.tar.age`;
- the script refuses a target git would track and anything inside `.secrets/`; backups are never committed.

**Secrets are not in the backup.** Back them up separately, encrypted, every time they change: `.env` (DB, MinIO and broker passwords, `JWT_SECRET`) and `.secrets/*` (the TI and AI seal private keys: without them the sealed provider keys are unrecoverable; the report signing keys; the MinIO KMS key: without it MinIO cannot read its IAM, config or any SSE object; the metrics token):

```bash
tar -C . -cf - .env .secrets | age -r <recipient> -o cyberlab-secrets.tar.age
```

Redis and the broker are not backed up (denylist, rate limits, queues): the reapers fail jobs that were in flight.

**The M8 symbol store is not in the backup** (the `memory_symbols` volume): it is rebuildable from its manifest. Keep a copy of `manifest.json` (`docker compose --profile tools run --rm memory-symbols list` shows what it holds) and of any operator-built ISF you imported; after a restore re-import or re-fetch them, then `reindex` and `verify` ([Memory forensics](#memory-forensics-m8)).

### Take a backup

```bash
pnpm backup                         # dev stack; -- --prod for the prod-like stack
pnpm backup -- --out D:/cyberlab-backups/2026-11-06 --drain-timeout 900
```

1. Preconditions: the stack is up and healthy; no test-profile or `compose run` container of the project runs (they share Postgres and MinIO); free disk ≥ 1.2 × (pgdata + MinIO volume) (`--force` skips the disk check).
2. **Drain:** it waits until no analysis job, TI run, AI run, render or retention run is queued or running (`--drain-timeout`, default 600 s; then it refuses unless `--force`, which turns in-flight work into reaper failures). Announce the window: the gateway and web stop too.
3. It stops every writer, dumps Postgres, captures `objects.json` while MinIO is still up, stops MinIO, tars its volume, writes the manifest and **restarts what was running, also after a failure**. It then prints what the backup holds and the secrets checklist.

Keep several generations according to your own backup-retention policy; the platform does not prune backups. A purge is not retroactive in older backups.

### Restore

A restore only fills an **empty** stack. It never removes a volume.

```bash
docker compose down -v                                   # deliberately: this destroys the current data
pnpm restore -- --from backups/20261106T101500Z --replace-empty-stack            # dev
pnpm restore -- --from <dir> --replace-empty-stack --prod                        # prod-like stack
```

1. **Before:** restore `.env` and `.secrets/` from the encrypted secrets backup of the same period. The restore refuses a KMS key whose fingerprint differs from the manifest's, a manifest or file hash mismatch, and a backup whose alembic head is newer than the image's (an older one is upgraded by `migrate`).
2. It refuses non-empty volumes (MinIO with `.minio.sys`, or `cyberlab` with an `alembic_version`) with exit code 3 and prints the `down -v` command.
3. postgres alone (its init creates the databases and roles), `db-bootstrap`, `pg_restore --exit-on-error --single-transaction` as the superuser, then **`restore_verify --db`** at once (security fingerprint and row counts equal the backup's).
4. Untar the MinIO volume into the target image's data dir, start minio and `minio-init`, then **`restore_verify --objects`** (every version of `objects.json` with its size, etag, retention and legal hold; evidence re-hashed against `evidence_hashes`; report snapshots re-hashed and their signatures checked with `REPORT_SIGNING_PUBLIC_KEYS`; renders and job results re-hashed). `--sample N` re-hashes a random sample of the evidence instead of all of it. A tombstoned evidence version still present is the warning `purged_pending_delete`; a pinned version missing without a tombstone is an error.
5. `migrate`, then **every refresh token is revoked** (`--keep-sessions` opts out), the stack starts and **`restore_verify --rls`** probes isolation as `cyberlab_app`.

After the restore:
- **After an incident, rotate `JWT_SECRET`** (and restart the api): Redis is not restored, so access tokens logged out after the backup point are valid again until they expire (≤ 15 min, RT26). Rotating it signs everyone out and invalidates in-flight render tokens.
- **After restoring an older backup, run retention again** (it is idempotent): request a manual run per org (`POST /api/v1/orgs/{org}/retention/runs`) or wait for the daily sweep.
- Run `reconcile_orphans.py` (Operations) if anything looked off: it lists objects without a row, `purged_pending_delete` and `missing_unexplained` versions.

### Restore drill

`pnpm restore:drill` proves the whole cycle on throwaway data in the project `cyberlab-drill` (own volumes and networks, no published ports, about 1.2 GB) and never touches the main project's data: `down -v` is refused for any project but the literal `cyberlab-drill`. Run it **alone**: it takes every lane slot and refuses while the main project's analyzers or renderer run. `--target-minio-image <img> [--target-minio-data-dir <dir>]` restores the seeded bitnami volume into another MinIO image (the image-switch proof). Results: `infra/backup/last-drill.json`. Details: [TESTING.md](TESTING.md#restore-drill).

## SSE-S3 and the KMS key

- MinIO's built-in KMS key (`MINIO_KMS_SECRET_KEY_FILE`, compose secret `minio_kms_key`, format `<key-name>:<base64 of 32 bytes>`) and `mc encrypt set sse-s3` on every bucket (`minio-init`, `MINIO_SSE_ENABLED=true`). Presigned uploads and downloads are unaffected.
- **New objects only.** Objects written before the key was enabled stay plaintext on disk and in backups until rewritten.
- **The key also encrypts MinIO's IAM and config** (RT7). Losing or changing it leaves MinIO unable to read its users and policies, not only the encrypted objects. Never change the key of an existing volume; back it up encrypted with the other secrets.
- Dev uses the committed `infra/minio/dev-kms-key` (name `cyberlab-dev-kms`); `minio-init` refuses that name when `ENV=prod`. Prod: generate once and keep it out of git:

  ```bash
  python -c "import os,base64;print('cyberlab-kms-1:'+base64.b64encode(os.urandom(32)).decode())" > .secrets/minio_kms_key
  ```
- **Separate volumes for `pnpm verify:prod`:** once dev MinIO has written its IAM with the dev key, a MinIO started on that volume with `.secrets/minio_kms_key` (a different key) cannot read its users. The gate therefore runs the prod phase in its own compose project, `cyberlab-prod` (or `$COMPOSE_PROJECT_NAME-prod`), with its own volumes, and never with `-v`. Do not "fix" a key mismatch by copying the dev key into `.secrets/`: prod refuses it.
- The key sits on the same host: SSE-S3 protects against the loss of a volume or disk, not against a host compromise. A restore refuses a key with another fingerprint than the backup's.

## Object-store image

Upstream MinIO archived its community repository (2026-04-25) and ships no images. **Since 2026-11-06 the store is `pgsty/silo`** (the maintained, on-disk-compatible fork; AGPL-3.0), release `RELEASE.2026-10-26T00-00-00Z`, through a local wrapper image:

- `docker-compose.yml` builds `localhost/cyberlab/silo:RELEASE.2026-10-26T00-00-00Z` from `infra/minio/silo/Dockerfile`, `FROM pgsty/silo@sha256:7bb2aff6b89efe1cb1303c10fc21d579447434ed06649ac9ec05a5e2dbf30ad7` (the multi-arch index). A fresh clone builds it on the first `docker compose up` or `docker compose build minio` (`pull_policy: never`: a `localhost/` tag is never pulled). Scripts that pass `--no-build` (backup, restore, the drill) need it built once.
- Verify the base before a rebuild or a bump: `gh attestation verify oci://index.docker.io/pgsty/silo@sha256:7bb2aff6… --repo pgsty/silo --signer-workflow pgsty/silo/.github/workflows/docker-release.yml --source-ref refs/tags/RELEASE.2026-10-26T00-00-00Z --deny-self-hosted-runners` (upstream ships no plain cosign signature). Bump `SILO` in `scripts/minio-switch.mjs`, the Dockerfile, the overlay and `docker-compose.yml` together; `node --test scripts/minio-switch.test.mjs` asserts that they agree.
- The wrapper adds only `USER 1001:0` and the server CMD. **gid 0 is required:** the bitnami-era volume root is `root:root 0775`, and new buckets are created through its group write bit (a `1001:1001` wrapper read every existing bucket but got `AccessDenied` creating a new one). The service runs `read_only` with a `/tmp` tmpfs, `cap_drop: ALL`, `no-new-privileges` and `pids_limit: 512`.
- The build refuses any other `MINIO_IMAGE` tag (`TARGET_IMAGE`), so a bitnami value in `.env` can never become the tag of a Silo build.
- `MC_IMAGE` stays `bitnamilegacy/minio-client:2025.5.21` (minio-init only): `pgsty/mc` ships `mcli`, and `infra/minio/init.sh` calls `mc`.

**Rollback:** Silo rewrites `.minio.sys` and cannot be downgraded in place. The only way back is a full restore of the pre-switch backup volume onto bitnami (every write since the backup is lost): set `MINIO_IMAGE=bitnamilegacy/minio:2025.5.24`, `MINIO_DATA_DIR=/bitnami/minio/data` and `MINIO_READ_ONLY=false` in `.env`, then follow the deliberate `down -v` and `node scripts/minio-switch.mjs rollback --backup-volume cyberlab-switch_pre-silo-<utc>` steps of the [runbook](../plans/reports/minio-switch-runbook-261107.md). Never start bitnami on a volume Silo has written.

Fallback: an own source build of the last upstream release (`infra/minio/image/Dockerfile`; no future patches). RustFS, SeaweedFS and Ceph RGW cannot read MinIO's format: moving to them breaks every version-id pin.

## Retention operations

Concepts: [ARCHITECTURE.md](ARCHITECTURE.md#retention-purge-and-legal-hold). Every org starts with **no policy: nothing is ever purged**.

- **Policy** (org settings → Retention, `org.update`): `ti_results_days`, `ai_runs_days` (≥ 30) and `closed_case_days` (≥ max(30, `EVIDENCE_LOCK_DAYS`)). A raised value applies at once; a lowered one, turning `enforce` on (with the destruction acknowledgement) and a hold release take effect after `RETENTION_POLICY_DELAY_DAYS` (7). Until `enforce` is effective every run is a dry run.
- **Preview first:** the preview shows the candidates, counts and bytes now, read-only, through the same selector as the purge, and is kept as a manual dry run in the run list. Read a run's items (`audit.read`) to see what was purged, skipped (`skipped_hold`, `skipped_locked`), kept because a report cites it (`kept_cited`) or failed to delete (`object_delete_failed`, retried by the next run).
- **Schedule:** `ingest-beat` sends `retention.sweep` daily at 02:30 UTC; one run per org with an effective policy, time-sliced and resumed. A manual run waits for none of that (`409` while one runs). The sweep also deletes `job_outcomes` rows older than `RETENTION_JOB_OUTCOMES_DAYS` (90).
- **Legal holds** (org or case, `org.update`, a reason is required): held data is excluded from every category. The retention worker mirrors them as S3 legal holds (`s3_sync: pending` until it ran; it runs on each placement and every sweep): a case hold on the case's evidence and report snapshots, an org hold on every evidence version of the org (at most 5 000 versions inspected and 500 changed per sync, resumed by the next sync, so a large org shows `pending` for a few syncs). A released hold keeps protecting for the delay.
- **Identities:** the worker connects as `cyberlab_retention` (`POSTGRES_RETENTION_PASSWORD`; created by `db-bootstrap`) with the broker user `retention` and the MinIO user `cyberlab-purge` (`MINIO_PURGE_*`, created by `minio-init` from `infra/minio/purge-policy.template.json`). Custody events of a purge name the inactive system user `retention@system.invalid`, which cannot log in.
- **What a purge leaves:** case, evidence and job metadata, hashes, custody (`purged`), audit (`evidence.purged`), findings, alerts, IOCs, correlation keys and signed snapshots. The evidence page shows "bytes purged"; download and verify answer `410 evidence_purged`. A purged rendition can be re-rendered.
- **Never purged by policy:** notes, collections, audit logs, custody, signed report snapshots and versions. Governance-locked or legal-held object versions are skipped, never bypassed.

## Runtime metrics

- **Token:** create `.secrets/metrics_token` (prod overlay), or point the dev stack at a token file with `METRICS_TOKEN_SECRET_FILE` (the dev default is an empty file, which turns the route off):

  ```bash
  python -c "import secrets;print(secrets.token_urlsafe(32))" > .secrets/metrics_token
  ```
- `/internal/metrics` is served by the api on port 8000 outside `/api`; **the gateway never routes it**, so a scraper must join the `backend` network (it is internal: the scraper gets no egress there). No Prometheus server is part of compose. Example scrape config for a Prometheus container attached to `cyberlab_backend`:

  ```yaml
  scrape_configs:
    - job_name: cyberlab
      scrape_interval: 60s
      metrics_path: /internal/metrics
      scheme: http
      authorization:
        type: Bearer
        credentials_file: /etc/prometheus/cyberlab_metrics_token
      static_configs:
        - targets: ["api:8000"]
  ```
  Do not put a proxy in between that adds `X-Forwarded-For` (the endpoint answers 403). 60 requests / min per peer.
- Per-org numbers for admins: org settings → Operations (`GET /orgs/{org}/ops/metrics`, `audit.read`).
- `pnpm ops:metrics` replays the synthetic datasets through the real workers and writes `plans/reports/ops-metric-YYMMDD.md` (heavy: run alone, with the dev stack up). `pnpm live:run` runs the budgeted live TI / AI checks with your own keys (`CYBERLAB_LIVE=1`, `.secrets/live.env`, `--max-calls`, `--max-usd`); it is never part of the gate.

## Global rate limit

`RATE_LIMIT_USER_PER_MIN` (api, default 600) caps authenticated requests per user and minute (`429` + `Retry-After`; Redis down: `503`). Raise it for automation-heavy users or the e2e (the test profile uses 100 000). Search has its own `SEARCH_PER_USER_PER_MIN` (30). There is no anonymous or gateway-level flood limit: put a rate-limiting proxy or WAF in front of a real deployment.

## Memory forensics (M8)

**In progress.** The services, volumes, network, broker user and settings below exist since phase 1 (untested in a container). The worker fails every job with `not_implemented` until phase 2, and the `memory:symbols` CLI exits 2 until phase 5. Steps marked *pending* describe the planned behaviour. Design: [MEMORY_ANALYSIS.md](MEMORY_ANALYSIS.md).

### First start (phase 1)

1. `cd apps/workers/memory && uv lock` once, and check it resolves `volatility3==2.28.2` and none of the forbidden packages.
2. In `.env`: `BROKER_MEMORY_PASSWORD` (required in prod) and `CADDY_EVIDENCE_MAX` ≥ max(`MAX_EVIDENCE_BYTES`, `MEMORY_MAX_BYTES`) + 1 MiB.
3. Heavy, alone: `docker compose build memory-worker` (and `docker build --target prod` for the prod image); then rebuild api, pcap-worker, static-worker and report-worker one at a time (py-jobs and py-worker-kit changed; the renderer must know the new `omissions` snapshot field).
4. Recreate `redis-broker` (new ACL user) and run `migrate` (0016).
5. `docker compose --profile tools run --rm memory-symbols-init` once, to own the symbol volumes.

### Sizing

| Resource | Need |
|---|---|
| RAM | the memory worker has `mem_limit 3g` (one plugin at a time, `RLIMIT_AS` 2.5 GiB per plugin); `memory-symbols` 2 GiB while it runs |
| Disk per image | plan for **about 3× the image size** while it is in flight: the API spool (`upload_tmp`) and the MinIO copy during the upload, then MinIO plus the worker's copy in `memory_work` during the analysis. The spool is removed after the commit and `/work` after the job, but MinIO keeps the evidence for at least `EVIDENCE_LOCK_DAYS` |
| Docker Desktop | its virtual disk grows and **does not shrink by itself** after large images are deleted; compact it from Docker Desktop (or `wsl --manage <distro> --set-sparse true` / `Optimize-VHD`) when space matters |
| Org quota | unchanged: the default 20 GiB holds two 8 GiB images; raise an org's quota (Operations) before it investigates larger or more images |
| Time | a run takes minutes to about an hour (job timeout 90 min, plugin timeout 20 min); every plugin re-stacks the layers in its own process |

### Upload limits

- `MEMORY_MAX_BYTES` defaults to 8 GiB and is refused above 16 GiB (RT14). `CADDY_EVIDENCE_MAX` must be at least the larger evidence limit + 1 MiB: `8590983168` for 8 GiB, `17180917760` for 16 GiB. The API still enforces each kind's own limit (memory: pending phase 6; until then a `kind=memory` upload is bounded by `MAX_EVIDENCE_BYTES`).
- Caddy keeps `read_body 30m`: an 8 GiB upload needs ≥ 4.6 MB/s sustained, 16 GiB ≥ 9.2 MB/s. A slower link fails the upload; there is no resume (direct multipart upload is ROADMAP "Later").
- Compressed or archived images are refused by the worker (`unsupported_memory_format`): upload the raw, LiME, AVML, ELF core, `.vmem` or crash-dump file itself.
- Tests never upload more than 64 MiB (`MEMORY_MAX_BYTES` is 64 MiB in `api-test`).

### Symbols runbook (pending phase 5)

The worker never fetches symbols. When a job fails `symbols_missing`, its page shows what is needed.

```bash
pnpm memory:symbols -- list                                    # identities, sources, import dates
pnpm memory:symbols -- fetch-windows --pdb ntkrnlmp.pdb --guid <32 hex> --age <n>
pnpm memory:symbols -- import --file /import/<file>.json.xz    # an operator-built ISF
pnpm memory:symbols -- import --file /import/<pack>.zip --sha256 <expected>
pnpm memory:symbols -- reindex                                 # rebuild the identifier cache
pnpm memory:symbols -- verify                                  # re-hash every file (exit 1 on a mismatch)
pnpm memory:symbols -- --store test <command>                  # the test store
```

- **Windows:** copy the `fetch-windows` command from the job page (built from the validated PDB name, GUID and age only), run it, then re-run the job. The PDB name must be a kernel PDB (`ntkrnlmp.pdb`, `ntoskrnl.pdb`, `ntkrnlpa.pdb`, `ntkrpamp.pdb`); the download is ≤ 128 MiB over verified HTTPS, and the converted ISF's GUID and age must match the request.
- **Linux:** the page shows the kernel banner as text, never as a command (it is attacker-chosen). Build the ISF **elsewhere**, on a machine with the matching kernel's debug symbols (for example dwarf2json ≥ 0.9.0 against the debug `vmlinux` and its `System.map`), compress it with xz, place it in `./.memory-import/` (gitignored, mounted read-only at `/import`) and `import` it. Third-party Linux ISF collections are not built in; importing one is the operator's judgement (licence and provenance).
- **Local zips** of ISFs are accepted by `import` (members checked for traversal, symlinks, type, count and size; pass `--sha256` when you know it). There is no URL-based pack import.
- **`reindex` always runs with the target store mounted at `/symbols`** (both services do this), because the identifier cache stores absolute `file:///symbols/…` locations (RT5). It records the cache's sha256 in the manifest; the worker seeds only a cache with that hash, so a store from before this change runs without a cache until `reindex` is run once.
- Parsing children (`import`, `fetch-windows`, `reindex`) work in a temp dir under the tool's `/tmp` tmpfs (512 MiB), never inside the store; an audit hook refuses any write outside it, and the tool copies, re-hashes and only then moves a produced ISF into the store.
- **After a restore** (the symbol volume is not in the backup), or when in doubt: re-import / re-fetch, `reindex`, `verify`.

**When a fetch is refused** (RT11): `fetch-windows` follows at most 3 redirects, each HTTPS to a host that is `msdl.microsoft.com` or ends with a suffix in the tool's recorded allow-list of Microsoft symbol CDN hosts, never an IP literal, userinfo or a non-443 port. No live fetch has ever been made to observe those hosts (by design: no test or gate contacts Microsoft), so the first real fetch may meet a CDN host the list lacks. The tool then refuses and prints the host. Check that the host is a genuine Microsoft symbol CDN, then change the constant deliberately in `memory_worker/symbols/` (a code change with its test), rebuild the image and fetch again; never work around it with another downloader into the store.

**Egress footprint:** only `memory-symbols` can leave the host, only on `symbols_egress`, only while an operator runs it, and only to `msdl.microsoft.com` and its CDN (by policy in the tool; the bridge itself is not filtered). A fetch tells Microsoft which kernel build is under investigation. ISF converted from Microsoft PDBs stays in the local volume; its redistribution terms are unverified, so never ship the volume or put it in an image.

### Operator smoke procedure for the first real image (manual, never automatic)

CI never runs a real Windows image (no third-party image is used; Windows is replay-tested, RT4). Before relying on memory results, run this once on an image you are entitled to analyse, after phases 2–8 have landed:

1. Create a throwaway case with TLP:RED. Upload the image with the memory option (`?kind=memory`); check the evidence shows "restricted" and that no analysis started.
2. Run memory analysis, profile `triage`, `os_hint` `auto`. If it fails `symbols_missing`, follow the runbook above and re-run.
3. On success, check the job page: OS, layer and build look right; `windows.pslist` / `linux.pslist` is `ok`; every other plugin has a status (`ok`, `failed`, `timeout`, `skipped`, `unsupported`); the process count and a few known processes match what you expect; the audit-hook counts (`audit_events` in the result header) are zero.
4. Compare a handful of processes, connections and command lines against another tool you trust. Report any normalizer or column mismatch as a bug (Volatility upgrades are deliberate, pinned changes).
5. Try `full` once and note the duration and peak disk.
6. Delete nothing by hand: retention and legal holds govern the case as usual.

## Disk forensics (M9)

**In progress.** The services, volumes, broker user, lane 9 and settings below exist since phase 1, and phases 2 and 5–9 fill the worker, the API and the ingest, but **nothing has run in a container yet**. The disk image cannot be built until phase 3a replaces the `plaso.lock` placeholder (the builder's `pip download --require-hashes` fails on an empty set by design) and `apps/workers/disk/uv.lock` exists. Steps marked *pending* describe the planned behaviour. Design: [DISK_FORENSICS.md](DISK_FORENSICS.md).

### Services

| Service | Image | Trust | Notes |
|---|---|---|---|
| `disk-worker` | `cyberlab/disk-worker` (python 3.12-slim-trixie + pytsk3 20260715 with TSK 4.15.0 embedded, libewf-python 20260924, yara-python, the M3 rule sources; Plaso 20261027 in its own venv `/opt/plaso`) | untrusted | the memory worker's isolation (`analysis` only, env `BROKER_URL` only as broker user `disk`, read-only rootfs, `cap_drop: ALL` + 6 caps, tini, fail-closed restart), 3 GiB / 2 CPUs, `pids_limit 256`, concurrency 1 with one task per child; `/work` on the named volume `disk_work`, `disk_hashsets` read-only at `/hashsets`; tool uid 10007; no privileged mount of any kind |
| `disk-ingest-worker` | `cyberlab/api` | trusted | `celery … worker --pool solo -Q ingest_disk` (RT9): the disk ingest in its own process, so one long transaction never delays the shared ingest queue; `backend` only, read-only rootfs, 1 GiB, the ingest temp volume |
| `disk-hashsets`, `disk-hashsets-test` | `cyberlab/disk-worker` | trusted operator tool | profile `tools` (never part of `up`), uid 10008, read-only rootfs, `cap_drop: ALL`, 2 GiB, `pids_limit 64`, **`network_mode: none`**, no secrets, `/tmp` tmpfs 1 GiB; the target store rw at `/hashsets` (`disk_hashsets`, or `disk_hashsets_test` for `--store test`) and `./.disk-import` read-only at `/import`. `disk-hashsets-init` (one-shot, no network) chowns both volumes to 10008, mode 0755 |
| `disk-worker-test`, `disk-ingest-worker-test` | as above | test profile | `/work` a per-container 1 GiB tmpfs, `TEST_PROFILE=1` (replay timeline engine and M3 test rules allowed), `DISK_WORK_MIN_FREE_BYTES` 64 MiB, the test hash-set store read-only; the test ingest consumes `test.ingest_disk` |

Volumes: `disk_work`, `disk_hashsets`, `disk_hashsets_test`. The prod overlay builds the `prod` target (no generator tools, no tests) and requires `BROKER_DISK_PASSWORD`.

### First start

1. `cd apps/workers/disk && uv lock` once (pending: no lock is committed), and, after phase 3a, the hash-pinned `plaso.lock`.
2. In `.env`: `BROKER_DISK_PASSWORD` (required in prod) and `CADDY_EVIDENCE_MAX` ≥ max(`MAX_EVIDENCE_BYTES`, `MEMORY_MAX_BYTES`, `DISK_MAX_UPLOAD_BYTES`) + 1 MiB.
3. Heavy, alone: `docker compose build disk-worker` (and `docker build --target prod` for the prod image). The `plaso-builder` stage installs a C toolchain, downloads the locked sources with `--require-hashes` and compiles the sdist-only libyal bindings (libevtx, libregf, libfsntfs, libfsext, libfsfat, libbde, libfsapfs, libvsgpt) into wheels with a `SHA256SUMS` manifest; only those wheels reach the runtime stages, installed with `--no-index`. Expect the longest build of the platform (not measured yet). `docker/finalize_image.py` then asserts no Debian `sleuthkit` / `python3-tsk` / `ewf-tools`, no compiler and, in `prod`, none of the generator's GPL tools. Rebuild api, pcap-worker, static-worker, memory-worker and report-worker one at a time afterwards (py-jobs and py-worker-kit changed; the renderer must know `omissions.disk_restricted`).
4. Recreate `redis-broker` (new ACL user `disk`) and run `migrate` (0017).
5. `docker compose --profile tools run --rm disk-hashsets-init` once, to own the hash-set volumes.

### Sizing

| Resource | Need |
|---|---|
| Upload | each segment is one request ≤ `DISK_MAX_UPLOAD_BYTES` (8 GiB default, ≤ 16 GiB); Caddy keeps `read_body 30m`: 8 GiB needs ≥ 4.6 MB/s sustained, 16 GiB ≥ 9.2 MB/s. `CADDY_EVIDENCE_MAX`: `8590983168` for 8 GiB segments, `17180917760` for 16 GiB. No resume |
| Set total | `DISK_MAX_IMAGE_BYTES` 16 GiB default (≤ 64 GiB), chosen to fit the 20 GiB default org quota; raise the org's quota (Operations) before raising it |
| Host disk while a job runs | about **2 × the image + 3 × the artifact budget**: the image in MinIO and its copy in `disk_work`, plus the collected artifact tree, the Plaso storage and the exported events (artifact budget 2 GiB in `triage`, 8 GiB in `full`), **plus the 4 GiB watchdog floor** (`DISK_WORK_MIN_FREE_BYTES`) that must stay free. The worker refuses a job unless `/work` has image + 3 × artifact budget + 4 GiB + 2 GiB free (`insufficient_disk`). During the upload the API spool (`upload_tmp`) holds a third copy of each segment until the commit. Example: a 16 GiB set in `triage` occupies 16 GiB in MinIO and needs 16 + 3 × 2 + 4 + 2 = 28 GiB free on `/work` when the job starts, about 44 GiB of the Docker disk in total |
| Retention of bytes | MinIO keeps every segment at least `EVIDENCE_LOCK_DAYS`; `/work` is emptied after every job; export objects live until promoted or expired (`DISK_EXPORT_TTL_S`, 7 days) and the retention worker deletes them |
| Postgres | not measured yet (phase 7 needs Docker); the plan estimates 0.5–1 GiB per job at the caps (500 000 files, 250 000 events, indexes) |
| Docker Desktop | its virtual disk grows and **does not shrink by itself** after images are deleted; compact it (Docker Desktop, or `wsl --manage <distro> --set-sparse true` / `Optimize-VHD`) when space matters |
| RAM | `disk-worker` 3 GiB (one stage at a time, `RLIMIT_AS` ≤ 2.5 GiB per stage) plus `disk-ingest-worker` 1 GiB; `disk-hashsets` 2 GiB while it runs. The always-on workers' `mem_limit`s add up to about 13.4 GiB (pcap 2, static 3, memory 3, disk 3, report 1, disk ingest 1, retention 0.375): limits, not reservations, but size host RAM so that the analyzers that can run at once fit |
| Concurrency | one disk job at a time on the platform (`DISK_MAX_ACTIVE_TOTAL` 1, one worker); a second request gets `429 analysis_queue_full`. Ingests of two disk results run one after the other |
| Time | `ANALYSIS_DISK_TIMEOUT_S` 4 h; **every re-run and every file export downloads and re-verifies the whole segment set** (no image cache, RT1): minutes for 16 GiB on localhost MinIO |

Tests never upload more than 64 MiB per segment (`api-test`: `DISK_MAX_UPLOAD_BYTES` 64 MiB, `DISK_MAX_IMAGE_BYTES` 256 MiB).

### Settings

| Variable | Read by | Default and notes |
|---|---|---|
| `BROKER_DISK_PASSWORD` | redis-broker (ACL user `disk`), disk-worker(-test), api-test (`TEST_BROKER_DISK_URL`) | confined to `disk*` / `test.disk*`, write-only to `ingest*`; dev default `change-me-broker-disk`, required in prod |
| `DISK_MAX_UPLOAD_BYTES`, `DISK_MAX_IMAGE_BYTES`, `DISK_MAX_MEDIA_BYTES` | api | 8 GiB (≤ 16 GiB), 16 GiB (≤ 64 GiB), 2 TiB (≤ 16 TiB); upload ≤ set ≤ media is checked at start-up |
| `ANALYSIS_DISK_TIMEOUT_S`, `DISK_INGEST_TIMEOUT_S` | api (sent in every disk job; the ingest hand-off) | 14 400 s (≤ 21 600), 1 800 s (below the job timeout) |
| `DISK_MAX_ACTIVE_PER_ORG`, `DISK_MAX_ACTIVE_TOTAL` | api | 1 / 1 (the test profile raises them) |
| `DISK_EXPORT_TTL_S` | api, ingest-beat | 7 days; unpromoted exports then expire |
| `DISK_MAX_SEGMENTS`, `DISK_MAX_RESULT_BYTES`, `DISK_MAX_RESULT_DECOMPRESSED_BYTES`, `DISK_MAX_{PARTITIONS,FILESYSTEMS,FILES,STREAMS_PER_FILE,EVENTS,EVENTS_READ,FINDINGS,IOCS,TIMELINE}`, `DISK_EXPORT_MAX_BYTES`, `DISK_EXPORT_MAX_FILES` | api | 64, 256 MiB, 1.5 GiB, 128, 32, 500 000, 16, 250 000, 20 000 000, 5 000, 20 000, 5 000, 64 MiB, 20; compose does not pass them; each can only be lowered below its contract ceiling |
| `DISK_WORK_MIN_FREE_BYTES` | disk-worker | 4 GiB (0..1 TiB); the watchdog floor |
| `DISK_TIMELINE_ENGINE` | disk-worker | `plaso`; `none` skips the timeline; `replay` only with `TEST_PROFILE=1` |
| `DISK_HASHSETS_DIR`, `DISK_RULES_DIR`, `DISK_TEST_RULES_DIR` | disk-worker | `/hashsets`, `/opt/rules/image`; the test rules only with `TEST_PROFILE=1` |

### Known-file hash sets runbook

Nothing is ever downloaded by the platform: you obtain the files yourself.

1. **Obtain a set.** NSRL RDSv3 from NIST's download page (the `minimal` set: the full Modern set is hundreds of GB uncompressed); unzip it on the host to its SQLite database. Or any list with one md5, sha1 or sha256 per line (an md5sum-style ` name` / ` *name` suffix and `#` comments are allowed), for example your own known-bad list.
2. **Place it** in `./.disk-import/` (gitignored, mounted read-only at `/import`).
3. **Import:**

   ```bash
   pnpm disk:hashsets -- import-nsrl --file /import/RDS_<version>_modern_minimal.db --name nsrl-modern-min
   pnpm disk:hashsets -- import-list --file /import/known_bad.sha256 --name ir-known-bad --kind known_bad --algo sha256
   pnpm disk:hashsets -- import-list --file /import/watch.md5 --name ir-watch --kind notable --algo md5
   pnpm disk:hashsets -- list                       # names, kinds, counts, import dates
   pnpm disk:hashsets -- verify                     # re-hash every file against the manifest (exit 1 on a mismatch)
   pnpm disk:hashsets -- remove --name ir-watch     # manifest first, then the files
   pnpm disk:hashsets -- --store test <command>     # the test store
   ```

   Names match `^[a-z0-9][a-z0-9._-]{0,63}$`; at most 64 sets. `import-nsrl` defaults to `known_good`. A schema other than RDSv3 (`FILE` view with `sha256, sha1, md5, …`; `DISTINCT_HASH` used when present) is refused. Invalid digests are counted and skipped.
4. **Temp space:** the external sort's chunks and the new set are written to a staging directory inside the store volume (`disk_hashsets`), so plan free space of about twice the set's final size there for the duration of the import; the set is re-read and verified, then moved into place with one rename, and leftovers of an interrupted import are removed by the next one. The final size is 32 + 20 + 16 bytes per distinct hash for sha256 + sha1 + md5, 68 bytes per distinct hash (use the `minimal` NSRL set: the full Modern set is not practical). An existing name is refused (`set_exists`: `remove` it first). Exit codes: 0 done, 1 refused or mismatch, 2 usage.
5. **Cadence:** when NIST publishes a new RDS release (or your list changes), import a new release under a new name, check `list`, then `remove` the old one; running jobs keep the manifest they loaded, and each job's header records the manifest sha256 of every set it used.
6. **After a restore** (the hash-set volume is not in the backup) or when in doubt: re-import, then `verify`. An invalid store disables all matching in jobs (reported in the job header), it never fails a job.

### Recovery

| Symptom | What to do |
|---|---|
| job `failed` / `insufficient_disk` before the download | free space on the Docker disk (old evidence past its lock, compaction) or lower the artifact budget by running `triage` instead of `full` |
| a stage `truncated` (`write_budget` / `min_free`) or the job `insufficient_disk` mid-run | the write watchdog stopped a stage: same as above; the floor is `DISK_WORK_MIN_FREE_BYTES` |
| stages `skipped` (`deadline`) | the deadline budget ran out (large image, many file systems): raise `ANALYSIS_DISK_TIMEOUT_S` (≤ 21 600 s) or run `triage` |
| `unsupported_disk_format` | the reason names the refused format (compressed, VMDK, VHD(X), QCOW, AFF, Ex01, L01) or `media_size`; convert to raw or E01 with your own tools, or check the segment set (E01 order, all segments listed) |
| `no_supported_filesystem` | the diagnostic page lists each partition's status (`encrypted`, `unsupported`, `undetermined`): out of scope by design |
| `integrity_mismatch` | a segment no longer matches its evidence record: verify the evidence (Evidence page) |
| `timed_out` on ingest | the disk ingest exceeded `DISK_INGEST_TIMEOUT_S` (a result at the caps on a slow host): raise it (below the job timeout) and re-run |

### Operator smoke procedure for the first real image (manual, never automatic)

CI never opens a real disk image (no third-party image or corpus is used; EVTX, Prefetch and LNK are replay-tested). Before relying on disk results, run this once on an image you are entitled to analyse, after phases 3, 4 and 10 have landed:

1. Create a throwaway case with TLP:RED. Upload the segments with the disk image option (`?kind=disk`); check each shows "restricted" and that no analysis started.
2. Run disk analysis with every segment in order, profile `triage`, `os_hint` `auto`.
3. On success, check the job page: format, segment hashes and the worker-reported media hash status; every partition has a status and the expected file system; the file count and a few known paths match what you expect; every stage has a status; the audit-hook counts in the stage reports are zero.
4. Compare a handful of files (hashes, times) and timeline events (an EVTX logon, a Prefetch entry, a registry Run key) against another tool you trust, for example `fls` / `mactime` on the body file or Autopsy on the downloaded segments. Report any parser or column mismatch as a bug (engine upgrades are deliberate, pinned changes).
5. Export one benign file and add it to the case; check the trusted hash equals the worker's, the new evidence is restricted and its static job runs.
6. Try `full` once and note the duration and the peak disk.
7. Delete nothing by hand: retention and legal holds govern the case as usual.

## Reverse engineering (M10)

**In progress.** The service, volume, broker user and settings below exist since phase 1 and phases 2–10 fill the worker, the API, the ingest and the web, but **nothing has run in a container yet**: the image has never been built, `apps/workers/reverse/uv.lock` does not exist, and the Ghidra-in-sandbox spike (phase 2 A′) has not run, so the JVM limits, the trim list and the JVM arguments are provisional. Design: [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md).

### Services

| Service | Image | Trust | Notes |
|---|---|---|---|
| `re-worker` | `cyberlab/re-worker` (python 3.12-slim-trixie + Eclipse Temurin JDK 25, Ghidra 12.2 trimmed, PyGhidra 3.2 from the Ghidra zip, JPype1, radare2 6.2.6, libmagic, libseccomp) | untrusted | the static / memory isolation (`analysis` only, env `BROKER_URL` only as broker user `reverse`, read-only rootfs, `cap_drop: ALL` + 6 caps, tini, fail-closed restart), **4 GiB** / 2 CPUs, `pids_limit 512`, `/tmp` tmpfs 64 MiB, concurrency 1 with one task per child; `/work` on the named volume `re_work`; tool uid 10010 |
| `re-worker-test` | `cyberlab/re-worker:dev` | test profile | `TEST_PROFILE=1` (replay engine allowed), `/work` an **anonymous per-container volume** (disk-backed, removed with `--rm`; a tmpfs would count against the 4 GiB cgroup, RT22); the worker's sources, tests, samples and dataset read-only; phase 12 adds `./apps/workers/static/samples` read-only at `/opt/samples/m3` (the M3 PE builder for the edge cases) |

Volume: `re_work`. The prod overlay builds the `prod` target (no compilers, no tests, no samples) and requires `BROKER_REVERSE_PASSWORD`. The dev target adds gcc, mingw-w64 (x86 / x64) and binutils for the synthetic samples (compiled at test time, never run) and the M3 C sources at `/opt/samples/m3c`.

### First start

1. `cd apps/workers/reverse && uv lock` once (no lock is committed); check the JPype1 pin against PyGhidra 3.2's requirement; r2pipe must not appear.
2. Re-check the pinned artefacts against their release pages: the Ghidra zip SHA-256 and the radare2 deb SHA-256 (`ARG`s in `apps/workers/reverse/Dockerfile`, read from the release API on 2026-11-07) and the Temurin image digest; confirm the zip's top dir (`ghidra_12.2_PUBLIC`), the PyGhidra wheel path and the decompiler path. A mismatch fails the build.
3. In `.env`: `BROKER_REVERSE_PASSWORD` (required in prod).
4. Heavy, alone: `docker compose build re-worker` (dev) and `docker build --target prod` once. `docker/finalize_image.py` asserts Ghidra 12.2 trimmed (x86 and DATA processors only, no Jython, debugger, server, docs or bundled extensions), our `launch.properties` byte for byte, JDK 25, PyGhidra 3.2.x without plugin entry points, no r2pipe / jython, radare2 6.2.6, root-owned install trees, the licence texts, and writes `/etc/cyberlab/versions.json`. **Image size: pending** (the plan expects 1.2–1.9 GB). Rebuild the api image, then pcap, static, memory, disk and report one at a time (py-jobs and the worker kit changed; the api before the static image, RT18).
5. Recreate `redis-broker` (new ACL user `reverse`) and run `migrate` (0018).
6. Run the phase-2 spike, then commit its measured values (trim list, JVM arguments, rlimits, loader and analysis option names).

### Sizing

| Resource | Need |
|---|---|
| RAM | `re-worker` 4 GiB while a job runs (analyze JVM heap `RE_JVM_HEAP` 2 GiB + metaspace, code cache and native memory; the decompile JVM 1 GiB + its native child ≤ 1.5 GiB). With M10 the analyzers' `mem_limit`s add up to about 16 GiB (pcap 2, static 3, report 1, memory 3, disk 3, reverse 4) on top of the stack: **keep `ANALYSIS_HEAVY_MAX_ACTIVE` at 1** (one memory, disk or RE job at a time, platform-wide) unless the host fits the sum of the heavy workers' limits that could then run together (e.g. 2 needs room for disk 3 + reverse 4 + the rest of the stack). Measured peaks: **pending** (`pnpm re:metrics`) |
| Disk | per job: the sample (≤ 16 MiB) plus the Ghidra project and stage outputs in `re_work`, bounded by `RE_MAX_WORK_BYTES` (2 GiB; the root watchdog kills the stage above it, `re_work_too_large`) and wiped after the job; the worker refuses a job without the free space for it (`insufficient_disk`). Project sizes: **pending** |
| Time | `ANALYSIS_RE_TIMEOUT_S` 1 h per job; each JVM stage ≤ 1 800 s by default; minutes per sample are expected (two JVM starts plus auto-analysis). Latency p50 / p95: **pending** |
| Concurrency | one RE job per org (`RE_MAX_ACTIVE_PER_ORG`) and one heavy job on the platform by default; a refusal is `429 too_many_active_jobs` / `heavy_analysis_busy` with `Retry-After: 60` (no queue, RT30) |

### Settings

| Variable | Read by | Default and notes |
|---|---|---|
| `BROKER_REVERSE_PASSWORD` | redis-broker (ACL user `reverse`), re-worker(-test), api-test (`TEST_BROKER_REVERSE_URL`) | confined to `reverse*` / `test.reverse*`, write-only to `ingest*`; dev default `change-me-broker-reverse`, required in prod |
| `RE_MAX_BYTES` | api | 16 MiB (≤ 64 MiB and ≤ `STATIC_MAX_BYTES`) |
| `ANALYSIS_RE_TIMEOUT_S`, `RE_ANALYSIS_TIMEOUT_S`, `RE_DECOMPILE_TIMEOUT_S`, `RE_QUICK_TIMEOUT_S` | api (sent in every RE job) | 3 600 s (≤ 21 600), 1 500 s, 30 s per function, 300 s; decompile < analysis < job and quick < job are checked at start-up |
| `RE_MAX_DECOMPILED`, `RE_MAX_WORK_BYTES` | api | 300 (≤ 2 000; always at least the number of requested addresses), 2 GiB (64 MiB..16 GiB) |
| `RE_MAX_ACTIVE_PER_ORG`, `ANALYSIS_HEAVY_MAX_ACTIVE` | api | 1, 1 (api-test raises the heavy cap to 1 000; the M10 tests set it back to 1) |
| `RE_QUICK_ENABLED` | api | `false`: the radare2 `quick` profile is refused `422 profile_unavailable`; set `true` only after `tests/engine/test_r2_smoke.py` has passed on the built image |
| `RE_MAX_RESULT_BYTES`, `RE_MAX_RESULT_DECOMPRESSED_BYTES`, `RE_MAX_{FUNCTIONS,CALL_EDGES,IMPORTS,IMPORT_REFS,STRINGS,STRING_REFS,FINDINGS,IOCS}` | api | 256 MiB, 768 MiB, 20 000, 100 000, 10 000, 50 000, 20 000, 50 000, 2 000, 10 000; each can only be lowered below its contract ceiling |
| `AI_MAX_CODE_CHARS` | api | 12 000 (256..12 000): the `Q` item of `explain_function` |
| `RE_ENGINE` | re-worker | `ghidra`; `replay` only with `TEST_PROFILE=1` |
| `RE_JVM_HEAP`, `RE_DECOMPILE_JVM_HEAP`, `RE_DECOMPILER_AS`, `RE_TOOL_RLIMIT_AS` | re-worker | 2 GiB (≤ 3 GiB), 1 GiB, 1.5 GiB (above the decompile heap), heap + 3 GiB; **provisional until the spike** |

### Updating the pinned artefacts

Ghidra, the JDK and radare2 are pinned by SHA-256 / digest in the `Dockerfile` and checked at build; `finalize_image.py` pins the expected versions and `re_worker/jvm_args.py` the expected JVM arguments. An upgrade is a deliberate change: update the `ARG`s and the version constants, re-run the spike checks (the JVM starts under the sandbox with our `launch.properties`, the effective arguments, the loader and analysis option names, the decompiler prlimit, the trim list, the PDB-path strace), then the engine smoke (`tests/engine/test_ghidra_smoke.py`, `test_r2_smoke.py`) and the recovery-quality run, and record the new image size. Licence notices: [`apps/workers/reverse/NOTICE.md`](../apps/workers/reverse/NOTICE.md) (in the image at `/usr/share/doc/cyberlab-re/NOTICE`).

### Checks (phase 12, written, not run)

`scripts/check-re-worker-env.mjs` checks the rendered dev and prod configs: `re-worker` gets only the broker URL, the `analysis` network and `re_work` (no DB, MinIO credentials, app Redis or egress network), `mem_limit` ≤ 4g, `pids_limit` above the probe's `nproc`, `re-worker-test`'s `/work` is not a tmpfs (RT22); with `--image cyberlab/re-worker:prod` it checks the built prod image (tool uid 10010, unique among the images; no compiler). `pnpm re:gen` builds the synthetic samples into the `cyberlab_e2e_samples` volume (`/samples/re`) for the pipeline test and the e2e. Fuzz-lite (`pnpm re:fuzz`) and the metric run (`pnpm re:metrics`) are heavy steps, each run alone with only the infra stack and the RE worker up, never part of the gate.
