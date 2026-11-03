---
phase: 1
title: Monorepo and Docker Compose
status: completed
priority: P1
effort: 8h
dependencies: []
---

# Phase 1: Monorepo and Docker Compose

## Overview
Scaffold monorepo + Compose stack so `pnpm dev` brings every service up healthy with hot reload, plus a prod override so the project stays deployable from day 1. No business logic.

## Requirements
- Functional: gateway, web, api, postgres, redis, minio, minio-init, migrate services; `GET /api/v1/health` returns db/redis/minio status; web home renders through gateway.
- Non-functional: works from a fresh clone on Windows (no host Python/uv needed); secrets only via `.env` (gitignored); images pinned by minor version; prod override builds & runs without bind mounts. [RT#9, RT#14]

## Architecture
```
browser ──► gateway (Caddy :8080)
              ├─ /api/*  ──► api (uvicorn :8000)  ──► postgres:5432, redis:6379, minio:9000
              └─ /*      ──► web (next :3000)
migrate    (one-shot: alembic upgrade head, owner DB creds)
minio-init (one-shot: buckets + lifecycle + scoped api user, root MinIO creds)
api depends_on: migrate + minio-init (service_completed_successfully), redis/postgres healthy  [RT#9]
```
- **Caddy** [RT#5]: global `request_body { max_size 1MB }`; route `POST /api/v1/orgs/*/investigations/*/evidence` overrides `max_size {$CADDY_EVIDENCE_MAX}` (= MAX_EVIDENCE_BYTES + 1MB) and `flush_interval -1`; server timeouts `read_header 10s`, `read_body 30m`, `idle 2m`. Sets `X-Forwarded-For`.
- **uvicorn** runs `--proxy-headers --forwarded-allow-ips='*'` — safe because api port is never published; only gateway reaches it on the internal network (documented). [RT#11]
- **Postgres init** `infra/postgres/init/01-init.sh` (reads env, no secrets committed) [RT#9]:
  - roles `cyberlab_owner` (LOGIN) and `cyberlab_app` (LOGIN, NOSUPERUSER, NOBYPASSRLS), passwords from `POSTGRES_OWNER_PASSWORD` / `POSTGRES_APP_PASSWORD`.
  - `CREATE DATABASE cyberlab OWNER cyberlab_owner;` same for `cyberlab_test` (fixes PG15+ no-CREATE-on-public).
  - `ALTER ROLE cyberlab_app SET idle_in_transaction_session_timeout = '60s'` and `statement_timeout = '30s'`. [RT#5]
  - Extensions are NOT created here (created by migration 0001; `pgcrypto`, `citext` are trusted extensions → DB owner can create).
  - Init scripts only run on an empty volume → any change requires `docker compose down -v` (documented in README).
- **minio-init** `infra/minio/init.sh` (idempotent) [RT#6, RT#9]:
  - buckets `evidence` and `evidence-test`, both `--with-lock` (versioned). Fail loudly if a bucket exists without lock.
  - lifecycle: abort incomplete multipart after 1d; `NoncurrentVersionExpiration` 7d; expired delete-marker cleanup.
  - scoped user `cyberlab-api` + policy: `GetObject, GetObjectVersion, PutObject, DeleteObjectVersion, PutObjectRetention, GetObjectRetention, ListBucket, ListBucketVersions, AbortMultipartUpload, ListMultipartUploadParts` on both buckets. **No** `BypassGovernanceRetention`. Root creds only in `minio` + `minio-init` env.
- **Dockerfiles** multi-stage `dev` / `prod` targets [RT#14]:
  - api: `python:3.12-slim` + `libmagic1` + uv; `UV_PROJECT_ENVIRONMENT=/opt/venv` (venv outside bind mount) [RT#9]; prod = no reload, non-root user.
  - web: build context = **repo root** (needs `packages/contracts` workspace pkg) [RT#9]; dev bind-mounts source + anonymous volumes for `/repo/node_modules`, `/repo/apps/web/node_modules` (Linux binaries, not host's); prod = `next build` (standalone) + `node server.js`.
- **docker-compose.prod.yml** override: prod targets, no bind mounts, `COOKIE_SECURE=true`, `ENV=prod`, Caddy site `{$SITE_ADDRESS}` with `tls internal` for local prod test.

## Related Code Files
- Create: `.gitignore`, `.gitattributes` (`* text=auto eol=lf`) [RT#9], `.editorconfig`, `.env.example`, `package.json` (root scripts), `pnpm-workspace.yaml`, `pnpm-lock.yaml`, `README.md`
- Create: `docker-compose.yml`, `docker-compose.prod.yml`, `infra/caddy/Caddyfile`, `infra/postgres/init/01-init.sh`, `infra/minio/init.sh`, `infra/minio/api-policy.json`
- Create: `apps/api/Dockerfile`, `apps/api/pyproject.toml`, `apps/api/uv.lock`, `apps/api/app/main.py`, `apps/api/app/core/config.py`, `apps/api/app/core/health.py`, `apps/api/tests/test_health.py`
- Create: `apps/web/Dockerfile`, `apps/web/package.json`, Next.js scaffold (`app/layout.tsx`, `app/page.tsx`, `next.config.ts` with `output: "standalone"`), Tailwind + shadcn init (`components.json`)
- Create: `packages/contracts/package.json` (empty `src/`)

## Implementation Steps
0. Bootstrap lockfiles without host Python [RT#9]: write `pyproject.toml`, then `docker run --rm -v "${PWD}/apps/api:/app" -w /app ghcr.io/astral-sh/uv:<pinned> uv lock`. `pnpm install` on host creates `pnpm-lock.yaml` (pnpm exists on host).
1. `git init`; `.gitignore` (node_modules, .venv, .env, .next, __pycache__, coverage, test-results, playwright-report); `.gitattributes` LF.
2. Root `package.json` scripts (Windows-friendly, no make):
   - `dev`: `docker compose up --build`
   - `down`: `docker compose down`
   - `prod:up`: `docker compose -f docker-compose.yml -f docker-compose.prod.yml up --build -d`
   - `test:api`: `docker compose --profile test run --rm api-test uv run pytest`
   - `lint:api`: `docker compose --profile test run --rm api-test sh -c "uv run ruff check . && uv run mypy app"`
   - `gen:contracts`, `verify`: added phases 7 / 9.
3. `pyproject.toml` deps: fastapi, uvicorn[standard], sqlalchemy[asyncio]>=2, asyncpg, alembic, pydantic-settings, argon2-cffi, pyjwt, redis, minio, python-magic, anyio. Dev: pytest, pytest-asyncio, httpx, ruff, mypy. Ruff (E,F,I,B,S,UP) + mypy strict.
4. `core/config.py` — `Settings(BaseSettings)` for the **api process only** (no owner DB URL) [RT#8]. All env vars defined here + `.env.example` [RT#11]:
   `ENV, DATABASE_URL (app role), REDIS_URL, MINIO_ENDPOINT, MINIO_ACCESS_KEY (cyberlab-api), MINIO_SECRET_KEY, MINIO_BUCKET, JWT_SECRET (≥32 chars, validated), COOKIE_SECURE, MAX_EVIDENCE_BYTES=2147483648, EVIDENCE_LOCK_DAYS=30, UPLOAD_TMP_DIR=/var/lib/cyberlab/upload-tmp, MAX_CONCURRENT_UPLOADS_PER_USER=2, RATE_LIMIT_LOGIN_PER_IP_PER_MIN=20, RATE_LIMIT_LOGIN_FAILURES_PER_15MIN=5, RATE_LIMIT_REGISTER_PER_IP_PER_10MIN=5`.
   Non-api env (`.env.example` only): `POSTGRES_*` passwords, `MIGRATION_DATABASE_URL` (migrate service only), `MINIO_ROOT_USER/PASSWORD` (minio + minio-init only), `TEST_DATABASE_URL`, `TEST_MIGRATION_DATABASE_URL`, `TEST_REDIS_URL=redis://redis:6379/1`, `SITE_ADDRESS`, `CADDY_EVIDENCE_MAX`.
5. `main.py`: app factory, mount `/api/v1`, `openapi_url="/api/openapi.json"` always on; Swagger UI only when ENV=dev. Health router pings db, redis, minio (`bucket_exists`).
6. Web scaffold (TS, App Router, Tailwind, ESLint), shadcn dark theme, `@tanstack/react-query`; `WATCHPACK_POLLING=true`.
7. `docker-compose.yml`: healthchecks (pg_isready, redis-cli ping, `mc ready`); named volumes incl. `upload_tmp` mounted at `UPLOAD_TMP_DIR`; internal network; only gateway `127.0.0.1:8080` + minio console `127.0.0.1:9001` published. `api-test` service under profile `test` (same image, TEST_* env mapped onto DATABASE_URL/REDIS_URL, `MINIO_BUCKET=evidence-test`, `EVIDENCE_LOCK_DAYS=0`, high rate limits).
8. `migrate` service: api image, `MIGRATION_DATABASE_URL`, cmd `uv run alembic upgrade head` (empty env this phase).
9. `README.md`: prerequisites, `cp .env.example .env`, `pnpm dev`, URLs, "init changed → `docker compose down -v`", WSL2 tip if bind mounts slow.

## Success Criteria
- [ ] Fresh clone on Windows: `cp .env.example .env && pnpm dev` → all services healthy (no host Python/uv used).
- [ ] `curl localhost:8080/api/v1/health` → `{"db":"ok","redis":"ok","minio":"ok"}`.
- [ ] `localhost:8080` renders dark Next.js page; editing `main.py` / `page.tsx` hot reloads.
- [ ] `curl -X POST localhost:8080/api/v1/health --data-binary @2MB.bin` → 413 from Caddy. [RT#5]
- [ ] Both buckets have object lock; `cyberlab-api` user cannot `remove_object(..., bypass_governance=True)`.
- [ ] `pnpm prod:up` builds prod targets and serves the same page + health. [RT#14]
- [ ] `pnpm test:api`, `pnpm lint:api` pass.

## Risk Assessment
- Docker Desktop bind mounts slow on Windows → polling; recommend WSL2 clone (README).
- Object lock only at bucket creation → init fails loudly on mismatch.
- `forwarded-allow-ips='*'` would be unsafe if api port ever published → compose comment + THREAT_MODEL note.

## Implementation Notes (deviations, 2026-11-04)
- **MinIO image**: upstream community images are no longer published (Docker Hub + quay.io unavailable). User-approved: `bitnamilegacy/minio:2025.5.24` + `bitnamilegacy/minio-client:2025.5.21` (frozen, no security patches → dev/learning only, THREAT_MODEL). Data dir `/bitnami/minio/data`; healthcheck via `curl /minio/health/live`; `MC_CONFIG_DIR=/tmp/.mc`.
- **Lifecycle**: no lifecycle rule on `evidence` bucket — `NoncurrentVersionExpiration` would auto-delete overwritten original evidence once retention lapses. `evidence-test` gets noncurrent expiry 1d. Incomplete multipart uploads are cleaned by MinIO's built-in stale-upload expiry (24h).
- **Caddy body limits**: `request_body max_size` only errors when upstream reads the body, so explicit `Content-Length` expression matchers return 413 up front (first `handle` blocks). Chunked oversize bodies are cut by `max_size` when the API reads them (verified in phase 3 with `/auth/login`).
- **Next 16 / Turbopack** ignores `WATCHPACK_POLLING`; dev sets `NEXT_WATCH_POLL_MS=1000` → `watchOptions.pollIntervalMs`. `tsc` requires `next typegen` first (`pnpm typecheck`).
- Compose prod override uses `!override` (not `!reset` with values) to replace volume lists.
- **Code review fixes (reviewer: CHANGES REQUIRED → fixed)**: fixed UID 10001 + upload dir created in image base (volume owner independent of which stack starts first); web dev mounts only `apps/web` + `packages` (root `.env` not visible); separate `backend`/`frontend` networks (web cannot reach api, so `--forwarded-allow-ips=*` only trusts gateway + data services); shared engine/Redis/MinIO clients with timeouts, health checks concurrent under `fail_after(3)`; psql variables for passwords; prod settings guard (`COOKIE_SECURE`, no `change-me`); policy rendered from bucket env + attach check on `policyName`; `.dockerignore` for api + `**/.env*`; web prod `--chown=node`; minor-pinned images (postgres 17.11, redis 7.4, node 22.23, caddy 2.10.2); healthchecks for api/web/gateway; prod hides MinIO console; distinct image tags `cyberlab/{api,web}:{dev,prod}` (dev/prod no longer overwrite each other); LF + exec bits on scripts.
- **Deferred**: shadcn `components.json` → phase 7 (when first components are added). Prod override still bind-mounts read-only infra config (Caddyfile, init scripts) — acceptable for local prod-like runs.

## Security Considerations
- Secrets only in `.env`; init scripts read env; no passwords in committed SQL. [RT#9]
- Owner DB creds only in `migrate` + `api-test`; MinIO root creds only in `minio` + `minio-init`. [RT#6, RT#8]
- Postgres/redis/minio API not published.
