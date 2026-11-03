# CyberLab AI

Defensive cybersecurity investigation platform (DFIR, PCAP, malware static analysis, threat intel, AI analyst).
Currently at **Milestone 1 — foundation**. See `plans/` for the active implementation plan.

## Prerequisites

- Docker Desktop (Compose v2.24+)
- Node 22 + pnpm 10 (only for workspace scripts and lockfile; everything runs in containers)
- No host Python needed — the API toolchain (Python 3.12 + uv) lives in the image.

## Quick start

```bash
cp .env.example .env      # then replace every change-me value
pnpm dev                  # docker compose up --build --renew-anon-volumes
```

| URL | What |
|---|---|
| http://localhost:8080 | Web app (through the Caddy gateway) |
| http://localhost:8080/api/v1/health | API health (db / redis / minio) |
| http://localhost:8080/api/docs | Swagger UI (dev only) |
| http://localhost:9001 | MinIO console (root creds from `.env`) |

## Scripts

| Command | Does |
|---|---|
| `pnpm dev` / `pnpm down` | Start / stop the dev stack (hot reload) |
| `pnpm test:api` | API tests in the `api-test` container (test DB, test bucket, Redis db 1) |
| `pnpm lint:api` | ruff + format check + mypy --strict |
| `pnpm lint:web` | Next typegen + tsc + eslint |
| `pnpm prod:up` / `pnpm prod:down` | Prod-like stack (built images, TLS) at https://localhost:8443 |

## Layout

```
apps/api            FastAPI (Python 3.12, uv) — modular monolith
apps/web            Next.js 16 App Router, Tailwind
packages/contracts  Generated API types (phase 7)
infra/              Caddy, Postgres init, MinIO init
plans/              Brainstorm reports + implementation plans
```

## Notes

- **Init scripts run only on empty volumes.** After changing `infra/postgres/init` or bucket setup: `docker compose down -v`.
- The API connects only as the RLS-bound `cyberlab_app` role. Owner DB credentials are given to `migrate` and the test profile only.
- MinIO upstream no longer publishes community images; dev uses the frozen `bitnamilegacy/minio` image (no further security patches — dev/learning only).
- Windows: bind mounts don't forward file events, so dev uses polling (`NEXT_WATCH_POLL_MS`, `WATCHFILES_FORCE_POLLING`). For faster I/O, clone inside WSL2.
