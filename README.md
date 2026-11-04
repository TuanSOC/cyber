# CyberLab AI

Defensive cybersecurity investigation platform (DFIR, PCAP, malware static analysis, threat intel, AI analyst).
**Milestone 3 — Malware static analysis** is done (M1 foundation and M2 PCAP Analyzer before it):
- **PCAP Analyzer (M2):** captures uploaded as evidence are analyzed automatically by Zeek, TShark and Suricata in an isolated worker; findings, alerts, flows, DNS/HTTP/TLS records, IOCs and timeline. See [docs/PCAP_ANALYSIS.md](docs/PCAP_ANALYSIS.md).
- **Malware Lab (M3):** PE/ELF uploads are analyzed statically (never executed) by ClamAV, YARA, pefile / pyelftools, capa and FLOSS in a second isolated worker; every other upload up to 64 MiB gets a ClamAV + YARA scan. Sample facts, sections, imports/exports, strings, signatures, capabilities, verdict-free findings, IOCs and a JSON / printable report. See [docs/MALWARE_ANALYSIS.md](docs/MALWARE_ANALYSIS.md).
- **Platform (M3):** nonce-based CSP, per-org storage quotas.

Plans are in `plans/`.

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

## Scripts

| Command | Does |
|---|---|
| `pnpm dev` / `pnpm down` | Start / stop the dev stack (hot reload) |
| `pnpm test:api` | API tests in the `api-test` container (test DB, test bucket, Redis db 1) |
| `pnpm lint:api` | ruff + format check + mypy --strict |
| `pnpm lint:web` | Next typegen + tsc + eslint |
| `pnpm test:web` | Web unit tests (vitest) |
| `pnpm test:workers` | PCAP worker, static worker and worker-kit tests, each inside the real worker image (sandbox, isolation, engines, detection quality, fuzz-lite) |
| `pnpm gen:contracts` | Regenerate `packages/contracts` from the API's OpenAPI schema |
| `pnpm e2e` | Playwright: M1 golden path, PCAP upload → findings, PE upload → Malware Lab + report, nonce CSP |
| `pnpm verify` | Full gate: lint, types, all tests, build, contract drift, headers, e2e |
| `pnpm verify:prod` | `verify` + prod stack health / headers / HSTS |
| `pnpm prod:up` / `pnpm prod:down` | Prod-like stack (built images, TLS) at https://localhost:8443 |

## Layout

```
apps/api            FastAPI (Python 3.12, uv) — modular monolith
apps/web            Next.js 16 App Router, Tailwind
packages/contracts  Generated API types (openapi-typescript)
apps/workers/pcap   PCAP analyzer worker (Zeek, TShark, Suricata; untrusted, sandboxed) + synthetic dataset
apps/workers/static Static malware analyzer worker (ClamAV, YARA, pefile, capa, FLOSS; untrusted, sandboxed) + synthetic samples
packages/py-jobs    Versioned job/result contracts shared by the API and workers
packages/py-worker-kit  Sandbox, transfer and result writer shared by both workers
infra/              Caddy, Postgres init, MinIO init, Redis broker ACL
docs/               Product, architecture, API, database, threat model, deployment, testing, roadmap
plans/              Brainstorm reports + implementation plans
scripts/verify.mjs  The verify gate
```

## Docs

[PRD](docs/PRD.md) · [Architecture](docs/ARCHITECTURE.md) · [API](docs/API.md) · [Database](docs/DATABASE.md) · [PCAP analysis](docs/PCAP_ANALYSIS.md) · [Malware analysis](docs/MALWARE_ANALYSIS.md) · [Threat model](docs/THREAT_MODEL.md) · [Deployment](docs/DEPLOYMENT.md) · [Testing](docs/TESTING.md) · [Roadmap](docs/ROADMAP.md)

## Notes

- **Init scripts run only on empty volumes.** After changing `infra/postgres/init` or bucket setup: `docker compose down -v`.
- The API connects only as the RLS-bound `cyberlab_app` role. Owner DB credentials are given to `migrate` and the test profile only.
- MinIO upstream no longer publishes community images; dev uses the frozen `bitnamilegacy/minio` image (no further security patches — dev/learning only).
- Windows: bind mounts don't forward file events, so dev uses polling (`NEXT_WATCH_POLL_MS`, `WATCHFILES_FORCE_POLLING`). For faster I/O, clone inside WSL2.
- Orphan check (report-only, DB rows vs. stored object versions): `apps/api/app/scripts/reconcile_orphans.py` (runs as the Postgres superuser; usage in its docstring).
- Not production-ready: see the known gaps in `docs/THREAT_MODEL.md`.
