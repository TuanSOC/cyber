---
phase: 9
title: Security E2E tests and docs
status: completed
priority: P1
effort: 12h
dependencies:
  - 8
---

# Phase 9: Security E2E tests and docs

## Overview
Add only what earlier phases can't: route-wide IDOR coverage, malicious-filename cases, Playwright smoke (dev + prod), one-command `verify`, M1 docs. Earlier per-phase security tests are referenced, not duplicated. [RT#14]

## Requirements
- Functional: `pnpm verify` (host Node script) runs: api lint/type/tests, web tsc/eslint/build, contracts drift check, header check, Playwright smoke; `pnpm verify --prod` also smokes the prod stack.
- Docs: `docs/PRD.md` (M1), `ARCHITECTURE.md`, `DATABASE.md` (finalize phase-2 draft), `API.md`, `THREAT_MODEL.md`, `DEPLOYMENT.md`, `TESTING.md`, `ROADMAP.md`.

## Architecture
- New security tests (`apps/api/tests/security/`):
  - `test_idor_routes.py`: enumerates `app.routes` with `{org_id}`; table `ROUTE_CASES` gives a minimal valid payload per route; test **fails if a route lacks an entry** (forces coverage of future routes). For each: org-A user hitting org-B ids → 404; non-member → 404; unauthenticated → 401.
  - `test_malicious_filenames.py`: `../../etc/passwd`, `a\r\nSet-Cookie: x`, NUL/control chars, RTL override, 300-char unicode, empty name, 0-byte body → stored safely; download header is RFC 5987-encoded, no header injection.
- Already covered elsewhere (TESTING.md maps §13 → test file): RLS coverage (phase 2), session/CSRF/JWT/rate limits/refresh reuse (phase 3), RBAC matrix + cross-tenant (phase 4), oversized/disconnect/tamper/unauthorized download/EICAR (phase 6).
- Deferred §13 items (TESTING.md "pending" + ROADMAP): parser vulnerabilities, prompt injection, sandbox escape, archive bombs (M1 never extracts archives — documented), malware scanning of uploads (ClamAV → M3), data retention/expiry policy, backup/restore.
- Playwright: container `mcr.microsoft.com/playwright:<pinned>` under compose profile `e2e`, `baseURL=http://gateway:8080`; e2e profile raises rate limits. `smoke.spec.ts`: register (unique email) → create case → upload small generated file → SHA256 shown equals precomputed → verify ok → custody shows `uploaded` + `verified_ok` (exact 2 events: no metadata-view events exist). [RT#13]
- `scripts/verify.mjs` (host Node 22, no bash dependency) [RT#14]:
  1. `docker compose up -d --build --wait`
  2. `docker compose --profile test run --rm api-test` → ruff, mypy, pytest
  3. `docker compose run --rm web` → `tsc --noEmit`, `eslint`, `next build`
  4. contracts: run `gen:contracts` then `git diff --exit-code packages/contracts`
  5. headers: `fetch('http://localhost:8080/')` → assert CSP, nosniff, referrer-policy; `fetch` 2 MB POST to `/api/v1/auth/login` → 413
  6. `docker compose --profile e2e run --rm e2e`
  7. `--prod`: `prod:up` + rerun step 5–6 against prod stack, then down.
  Exit non-zero on first failure with step name.

## Related Code Files
- Create: `apps/api/tests/security/{test_idor_routes.py,test_malicious_filenames.py}`
- Create: `apps/web/playwright.config.ts`, `apps/web/e2e/smoke.spec.ts`
- Create: `scripts/verify.mjs`, `apps/api/scripts/reconcile_orphans.py` (report-only, from phase 6 risk)
- Modify: `docker-compose.yml` (e2e profile), root `package.json` (`verify`)
- Create: `docs/{PRD,ARCHITECTURE,DATABASE,API,THREAT_MODEL,DEPLOYMENT,TESTING,ROADMAP}.md`
- Modify: `README.md`

## Implementation Steps
1. IDOR route-coverage + filename tests; fix bugs in owning modules.
2. Playwright container + smoke.
3. `verify.mjs`.
4. Docs:
   - PRD: M1 scope, personas, user stories, explicit non-goals + deferred §13 items.
   - ARCHITECTURE: component diagram, module layout, request lifecycle (`current_user` → `require()` single tenant session → commit-before-respond), evidence flow (spool → MinIO by version → short txns), M2 worker boundary.
   - DATABASE: ERD (mermaid), table dictionary, RLS model, grants, triggers, trust boundary (owner trusted).
   - API: conventions (error envelope, `{items,total}` pagination, cookies, CSRF, 401 codes `stale_refresh`/`refresh_reused`), endpoint list → `/api/docs`.
   - THREAT_MODEL: STRIDE per component; trust boundaries; known gaps w/ milestone: no email verification/MFA, membership add w/o consent, `'unsafe-inline'` CSP, libmagic in API, no ClamAV, no backups, refresh grace window, custody logs download requests not completions, register 409 reveals existing emails (rate-limited), email domains `.local`/`.test` rejected, MinIO image frozen (no security patches), RLS trusts `app.org_id` (only require()/authorize() may set it from request input), `forwarded-allow-ips='*'` assumption.
   - DEPLOYMENT: Windows/WSL2 dev, env var table (from `.env.example`), temp-disk sizing, prod override (`COOKIE_SECURE`, TLS at Caddy, scoped MinIO user), `down -v` when init changes.
   - TESTING: how to run, §13/§14 coverage map (done/pending), metrics to start collecting in M2.
   - ROADMAP: M2 PCAP (Celery, tshark/zeek/suricata workers, versioned job schema, normalized findings, OpenSearch, strict CSP), M3 Malware static (+ ClamAV upload scan), M4 TI, M5 AI Analyst, M6 Reports, later dynamic sandbox (gated on isolation tests), memory/disk/RE.

## Success Criteria
- [ ] `pnpm verify` green from `docker compose down -v`; `pnpm verify --prod` green.
- [ ] IDOR coverage test enumerates every org-scoped route.
- [ ] Every brainstorm DoD security test exists (TESTING.md links each to its file).
- [ ] 8 docs consistent with code (endpoints, tables, env vars).
- [ ] No "production-ready" claim; known gaps listed.

## Implementation Notes (2026-11-04)
- IDOR enumeration uses `app.openapi()["paths"]`, not `app.routes` (FastAPI 0.162 nests included routers). An AST test forbids `include_in_schema` / `add_api_route` / `add_route` in `app/`, so no route can escape enumeration. Each of the 18 cases also runs as an owner-side positive control (`status < 400`), so a route failing for everyone cannot pass vacuously. Victim state includes the victim case's evidence list. The member-add case uses a real outsider email.
- Filename cases: RFC 5987 `filename*` equals the stored name, percent-encoded; the header is pure ASCII; a 300-char CJK name is capped to 255 characters; empty and NUL names get 422.
- Rate limits: rather than raising limits for an e2e profile (the api isn't in it), `scripts/e2e.mjs` clears `rl:register:*` in that stack's Redis before every run. E2E leaves one user, org, case and a small locked object per run (documented in TESTING.md).
- Prod e2e: the prod override serves `gateway:8443` in addition to `SITE_ADDRESS`; Playwright uses `ignoreHTTPSErrors` only when `E2E_IGNORE_HTTPS_ERRORS=1`.
- `verify.mjs`:
  - Step failures and HTTP probe errors throw and are reported as `FAILED: <step>`.
  - The prod phase runs in `try/finally`, so the dev stack is always restored.
  - `COMPOSE_PROJECT_NAME` lets it run against fresh volumes without touching dev data.
- `gen:contracts` is now a Node script (`scripts/gen-contracts.mjs`) with no `mv` or shell redirection; it validates the JSON before an atomic rename.
- Healthchecks got `start_period` (postgres 60 s, minio 30 s), because the stack sometimes came back unhealthy right after the prod stack went down.
- `reconcile_orphans` needs a role that bypasses RLS. The owner role fails loudly under FORCE RLS, so it runs with the superuser URL inside the api container. Dev result: 0 orphans, 0 missing.
- `ck plan check` rewrote the "Applied To" column of the red-team table in plan.md. It was restored by hand; row 1's original value had already been lost and was reconstructed as "Phase 3, 7".
- Known gap: one unexplained verify run with 13 API failures, not reproduced since (TESTING.md).

## Risk Assessment
- Playwright image heavy on Windows → only in `verify`, cached after first pull.
- Docs drift → API.md points to generated `/api/docs` for details instead of duplicating schemas.

## Security Considerations
- Test fixtures (EICAR, weird filenames) generated at runtime; nothing malicious committed.
- THREAT_MODEL is the honest record of what M1 does NOT protect against.
