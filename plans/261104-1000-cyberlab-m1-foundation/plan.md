---
title: CyberLab AI Milestone 1 Foundation
description: >-
  Monorepo + Docker Compose stack, auth, orgs/RBAC, investigations, evidence
  upload with hash verification + chain of custody, dark dashboard shell.
status: pending
priority: P1
effort: 80h
branch: ''
tags:
  - feature
  - infra
  - backend
  - frontend
  - database
  - auth
  - security
blockedBy: []
blocks: []
created: '2026-11-03T20:33:17.293Z'
createdBy: 'ck:plan'
source: skill
---

# CyberLab AI Milestone 1 Foundation

## Overview

Build deployable foundation for CyberLab AI (defensive DFIR platform). Source design: [brainstorm report](../reports/brainstorm-261104-cyberlab-m1-foundation.md). Spec: `requirement.txt` §17.

End state: `pnpm dev` (→ `docker compose up`) runs gateway + web + api + postgres + redis + minio. User can register → org → case → upload evidence → see SHA256/SHA1/MD5 → verify → download → view custody chain + audit log. All mandatory security tests pass.

Out of scope: Celery, OpenSearch, analysis workers, TI, AI, real email, backups/restore, HA, malware scanning of uploads (ClamAV → M3), data retention/expiry policy, membership invite acceptance, strict nonce CSP (→ M2). [RT#14]

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Monorepo and Docker Compose](./phase-01-monorepo-and-docker-compose.md) | Completed |
| 2 | [Database schema RLS and migrations](./phase-02-database-schema-rls-and-migrations.md) | Completed |
| 3 | [Authentication](./phase-03-authentication.md) | Pending |
| 4 | [Organizations RBAC and audit](./phase-04-organizations-rbac-and-audit.md) | Pending |
| 5 | [Investigations](./phase-05-investigations.md) | Pending |
| 6 | [Evidence storage and chain of custody](./phase-06-evidence-storage-and-chain-of-custody.md) | Pending |
| 7 | [Frontend shell and auth pages](./phase-07-frontend-shell-and-auth-pages.md) | Pending |
| 8 | [Frontend investigations evidence audit pages](./phase-08-frontend-investigations-evidence-audit-pages.md) | Pending |
| 9 | [Security E2E tests and docs](./phase-09-security-e2e-tests-and-docs.md) | Pending |

Order: 1 → 2 → 3 → 4 → 5 → 6 (backend chain). 7 can start after 4 (needs auth + org/member API). 8 after 6 + 7. 9 last. [RT#13]

## Key decisions (brainstorm + planning + red team)

- Modular monolith FastAPI (Python 3.12, uv) + Next.js App Router; all in Docker Compose; prod override from phase 1.
- Same-origin via **Caddy gateway** (`/api/*` → api, rest → web); Caddy enforces 1 MB default body limit, larger only on upload route.
- Auth: argon2id; JWT access 15m (`cl_access`, Path=/api); opaque refresh 7d, **atomic rotation** + reuse detection + 10 s multi-tab grace; `cl_csrf` Path=/ double-submit; **client-side route guard** (no SSR cookie check).
- Tenancy: explicit `/api/v1/orgs/{org_id}/...`; `require()` opens ONE `tenant_session(org, user)` and checks membership inside it; RLS ENABLED+FORCED; **commit before responding**, never via dependency teardown.
- Auth events → separate append-only `auth_events` table; `audit_logs` always org-scoped (NOT NULL).
- Evidence: request body spooled to size-capped temp file + inline MD5/SHA1/SHA256 → `fput_object` → object-locked MinIO; **every read/verify/delete by `storage_version_id`**; scoped MinIO user (no governance bypass); no DB connection held during transfer.
- Owner DB creds only in `migrate` + test profile; DB owner is a trusted admin (triggers stop the app role, not the owner).
- One pagination envelope `{items, total}` (offset) everywhere.

## Global conventions

- Paths relative to repo root `D:\Downloads\learn\cyber`.
- Each backend module: `models.py, schemas.py, repository.py, service.py, router.py`. Files < 200 LOC; split if larger.
- Every phase ends: `ruff check`, `mypy --strict`, `pytest`, (web) `tsc --noEmit` + `eslint` green; docs touched updated.
- Never mock analysis results; never return fake data in UI.
- Cross-tenant/non-member access → 404; member w/ insufficient role → 403.

## Dependencies

- None (greenfield). Next milestone (M2 PCAP) will be blocked by this plan.

## Red Team Review

### Session — 2026-11-04
**Findings:** 15 (14 accepted, 1 partially accepted, 0 rejected) — deduplicated from 40 raw findings by 4 reviewers (Security Adversary, Failure Mode Analyst, Assumption Destroyer, Scope & Complexity Critic)
**Severity breakdown:** 2 Critical, 8 High, 5 Medium

| # | Finding | Severity | Disposition | Applied To |
|---|---------|----------|-------------|------------|
| 1 | Cookie Path=/api invisible to SSR guard; cl_csrf unreadable | Critical | Accept | Completed |
| 2 | require() membership lookup returns 0 rows under FORCE RLS → all org routes 404 | Critical | Accept | Completed |
| 3 | NULL-org audit insert fails RLS on INSERT…RETURNING | High | Accept (auth_events table) | Phase 2, 3 |
| 4 | Request-wide txn rollback erases revocation/failure audit before 401 | High | Accept | Phase 2, 3 |
| 5 | No gateway body limit (unauth OOM); DB txn held during streams (pool exhaustion) | High | Accept | Phase 1, 2, 6 |
| 6 | Object lock = versioning: hidden orphans, overwrite via new version, root creds bypass | High | Accept (keep lock, version_id + scoped user) | Phase 1, 2, 6 |
| 7 | Non-atomic refresh rotation; multi-tab false reuse | High | Accept | Phase 2, 3, 7 |
| 8 | Owner DB creds in api runtime; false "defends owner" claim; tests could wipe dev DB | High | Accept | Phase 1, 2 |
| 9 | Windows/Docker bootstrap breakages (uv.lock, bind mounts, CRLF, build context, init SQL, PG15 schema, grants, buckets) | High | Accept | Phase 1, 2 |
| 10 | CSP default-src 'self' breaks Next/Radix; added too late | High | Accept | Phase 7, 9 |
| 11 | Rate limits global behind proxy; per-email lockout; test Redis leakage | Medium | Accept | Phase 1, 2, 3 |
| 12 | Undecided async→sync upload bridge; hang risk; underestimated | Medium | Accept (spool-to-temp, 14h) | Phase 6 |
| 13 | Phase deps/contract mismatches (audit stub, P7 deps, slug, overview, pagination, dead contracts) | Medium | Accept (jti denylist kept) | Phase 3, 4, 5, 6, 7, 8 |
| 14 | Phase 9 duplicated/overloaded; verify runner unworkable; not deployable; silent §13 drops | Medium | Accept | Phase 1, 2, 7, 9, plan |
| 15 | Membership add w/o consent + "first org" redirect; owner-count write skew | Medium | Partial (FOR UPDATE + deterministic redirect; invite acceptance rejected as YAGNI) | Phase 4, 7 |

### Whole-Plan Consistency Sweep
- Files reread: plan.md, phase-01 … phase-09, brainstorm report
- Decision deltas checked: 15
- Reconciled stale references: 3 (Page[T] moved phase 5 → 4; brainstorm report post-plan section; permission names unified to evidence.read/evidence.write)
- Unresolved contradictions: 0

