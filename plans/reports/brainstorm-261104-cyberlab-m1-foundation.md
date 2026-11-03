# Brainstorm — CyberLab AI Milestone 1 (Foundation)

Date: 2026-11-04 · Source: `requirement.txt` · Status: APPROVED

## Problem / context
- Greenfield repo (only `requirement.txt`). Full spec = DFIR/PCAP/malware/TI/AI platform → far too big for one round.
- Spec §17 orders work: M1 foundation → M2 PCAP → M3 Malware Static.
- Host: Win11, Docker 29 + Compose v5, Node 22, pnpm 10, Python 3.14 (too new for security libs). No tshark/zeek/uv on host.
- Goal: learning / portfolio → correct architecture, clean code, real tests; skip HA, auto backup, multi-region.

## Decisions (user-confirmed)
| Topic | Decision |
|---|---|
| Scope | Milestone 1 only |
| Auth | Self-built in FastAPI (argon2id, JWT access + rotating refresh, httpOnly cookies) |
| Tenancy | App-level org filter + Postgres RLS (defense in depth) |
| Frontend | Full 12-item nav shell; unbuilt modules = "Planned — Milestone N" page, no fake data |
| Upload | Stream through API → MinIO, hash on-the-fly, default limit 2 GB (configurable) |
| Dev env | Everything in Docker Compose (Python 3.12 + uv, Node 22 + pnpm) |
| Onboarding | Register creates org (owner); owner/admin add existing users by email; no real email in M1 |
| Docs in M1 | PRD (M1), ARCHITECTURE, DATABASE, API, THREAT_MODEL, DEPLOYMENT, TESTING, ROADMAP |

## Approaches evaluated
- Session transport: **same-origin httpOnly cookies via Caddy gateway** (`/api/*` → FastAPI, rest → Next) ✅ — refined in planning: Next rewrites buffer/limit large uploads vs localStorage bearer (XSS token theft) ❌.
- Backend shape: **modular monolith** (`modules/<name>/{models,schemas,repository,service,router}.py` + `core/`) ✅ vs microservices (overhead) ❌.
- Tenant scoping: **explicit `/api/v1/orgs/{org_id}/...`** ✅ vs implicit session org (harder audit/IDOR testing) ❌.
- Contracts: **OpenAPI → `openapi-typescript`** into `packages/contracts` ✅ vs hand-written TS types (drift) ❌.
- Upload: **API streaming + inline hashing** ✅ vs presigned direct-to-MinIO (needs worker + pending-verify state in M1) ❌.

## Final design
### Repo
```
apps/api/            FastAPI, SQLAlchemy 2 async, Alembic, Pydantic v2, uv
apps/web/            Next.js App Router, TS, Tailwind, shadcn/ui, React Query
packages/contracts/  generated API types
infra/               Dockerfiles, postgres init SQL (roles, RLS), minio bootstrap
docs/
docker-compose.yml   (+ test profile)
```
Out of M1: Celery, OpenSearch, analysis workers (arrive in M2). Redis only for rate limit + token revocation.

### Database (M1 tables only)
`users, organizations, organization_members(role), refresh_tokens, investigations, evidence, evidence_hashes, evidence_custody_events, audit_logs`
- UUID PKs, `created_at/updated_at`, `organization_id` FK + index on tenant tables.
- App DB role `cyberlab_app` (non-superuser, no BYPASSRLS). Per-request txn `SET LOCAL app.org_id`; RLS policies on tenant tables.
- `audit_logs`, `evidence_custody_events`: append-only (REVOKE UPDATE/DELETE + trigger).
- `evidence` hash/storage columns immutable via trigger. No evidence delete in M1 (archive only).

### Auth / RBAC
- argon2id; access JWT 15 min; refresh 7 d, rotation + reuse detection → revoke family.
- Cookies httpOnly, SameSite=Strict, Secure in prod; CSRF double-submit header on mutations.
- Roles: owner > admin > analyst > viewer. viewer=read; analyst=cases+evidence; admin=+members; owner=+manage owners (org delete/transfer deferred).
- Redis rate limit on login/register.

### Evidence pipeline
- Stream upload → MinIO bucket `evidence` (object lock enabled at creation), key = UUID; original filename = metadata only (sanitized).
- SHA256/SHA1/MD5 computed while streaming; size limit enforced mid-stream, aborted upload leaves no orphan.
- Magic-byte type detection recorded, NOT used to block (evidence may be malware). API never parses/extracts content; no archive extraction.
- Download: authz → stream `application/octet-stream`, `nosniff`, `attachment`; writes custody event + audit.
- `POST .../evidence/{id}/verify`: re-hash object, compare, log custody event (match/mismatch).

### API surface (v1)
- `/auth/{register,login,refresh,logout,me}`
- `/orgs`, `/orgs/{org_id}`, `/orgs/{org_id}/members`
- `/orgs/{org_id}/investigations[/{id}]` (status: open/in_progress/closed/archived)
- `/orgs/{org_id}/investigations/{id}/evidence` (upload/list), `/orgs/{org_id}/evidence/{id}[/download|/verify|/custody]`
- `/orgs/{org_id}/audit-logs`
- Cross-org access → 404 (no existence leak).

### Frontend
Dark dashboard; sidebar 12 items. Real pages: Login/Register, org switcher + members, Investigations list (filter/search) + detail, Evidence upload (progress) + hashes + custody chain + verify/download, Audit log.

## Acceptance criteria (Definition of Done)
- `docker compose up` → full stack healthy.
- Flow works: register → org → case → upload → see SHA256 → verify → download → custody chain + audit log populated.
- Backend: `ruff`, `mypy --strict`, pytest unit + integration against real Postgres/MinIO pass.
- Mandatory security tests:
  - IDOR on other org's investigation/evidence → 404
  - raw DB query without `app.org_id` → 0 rows (RLS)
  - viewer cannot upload; analyst cannot manage members
  - oversized upload rejected, no orphan object
  - stored-object tamper → verify reports mismatch
  - UPDATE/DELETE on audit_logs fails
  - refresh-token reuse revokes family
  - unauthenticated download → 401
- Frontend: `tsc --noEmit`, eslint, 1 Playwright smoke (register → case → upload → verify).
- Docs listed above written & consistent with code.

## Risks
- RLS + async SQLAlchemy: `SET LOCAL` must be inside each request txn; pooled connections can leak context → dedicated test.
- MinIO object lock only settable at bucket creation → bootstrap script must create it correctly.
- Docker Desktop on Windows: bind-mount hot reload slow → polling watchers (`WATCHFILES_FORCE_POLLING`, `WATCHPACK_POLLING`).
- Streaming 2 GB through API ties up worker; acceptable for M1, revisit (presigned + worker verify) in M2 if needed.
- Scope creep: no Celery/OpenSearch/TI/AI in M1.

## Next steps
1. `/ck:plan` M1 using this report.
2. After M1 passes DoD → brainstorm M2 (PCAP: Celery workers, tshark/zeek/suricata containers, normalized finding schema).

## Post-plan changes (2026-11-04, red team)
Superseded details — plan is source of truth: `plans/261104-1000-cyberlab-m1-foundation/plan.md` (§ Key decisions, § Red Team Review).
- Upload: spool to size-capped temp file while hashing → `fput_object`; reads/verify/deletes by MinIO `version_id`; scoped MinIO user.
- Tenancy: `require()` opens one `tenant_session` (set_config, txn-local); commit before responding; short txns for evidence transfers.
- Auth events in separate `auth_events` table; `audit_logs.organization_id` NOT NULL.
- Refresh rotation atomic + 10 s multi-tab grace; client-side route guard; `cl_csrf` Path=/.
- Explicit out-of-scope: ClamAV upload scanning (M3), retention/expiry policy, invite acceptance, strict nonce CSP (M2).
- Effort 70h → 80h.

