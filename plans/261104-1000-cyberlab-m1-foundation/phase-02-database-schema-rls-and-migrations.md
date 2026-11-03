---
phase: 2
title: Database schema RLS and migrations
status: completed
priority: P1
effort: 8h
dependencies:
  - 1
---

# Phase 2: Database schema RLS and migrations

## Overview
SQLAlchemy models + first Alembic migration for all M1 tables, RLS policies, explicit grants, append-only + immutability triggers, tenant session plumbing, and safe test DB harness.

## Requirements
- Functional: tables `users, auth_events, refresh_tokens, organizations, organization_members, investigations, evidence, evidence_hashes, evidence_custody_events, audit_logs`.
- Non-functional: UUID PKs (`gen_random_uuid()`), `timestamptz`, FKs + indexes on every `organization_id`, RLS ENABLED + FORCED on tenant tables, migrations run as owner, app runs as `cyberlab_app`.

## Architecture

### Schema (key columns)
| Table | Columns | Notes |
|---|---|---|
| users | id, email (citext unique), password_hash, display_name, is_active, created_at, updated_at | no RLS (global identity) |
| auth_events [RT#3] | id, user_id FK NULL, email_attempted citext NULL, event enum(register,login_success,login_failure,logout,refresh_reuse_detected), occurred_at, ip, user_agent, details jsonb | no RLS; append-only; no read API in M1 (DB/admin only, documented) |
| refresh_tokens | id, user_id FK, family_id, token_hash unique, expires_at, revoked_at, revoked_reason enum(rotated,logout,reuse) [RT#7], replaced_by, created_at, ip, user_agent | no RLS (user-scoped, app-filtered) |
| organizations | id, name, slug unique, next_case_number int, created_by FK, created_at, updated_at | RLS |
| organization_members | id, organization_id FK, user_id FK, role enum(owner,admin,analyst,viewer), created_at; unique(org,user) | RLS |
| investigations | id, organization_id FK, case_number int, title, description, status enum(open,in_progress,closed,archived), severity enum(low,medium,high,critical), created_by FK, created_at, updated_at; unique(org, case_number) | RLS |
| evidence | id, organization_id FK, investigation_id FK, original_filename, detected_mime, detected_description, size_bytes bigint, storage_bucket, storage_key unique, **storage_version_id** [RT#6], status enum(active,archived), uploaded_by FK, uploaded_at, description | RLS; immutable cols trigger |
| evidence_hashes | id, organization_id FK, evidence_id FK, algorithm enum(md5,sha1,sha256), value, computed_at; unique(evidence_id, algorithm) | RLS; append-only |
| evidence_custody_events | id, organization_id FK, evidence_id FK, action enum(uploaded,downloaded,verified_ok,verified_mismatch,archived) [RT#13], actor_id FK, occurred_at, ip, user_agent, details jsonb | RLS; append-only |
| audit_logs | id, organization_id FK **NOT NULL** [RT#3], actor_id FK, action text, target_type, target_id uuid NULL, occurred_at, ip, user_agent, details jsonb | RLS; append-only |

Indexes: `(organization_id, created_at desc)` on investigations; `(organization_id, occurred_at desc)` on audit_logs; `(evidence_id, occurred_at)` on custody; `(investigation_id)` on evidence; `(family_id)` on refresh_tokens. No pg_trgm in M1 (ILIKE fine at M1 volumes). [RT#13]

### RLS pattern
```sql
-- GUCs set per transaction by app; value is '' after txn end → NULLIF guards cast error
CREATE FUNCTION app_org_id() RETURNS uuid LANGUAGE sql STABLE AS
$$ SELECT NULLIF(current_setting('app.org_id', true), '')::uuid $$;
CREATE FUNCTION app_user_id() RETURNS uuid ... 'app.user_id' ...;

ALTER TABLE investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE investigations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON investigations
  USING (organization_id = app_org_id()) WITH CHECK (organization_id = app_org_id());
```
- Same `tenant_isolation` policy on investigations, evidence, evidence_hashes, evidence_custody_events, audit_logs.
- `organization_members`: `USING (organization_id = app_org_id() OR user_id = app_user_id())`, `WITH CHECK (organization_id = app_org_id())`. Self-contained (no reference to organizations → no recursion).
- `organizations`: `USING (id = app_org_id() OR id IN (SELECT organization_id FROM organization_members WHERE user_id = app_user_id()))`; `WITH CHECK (id = app_org_id())` (register pre-generates org UUID).
- Note: `INSERT … RETURNING` also evaluates the USING clause → every tenant insert must run with matching `app.org_id`; no NULL-org rows exist anywhere (auth events live in `auth_events`). [RT#3]

### Grants (explicit, per table) [RT#9]
| Table | cyberlab_app |
|---|---|
| users | SELECT, INSERT, UPDATE |
| refresh_tokens | SELECT, INSERT, UPDATE, DELETE |
| auth_events, audit_logs, evidence_hashes, evidence_custody_events | SELECT, INSERT |
| organizations, investigations, evidence | SELECT, INSERT, UPDATE |
| organization_members | SELECT, INSERT, UPDATE, DELETE |
Plus `USAGE ON SCHEMA public`, `EXECUTE` on `app_org_id/app_user_id`.

### Triggers
- `forbid_mutation()` BEFORE UPDATE OR DELETE on auth_events, audit_logs, evidence_hashes, evidence_custody_events → `RAISE EXCEPTION`.
- `evidence_immutable()` BEFORE UPDATE on evidence → raise if any of `organization_id, investigation_id, storage_bucket, storage_key, storage_version_id, size_bytes, original_filename, uploaded_by, uploaded_at` changed. Only `status`, `description` mutable.
- **Trust boundary (honest claim)** [RT#8]: grants + triggers stop the **app role** (and accidental owner UPDATE/DELETE). The DB owner is a trusted admin and can TRUNCATE / DROP TRIGGER; owner creds never reach the api process. Documented in THREAT_MODEL.

### Tenant session plumbing (`core/db.py`, `core/tenancy.py`)
```python
@asynccontextmanager
async def tenant_session(org_id: UUID | None, user_id: UUID | None) -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as s:
        async with s.begin():               # commits on clean exit, rolls back on exception
            await s.execute(text("SELECT set_config('app.user_id', :u, true), set_config('app.org_id', :o, true)"),
                            {"u": str(user_id or ""), "o": str(org_id or "")})
            yield s
```
- `SET LOCAL` can't take bind params → always `set_config(..., true)` (txn-local, auto-reset at commit/rollback → no leak across pooled connections).
- GUCs die with the transaction → **a flow needing several transactions opens a new `tenant_session` each time**.
- **Commit rule** [RT#4, RT#5]: never rely on FastAPI dependency teardown to commit (timing differs across FastAPI versions). Handlers/services finish their `tenant_session` block (commit) **before** returning the response. Long-running flows (evidence upload/download/verify) use short sessions and hold no connection while streaming (phase 6).
- No `system_session`. Non-RLS tables (users, refresh_tokens, auth_events) are accessed via `tenant_session(None, None)` or `(None, user_id)`. [RT#2]

### Test harness (`tests/conftest.py`) [RT#8, RT#11]
- Uses `TEST_DATABASE_URL` (app role) + `TEST_MIGRATION_DATABASE_URL` (owner); **aborts unless db name ends with `_test`**.
- Migrations once per session (owner); `TRUNCATE ... CASCADE` between tests as owner (TRUNCATE bypasses row triggers — test-only, test DB only).
- Engine with `NullPool` + pytest-asyncio `loop_scope="session"` → no cross-loop asyncpg errors.
- Redis `TEST_REDIS_URL` (db 1) `FLUSHDB` per test.
- Factories (`tests/factories.py`) introduced in phase 3.

## Related Code Files
- Create: `apps/api/alembic.ini`, `apps/api/alembic/env.py` (reads `MIGRATION_DATABASE_URL` from env directly, not from api Settings), `apps/api/alembic/versions/0001_m1_schema.py`
- Create: `apps/api/app/core/db.py`, `apps/api/app/core/tenancy.py`, `apps/api/app/core/models_base.py`
- Create: `apps/api/app/modules/{users,organizations,investigations,evidence,audit}/models.py`, `apps/api/app/modules/auth/models.py` (RefreshToken, AuthEvent)
- Create: `apps/api/tests/conftest.py`, `apps/api/tests/integration/{test_rls.py,test_append_only.py,test_rls_coverage.py}`

## Implementation Steps
1. Base mixins; enums as Postgres ENUM types.
2. Models per module (table defs only).
3. Migration 0001: `CREATE EXTENSION IF NOT EXISTS pgcrypto, citext`; autogenerated tables (hand-reviewed); then `op.execute` for functions, RLS, grants, triggers. Downgrade drops all.
4. `tenant_session` + `get_engine()`.
5. conftest harness as above.
6. Tests (as `cyberlab_app`):
   - no GUC → 0 rows in investigations even with seeded rows.
   - org A → only A rows; INSERT with org B id → RLS error.
   - only `app.user_id` set → `organization_members` returns that user's memberships across orgs (needed by `require()` / `me`). [RT#2]
   - pool reuse: txn1 org A, txn2 no GUC on pool_size=1 engine → 0 rows.
   - UPDATE/DELETE on append-only tables → error; UPDATE `evidence.storage_key` / `storage_version_id` → error; UPDATE status → ok.
   - app role cannot `ALTER TABLE` or `SET row_security = off` to bypass.
   - `test_rls_coverage.py`: every table having `organization_id` has `relrowsecurity AND relforcerowsecurity` (the single RLS-coverage test; not duplicated in phase 9). [RT#14]

## Success Criteria
- [ ] `alembic upgrade head` → `downgrade base` → `upgrade head` clean on a fresh volume.
- [ ] All RLS / append-only / immutability / coverage tests pass.
- [ ] conftest refuses non-`_test` DB (tested by pointing at `cyberlab`).
- [ ] `mypy --strict` clean.
- [ ] `docs/DATABASE.md` written for tables, RLS model, roles/grants, trust boundary. [RT#14]

## Implementation Notes (2026-11-04)
- Code review found a **cross-tenant write** via the single ALL-command `organization_members` policy (own-row clause authorized UPDATE/DELETE of the caller's membership in another org). Fixed: per-command policies (SELECT broad; INSERT/UPDATE/DELETE org-only) for `organization_members` and `organizations`; regression tests added.
- `refresh_tokens.replaced_by` FK is `DEFERRABLE INITIALLY DEFERRED` (phase 3 atomic rotation updates old row before inserting successor).
- `Timestamps` mixin uses `eager_defaults` (updated_at loaded after commit).
- Immutability trigger covers every evidence column except status/description; org-leading indexes on hashes/custody.
- Functions schema-qualified / pinned search_path; `TEMPORARY` revoked from PUBLIC on both DBs; pgcrypto dropped (built-in `gen_random_uuid`).
- Harness: refuses non-`_test` DB **and** Redis db 0; resets state at session start and after each test; disposes the app engine at session end. Uses pooled app engine with session-scoped event loop instead of NullPool (no cross-loop issues observed).
- Alembic: `prepend_sys_path = .`; asyncpg needs one SQL statement per `op.execute`.

## Risk Assessment
- New tenant table without RLS → coverage test catches it.
- Forgetting the commit rule → phase 3/4 tests assert DB state after responses.

## Security Considerations
- App role NOBYPASSRLS, not owner → app code cannot disable RLS.
- Append-only enforced by grants + triggers against app role; owner is trusted (documented).
