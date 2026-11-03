---
phase: 3
title: Authentication
status: completed
priority: P1
effort: 9h
dependencies:
  - 2
---

# Phase 3: Authentication

## Overview
Register (user + org + owner membership), login, atomic refresh rotation with reuse detection, logout, `me`. Cookie sessions + CSRF + Redis rate limiting. Also delivers the minimal audit writer, auth_events writer, client-IP helper and test factories used by later phases. [RT#13]

## Requirements
- Functional: `POST /api/v1/auth/register|login|refresh|logout`, `GET /api/v1/auth/me` (user + memberships with org name/role).
- Non-functional: argon2id; generic error on bad creds; timing-equalized login (hash dummy on unknown email); every auth event persisted in `auth_events`, **including on 401 paths**. [RT#4]

## Architecture

### Cookies [RT#1]
| Cookie | Attributes | Purpose |
|---|---|---|
| `cl_access` | httpOnly, SameSite=Strict, **Path=/api**, Secure if COOKIE_SECURE, 15 min | JWT HS256 `sub, jti, iat, exp, typ="access"` |
| `cl_refresh` | httpOnly, Strict, Path=/api/v1/auth, 7 d | opaque 32B token; DB stores sha256 |
| `cl_csrf` | **NOT httpOnly**, Strict, **Path=/** | double-submit token readable by JS on any page |
- No server-side page guard reads auth cookies (frontend guard is client-side, phase 7) → `cl_access` never needs to reach Next.

### Refresh rotation (atomic) [RT#7]
```sql
UPDATE refresh_tokens SET revoked_at = now(), revoked_reason = 'rotated', replaced_by = :new_id
WHERE token_hash = :h AND revoked_at IS NULL AND expires_at > now()
RETURNING user_id, family_id;
```
- 1 row → insert new token (same family), set cookies.
- 0 rows → look up by hash:
  - not found / expired → 401 `invalid_refresh`.
  - `revoked_reason='rotated'` AND `revoked_at > now() - 10s` → **grace**: 401 `stale_refresh`, no revocation (another tab already rotated; cookie jar already holds the new token → client just retries).
  - otherwise → **reuse**: revoke whole family (`revoked_reason='reuse'`), write `auth_events(refresh_reuse_detected)`, **commit, then return** 401 `refresh_reused`.
- 401 paths return `JSONResponse` after the `tenant_session` block commits — never raise inside the session. [RT#4]

### Login / logout
- Login failure: write `auth_events(login_failure)` in its own short session (committed), then return 401 generic. [RT#4]
- Logout: revoke family (`logout`), Redis denylist `denylist:{jti}` TTL = remaining exp (kept — cheap, makes logout immediate), clear cookies, auth_event.

### Register
- Pre-generate org UUID → `tenant_session(org_id, user_id)`: insert user, org (slug from name + short suffix, `created_by`), owner membership, `audit_logs(org.created)`; `auth_events(register)`.
- Password policy: 12–128 chars, ≠ email.

### CSRF
- Pure ASGI middleware: POST/PUT/PATCH/DELETE under `/api/v1` (except `auth/login`, `auth/register`) require `X-CSRF-Token == cl_csrf` (constant-time). Set on login/register/refresh.

### Client IP + rate limiting [RT#11]
- `core/client_ip.py`: `request.client.host` (already XFF-resolved by uvicorn `--proxy-headers`, phase 1). Single helper used by limiter, audit, auth_events, custody.
- Redis fixed window (`core/rate_limit.py`), limits from Settings:
  - login: `RATE_LIMIT_LOGIN_PER_IP_PER_MIN` per IP (all attempts).
  - login **failures** per `(email, IP)`: `RATE_LIMIT_LOGIN_FAILURES_PER_15MIN` → 429 for that pair only (victim from another IP unaffected).
  - register: `RATE_LIMIT_REGISTER_PER_IP_PER_10MIN`.
  - 429 includes `Retry-After`.

### `current_user` / `me`
- Dependency: read `cl_access`, verify (PyJWT `algorithms=["HS256"]`, `leeway=0`), check denylist, load user via `tenant_session(None, None)` (users not RLS), `is_active`.
- `GET /auth/me` runs memberships query inside `tenant_session(None, user.id)` (members policy `user_id = app_user_id()`), ordered by `created_at` asc. [RT#2]

### Audit writer (minimal, moved here) [RT#13]
- `modules/audit/service.py::record(session, *, action, actor_id, org_id, target_type=None, target_id=None, details=None, request=None)` — inserts into `audit_logs` in caller's session; strips keys matching `password|token|secret`. Read API in phase 4.
- `modules/auth/events.py::record_auth_event(...)` → `auth_events`.

## Related Code Files
- Create: `apps/api/app/core/{security.py,rate_limit.py,csrf.py,client_ip.py,deps.py,errors.py}`
- Create: `apps/api/app/modules/auth/{schemas,repository,service,router,events}.py`
- Create: `apps/api/app/modules/users/{schemas,repository}.py`
- Create: `apps/api/app/modules/audit/{service,repository}.py` (write side)
- Create: `apps/api/tests/factories.py` (real DB rows via app/owner sessions, no mocks)
- Create: `apps/api/tests/unit/test_security.py`, `apps/api/tests/integration/test_auth.py`, `test_auth_rate_limit.py`
- Modify: `apps/api/app/main.py` (routers, CSRF middleware, error handlers)

## Implementation Steps
1. `errors.py`: NotFound/Forbidden/Conflict/Unauthorized → `{"error": {"code","message"}}`.
2. `security.py`: argon2-cffi (argon2id, `needs_rehash` on login), JWT encode/decode, token gen + sha256.
3. Refresh repository with atomic rotate SQL above + `revoke_family`.
4. Auth service + router (commit-before-respond rule).
5. CSRF middleware, client-IP helper, rate limiter.
6. Audit + auth_events writers; factories.
7. Tests (all as `cyberlab_app`, assert **DB state**, not just status):
   - register → cookies (`cl_csrf` Path=/), user/org/owner rows, `auth_events(register)`, `audit_logs(org.created)`; password hashed.
   - duplicate email → 409 generic.
   - wrong pw / unknown email → same 401 body; `auth_events(login_failure)` row exists after response.
   - refresh rotates; reuse of old token > 10 s later → 401 AND all family rows `revoked_at` set AND auth_event row exists.
   - grace: reuse within 10 s → 401 `stale_refresh`, family still valid.
   - two concurrent refreshes (`asyncio.gather`) with same token → exactly one succeeds; no forked family.
   - logout → access rejected (denylist), refresh dead.
   - mutation w/o CSRF → 403.
   - rate limits: per-IP; failures per (email, IP) with different `X-Forwarded-For` via gateway-like header → other IP not blocked.
   - tampered JWT / `alg=none` / expired → 401.

## Success Criteria
- [ ] All tests green; `ruff` + `mypy --strict` clean.
- [ ] No token in response bodies; only `cl_csrf` readable by JS.
- [ ] auth_events rows written for register/login success/failure/logout/reuse, including on 401 paths.

## Implementation Notes (2026-11-04)
- Split: `auth/service.py` (register, login, me) + `auth/sessions.py` (token issue, refresh rotation, logout, family revocation).
- Access JWT carries `fid` (refresh family); revoking a family (logout / reuse / deactivation) sets `denylist:fam:{fid}` for 15 min, so access tokens die with their family. Per-token `denylist:{jti}` kept for logout.
- Rotation + revocation serialized per family with `pg_advisory_xact_lock`; absolute session lifetime 30 days (`SESSION_MAX_AGE`) on top of the 7-day sliding refresh.
- Login failure limiter reserves a slot atomically before verifying (released on success) → concurrent guesses cannot exceed the limit. Limiter key uses explicit `unknown` when no client IP.
- argon2 runs in a worker thread; register hashes before opening the transaction.
- CSRF middleware parses cookies with Starlette's lenient parser (a malformed foreign cookie no longer hides `cl_csrf`); exactly one `X-CSRF-Token` header required.
- Error envelope everywhere: AppError, validation (no input echo), Starlette 404/405, Redis outage → 503 `service_unavailable` (fail closed), unhandled → 500 `internal_error`.
- Names reject control characters / blank; register maps only `uq_users_email` violations to 409.
- email-validator rejects special-use domains (`.local`, `.test`) — known limitation (API docs).
- Inactive-user refresh bug found by tests: rotation pointed `replaced_by` at a successor never created (deferred FK failed at commit) → `abandon_rotation` clears it.

## Risk Assessment
- SameSite=Strict: arriving via external link sends no cookies on that first navigation → client guard calls `me` (same-site fetch) → cookies sent → fine.
- JWT_SECRET rotation = restart + all sessions invalid (documented).

## Security Considerations
- Refresh stored hashed; atomic rotation prevents token cloning races.
- Per-(email, IP) failure limit avoids trivial victim lockout.
- Known M1 gaps → THREAT_MODEL: no email verification, no MFA, no breached-password check.
