---
phase: 9
title: "Platform API keys and service accounts"
status: pending
priority: P2
effort: "16h"
dependencies: [1]
---

# Phase 9: Platform API keys and service accounts (group B, 2h, lane 9; the cut line)

## Overview
Programmatic access for automation: scoped, expiring, revocable per-org keys belonging to service accounts, sent as `Authorization: Bearer`, hashed at rest, shown once, audited and never in browser storage. Design: plan.md "Platform API keys". This phase and the API-keys part of phase 11 can be dropped without touching any other phase.

**Owns:** `app/modules/api_keys/**` (after the stubs), `core/csrf.py` (the bearer rule; phase 1 already extended `EXEMPT_PATHS`, RT4), `evidence/{router,transfer,uploads}.py` (the principal on the transfer and upload routes; the upload's `org_session` calls live in `uploads.py`, RT15), `tests/security/idor_cases_api_keys.py`, `tests/integration/test_api_keys_{lifecycle,auth,scopes,csrf,evidence}.py`, `tests/unit/test_api_key_format.py`, `test_log_redaction.py`.

## Requirements
- **Create** (`POST /orgs/{org}/api-keys {name, role, scopes, expires_in_days}`): `security.manage`, step-up `api_key_create`, org policy `api_keys_enabled` (`403 api_keys_disabled`), ≤ `API_KEYS_MAX_PER_ORG` (20) live keys (`409 api_key_limit_reached`); `role` ∈ analyst / viewer; `scopes` a non-empty subset of the allowed five, each also granted by the role; `expires_in_days` 1..`API_KEY_MAX_DAYS` (365). In one transaction: the service user (`kind='service'`, `is_active=true` for RLS and membership purposes but unusable for every login path: hash `!service`, email `svc-<uuid>@service.invalid`, display name = key name), the membership, the `api_keys` row with `public_id` (12 chars of Crockford base32 from `secrets`) and `secret_hash` (sha256 of the 32-byte secret), audit `api_key.created` (name, role, scopes, expiry, public id), outbox `api_key_created` to every owner. Response `201 {key: "clk_<public>_<secret>", id, public_id, …}` with `Cache-Control: no-store`; the full key is never returned again.
- **List** (`GET`): id, name, `clk_<public_id>…` display prefix, role, scopes, created by / at, expires at, computed status (`active/expired/revoked`), last used at / IP; never the hash.
- **Revoke** (`POST …/{id}/revoke`): `security.manage` (no step-up: revoking is always safe); sets `revoked_*`; the service user's membership stays (history and audit actor), the user is deactivated (`is_active=false`); audit `api_key.revoked`.
- **Login paths refuse service users:** password login (unusable hash), SSO (identities only for humans), reset (`kind` check, phase 4), invitations (`kind` check at accept) — tests here assert each refuses a service account's email.
- **Resolve** (`api_keys/auth.resolve`, called by `core/rbac.org_session` inside the org's tenant session): `SELECT … WHERE public_id = :p` (RLS confines it to the path org; another org's key → not found → `401 invalid_api_key`); `hmac.compare_digest(sha256(secret), secret_hash)`; not revoked; `expires_at > now()`; returns the service user id, role and scopes; `last_used_at/ip` updated when `once_per(f"apikey:{id}", 300)` is true (its own small UPDATE in the same transaction); failures: auth event `api_key_auth_failure` (public id only, deduplicated per minute) and the per-IP failure counter.
- **Permissions:** the route's permission must be in `role permissions ∩ scopes` (phase-1 helper), and every in-service check reads the same set from `ctx.permissions` (phase 1 rewrote the six `ROLE_PERMISSIONS[ctx.role]` reads and the `_tlp_rule` arguments, RT1); `security.manage`, `members.manage`, `org.update`, `integrations.manage`, `audit.read` can never be scopes; every step-up action refuses keys (phase-1 check). Non-org routes refuse keys (`CurrentUserDep` is session-only, phase 1).
- **CSRF** (`core/csrf.py`): skip the check only when there is exactly one `authorization` header starting with `Bearer clk_` and **no** `cookie` header; a request with both is already refused by `current_principal` (`400 ambiguous_credentials`), and the middleware also refuses it (defence in depth). Browsers cannot send a cookie-less credentialed request to the same origin with ambient credentials, and a script that can set the header already holds the key.
- **Evidence transfer:** the upload (`evidence/uploads.py`), download and verify routes (`org_session` callers) take the principal so automation can move bytes; each `org_session` step re-resolves the key (revocation mid-transfer stops the next step). Upload slots and the per-user limit key on the service user.
- **No key in logs:** `core/logging` (phase 1) drops `Authorization`; `test_log_redaction.py` captures api logs during a full key lifecycle plus failed auths and asserts no `clk_` substring and no secret.
- **Tests:** lifecycle (create shown once, list never shows the secret, revoke, expiry by time travel), auth (valid key on an allowed route; wrong org → 401; revoked → 401 at once; expired → 401; tampered secret → 401; malformed → 401 before any DB query; the per-IP failure limit), scopes (a viewer-scoped key cannot write; an analyst key without `evidence.write` cannot upload, cannot run AI with evidence writes, cannot export IOCs with `defang=false`, cannot release the share policy; RT1: one test per rewritten in-service check; no key reaches `members`, `security-policy`, `integrations`, audit logs), the service account's membership cannot be re-roled or removed through the members routes (`service_account_member`, RT14), step-up refusal, CSRF (bearer without cookies passes; bearer + cookie refused; cookie-only without the CSRF header still refused), evidence upload + download with a key, audit actor = service account; IDOR module and the enumerator's "foreign API key" pass over every org route (each must answer 401 or 404, never 200).

## Implementation Steps
1. Key format, parse and resolve; unit tests.
2. Lifecycle routes with the service account; tests.
3. CSRF rule; tests.
4. Evidence transfer principal; tests.
5. Scope matrix tests, the enumerator pass, log redaction.

## Success Criteria
- [ ] Keys are shown once, stored hashed, scoped by role ∩ scopes, bound to one org, expiring and revocable with immediate effect.
- [ ] No key reaches a non-org route, another org, a management permission or a step-up action.
- [ ] CSRF is skipped only for cookie-less bearer requests.
- [ ] Automation can upload and download evidence with a key.
- [ ] No key or secret appears in logs.

## Risk Assessment
- **Service accounts appear as members:** the members list labels them (`kind`), owner counts ignore them and the members routes refuse to re-role or remove them (phase 3, RT14), and phase 11 shows them under API keys rather than people.
- **Sibling overlap (RT15):** M8–M10 edit `evidence/uploads.py`; this phase starts only after M10 is merged if M11 runs in parallel with M9 / M10.
- **A leaked key** works until revoked or expired: mandatory expiry, owner notification on creation, last-used display, immediate revoke.
