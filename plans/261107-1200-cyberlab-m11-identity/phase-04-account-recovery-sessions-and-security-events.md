---
phase: 4
title: "Account recovery sessions and security events"
status: pending
priority: P2
effort: "11h"
dependencies: [1]
---

# Phase 4: Account recovery, session management and the security log (group B, 2c, lane 4)

## Overview
Password reset by email, password change, a list of the user's sessions with revoke, and the user's own auth events. Design: plan.md "Sessions, recovery and security log".

**Owns:** `identity/{recovery,sessions_api,events_api,ua}.py`, `identity/router_{recovery,sessions}.py`, `tests/integration/test_password_{reset,change}.py`, `test_sessions_api.py`, `test_security_events.py`, `tests/unit/test_ua_parse.py`.

## Requirements
- **Forgot** (`POST /auth/password/forgot {email}`, CSRF-exempt since phase 1, RT4): always `202 {}`; limits 5 / 10 min per IP and 3 / hour per email (the email key is the lowercase address hashed, so Redis keys carry no address); **the response is sent right after the limits** and a `BackgroundTasks` job does the lookup, the token and the outbox row (RT6: the earlier "token or dummy argon2" split made unknown emails the slow ones); no argon2 on this route; a token only for `kind='human'`, active, with a usable password (`!`-prefixed hashes are unusable); one live reset token per user (a new one consumes the old); auth event `password_reset_requested` (with `user_id` when known, never for unknown emails).
- **Reset** (`POST /auth/password/reset {token, new_password}`): the M1 password rules (`RegisterIn` validators reused); consume atomically; argon2 hash off the event loop before the transaction; set `password_hash`, `password_changed_at`, and `email_verified_at` when NULL (the link proves the mailbox, RT8); revoke **every** session through `sessions_store.revoke_all(user_id, reason=password_reset)` (families + Redis denylist, RT17, RT18); keep MFA; auth event `password_reset`; mail `password_changed`; `204`. Invalid, used or expired → `404 token_invalid`.
- **Change** (`POST /auth/password/change {current_password, new_password}`): session principal, not an SSO session of a user with a password (`403 local_reauth_required`, RT2); step-up `password_change` (phase-1 check) **and** the current password; revoke all other sessions, keep the current one; mail `password_changed`; auth event `password_changed`.
- **Sessions** (`GET /auth/sessions`): the user's non-revoked, non-expired `user_sessions` rows: `id`, `created_at`, `last_seen_at`, `ip`, `ua` summary from `ua.py` (an allowlist parser: browser family + OS family + "unknown"; never the raw string in the UI), `method`, `amr`, `sso_org_name` (resolved through the user's memberships only), `current` (row id == principal `session_id`). `DELETE /auth/sessions/{id}`: only the caller's own sessions (another user's id → 404); revokes and denylists; auth event `session_revoked`; revoking the current one clears cookies. `POST /auth/sessions/revoke-others` (`revoke_all(…, keep=current)`; refused for an SSO session of a user with a password: `403 local_reauth_required`, RT2).
- **Security log** (`GET /auth/events?limit≤100`): the caller's `auth_events` newest first, with `event`, `occurred_at`, `ip`, UA summary, and safe details (never `email_attempted` of other addresses: failures for the caller's email are shown with the IP only).
- **Tests:** reset happy path (Mailpit or `capture`), every session dead after reset (old access token → 401 at once), MFA still required after reset (use the phase-1 helper to seed an active factor; the login path itself is phase 5, so assert `user_mfa_factors` unchanged and `login_requires_mfa` once merged in phase 13); forgot answers the same for unknown, inactive, SSO-only and service users (status, body, and no outbox row), and the handler returns before the background job runs (RT6: assert the job is scheduled, not awaited, for every state); token reuse refused; change needs step-up and the current password; sessions list shows only own rows; revoke kills the access token through the family denylist; the log never shows another user's events.

## Implementation Steps
1. Recovery service and routes; tests.
2. UA parser with unit tests.
3. Sessions API; tests.
4. Events API; tests.

## Success Criteria
- [ ] Password reset works by mail, is single-use and time-limited, revokes every session and leaves MFA in place.
- [ ] `forgot` is indistinguishable across account states.
- [ ] Users list and revoke their own sessions; a revoked session's access token stops working immediately.
- [ ] The personal security log shows the caller's events only.

## Risk Assessment
- **Reset as an MFA bypass:** prevented by keeping the factor; asserted in phase 13 across the merged login.
- **UA strings are attacker-controlled:** parsed by an allowlist and rendered as text only.
