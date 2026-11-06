---
phase: 5
title: "TOTP MFA recovery codes login challenge and step-up"
status: pending
priority: P2
effort: "19h"
dependencies: [1]
---

# Phase 5: TOTP MFA, recovery codes, the login challenge and step-up (group B, 2d, lane 5)

## Overview
A second factor for password logins and the re-authentication that sensitive actions require. Own RFC 6238 verifier, secrets sealed at rest, replay-proof acceptance, NIST-style throttling, recovery codes and an operator reset. Design: plan.md "MFA" and "Step-up".

**Owns:** `identity/{totp,mfa,challenge,stepup_api,admin_mfa}.py`, `identity/router_mfa.py`, `auth/service.py` (login), `tests/unit/test_totp.py`, `tests/integration/test_mfa_{enroll,login,replay,throttle,recovery,disable}.py`, `test_step_up.py`, `test_identity_admin_mfa.py`.

## Requirements
- **`totp.py`** (no dependency): `new_secret() -> bytes` (20 bytes from `secrets`), `b32(secret)`, `otpauth_uri(secret, account=email, issuer="CyberLab")` (`otpauth://totp/CyberLab:<email>?secret=…&issuer=CyberLab&algorithm=SHA1&digits=6&period=30`, URI-escaped), `code_at(secret, step) -> str` (RFC 4226 dynamic truncation), `verify(secret, code, now, window=1) -> int | None` (only 6 ASCII digits accepted; every candidate step compared with `hmac.compare_digest`, all steps always computed). **Tests:** RFC 6238 Appendix B SHA-1 vectors (8-digit variant computed through the same truncation), RFC 4226 Appendix D vectors, window edges, non-digit and wrong-length codes, a property test against `pyotp` (test-only dependency).
- **Enrollment** (`mfa.py`, `router_mfa.py`):
  - every MFA mutation (`setup`, `confirm`, `recovery-codes`, `DELETE totp`) refuses an SSO session of a user with a usable password (`403 local_reauth_required`, RT2: an org's IdP must not be able to enroll or remove a factor on a global account);
  - `POST /auth/mfa/totp/setup`: session principal, `users.email_verified_at` set (`403 email_verification_required`, RT8), step-up `mfa_setup` (password; for a `locked` factor a recovery-code step-up, after which setup replaces the locked factor, RT26); refuses if an active factor exists (`409`); creates or replaces a `pending` factor with the secret sealed (`identity/seal.py`, provider `totp`, the user id as the AAD uuid); returns `{otpauth_uri, secret_b32}` with `Cache-Control: no-store`; pending factors older than 15 min are replaced.
  - `POST /auth/mfa/totp/confirm {code}`: opens the secret (`identity/unseal.py`), verifies, sets `active`, `confirmed_at`, `last_used_step = matched step`; generates 10 recovery codes (80 bits each, Crockford base32, sha256 of the normalized form stored, a new `batch_id`) returned once; input is normalized before hashing (uppercase, spaces and hyphens removed, `I`/`L` → `1`, `O` → `0`, RT26); `sessions_store.add_amr(current, "otp")` and re-issues the access cookie; revokes the user's other sessions (`revoke_all(…, reason=mfa_change, keep=current)`, RT17); auth event `mfa_enabled`; mail `mfa_enabled`.
  - `GET /auth/mfa`: `{totp: none|pending|active|locked, recovery_codes_remaining, confirmed_at}`.
  - `POST /auth/mfa/recovery-codes`: step-up `recovery_codes_regenerate`; new batch; old batch dead; auth event.
  - `DELETE /auth/mfa/totp`: step-up `mfa_disable` with TOTP or a recovery code (not the password alone); `409 mfa_required_by_org` if any of the user's orgs has `require_mfa` (read in a user-level `tenant_session(None, user_id)` through the RT13 SELECT policy, no per-org session); status `disabled`, recovery codes dead; other sessions revoked; event and mail.
- **Login challenge** (`challenge.py`, `auth/service.login`):
  - after a valid password, a user with an `active` or `locked` factor gets no session: create a Redis challenge `{user_id, created, attempts:0}` under a random 256-bit id (5 min), return the phase-1 `202 MfaChallengeOut {mfa_required: true, methods}` with `cl_mfa` and `cl_csrf`; auth event `mfa_challenge`; the login failure slot is released as today;
  - the challenge also stores the user's `password_changed_at`; `POST /auth/mfa/verify` re-reads the user and refuses (`401 mfa_challenge_invalid`) if it is inactive or the password changed since (RT26);
  - `POST /auth/mfa/verify {code}` or `{recovery_code}`: challenge from the cookie (missing or expired → `401 mfa_challenge_invalid`); attempts ≤ 5 per challenge (then the challenge is deleted); per-user failures 10 / 15 min (`rate_limit.hit`); TOTP path: verify, then the **replay guard** `UPDATE user_mfa_factors SET last_used_step=:s, consecutive_failures=0 WHERE id=:f AND status='active' AND last_used_step < :s` (0 rows → `401 mfa_code_invalid`, counted as a failure); recovery path: atomic `UPDATE … SET used_at=now() WHERE code_hash=:h AND user_id=:u AND batch_id=<current> AND used_at IS NULL`; failures increment `consecutive_failures` (100 → `locked`, auth event `mfa_locked`, mail); a `locked` factor accepts recovery codes only; success: delete the challenge, clear `cl_mfa`, `start_session(method=password, amr=[pwd, otp|recovery])`, auth event `mfa_success` or `recovery_code_used` (+ mail), `200 MeOut`.
- **Step-up** (`stepup_api.py`, `POST /auth/step-up`): session principal; `{code}` / `{recovery_code}` (users with a factor; same replay guard and counters as login) or `{password}` (users without a factor; argon2 verify; the login failure limits apply); success → `sessions_store.mark_step_up` (re-issued cookie), auth event `step_up_success`; failure → `step_up_failure`, `401`. SSO sessions get `409 step_up_via_sso` with the phase-8 start route in the body.
- **Operator reset** (`admin_mfa.py`, `pnpm identity:admin reset-mfa --email <e> [--yes]`): runs as a one-off api container; prints what it will do and needs `--yes`; disables the factor and codes, revokes every session, auth event `mfa_reset_by_operator` (details: operator host user from env), mail `mfa_reset_by_operator`.
- **Tests:** enrollment refused for an unverified email and for an SSO session of a password user (RT8, RT2); a challenge dies after a password reset (RT26); re-enrollment over a locked factor; recovery codes accepted in lower case and with hyphens; enrollment round trip (QR URI format, confirm with a computed code, recovery codes once); login with TOTP and with a recovery code; **concurrent replay** (two `verify` calls with the same code at once → exactly one session); code reuse in the next request refused; window ±1 accepted, ±2 refused; challenge attempt cap, per-user cap, 100-failure lock and recovery after lock; recovery code single-use and batch invalidation; disable refused under `require_mfa` (seed the policy row) and requires a second factor; step-up by code / password / refused for API keys; the sealed secret never appears in any response after setup, in logs or in `auth_events.details`; operator script.

## Implementation Steps
1. `totp.py` with vectors and the property test.
2. Enrollment, status, recovery codes, disable.
3. Login challenge and verify; adapt `auth/service.login`; the existing login tests stay green for users without a factor.
4. Step-up route.
5. Operator script; concurrency and throttle tests.

## Success Criteria
- [ ] TOTP matches the RFC vectors and pyotp; a code is accepted at most once even under concurrency.
- [ ] Password logins of enrolled users need a second factor; the per-challenge, per-user and 100-failure limits hold; a locked factor recovers only through a recovery code or the operator.
- [ ] Recovery codes are single-use, shown once, hashed, and regenerating invalidates the previous batch.
- [ ] Step-up sets `step_up_at` and refreshes the access cookie; failures are recorded.
- [ ] No TOTP secret or recovery code is ever stored or logged in clear after the setup response.

## Risk Assessment
- **Clock drift** on user devices: ±1 step (±30 s); the UI (phase 10) shows the device-time hint on repeated failures.
- **Per-user limit as a DoS lever:** accepted (plan.md Open risks); the limit is 15 min and recovery codes stay usable.
