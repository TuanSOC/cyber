---
title: "CyberLab M11 Identity and Access"
description: >-
  Replace direct member adds with signed, single-use, expiring email invitations delivered
  through a sealed outbox and a mail worker (Mailpit in dev and test, never real mail in
  tests); email verification, password reset and an invite-only registration mode. TOTP MFA
  (own RFC 6238 verifier, replay-proof, NIST-throttled) with secrets sealed at rest through
  core/sealbox, hashed single-use recovery codes, a two-step login challenge and server-side
  step-up for sensitive actions (provider keys, TLP downgrade, share-policy release, retention
  enforce and hold release, role elevation, security settings). Per-org OIDC SSO (no SAML)
  behind DNS-verified domains, with (iss, sub) identities, guarded JIT provisioning, a hostile
  IdP mock and an SSRF-hardened egress proxy so the API keeps no direct internet route.
  Session management (list and revoke), a personal security log, org security policy
  (require MFA, enforce SSO) and platform API keys as scoped, expiring keys of service
  accounts. Red-teamed 2026-11-07 (RT1-RT34): API-key scopes enforced in every service
  permission read, SSO sessions confined to their org, SSO step-up bound to auth_time, OIDC
  as a second cut line.
status: pending
priority: P2
effort: 200h
branch: "feat/m11-identity"
tags:
  - feature
  - identity
  - auth
  - mfa
  - sso
  - invitations
  - api-keys
  - security
blockedBy: [261107-1200-cyberlab-m10-reverse-engineering]
blocks: []
created: "2026-11-07T12:00:00.000Z"
createdBy: "ck:plan"
source: skill
---

# CyberLab M11 Identity and Access

## Overview

**Requirements this milestone covers** (`requirement.txt`):
- §4: the `authentication`, `users` and `organizations` modules, completed.
- §8 / §13 "API key management", "API key encryption": the IdP client secret and TOTP secrets sealed like provider keys; platform API keys hashed, scoped and audited.
- §11: the `api_keys` table, now literally a table of **platform API keys** (DATABASE keeps the mapping of sealed provider keys).
- §13: "Authentication" (the requirement names no factor; MFA, SSO and recovery come from the ROADMAP "Later" list, so OIDC SSO is the second cut line, RT16), RBAC (a new owner-only `security.manage`), tenant isolation (every new tenant table under FORCE RLS, every new org route in the IDOR enumerator), rate limiting (new per-flow limits), audit logging (auth events, audit rows, a readable personal log). Test: IDOR, cross-tenant access.
- §16: "Review security" for the new attack surface, recorded in THREAT_MODEL.

**Inputs:**
- ROADMAP "Later": invitations / MFA / SSO, platform API keys / service accounts;
- THREAT_MODEL "Known gaps (accepted for M1)": no email verification or MFA, members added without consent, add-member enumeration, register 409 enumeration, special-use domains "revisit with SSO";
- PRD non-goals table ("Platform API keys / service accounts, MFA, SSO, invitations, email verification: Later"); DATABASE §11 mapping of `api_keys`;
- the research report [`plans/reports/researcher-261107-m11-identity.md`](../reports/researcher-261107-m11-identity.md) (standards, libraries, images, decisions, open questions).

**What exists today (scout, 2026-11-06, after M7; M8–M10 may move line numbers, phase 1 re-checks):**
- **Alembic head:** `0015_m7_hold_sync`. M8, M9 and M10 each plan one migration, so M11 expects **`0019_m11_identity`** (head + 1 at branch time; phase 1 confirms, and the parent renumbers only the revision id and `down_revision` if M11 is merged out of order, see Dependencies).
- **Auth** (`modules/auth`): register (creates the user, an org and the owner membership, then a session), login (per-IP and per-email+IP failure limits, dummy-hash timing), refresh rotation with reuse detection and family denylist, logout. Access JWT HS256 claims `sub`, `fid`, `jti`, `iat`, `exp`, `typ`. `auth_events` (enum `auth_event_type`: register, login_success, login_failure, logout, refresh_reuse_detected), append-only, non-tenant, no read API.
- **Users** are global (no RLS): no `kind`, no verification timestamp; the M7 retention system user is inactive with the hash `!unusable:retention-system-user`.
- **Members:** `POST /orgs/{org}/members {email, role}` adds an existing user without consent and answers `404 user_not_found` otherwise (enumeration, 30 / 10 min). Tests and helpers may call it (phase 1 lists the callers).
- **RBAC** (`core/rbac.py`): `require(permission)` opens one tenant session and checks membership inside it; `org_session` is also called directly by the evidence transfer routes. Permissions: `org.read/update`, `members.read/manage`, `investigation.read/write`, `evidence.read/write`, `audit.read`, `integrations.manage`.
- **CSRF:** double-submit on every mutating `/api/v1/*` except login and register; there is no bearer authentication anywhere.
- **Sealing:** `core/sealbox.py` (API seals only), `sealbox_open.py` importable only by `threat_intel/unseal.py` and `ai/unseal.py` (`test_ai_import_guard.py`, `test_ti_import_guard.py`). The API already holds the report signing private key (M6).
- **Networks:** the API is on `backend` (`internal: true`, M4). It cannot reach an IdP, DNS-over-HTTPS or an SMTP relay. `threat_intel/ssrf.py` has `resolve_pinned` and `PinnedTransport` (every DNS answer global, connect to the validated IP, TLS against the hostname).
- **Logging:** uvicorn writes an access log with the full query string (M7 RT13 moved search to POST for this reason); Caddy writes none.
- **Tenancy guard:** `test_tenant_session_guard.py` allowlists every `tenant_session(<org>, …)` site; flows whose org comes from a token need an entry backed by a non-tenant lookup (the `*_index` pattern).
- **Web:** `(auth)/login` and `(auth)/register` use `components/auth/auth-form.tsx`; org settings tabs in `lib/nav.ts:SETTINGS_TABS`; `components/members/add-member-dialog.tsx`; no account (user-level) area; `proxy.ts` sets a nonce CSP on every page; `lib/api.ts` does single-flight refresh.
- **Mocks:** `ti-mock` / `ai-mock` are in-house test-profile services (`infra/ti-mock/server.py` on `python:3.12-alpine`).
- **Lanes:** `scripts/lane-test.sh` accepts lanes 2..8, `LANE_SLOTS=3`; the M9 and M10 plans both add lane 9 (`cyberlab_b9_test`), so after M10 it exists (RT23).
- **Red-team scout additions (2026-11-07):**
  - **Service-level permission reads:** six sites read `ROLE_PERMISSIONS[ctx.role]` after `require()` (`ai/service_runs.py:440`, `evidence/share_policy.py:71`, `investigations/service.py:136`, `ioc_collections/export.py:74`, `notes/service.py:137,222`), and `reports/service.py` passes `ctx.role` to `_tlp_rule` at four sites (403, 483, 677, 848) (RT1).
  - **`org_session` callers** besides the transfer routes: `analysis/service.py`, `evidence/{locking,uploads}.py`, `reports/service.py:836,979`, `threat_intel/service_runs.py:426`; the upload itself is `evidence/uploads.py`, not `transfer.py` (RT15).
  - **CSRF:** `cl_csrf` is only ever set together with the session cookies (`set_auth_cookies`), and `csrf.py` exempts only login and register, so an anonymous browser has no token for any other POST (RT4).
  - **Password verify:** `verify_password` hands a stored `!…` hash to argon2, which raises `InvalidHashError` at once: an unusable hash answers faster than the dummy-hash path (RT5).
  - **Refresh:** `refresh_tokens.revoked_reason` is the PG enum `refresh_revoked_reason` (`rotated`, `logout`, `reuse`); the family denylist TTL is the access TTL (15 min) (RT7, RT18).
  - **RLS:** `organizations` and `organization_members` already allow reads by `app_user_id()` membership (the pattern for user-level reads of org rows, RT13); M7 gave the retention worker its own DB role `cyberlab_retention` (the precedent for RT9).
  - **Members:** `change_role` / `remove_member` accept any member, so a service account could be made owner and counted by `count_owners` (RT14).
  - **Sibling plans:** M8–M10 edit `evidence/uploads.py`, `evidence/share_policy.py`, `investigations/policy.py` and report snapshot files (RT15).

Decisions taken by the planner are marked **(decision)**. The red-team pass ran on 2026-11-07; its changes are applied below and in the phase files (table under "Red-team changes").

## Architecture (decided)

    INVITATION
    admin: POST /orgs/{org}/invitations {email, role} --(members.manage; admin/owner roles need step-up)-->
      one tx: org_invitations (token sha256, 7 d) + invitation_index (system lookup) + audit
              + email_outbox (template invite, link token sealed for the mail worker)
      -> commit -> publish mail.send(outbox_id)            (same 201 whether the email is registered)
    mail-worker (PROCESS_ROLE=mail, broker user `mail`, DB role `cyberlab_mail` (email_outbox only, RT9),
                 SMTP creds + mail seal key only)
      -> open sealed token -> render plain-text template -> SMTP (dev/test: Mailpit on `mail`;
         prod: relay via `egress`) -> status sent, sealed column NULL       (beat mail.sweep 60 s retries)
    invitee: {PUBLIC_BASE_URL}/invite#t=<token>  (fragment: never in logs or Referer)
      -> POST /invitations/inspect {token} (org name, role, inviter, masked email)
      -> signed in as that email: POST /invitations/accept {token}
         | new user: POST /auth/register {..., invitation_token} (joins that org, no new org,
           email verified by the token)
      accept = atomic UPDATE ... WHERE token_hash AND pending AND not expired RETURNING
               (org from invitation_index -> tenant_session(org) -> membership + audit)

    PASSWORD LOGIN WITH MFA
    POST /auth/login -> password OK, no MFA -> 200 MeOut + session (amr [pwd])
                     -> MFA factor active   -> 202 {mfa_required, methods} + cl_mfa (HttpOnly,
                        Strict, Path=/api/v1/auth/mfa; Redis 5 min, 5 attempts) + cl_csrf; no session
    POST /auth/mfa/verify {code | recovery_code}
      -> TOTP: own RFC 6238 verifier, window +-1 step, matched step S;
         UPDATE user_mfa_factors SET last_used_step = S WHERE last_used_step < S (replay-proof)
      -> throttles: per challenge 5, per user 10 / 15 min, 100 consecutive failures -> factor locked
      -> session (amr [pwd, otp] or [pwd, recovery]) ; recovery code use -> notification mail

    SESSIONS AND STEP-UP
    user_sessions (one row per refresh family): amr, mfa_at, step_up_at, sso_org_id, ip, ua,
      last_seen_at, expires_at (30 d, SSO 12 h), revoked_at
    access JWT gains `sid` (= family), `amr`, `sso` (org id or absent); refresh copies them from the row
    sensitive action -> core/stepup.require_recent_auth(session, principal, action)
      -> 403 step_up_required {methods} unless step_up_at within STEP_UP_MAX_AGE_S (600)
         (compared in SQL against now(), RT21)
      web: global step-up dialog -> POST /auth/step-up {code | password} (SSO: IdP re-auth,
           prompt=login + max_age=0, ID token auth_time >= state creation - 60 s, RT3)
           -> retry the request once
      API keys: always refused (`api_key_step_up_forbidden`)
    org_session(): after the membership check -> identity/policy.check_org_access
      (skipped only for require(..., policy_exempt=True) routes, RT13)
      SSO session of org S on org X != S, user with a usable password -> 403 sso_session_scope (RT2)
      require_mfa and "otp" not in amr (an SSO session counts only when sso == org) -> 403 mfa_required
      sso_enforced and sso != org -> 403 sso_required (owners with otp: break-glass, audited once
      per session)
    effective permissions: OrgContext.permissions (role, or role ∩ scopes for keys); no service
      reads ROLE_PERMISSIONS[ctx.role] (RT1)

    OIDC SSO (per org, authorization code + PKCE S256, no SAML; cut line 2, RT16)
    owner: PUT /orgs/{org}/sso {issuer, client_id, client_secret, jit...} (security.manage + step-up)
      -> issuer validated (https, public, ssrf.validate_base_url rules); secret sealed in
         cyberlab.identity.v1, URL-bound to the issuer; discovery + JWKS fetched via egress-proxy
    owner: POST /orgs/{org}/domains {domain} -> TXT _cyberlab-challenge.<domain> = token
      -> POST .../verify -> DoH query via egress-proxy (or operator: identity:admin approve-domain)
      -> verified (unique across orgs) -> sso_domain_index (system lookup: domain -> org, idp)
    user: POST /auth/sso/start {email} -> home realm discovery by domain -> Redis state
            {state, nonce, code_verifier, org, idp config version, purpose, next} 10 min
          + cl_sso (HttpOnly, SameSite=Lax, Path=/api/v1/auth/sso, binds state to this browser)
          -> {redirect_url} -> IdP
    IdP -> GET /api/v1/auth/sso/callback?code&state&iss   (query redacted in the access log)
      -> GETDEL state, cookie binding, iss == config issuer (RFC 9207), token exchange via
         egress-proxy (PKCE verifier, client secret), ID token via PyJWT: alg in {RS256, PS256,
         ES256}, kid in cached JWKS (one refetch on miss), iss, aud, azp, exp/iat (60 s), nonce,
         hd (when present, or always for https://accounts.google.com) == the email domain (RT10)
      -> identity (config, iss, sub) -> user_identities (RT11) ; else JIT: email_verified AND
         domain verified by this org (exact match, RT27); JIT creates new users only; an existing
         local account is linked only if it is already a member of this org AND its email is
         verified (RT2); never admin/owner; jit off -> sso_not_member (needs an invitation)
      -> session (amr [sso], sso = org, 12 h cap; confined to that org for users with a local
         password, RT2) -> 303 /sso/complete#next=… (safe_next)

    EGRESS
    api --(network `idp`, internal)--> egress-proxy (PROCESS_ROLE=egress_proxy, no DB/Redis/
      broker/MinIO/secrets) --(`egress`)--> internet
      HTTP CONNECT host:443 only; resolve_pinned with explicit arguments (every answer global;
      allow_private only for a dev/test-only allowlisted mock host name; TI settings never
      read, RT25); TLS end-to-end (the proxy never sees a token or secret); 10 s connect,
      30 s total, 1 MiB per tunnel; 60 tunnels / min

    PLATFORM API KEYS (cut line: phase 9 + its web part can be dropped without touching others)
    owner: POST /orgs/{org}/api-keys {name, role analyst|viewer, scopes, expires_in_days <= 365}
      (security.manage + step-up; org policy api_keys_enabled)
      -> service account user (kind=service, no password, svc-<id>@service.invalid)
         + membership (role) + api_keys row (public id, sha256 of a 256-bit secret)
      -> clk_<public id>_<secret> shown once (no-store), mail notification to every owner
    client: Authorization: Bearer clk_… (no cookie at all; both -> 400 ambiguous_credentials)
      -> current_principal: format check, per-IP failure limit, per-key rate limit
      -> require()/org_session(path org): key looked up inside the org's tenant session,
         constant-time hash compare, not revoked, not expired; app.user_id = service user;
         effective permissions = role ∩ scopes in OrgContext.permissions, used by require() AND
         every in-service check (RT1); last_used debounced (5 min)
      -> CSRF skipped only for bearer requests without cookies; non-org routes refuse keys

### Invitations (phase 3)

- **Token:** `secrets.token_urlsafe(32)` (256 bits), stored as sha256 in `org_invitations.token_hash` and `invitation_index`. Expiry `INVITATION_TTL_DAYS` (7; max 14). Resend rotates the token (the old link dies) and is limited to 3 per invitation per day.
- **Create:** `members.manage`; the role rule of `_ensure_may_manage` (only owners invite owners); admin and owner roles need step-up. One pending invitation per (org, email): re-inviting revokes the previous one in the same transaction. Always `201` with the invitation (no "user exists" signal). Optional org allowlist `invite_domain_allowlist` (phase 6 policy) → `422 invite_domain_not_allowed`. Limits: 30 / 10 min per user, 100 / day per user across orgs, 200 / day per org (RT20).
- **Inspect** (`POST /invitations/inspect`, public): returns org name, role, inviter display name, the email masked (`j***@example.com`), expiry; `404 invitation_invalid` for unknown, used, revoked or expired (one code for all). 20 / 10 min per IP.
- **Accept** (signed in): the account email must equal the invited email (citext) → else `409 invitation_email_mismatch` (the invitation stays pending). Already a member → the invitation is consumed, membership unchanged. Consumes and inserts the membership in one tenant session whose org comes from `invitation_index` (vetted allowlist entry). Marks the email verified. Audit `invitation.accepted` and `member.added` (details: `via: invitation`).
- **Register with invitation:** `RegisterIn.invitation_token` → creates the user, consumes the invitation, joins that org, **no new org** and no owned-org count. The emails must match (else `409 invitation_email_mismatch`, nothing created).
- **Direct add removed (decision):** `POST /orgs/{org}/members` answers `410 members_direct_add_removed`. Test helpers insert memberships through `tests/factories.py` (phase 1 migrates every caller). Role changes and removals refuse a service-account target (`409 service_account_member`: keys are managed on the API keys tab), so a service account is never an owner and `count_owners` counts humans only (RT14).
- **Registration mode:** `REGISTRATION_MODE=open|invite_only` (dev `open`, prod default `invite_only`, documented, with an upgrade note for existing installs). In `invite_only`, register without a valid invitation token → `403 registration_closed` before any user lookup. **Bootstrap (decision, RT12):** no automatic "first registration" rule (the first internet registrant of a fresh install would win it and lock the operator out). The operator runs `pnpm identity:admin bootstrap-owner --email <e> --org-name <n> --yes` (phase 3): it creates the org (`created_by` = the M7 system user) and an owner invitation and prints the `/register#t=…` link once; the normal register-with-invitation flow does the rest. Signed-in users still create further orgs with `POST /orgs`.
- **Email verification:** `users.email_verified_at`. Set by invitation accept or register-with-invitation, SSO (verified domain), password reset (the reset link proves the mailbox, RT8) or `POST /auth/email/verify {token}` after `POST /auth/email/verify-request` (3 / hour per user; token 24 h). **Verify requires a session of the token's user** (RT8): a link scanner that runs JavaScript, or anyone holding a forwarded link, cannot verify an account they are not signed into, and the page never auto-submits. Required before an SSO link and before TOTP enrollment (RT8); shown in the UI.

### Mail (phases 1 and 2)

- **Outbox** `email_outbox` (system table, no RLS, no tenant data beyond an optional org id for audit context): `template` (fixed enum), `to_email`, `params` jsonb (non-secret, ≤ 4 KiB, values validated by the template's schema), sealed `secret` (the link token or nothing; `cyberlab.mail.v1`, mail worker public key), `status` (`pending/sending/sent/failed`), `attempts`, `next_attempt_at`, `claimed_at` (the sweep's crash test, RT19), `sent_at`, `last_error` (fixed code: `smtp_transient`, `smtp_permanent`, `render_refused`, `unseal_failed`, `mail_disabled`, `max_attempts`), `created_at`; every time column defaults to the DB `now()`. App S/I (insert only, RT9); the mail DB role `cyberlab_mail` S + UPDATE (status columns, `claimed_at`, `secret_*` to NULL, `captured`).
- **`mail/outbox.enqueue(...)`** (implemented in phase 1, frozen) inserts in the caller's transaction; the caller publishes `mail.send(outbox_id)` after commit (`mail/outbox.publish_after_commit`). `mail.sweep` (beat, 60 s) re-publishes due `pending` rows and fails rows after 5 attempts (exponential back-off).
- **Templates** (`mail/templates.py`, frozen in phase 1): `invite`, `email_verify`, `password_reset`, `password_changed`, `mfa_enabled`, `mfa_disabled`, `recovery_code_used`, `mfa_reset_by_operator`, `sso_account_linked`, `api_key_created`, `new_owner_security_change` (security policy or SSO changed). **Plain text only** (decision): no HTML, no remote images, no tracking. Org and user names pass `SafeName`; headers are built with `email.message.EmailMessage` (SMTP policy: CR/LF refused); subjects are fixed strings. Names rendered into a body are quoted, and a name that looks like a link (`://`, `www.`, or a dotted host-like token) is replaced by a neutral label ("an organization on CyberLab"), so an org name cannot turn invitations into a phishing relay (RT20).
- **Worker:** `mail-worker` (api image, `PROCESS_ROLE=mail`): broker ACL user `mail` (`~mail* ~test.mail*`), its own DB role **`cyberlab_mail`** (RT9, the M7 `cyberlab_retention` precedent: SELECT / UPDATE on `email_outbox` only, nothing on `users` or any tenant table; created by `infra/postgres/bootstrap.sh`, password `POSTGRES_MAIL_PASSWORD`; `Settings` refuses the app role for `PROCESS_ROLE=mail` and the mail role for every other role) on the `enrich` network, the mail seal private key and SMTP credentials only (`Settings` refuses the JWT secret, app Redis, MinIO, every other seal or signing key, the metrics token). Idempotent: `UPDATE … SET status='sending' WHERE status='pending'` claims a row; after SMTP success `status='sent'`, `secret_*` NULL. At-least-once (a crash after SMTP and before the update re-sends once; documented).
- **Transports:** `MAIL_TRANSPORT=smtp|capture|disabled`. `capture` writes the rendered message to the outbox row's `captured` jsonb (test profile only). `disabled` marks rows `failed` / `mail_disabled` (never `sent`), so the invitations card shows the mail was not delivered (RT19). `ENV=test` refuses `smtp` unless `SMTP_HOST` is `mailpit-test` (decision: **no test can send real mail**). `ENV=prod` refuses `capture`, requires `MAIL_FROM`, `PUBLIC_BASE_URL` (https) and STARTTLS or implicit TLS to the relay.
- **Mailpit** (`axllent/mailpit:v1.33.0`, MIT, pinned by digest in phase 2): service `mailpit` (dev, UI on `127.0.0.1:8025` only) and `mailpit-test` (test profile, not published; the e2e profile publishes its REST port on `127.0.0.1` only for the Playwright runner) on the internal network `mail`. `api-test` joins `mail` (test profile only) for the Mailpit REST client; the runtime `api` never joins `mail` (RT24). Not part of `docker-compose.prod.yml`.

### MFA (phase 5)

- **Factor:** TOTP, RFC 6238, SHA-1, 6 digits, 30 s, secret 20 random bytes (160 bits, base32). **Own verifier** (decision, research §3): `totp.verify(secret, code, now, window=1) -> int | None` returns the matched step; tested against RFC 6238 Appendix B and RFC 4226 vectors; pyotp is a test-only cross-check.
- **Storage:** `user_mfa_factors` row sealed in `cyberlab.identity.v1` (provider `totp`, the AAD uuid is the user id, decision 1 below). Statuses `pending → active → (locked) → disabled`. One non-disabled TOTP factor per user.
- **Enrollment:** needs `users.email_verified_at` (`403 email_verification_required`, RT8: otherwise whoever pre-registered a victim's address in `open` mode could enroll a factor that survives the victim's password reset) and a non-SSO session (`403 local_reauth_required`, RT2). `POST /auth/mfa/totp/setup` (step-up by password; over a `locked` factor, step-up by a recovery code, which replaces it, RT26) → `{otpauth_uri, secret}` once, `Cache-Control: no-store`; `POST /auth/mfa/totp/confirm {code}` → active + 10 recovery codes (shown once); the current session gets `otp` in `amr`; **other sessions are revoked** (they were not MFA-authenticated). Mail `mfa_enabled`.
- **Recovery codes:** 10 × 80-bit codes (16 Crockford base32 characters, shown `XXXX-XXXX-XXXX-XXXX`), sha256 at rest (high entropy, decision) of the normalized input (uppercase, spaces and hyphens removed, Crockford `I`/`L` → `1`, `O` → `0`, RT26), single-use (atomic `used_at`), one active batch (regeneration needs step-up and invalidates the batch). Using one sends `recovery_code_used`; the UI then urges regeneration.
- **Disable:** step-up with TOTP or a recovery code; refused with `409 mfa_required_by_org` while any org of the user has `require_mfa`. Mail `mfa_disabled`; other sessions revoked.
- **Throttles:** per challenge 5 attempts; per user 10 failures / 15 min across challenges and step-ups; `consecutive_failures` reaching 100 locks the factor (NIST 800-63B §3.2.2): then only a recovery code or the operator reset works. Every failure is an auth event (`mfa_failure`); a lock sends a mail.
- **Operator reset:** `pnpm identity:admin reset-mfa --email …` (one-off api container, app role): disables the factor and recovery codes, revokes every session, auth event `mfa_reset_by_operator`, mail. Org admins cannot reset MFA (users are global, decision).

### Step-up (phases 1, 5, 6)

- **Store:** `user_sessions.step_up_at` (written as DB `now()` and checked in SQL as `step_up_at > now() - make_interval(secs => :max_age)`, so API and DB clocks never mix, RT21), set by `POST /auth/step-up` (TOTP or recovery code if the user has an active factor, else the password; SSO sessions use the IdP re-auth flow with `max_age=0`, phase 8). `STEP_UP_MAX_AGE_S=600`.
- **Check:** `core/stepup.require_recent_auth(session, principal, action: StepUpAction)` (implemented in phase 1) → `403 step_up_required {methods, action}`; every pass and failure is an auth event; API keys → `403 api_key_step_up_forbidden`.
- **Actions** (the frozen `StepUpAction` enum: `password_change`, `mfa_setup`, `mfa_disable`, `recovery_codes_regenerate`, `member_elevate`, `member_remove`, `security_policy_update`, `sso_config_update`, `domain_change`, `api_key_create`, `provider_key_change`, `tlp_downgrade`, `share_policy_release`, `retention_destructive`, `legal_hold_release`; owner of each call site in brackets):
  - own account: `password_change`, `mfa_setup`, `mfa_disable`, `recovery_codes_regenerate` [4, 5];
  - members: invite or change a role **to** admin / owner, remove a member [3];
  - org security: `security_policy_update`, `sso_config_update`, `domain_change`, `api_key_create` [6, 7, 9];
  - M4/M5 provider keys: TI and AI key PUT with `api_key`, key DELETE [6];
  - M6: lowering a case or report TLP (`acknowledge_tlp_downgrade` used), turning a share-policy flag off [6];
  - M7: retention PUT that lowers a value or turns `enforce` on, a manual enforce run, a legal hold release [6].

### Sessions, recovery and security log (phase 4)

- `GET /auth/sessions` lists the user's live sessions (created, last seen, coarse UA "Firefox on Windows" parsed by a small allowlist parser, IP, method, `amr`, current flag); `DELETE /auth/sessions/{id}` and `POST /auth/sessions/revoke-others` revoke the family, denylist its access tokens and write `session_revoked`. Every bulk revocation goes through `sessions_store.revoke_all(user_id, *, reason, keep=None)` (phase 1, RT17); `refresh_revoked_reason` gains `password_reset`, `user_revoked`, `mfa_change`, `operator` (RT18).
- **Pre-M11 sessions:** the migration backfills one `user_sessions` row per live refresh family (`method=password`, `amr={pwd}`, `created_at` = the family start, `expires_at` = start + 30 d), so refresh re-issues `sid` / `amr` tokens without a forced logout; a refresh whose family has no row answers `invalid_refresh` (RT7).
- **Password reset:** `POST /auth/password/forgot {email}` → always `202` right after the per-IP and per-email limits; the lookup, token and outbox row run in a `BackgroundTasks` job after the response is sent, so the response time does not depend on the account state (RT6: the earlier "dummy hash on the unknown path" made unknown emails the slow ones). 5 / 10 min per IP and 3 / hour per email; a token (30 min) mailed only for an active human user with a usable password. `POST /auth/password/reset {token, new_password}` sets the password, sets `email_verified_at` if NULL (RT8), revokes **every** session, keeps MFA (the next login still asks for TOTP), mails `password_changed`. SSO-only users (no password) get no mail (they sign in through their IdP).
- **Password change** (signed in, not from an SSO session of a password user, RT2): current password + step-up; other sessions revoked; mail.
- `GET /auth/events?limit` (≤ 100): the user's own auth events (time, type, coarse UA, IP), the personal security log.

### SSO (phases 7 and 8)

- **One OIDC IdP per org** (`org_idp_configs`), managed by owners (`security.manage`) with step-up. Issuer: https, IDNA host, public (the TI `validate_base_url` rules; dev/test-only private allowlist for `idp-mock`). Client authentication `client_secret_basic` or `client_secret_post`. The client secret is sealed (`cyberlab.identity.v1`, provider `oidc`, **URL-bound to the normalized issuer**) and write-only in the UI (last 4 only).
- **Discovery:** `GET {issuer}/.well-known/openid-configuration` through the egress proxy; the document's `issuer` must equal the configured one exactly; endpoints must be https on public hosts; cached on the row with the JWKS (≤ 64 KiB, refreshed after 24 h or once on an unknown `kid`, at most once per minute per org).
- **Domains:** `org_domains` with a DNS TXT challenge at `_cyberlab-challenge.<domain>`; `POST …/verify` queries DoH (`IDENTITY_DOH_URL`) through the proxy; a verified domain is unique across all orgs (`409 domain_claimed`); re-checked by the operator script `pnpm identity:admin recheck-domains` (weekly host cron, documented; no beat task, since only the api and the proxy reach DoH); a vanished record → `failed`, JIT stops, audit. Air-gapped fallback: `pnpm identity:admin approve-domain --org … --domain …` (method `operator`).
- **Flow** as in the diagram. `state`, `nonce` and the PKCE verifier are 256-bit, single-use (Redis `GETDEL`), 10 min; `cl_sso` is `SameSite=Lax` because the callback is a cross-site top-level GET (decision; research open question 2).
- **Account resolution:** by (`idp_config_id`, `iss`, `sub`) only (nOAuth, research §2), with `iss` the config's current issuer, so an issuer change never maps a new IdP's colliding `sub` onto old users (RT11). JIT (`jit_enabled`, `jit_default_role` ∈ viewer / analyst) requires `email_verified=true` and an email domain verified **by this org**, compared exactly (no parent or subdomain inheritance, RT27); when the ID token carries `hd`, and always for the shared issuer `https://accounts.google.com`, `hd` must equal that domain (RT10: a consumer Google account created with a work address, for example by a former employee, asserts `email_verified=true` without `hd`). **JIT creates new users only** (RT2). An existing local user with that email is linked only if it is **already a member of this org** (joined through an invitation) and `users.email_verified_at` is set (pre-account-takeover defence); else `sso_not_member` / `sso_link_requires_verified_email`. Links mail `sso_account_linked`. New SSO users get the unusable password hash `!sso`, `email_verified_at=now()`, a display name from `name` (sanitized, fallback the email local part). A squatted unverified local account blocking a JIT is resolved by the owner of the mailbox through password reset, then an invitation (runbook, phase 12).
- **Sessions:** `amr` `[sso]` (+ the IdP's `amr` values when present, informational), `sso` claim = org id, capped at `SSO_SESSION_MAX_AGE_H` (12) so disabling a user at the IdP takes effect within 12 h without SCIM. Local TOTP is not asked for SSO sessions (decision: MFA is the IdP's job; documented). **Scope (RT2):** an org's IdP is controlled by that org's owners, and users are global, so an SSO session of org S used by a user with a usable local password reaches only org S (`403 sso_session_scope` elsewhere: sign in with the password for other orgs) and cannot change local account security (`/auth/mfa/*` mutations, `/auth/password/change`, `/auth/sessions/revoke-others` → `403 local_reauth_required`). An SSO-provisioned user (hash `!sso`) has no other identity, so their SSO session reaches every org they were invited to. An SSO session satisfies `require_mfa` only in its own org.
- **SSO step-up (RT3):** `prompt=login` and `max_age=0`, and the ID token must carry `auth_time` no older than the state's creation minus 60 s (OIDC Core §3.1.2.1: `auth_time` is required when `max_age` is sent); an IdP that silently reuses its session fails with `sso_token_invalid`.
- **Enforcement** (`sso_enforced`, phase 6): org routes need a session whose `sso` equals the org; owners with `otp` keep break-glass access (`owners_break_glass`, default true; audited `org.sso_break_glass` once per session).
- **Errors** redirect to `/login#sso_error=<fixed code>` (the frozen redirect list, including `sso_not_member` and `sso_link_requires_verified_email`, RT22), never echoing IdP text. The callback answers with `Cache-Control: no-store` and `Referrer-Policy: no-referrer`; `core/logging` redacts the query of `/api/v1/auth/sso/callback` in the uvicorn access log (phase 1).

### Egress proxy (phase 7)

- In-house (decision, research §3): `app/egress_proxy/` run by `egress-proxy` (api image, `PROCESS_ROLE=egress_proxy`) on networks `idp` (internal, shared with the api only) and `egress`. Holds nothing secret; `Settings` refuses every secret for the role.
- `CONNECT host:port` only (any other method → 405), port 443 only, host an IDNA name or a global literal; `resolve_pinned` (all answers global) then connect to the validated address. The proxy builds the `ValidatedBase` itself and passes `allow_private` explicitly (true only for a host named in the dev/test allowlist), so `TI_MISP_ALLOW_PRIVATE` and `TI_MISP_ALLOWED_PORTS` have no effect on it (RT25); caps: 10 s connect, 30 s idle, 60 s total, 1 MiB per direction per tunnel, 32 concurrent, 60 new tunnels / min. No logging of hosts beyond a counter (the hosts are IdP names, low sensitivity, but kept out anyway).
- The API's `identity/egress.egress_client()` (phase 1) builds an `httpx.AsyncClient(proxy=IDENTITY_EGRESS_PROXY_URL)` with `trust_env=False`, `follow_redirects=False`, response size caps. Test profile may point straight at `idp-mock` (`IDENTITY_EGRESS_PROXY_URL` unset only when `ENV=test`). The `idp-mock` CA reaches the api only through the test / e2e-only `IDENTITY_EXTRA_CA_FILE` (refused when `ENV=prod`) (RT24).

### Platform API keys (phase 9)

- **Service accounts** (decision): `users.kind='service'`, inactive for every login path, email `svc-<uuid>@service.invalid`, display name = key name; one service account per key; membership with the key's role (`analyst` or `viewer`, never admin / owner).
- **Key:** `clk_` + 12-char public id + `_` + 43-char secret (`token_urlsafe(32)`). `api_keys` row: sha256 of the secret, `scopes` ⊆ {`org.read`, `investigation.read`, `investigation.write`, `evidence.read`, `evidence.write`}, `expires_at` required (1–365 days), `last_used_at/ip` (debounced 5 min with `core/audit_dedupe.once_per`), `revoked_at/by`. Max 20 live keys per org.
- **Auth:** `Authorization: Bearer clk_…` → `current_principal`; invalid format or unknown key → `401 invalid_api_key` (20 failures / min per IP before any DB read). Keys are refused on every non-org route (`/auth/*`, `/orgs` list, `/invitations/*`) and on `members.manage`, `org.update`, `integrations.manage`, `audit.read`, `security.manage` routes by the scope ∩ role rule. **The same set governs in-service checks** (RT1): `OrgContext` gains `permissions: frozenset[Permission]` (role permissions for a session, role ∩ scopes for a key), phase 1 replaces every `ROLE_PERMISSIONS[ctx.role]` read in the services (six sites) and passes `ctx.permissions` to `reports._tlp_rule`, and a guard test refuses `ROLE_PERMISSIONS[` outside `core/rbac.py`; otherwise a key scoped to `investigation.read` would still pass the `evidence.write` checks of AI runs, IOC export (`defang=false`) and the share policy. Revocation is immediate (looked up on every request).
- **CSRF:** `core/csrf.py` skips the double-submit check only when the request has an `Authorization: Bearer clk_` header **and no `Cookie` header**; a request with both → `400 ambiguous_credentials`.
- **Evidence transfer** routes (`org_session` callers in `evidence/{router,transfer,uploads}.py`, RT15) accept the principal so automation can upload and download (each step re-resolves the key). Every other `org_session` caller keeps `CurrentUserDep` and so refuses keys.
- **Audit:** `api_key.created`, `api_key.revoked` (expiry needs no sweep: it is checked on every request and shown as a computed status), every action with the service account as actor; mail `api_key_created` to every owner. Keys are never logged: the log filter drops `Authorization`; a test greps captured logs for `clk_`.
- **Browser:** the key appears once in a dialog from the mutation result kept in component state; never in React Query cache, `localStorage`, `sessionStorage`, IndexedDB or the URL (lint rule + unit test).

### Decisions with alternatives

1. **Secrets the API opens itself reuse `core/sealbox`** with a new domain `cyberlab.identity.v1` (providers `totp`, `oidc`), opened by `identity/unseal.py`, the third allowed importer of `sealbox_open.py`; the api role alone may hold `IDENTITY_SEAL_PRIVATE_KEYS_FILE`. Alternative: a symmetric AES-GCM keyring (simpler, same security since one process holds both halves). Chosen for reuse of a tested format with kid rotation and domain separation (research open question 1 for the red team).
2. **The API keeps no internet route**: an in-house CONNECT proxy rather than putting the API on `egress` or adopting Smokescreen (MIT but `v0.1.0` release line; documented alternative).
3. **OIDC only, no SAML, no SCIM** (research §5). **authlib client + PyJWT ID-token validation**.
4. **No WebAuthn in M11** (M11.1); the factor table has a `type`.
5. **Invitations replace direct add** (410), and **`invite_only` is the prod default**.
6. **Service accounts as users** so RBAC, RLS, audit and rate limits need no second principal model in the data layer.
7. **New permission `security.manage`, owners only** (SSO, domains, security policy, API keys): these can lock an org out or create non-human principals.

### Data model (migration **`0019_m11_identity`**; the M4–M7 conventions: FORCE RLS on every tenant table, composite tenant FKs, S/I grants plus per-column UPDATE, named checks with `octet_length` caps, no DELETE grant to the app role)

| Table / change | Scope / grants | Notes |
|---|---|---|
| `users` (+cols) | existing (global) | `kind` text NOT NULL default `human` check (`human`, `service`, `system`), the M7 retention user backfilled `system`; `email_verified_at`, `password_changed_at`; app UPDATE on those + `password_hash` (existing). Existing users keep `email_verified_at` NULL (they verify once before TOTP or an SSO link, RT8) |
| `refresh_revoked_reason` enum | existing | `ALTER TYPE ADD VALUE`: `password_reset`, `user_revoked`, `mfa_change`, `operator` (same autocommit block as `auth_event_type`, RT18) |
| `auth_event_type` enum | existing | `ALTER TYPE ADD VALUE`: `mfa_challenge`, `mfa_success`, `mfa_failure`, `mfa_locked`, `mfa_enabled`, `mfa_disabled`, `mfa_reset_by_operator`, `recovery_code_used`, `recovery_codes_regenerated`, `step_up_success`, `step_up_failure`, `password_reset_requested`, `password_reset`, `password_changed`, `email_verified`, `session_revoked`, `sso_login`, `sso_failure`, `sso_linked`, `invitation_accepted`, `api_key_auth_failure` (usable after commit; the downgrade leaves them, as M7 RT12) |
| `user_sessions` | user-scoped (no RLS, like `refresh_tokens`); app S/I + UPDATE (`last_seen_at`, `amr`, `mfa_at`, `step_up_at`, `revoked_at`, `revoked_reason`) | PK `id` = the refresh `family_id`; `user_id`, `method` (`password`/`sso`), `amr` text[] check ⊆ {pwd, otp, recovery, sso}, `sso_org_id` FK organizations NULL, `ip`, `user_agent` ≤ 512, `created_at`, `expires_at`, `revoked_reason` (`refresh_revoked_reason`); index (user_id, revoked_at); backfilled from live refresh families (RT7) |
| `user_mfa_factors` | user-scoped; app S/I + UPDATE (`status`, `last_used_step`, `consecutive_failures`, `confirmed_at`, `disabled_at`, `recovery_batch_id`) | `type` check (`totp`); sealed `kid`, `key_version`, `epk`, `nonce`, `ct`; partial unique (user_id, type) WHERE status <> 'disabled' |
| `user_recovery_codes` | user-scoped; app S/I + UPDATE (`used_at`) | `user_id`, `batch_id`, `code_hash` char(64) unique; a code counts only when its batch is the factor's `recovery_batch_id` |
| `user_action_tokens` | user-scoped; app S/I + UPDATE (`consumed_at`) | `purpose` (`email_verify`, `password_reset`), `token_hash` unique, `email` (sent to), `expires_at`, `consumed_at`; one live token per (user, purpose): a new one consumes the old |
| `email_outbox` | system (no RLS); app S/I; `cyberlab_mail` S + UPDATE (status columns, `claimed_at`, `secret_*`, `captured`) (RT9) | see Mail; `claimed_at` (RT19); `captured` jsonb ≤ 16 KiB (test only, check) |
| `org_invitations` | tenant; app S/I + UPDATE (`accepted_*`, `revoked_*`, `token_hash`, `expires_at`, `resend_count`, `last_sent_at`) | `email` citext, `role` member_role, `invited_by`; partial unique (org, email) WHERE pending |
| `invitation_index` | system lookup (policy `app_org_id() IS NULL OR organization_id = app_org_id()`); app S/I/U | PK `invitation_id`, `token_hash` unique, `organization_id`, `expires_at` |
| `org_security_policies` | tenant; app S/I + UPDATE; the SELECT policy also admits rows of orgs where `app_user_id()` is a member (the `orgs_select` pattern), so the MFA-disable check reads the user's orgs without a cross-tenant session (RT13) | PK org; `require_mfa`, `sso_enforced`, `owners_break_glass` (default true), `api_keys_enabled` (default false), `invite_domain_allowlist` text[] ≤ 20, `updated_by/at` |
| `org_domains` | tenant; app S/I + UPDATE (`status`, `verified_at`, `method`, `last_checked_at`) | `domain` (punycode ≤ 253), `challenge` (32 bytes b64url), `status` (`pending/verified/failed/removed`); unique (domain) WHERE status = 'verified' (global) |
| `sso_domain_index` | system lookup; app S/I/U | PK `domain`, `organization_id`, `idp_config_id`, `enabled`; written with every domain or IdP change; read by `POST /auth/sso/start` |
| `org_idp_configs` | tenant; app S/I + UPDATE | one per org; `issuer` ≤ 512, `client_id` ≤ 255, sealed secret + `secret_last4`, `client_auth`, `scopes` ≤ 200, `enabled`, `jit_enabled`, `jit_default_role` check (viewer, analyst), discovery and `jwks` jsonb ≤ 64 KiB + `fetched_at`, `config_version` int (state must match) |
| `user_identities` | tenant; app S/I + UPDATE (`last_login_at`) | `idp_config_id` (composite FK), `user_id`, `issuer`, `subject` ≤ 255, `email_at_link`; unique (idp_config_id, issuer, subject), looked up with the config's current issuer (RT11) |
| `api_keys` | tenant; app S/I + UPDATE (`last_used_at`, `last_used_ip`, `revoked_at`, `revoked_by`) | `service_user_id` FK users, `name` ≤ 100, `public_id` char(12) unique, `secret_hash` char(64), `role` check (analyst, viewer), `scopes` text[], `created_by`, `expires_at` NOT NULL check ≤ created + 366 d |

Retention (M7) does not cover these tables in M11 (out of scope; `email_outbox` and `user_action_tokens` grow slowly, recorded).

## Red-team changes (2026-11-07)

**Reviewers and sources.** Four hostile reviewers (security, reliability, product, scope / parallelism) checked this plan and the research report against the code:
- api `core/{security,deps,rbac,csrf,cookies,rate_limit,tenancy,sealbox,sealbox_open,config,audit_dedupe}.py`, `modules/auth/{service,sessions,repository,router,models,events}.py`, `modules/users/models.py`, `modules/organizations/{router,members,models}.py`, `threat_intel/{ssrf,normalize}.py`, the `ROLE_PERMISSIONS[ctx.role]` and `org_session(` call sites across `modules/**`, `reports/service.py` (`_tlp_rule` sites), migration 0001 (RLS policies) and the head `0015_m7_hold_sync`;
- infra and scripts: `docker-compose.yml` networks (`backend` internal, `egress`, `enrich`, `analysis`), `infra/redis-broker/entrypoint.sh` (ACL users), `infra/postgres/bootstrap.sh` (lane DBs, the M7 retention role), `scripts/lane-test.sh`, `apps/api/app/scripts/drill_seed.py`;
- the M8, M9 and M10 plans (migration numbers 0016–0018, lane 9, the evidence and share-policy files they edit);
- standards: RFC 6238 / 4226, NIST SP 800-63B (§3.2.2 throttling), OIDC Core 1.0 (§3.1.2.1 `max_age` / `auth_time`, §3.1.3.7 ID-token validation), RFC 9207 (`iss`), RFC 9700 (OAuth security BCP), the nOAuth class, Google's `hd` guidance, the Mailpit docs.

No container was run, nothing was downloaded beyond documentation, and no code was touched.

**Result:** 34 findings: 3 High, 17 Medium, 14 Low. 27 were accepted and applied, 7 rejected. Effort 194 h → **200 h** (phase 1 +3 h, phases 5, 6 and 8 +1 h each). Seed questions: Q1 → RT28 / RT29 / RT30 / RT3; Q2 → no finding (login and register take JSON bodies only, SameSite cookies are not stored from cross-site subresource responses, `cl_mfa` / `cl_sso` are HttpOnly and random, the MFA verify is CSRF-checked and the SSO state is cookie-bound); Q3 → RT2 / RT10 / RT11 / RT27; Q4 → RT5 / RT6 / RT20 (invitation create and inspect were clean); Q5 → RT26 / RT31 (the replay `UPDATE … WHERE last_used_step < :s` is race-free); Q6 → RT1 / RT3 (the four `_tlp_rule` sites and the case PATCH are listed in phase 6); Q7 → RT1 / RT14 / RT15; Q8 → RT9 / RT19 (params are non-secret, the token is sealed, `captured` is test-only, Mailpit is absent in prod); Q9 → RT12 / RT14; Q10 → RT16 / RT32 / RT33 / RT34.

| ID | Finding (failure scenario) | Severity | Disposition |
|---|---|---|---|
| RT1 | **API-key scopes are bypassed inside the services.** `require()` would check role ∩ scopes, but six service sites read `ROLE_PERMISSIONS[ctx.role]` (AI runs `EVIDENCE_WRITE`, IOC export `defang=false`, the share-policy release, `investigations/service.py:136`, notes) and `_tlp_rule` takes `ctx.role` at four sites: a key with `investigation.read` only still passes every secondary `evidence.write` check of its analyst role. | High | Accepted → `OrgContext.permissions` (role, or role ∩ scopes); phase 1 rewrites the six reads and the `_tlp_rule` arguments; a guard test refuses `ROLE_PERMISSIONS[` outside `core/rbac.py`; phase 9 adds a scope test per site (plan API keys; phases 1, 9). |
| RT2 | **An org's IdP can impersonate its members everywhere.** Users are global and an SSO session is a normal session: org B's owners (who control B's IdP) could mint a session for a linked member and use it in the member's other orgs, enroll a TOTP factor on the account (step-up via the same IdP), or revoke the member's other sessions. JIT-on also linked any verified local account of the domain, member or not. | High | Accepted → SSO sessions of users with a usable password reach only their SSO org (`403 sso_session_scope`) and cannot change local account security (`403 local_reauth_required`); SSO satisfies `require_mfa` only in its own org; JIT creates new users only, and linking needs an existing membership plus a verified email (plan SSO; phases 1, 5, 6, 8). |
| RT3 | **SSO step-up is a rubber stamp** when the IdP ignores `prompt=login` / `max_age=0` and silently reuses its session: the callback never checks `auth_time`. | High | Accepted → step-up requires `auth_time` ≥ state creation − 60 s (OIDC Core §3.1.2.1); `idp-mock` mode `stale_auth_time` (plan SSO; phase 8). |
| RT4 | **Every new public POST fails CSRF.** `cl_csrf` exists only with a session and only login / register are exempt, so `sso/start`, `password/forgot`, `password/reset` and `invitations/inspect` answer `403 csrf_failed` to a signed-out browser; the plan said "exempt list unchanged". | Medium | Accepted → phase 1 adds those four to `EXEMPT_PATHS` (JSON bodies only, no session cookie set: the login / register rationale); `mfa/verify` stays checked (token set at the 202); `email/verify` is signed in (RT8) (phase 1). |
| RT5 | **Login timing reveals SSO, service and system accounts.** `verify_password` passes a `!…` hash to argon2, which fails instantly, while an unknown email pays the dummy hash: a fast 401 means "account exists without a password". M11 creates many such accounts. | Medium | Accepted → `verify_password` verifies the dummy hash whenever the stored hash is unusable, then returns false; a timing-class unit test (phase 1). |
| RT6 | **`forgot` timing is inverted.** The known-user path (token + outbox row) is fast and the unknown path runs the dummy argon2, so slow answers mean "no account". | Medium | Accepted → `202` right after the limits; lookup, token and outbox in a `BackgroundTasks` job after the response; no argon2 on this route (plan Sessions; phase 4). |
| RT7 | **Pre-M11 sessions have no `user_sessions` row.** After deploy, old access tokens are refused (no `sid`), and refresh either fails on the missing row or issues tokens for a family that is invisible to the session list and to `revoke_all`. | Medium | Accepted → the migration backfills one row per live refresh family (`password`, `{pwd}`); refresh without a row → `invalid_refresh` (plan Data model; phase 1). |
| RT8 | **Pre-account takeover survives the victim's recovery.** In `open` mode an attacker registers the victim's address and enrolls TOTP; the victim's password reset keeps MFA, so the victim is locked out. A public `email/verify` could also be completed by a JS-executing link scanner for the attacker's account. | Medium | Accepted → TOTP enrollment needs `email_verified_at` (`403 email_verification_required`); `POST /auth/email/verify` needs a session of the token's user and never auto-submits; password reset sets `email_verified_at` (plan Invitations, MFA; phases 3, 4, 5, 10). |
| RT9 | **The mail worker gets the app DB role** (all of `users`, sessions, refresh hashes: no RLS on global tables) while it is the one process with an internet route in prod (SMTP relay). | Medium | Accepted → DB role `cyberlab_mail` (SELECT / UPDATE on `email_outbox` only) created by `infra/postgres/bootstrap.sh`, the M7 retention precedent; `Settings` role checks (plan Mail; phases 1, 2). |
| RT10 | **Shared Google issuer.** With issuer `https://accounts.google.com`, any Google account whose address is in the org's domain (a consumer account created with a work address, a former employee's) asserts `email_verified=true` and is JIT-provisioned. | Medium | Accepted → when `hd` is present it must equal the email domain, and it is required for that issuer; hostile mode `missing_hd` (plan SSO; phase 8). |
| RT11 | **Identities keyed by (config, `sub`) outlive an issuer change:** re-pointing the IdP to another issuer whose `sub` values collide (`1`, `2`, …) signs the new subjects in as the old users. | Medium | Accepted → unique (idp_config_id, issuer, subject), lookup with the current issuer (plan Data model; phases 1, 8). |
| RT12 | **The bootstrap rule is a race on a fresh prod install.** The first internet registrant becomes "the first human"; `invite_only` then locks the operator out. The rule also lived in `auth/service.py` (phase 5) while phase 3 owned its tests. | Medium | Accepted → no automatic rule; `pnpm identity:admin bootstrap-owner --email --org-name --yes` creates the org (created by the system user) and an owner invitation link (phase 3, `invitations/admin_bootstrap.py`); register only enforces `registration_closed` (plan Invitations; phases 1, 3, 12). |
| RT13 | **`check_org_access` cannot see the route**, so the documented exemptions (`GET /orgs/{org}`, the policy GET) had no mechanism; and the MFA-disable rule must read `org_security_policies` of every org of the user, which FORCE RLS hides outside each org's session. | Medium | Accepted → `require(permission, *, policy_exempt=False)` (frozen); the policy table's SELECT policy also admits the caller's member orgs (`orgs_select` pattern) (plan Data model; phases 1, 5, 6). |
| RT14 | **Members routes accept service-account targets:** an owner can make a key's service account an owner, after which it counts in `count_owners` and the last human owner can leave; an admin can silently break a key by changing its role. | Medium | Accepted → `change_role` / `remove_member` refuse `kind='service'` targets (`409 service_account_member`); owner counts count humans (plan Invitations; phases 3, 9). |
| RT15 | **File ownership and sibling overlap.** The upload `org_session` callers are in `evidence/uploads.py`, owned by no phase; M8–M10 edit `evidence/uploads.py` and `evidence/share_policy.py`, so running M11 in parallel with M9 / M10 conflicts in phases 6 and 9. | Medium | Accepted → phase 9 owns `evidence/uploads.py` (principal only); recommendation: keep M11 after M10 (blockedBy stays); if run in parallel, phases 6 and 9 start only after M10 is merged (plan Dependencies; phase 9). |
| RT16 | **Scope overclaim.** `requirement.txt` §13 says only "Authentication."; SSO is a ROADMAP item, yet OIDC (phases 7, 8, the SSO parts of 6, 10, 11 and 13, the egress proxy, `idp-mock`) is about 41 h and most of the new attack surface. | Medium | Accepted → OIDC is a **second cut line** (not cut by default; parent / user decides); overview wording fixed (plan Overview, Phases). |
| RT17 | **Missing frozen interfaces:** phase 8 calls phase 7's `refresh_jwks_if_unknown_kid`, and phases 4, 5 and 9 each need "revoke every session of a user". | Low | Accepted → phase-1 stubs `identity/discovery.refresh_jwks_if_unknown_kid(session, config, kid) -> bool` and `sessions_store.revoke_all(user_id, *, reason, keep=None)` (plan Frozen interfaces 3). |
| RT18 | `refresh_revoked_reason` has only `rotated` / `logout` / `reuse`, so reset, user revoke, MFA change and operator revocations had no reason value. | Low | Accepted → `ALTER TYPE … ADD VALUE` ×4 in the M7 RT12 autocommit block (plan Data model; phase 1). |
| RT19 | **Outbox gaps:** the sweep's "`sending` older than 5 min" has no timestamp column; an unopenable seal and `MAIL_TRANSPORT=disabled` had no terminal state (disabled marked rows `sent`). | Low | Accepted → `claimed_at`; fixed `last_error` codes incl. `unseal_failed`, `mail_disabled` (rows `failed`) (plan Mail; phases 1, 2). |
| RT20 | **Invitations as a phishing relay:** anyone who can create an org names it "Reset your password at evil.example" and invites arbitrary addresses (200 / day per org, any number of orgs over time). | Low | Accepted → link-like names replaced by a neutral label in mail bodies; 100 invitations / day per actor across orgs (plan Invitations, Mail; phases 2, 3). |
| RT21 | **Clock mixing:** `step_up_at`, token expiries and the outbox schedule compared between API time and DB time; TOTP relies on the host clock. | Low | Accepted → DB `now()` on both sides; DEPLOYMENT notes NTP (plan Step-up; phases 1, 12). |
| RT22 | The frozen SSO redirect codes omitted `sso_not_member` and `sso_link_requires_verified_email`, which the callback redirects with; RT2 / RT8 / RT14 add codes. | Low | Accepted → lists updated: `sso_session_scope`, `local_reauth_required`, `email_verification_required`, `service_account_member` (plan Frozen interfaces 2). |
| RT23 | **Lane 9 already exists** after M9 / M10 (both plans add it); "phase 1 adds lane 9" would collide. | Low | Accepted → phase 1 confirms and adds it only if missing (plan Lanes; phase 1). |
| RT24 | **Test plumbing:** the Mailpit REST client runs in `api-test`, which is not on `mail`; the Playwright runner cannot reach an unpublished Mailpit; trusting the `idp-mock` CA had no prod-safe mechanism. | Low | Accepted → `api-test` joins `mail` (test only); e2e publishes Mailpit REST on 127.0.0.1; `IDENTITY_EXTRA_CA_FILE` test / e2e only, refused in prod (plan Mail, Egress; phases 1, 8, 13). |
| RT25 | **`resolve_pinned` reads TI settings** (`TI_MISP_ALLOW_PRIVATE` opens every private range, TI ports): reused as is in the proxy, a TI dev flag would widen the proxy. | Low | Accepted → the proxy builds `ValidatedBase` and passes `allow_private` per allowlisted host name; a test proves the TI flags are ignored (plan Egress; phase 7). |
| RT26 | **MFA edge cases:** a challenge stays valid after a password change or deactivation; a `locked` factor could not be re-enrolled (setup refuses an existing factor); recovery-code input was not normalized. | Low | Accepted → verify re-reads `is_active` and `password_changed_at`; setup replaces a locked factor after a recovery-code step-up; normalization before hashing (plan MFA; phase 5). |
| RT27 | **Domain matching unspecified:** does a verified `corp.com` admit `eng.corp.com`, or `sub.corp.com` admit `corp.com`? | Low | Accepted → exact match only (plan SSO; phase 8). |
| RT28 | Use a symmetric AES-GCM keyring instead of the sealbox for secrets the API opens itself (research Q1). | Low | Rejected → same security (one process holds both halves), but the sealbox brings tested kid rotation, domain separation and fixed errors; the residual (API compromise reads TOTP and IdP secrets) is recorded. |
| RT29 | Push an issuer-host allowlist to the egress proxy (research Q3). | Medium | Rejected → the proxy holds no DB by design; a compromised API already holds all data and can tunnel through any configured issuer; residual "any public host on 443" kept in THREAT_MODEL. |
| RT30 | Let API keys pass step-up so CI can rotate provider keys (research Q4). | Low | Rejected → rotation stays a human, step-up-gated action; documented. |
| RT31 | Key the MFA failure limiter by (user, IP) to stop the lock-out DoS. | Medium | Rejected → NIST throttles per account; per-IP keys let a botnet brute-force; the attacker needs the password first, the window is 15 min and recovery codes stay usable (Open risks). |
| RT32 | Drop the egress proxy and put the api on `egress`. | Medium | Rejected → keeps the M4 "api has no internet route" invariant; the proxy is about 6 h and goes with the OIDC cut line (RT16). |
| RT33 | Cut the personal security log and owner break-glass. | Low | Rejected → the log is about 2 h and closes the "no read API on auth_events" gap; break-glass is the lock-out bound of `sso_enforced`. |
| RT34 | Cut OIDC now to bring M11 near 150 h. | Medium | Rejected → kept as the second cut line (RT16) for the parent / user to decide; 200 h is in line with M8 (178 h). |

Seed questions given to the reviewers (kept for traceability):
1. Research open questions 1–4 (sealbox reuse; `Lax` / `Strict` cookie behaviour after the SSO redirect in Chromium, Firefox and Safari; what a compromised API can reach through the proxy; step-up vs automation).
2. Can a login CSRF or session fixation happen in the MFA challenge or the SSO callback (attacker's challenge cookie, attacker's state)?
3. Can an org admin take over an account of another org through SSO: an unverified domain, a domain verified then lost, an IdP that asserts `email_verified=true` for any address, a multi-tenant issuer (Entra `common`)?
4. Does any invitation path reveal whether an email is registered (timing, error codes, the inspect route)?
5. Is the TOTP replay check race-free under two concurrent verifies of the same code; can the per-user limit be used to lock a victim out (DoS), and is that acceptable?
6. Do step-up checks cover every route that reaches the protected state change (for example the TLP downgrade through report finalize, the share policy through case PATCH)?
7. Can an API key reach a non-org route, a step-up action, another org, or survive revocation; can the CSRF exemption be triggered by a browser (ambient `Authorization` is impossible, but check `fetch` with credentials and a header)?
8. Does the outbox leak tokens: in `params`, logs, Mailpit in prod, backups (M7 backups include `email_outbox`)?
9. Does `users.kind` break existing queries that assume every user is a human (members list, audit actor rendering, retention system user, owner counts)?
10. Scope: what is YAGNI for a learning-grade single-node platform (candidates: domain re-verification beat, break-glass, the personal security log, the egress proxy vs documented API egress, API keys altogether)?

## Phases

| Phase | Name | Group | Depends on | Effort | Status |
|-------|------|-------|------------|--------|--------|
| 1 | [Foundation contracts migration and identity services](./phase-01-foundation-contracts-migration-and-identity-services.md) | A | — | 29h | Pending |
| 2 | [Mail outbox worker and Mailpit](./phase-02-mail-outbox-worker-and-mailpit.md) | B (2a, lane 2) | 1 | 10h | Pending |
| 3 | [Invitations email verification and registration modes](./phase-03-invitations-email-verification-and-registration-modes.md) | B (2b, lane 3) | 1 | 14h | Pending |
| 4 | [Account recovery sessions and security events](./phase-04-account-recovery-sessions-and-security-events.md) | B (2c, lane 4) | 1 | 11h | Pending |
| 5 | [TOTP MFA recovery codes login challenge and step-up](./phase-05-totp-mfa-recovery-codes-login-challenge-and-step-up.md) | B (2d, lane 5) | 1 | 19h | Pending |
| 6 | [Org security policy and step-up wiring](./phase-06-org-security-policy-and-step-up-wiring.md) | B (2e, lane 6) | 1 | 13h | Pending |
| 7 | [Egress proxy IdP configuration and domain verification](./phase-07-egress-proxy-idp-configuration-and-domain-verification.md) (cut line 2) | B (2f, lane 7) | 1 | 12h | Pending |
| 8 | [OIDC login flow JIT provisioning and hostile IdP mock](./phase-08-oidc-login-flow-jit-provisioning-and-hostile-idp-mock.md) (cut line 2) | B (2g, lane 8) | 1 | 21h | Pending |
| 9 | [Platform API keys and service accounts](./phase-09-platform-api-keys-and-service-accounts.md) (cut line) | B (2h, lane 9) | 1 | 16h | Pending |
| 10 | [Identity frontend auth flows and account security](./phase-10-identity-frontend-auth-flows-and-account-security.md) | B (2i, web only) | 1 (frozen contracts) | 18h | Pending |
| 11 | [Org identity frontend invitations security SSO and API keys](./phase-11-org-identity-frontend-invitations-security-sso-and-api-keys.md) | B (2j, web only) | 1 (frozen contracts) | 13h | Pending |
| 12 | [Docs threat model and identity runbooks](./phase-12-docs-threat-model-and-identity-runbooks.md) | C | B merged | 8h | Pending |
| 13 | [Hardening e2e and gate](./phase-13-hardening-e2e-and-gate.md) | D | all | 16h | Pending |

Effort: 29 + 10 + 14 + 11 + 19 + 13 + 12 + 21 + 16 + 18 + 13 + 8 + 16 = **200 h** (194 h before the red team: phase 1 +3 h for RT1 / RT4 / RT5 / RT7 / RT9 / RT13 / RT17–RT19, phases 5, 6 and 8 +1 h each for RT2 / RT3 / RT8 / RT10 / RT11 / RT26). Critical path: 1 → max(B) (phase 8, 21 h) → 12 → 13, about 29 + 21 + 8 + 16 = **74 h** of wall time with ten group-B agents, at most three API lanes at once.

**Cut lines** (the parent / user decides; neither is cut by default):
1. **API keys:** dropping phase 9 and the API-keys part of phase 11 saves about 20 h and touches no other phase (its stubs answer 501, its IDOR module stays pending, phase 13 records the cut). RT1 (`OrgContext.permissions`) stays in phase 1 either way.
2. **OIDC SSO (RT16):** dropping phases 7 and 8, the SSO parts of phases 10, 11 and 13 and the `sso_enforced` / break-glass part of phase 6 saves about 41 h and removes the egress proxy, `idp-mock`, domains and DoH from the stack. The phase-1 schema keeps the SSO tables (empty), the SSO routes answer 501, `sso_enforced` is refused by the policy PUT (`409 sso_not_ready`), and the THREAT_MODEL gap "special-use domains revisit with SSO" stays open. Requirement §13 ("Authentication") is met without it.

## Dependencies and parallelism

**Cross-plan:** `blockedBy: [261107-1200-cyberlab-m10-reverse-engineering]` is **ordering only**. M11 touches no analyzer, worker contract or analysis table, so it is file-independent of M8–M10 except for the shared files every milestone edits: the migration chain, `core/config.py`, `app/main.py`, `app/models.py`, compose, `.env.example`, `scripts/lane-test.sh`, `lib/{nav,audit-actions,http-errors}.ts`, `packages/contracts/**`, and the docs. **Recommendation after the red team (RT15): keep M11 after M10.** M8–M10 edit `evidence/uploads.py` and `evidence/share_policy.py`, which M11 phases 9 and 6 also edit, plus the report and investigation files phase 6 wires step-up into. If the parent still runs M11 in parallel with M9 / M10, phases 6 and 9 start only after M10 is merged (the other phases may start earlier), and phase 1 branches from the latest merged head, takes the next free migration number, and the later merge renumbers only the revision id and `down_revision` (no table overlap), re-runs `pnpm gen:contracts`, and resolves the shared-file hunks (additive). Phase 1 confirms the alembic head (expected `0018_*`: M8 0016, M9 0017, M10 0018), the lane range (M9 / M10 add lane 9, RT23) and that the M7–M10 files it edits are final, then creates `feat/m11-identity` from the merge.

**Group A: phase 1, one agent; frozen when committed.** Only the parent changes frozen files afterwards. A change request goes to the parent, which decides and broadcasts it.

**Frozen interfaces** (phase 1 notes record the exact signatures):
1. **Migration `0019_m11_identity.py`** and the models: `identity/models.py` (`UserSession`, `MfaFactor`, `RecoveryCode`, `ActionToken`, `OrgSecurityPolicy`, `OrgDomain`, `SsoDomainIndex`, `OrgIdpConfig`, `UserIdentity`), `invitations/models.py` (`OrgInvitation`, `InvitationIndex`), `mail/models.py` (`EmailOutbox`), `api_keys/models.py` (`ApiKey`), `users/models.py` (`kind`, `email_verified_at`, `password_changed_at`), `auth/models.py` (event types). Later schema needs go into head + 1, assigned by the parent.
2. **Schemas and 501 stubs for every new route**, then one `pnpm gen:contracts` run. The error codes: `mfa_required` (202 body flag on login; 403 on org routes), `mfa_challenge_invalid`, `mfa_code_invalid`, `mfa_locked`, `mfa_required_by_org`, `step_up_required`, `api_key_step_up_forbidden`, `invitation_invalid`, `invitation_email_mismatch`, `invite_domain_not_allowed`, `members_direct_add_removed` (410), `registration_closed`, `token_invalid`, `sso_required`, `sso_not_member`, `sso_link_requires_verified_email`, `sso_unavailable`, `domain_claimed`, `domain_not_verified`, `issuer_invalid`, `invalid_api_key`, `ambiguous_credentials`, `api_keys_disabled`, `api_key_limit_reached`, `mfa_required_for_actor`, `sso_not_ready`, `step_up_via_sso`, `secret_required_for_new_issuer`, and from the red team `sso_session_scope`, `local_reauth_required` (RT2), `email_verification_required` (RT8), `service_account_member` (RT14); the fixed SSO redirect codes `idp_denied`, `sso_state_invalid`, `sso_state_unbound`, `sso_email_not_eligible`, `sso_token_invalid`, `sso_unavailable`, `sso_not_member`, `sso_link_requires_verified_email` (RT22).

   | Method and path (`/api/v1`) | Permission | Phase |
   |---|---|---|
   | `POST /auth/login` → 200 `MeOut` \| 202 `MfaChallengeOut` | public | 5 |
   | `POST /auth/mfa/verify` `{code}` \| `{recovery_code}` → `MeOut` | challenge cookie | 5 |
   | `GET /auth/mfa` · `POST /auth/mfa/totp/setup` · `POST /auth/mfa/totp/confirm` · `DELETE /auth/mfa/totp` · `POST /auth/mfa/recovery-codes` | signed in (+ step-up) | 5 |
   | `POST /auth/step-up` `{code}` \| `{recovery_code}` \| `{password}` → 204 | signed in | 5 |
   | `POST /auth/register` (+ `invitation_token?`) | public | 3 (phase 1 wires the hook) |
   | `POST /auth/email/verify-request` · `POST /auth/email/verify` `{token}` | signed in / signed in as the token's user (RT8) | 3 |
   | `POST /invitations/inspect` · `POST /invitations/accept` | public / signed in | 3 |
   | `GET`, `POST /orgs/{org}/invitations` · `POST /orgs/{org}/invitations/{id}/resend` · `/revoke` | `members.read` / `members.manage` | 3 |
   | `POST /orgs/{org}/members` → 410 | — | 3 |
   | `POST /auth/password/forgot` · `POST /auth/password/reset` · `POST /auth/password/change` | public / public / signed in + step-up | 4 |
   | `GET /auth/sessions` · `DELETE /auth/sessions/{id}` · `POST /auth/sessions/revoke-others` · `GET /auth/events` | signed in | 4 |
   | `GET`, `PUT /orgs/{org}/security-policy` | `org.read` / `security.manage` + step-up | 6 |
   | `GET`, `PUT /orgs/{org}/sso` · `DELETE /orgs/{org}/sso/secret` · `POST /orgs/{org}/sso/refresh-metadata` | `org.read` / `security.manage` + step-up | 7 |
   | `GET`, `POST /orgs/{org}/domains` · `POST /orgs/{org}/domains/{id}/verify` · `DELETE /orgs/{org}/domains/{id}` | `org.read` / `security.manage` (+ step-up on create and delete) | 7 |
   | `POST /auth/sso/start` `{email, next?, purpose?}` · `GET /auth/sso/callback` | public (cookie-bound) | 8 |
   | `GET`, `POST /orgs/{org}/api-keys` · `POST /orgs/{org}/api-keys/{id}/revoke` | `security.manage` (+ step-up on create) | 9 |

3. **Cross-phase entry points** (implemented in phase 1 where marked, else stubs; ownership moves to the named phase, which never changes the signature):
   - `core/stepup.py`: `class StepUpAction(StrEnum)` and `async require_recent_auth(session, principal, *, action) -> None` (**implemented**; the age check in SQL, RT21);
   - `core/rbac.py`: `OrgContext.permissions` and `require(permission, *, policy_exempt=False)` (**implemented**, RT1, RT13); every service reads `ctx.permissions`, never `ROLE_PERMISSIONS[ctx.role]`;
   - `core/security.verify_password`: the dummy hash also for unusable stored hashes (**implemented**, RT5);
   - `core/deps.py`: `CurrentUser` gains `session_id`, `amr: frozenset[str]`, `sso_org_id`, `kind: Literal["session", "api_key"]`; `PrincipalDep` (session or API key) used by `require()`; `CurrentUserDep` stays session-only (**implemented**, API-key branch calls the phase-9 stub);
   - `identity/sessions_store.py`: `create(session, user_id, *, method, amr, sso_org_id, request) -> UUID`, `touch`, `revoke(family_id, reason)`, `revoke_all(user_id, *, reason, keep=None)` (RT17), `mark_step_up`, `add_amr` (**implemented**; `auth/sessions.py` uses it);
   - `identity/policy.py`: `async check_org_access(session, org_id, principal) -> None` (stub: no-op; phase 6), called by `core/rbac.org_session` after the membership check;
   - `identity/seal.py` (`IDENTITY_DOMAIN`), `identity/unseal.py` (`open_identity_secret`) and `mail/seal.py` (`MAIL_DOMAIN`, seal only) (**implemented**, with the import-guard update);
   - `identity/egress.py`: `egress_client(*, timeout_s) -> httpx.AsyncClient` (**implemented**);
   - `identity/discovery.py`: `async refresh_jwks_if_unknown_kid(session, config, kid) -> bool` (stub returning false; phase 7), called by phase 8 (RT17);
   - `mail/outbox.py`: `enqueue(session, *, template, to, params, secret=None, user_id=None, org_id=None) -> UUID` and `publish_after_commit(outbox_id)` (**implemented**); `mail/templates.py`: `MailTemplate` and per-template param models (**implemented**; rendering is phase 2);
   - `invitations/service.py`: `async register_with_invitation(session, data, user_id, request) -> uuid.UUID` (stub raising 501; phase 3), called by `auth/service.register`;
   - `api_keys/auth.py`: `parse_bearer(value) -> ParsedKey | None` (**implemented**: format only) and `async resolve(session, org_id, parsed) -> ResolvedKey` (stub raising `invalid_api_key`; phase 9);
   - `core/logging.py`: the access-log filter redacting the SSO callback query and dropping `Authorization` (**implemented**).
4. **Settings** (`core/config.py`, all added by phase 1, with the role refusals):
   - `REGISTRATION_MODE`, `INVITATION_TTL_DAYS`, `ACTION_TOKEN_TTL_*` (no bootstrap setting: RT12);
   - `MAIL_TRANSPORT`, `MAIL_FROM`, `SMTP_HOST/PORT/USERNAME/PASSWORD_FILE/TLS`, `MAIL_SEAL_PUBLIC_KEYS`, `MAIL_SEAL_ACTIVE_KID`, `MAIL_SEAL_PRIVATE_KEYS_FILE` (role `mail` only); `PROCESS_ROLE=mail` requires the `cyberlab_mail` DB user and every other role refuses it (RT9);
   - `IDENTITY_SEAL_PUBLIC_KEYS`, `IDENTITY_SEAL_ACTIVE_KID`, `IDENTITY_SEAL_PRIVATE_KEYS_FILE` (role `api` only);
   - `STEP_UP_MAX_AGE_S`, `MFA_*` limits, `SSO_SESSION_MAX_AGE_H`, `SSO_STATE_TTL_S`, `IDENTITY_EGRESS_PROXY_URL`, `IDENTITY_DOH_URL`, `IDENTITY_ALLOW_PRIVATE_ISSUER_HOSTS` and `IDENTITY_EXTRA_CA_FILE` (dev/test only, RT24);
   - `EGRESS_PROXY_*` caps (role `egress_proxy` only; it refuses every secret);
   - `API_KEYS_MAX_PER_ORG`, `API_KEY_MAX_DAYS`;
   - `PROCESS_ROLE` gains `mail` and `egress_proxy` with their refusals; prod refuses the committed dev seal keys of both new domains, `MAIL_TRANSPORT=capture` and a missing `PUBLIC_BASE_URL`.
5. **Services** (compose; dev, test and prod):
   - networks `mail` (internal) and `idp` (internal); the api joins `idp`; `api-test` joins `mail` (test profile only, RT24);
   - the DB role `cyberlab_mail` in `infra/postgres/bootstrap.sh` (+ `POSTGRES_MAIL_PASSWORD`), grants in the migration (RT9);
   - `mail-worker` and `mail-worker-test` (test profile, own broker prefix), the broker ACL user `mail`, the beat entry `mail.sweep` (60 s; no other new beat task: domain re-checks are an operator script and key expiry is enforced at authentication time);
   - `mailpit` (dev) and `mailpit-test` (test profile; REST on `127.0.0.1` in the e2e profile only) on `mail`, pinned by phase 2;
   - `egress-proxy` (dev, prod) and `egress-proxy-test` (test profile) on `idp` + `egress`;
   - `idp-mock` (test and e2e profiles; api image running `infra/idp-mock/server.py`, on `egress` like `ti-mock`), with its signing keys generated at start (never committed);
   - committed dev seal key pairs `infra/identity/dev-seal-{public,private}.json` (kid `dev-id-1`) and `infra/mail/dev-seal-*.json` (kid `dev-mail-1`); prod refuses both;
   - `scripts/lane-test.sh`: lane 9 (`cyberlab_b9_test`, Redis and broker db 9) already exists after M9 / M10 (confirm; add only if missing, RT23); add `--service mail-worker-test` and `egress-proxy-test`.
6. **Root scripts:** `package.json` `identity:admin` → `apps/api/app/scripts/identity_admin.py` (dispatcher with the subcommands `bootstrap-owner` (phase 3, `invitations/admin_bootstrap.py`, RT12), `reset-mfa` (phase 5, `identity/admin_mfa.py`), `approve-domain` and `recheck-domains` (phase 7, `identity/admin_domains.py`), stubs exiting 2).
7. **Test helpers** `tests/identity_helpers.py`: users with a known TOTP secret, sessions with chosen `amr` / `step_up_at`, invitations, IdP configs with a verified domain, service accounts and keys, outbox readers, a Mailpit REST client; `tests/factories.py` gains `add_membership()` (replacing the direct-add route in every existing test).
8. **IDOR modules:** `tests/security/idor_cases_invitations.py` (phase 3), `idor_cases_identity.py` (phases 6 and 7; two sections), `idor_cases_api_keys.py` (phase 9), merged by `test_idor_routes.py`, each with `PENDING_ROUTES` filled by phase 1; phase 13 asserts they are empty. The enumerator also runs each org route **with an API key of another org** (phase 9 adds the principal kind).
9. **Web shared:**
   - `lib/api.ts`: the `step_up_required` interception (emit `STEP_UP_EVENT`, await the dialog's promise, retry once) and 202 pass-through for login;
   - `lib/nav.ts` (`SETTINGS_TABS` + Security, API keys with `security.manage`; the account link), `lib/roles.ts` (`security.manage`), `lib/audit-actions.ts`, `lib/http-errors.ts`;
   - slot components mounted once: `components/step-up/step-up-dialog.tsx` (app shell), `components/shell/account-link.tsx` (header), `components/members/invitations-card.tsx` (members page); `components/members/add-member-dialog.tsx` is removed and its mount replaced by `components/members/invite-dialog.tsx` (slot);
   - empty route shells: `app/(app)/account/{page,security/page}.tsx`, `app/(auth)/{invite,forgot-password,reset-password,verify-email,sso/complete}/page.tsx`, `app/(app)/o/[orgId]/settings/{security,api-keys}/page.tsx`.
10. **Frozen test files:** `tests/conftest.py`, `test_rls_coverage.py` (the new tenant tables), `test_append_only.py`, `test_tenant_session_guard.py` (new entries `modules/invitations/service.py`: org from `invitation_index`; `modules/identity/sso/flow.py`: org from the server-side SSO state set from `sso_domain_index`; the operator scripts `invitations/admin_bootstrap.py` (the org it creates) and `identity/admin_domains.py` (org from the CLI or the verified-domain list); all in `PENDING_ALLOWED`), the new `test_permission_reads.py` guard (no `ROLE_PERMISSIONS[` outside `core/rbac.py`, RT1), the import guards (`identity/unseal.py` allowed; `mail` role refuses the identity key; `mail/seal.py` never opens).

**Group B: phases 2–11, in parallel** (one subagent each, own worktree from the phase-1 commit, file-disjoint). Each phase's tests pass in isolation against the phase-1 stubs, helpers and frozen schemas. Cross-phase behaviour is tested after the merge (phase 13). Lanes run only their own test files plus `ruff` / `mypy` (API) or `pnpm --filter web lint typecheck test` on their own files (web). Nobody runs `pnpm verify` or the full suite in a lane.

| Phase | Owns (creates or edits; nobody else touches these in group B) |
|---|---|
| 2 (2a) | `app/modules/mail/{render,transport,worker}.py`, `app/workers/{mail_app,mail_tasks}.py`, the Mailpit pins in compose (the `image:` lines of `mailpit` / `mailpit-test` only), `tests/unit/test_mail_{render,transport_guard}.py`, `tests/integration/test_mail_{outbox_worker,mailpit_delivery}.py` |
| 3 (2b) | `app/modules/invitations/**` (after the stubs, incl. `admin_bootstrap.py`), `organizations/{members,router,repository}.py` (`count_owners`, RT14), `identity/{email_verify,router_email}.py`, `tests/security/idor_cases_invitations.py`, `tests/integration/test_invitations_{create,accept,register,enumeration}.py`, `test_email_verify.py`, `test_registration_mode.py`, `tests/integration/test_members_hardening.py` (updated for invitations) |
| 4 (2c) | `identity/{recovery,sessions_api,events_api,ua}.py`, `identity/router_{recovery,sessions}.py`, `tests/integration/test_password_{reset,change}.py`, `test_sessions_api.py`, `test_security_events.py`, `tests/unit/test_ua_parse.py` |
| 5 (2d) | `identity/{totp,mfa,challenge,stepup_api,admin_mfa}.py`, `identity/router_mfa.py`, `auth/service.py` (login), `tests/unit/test_totp.py`, `tests/integration/test_mfa_{enroll,login,replay,throttle,recovery,disable}.py`, `test_step_up.py`, `test_identity_admin_mfa.py` |
| 6 (2e) | `identity/{policy,router_policy}.py`, and the step-up calls (one guarded line each, plus the import) in `threat_intel/service_integrations.py`, `ai/service_providers.py`, `investigations/service.py`, `reports/service.py`, `evidence/share_policy.py`, `retention/{policy,service,holds}.py`; `tests/security/idor_cases_identity.py` (policy section), `tests/integration/test_security_policy.py`, `test_org_mfa_enforcement.py`, `test_sso_enforcement.py`, `test_step_up_wiring.py` |
| 7 (2f) | `app/egress_proxy/**`, `identity/{domains,idp_config,discovery,dns,admin_domains,router_sso_admin}.py`, `tests/security/idor_cases_identity.py` (SSO-admin section, a separate list in the same module created by phase 1), `tests/unit/test_egress_proxy.py`, `tests/integration/test_egress_proxy_tunnel.py`, `test_idp_config.py`, `test_domains.py` |
| 8 (2g) | `identity/sso/**` (`flow`, `state`, `id_token`, `jit`), `identity/router_sso.py`, `infra/idp-mock/**`, `tests/integration/test_sso_{login,hostile_idp,jit,link,state,step_up}.py`, `tests/unit/test_id_token.py` |
| 9 (2h) | `app/modules/api_keys/**` (after the stubs), `core/csrf.py` (the bearer rule; phase 1 made the exempt-list change), `evidence/{router,transfer,uploads}.py` (principal on the transfer and upload routes, RT15), `tests/security/idor_cases_api_keys.py`, `tests/integration/test_api_keys_{lifecycle,auth,scopes,csrf,evidence}.py`, `tests/unit/test_api_key_format.py`, `test_log_redaction.py` |
| 10 (2i) | `components/auth/**`, `app/(auth)/**`, `components/step-up/**` (after the slot), `components/account/**`, `app/(app)/account/**`, `components/shell/account-link.tsx` (slot), `lib/{identity,mfa,sessions}.ts` (+ tests) |
| 11 (2j) | `components/members/**` (except the removed dialog), the members settings page, `components/{invitations,org-security,sso,api-keys}/**`, `app/(app)/o/[orgId]/settings/{security,api-keys}/**`, `lib/{invitations,org-security,sso-admin,api-keys}.ts` (+ tests) |

- **Shared files touched only by phase 1:** `core/{config,security,deps,rbac,cookies,stepup,logging}.py`, the `EXEMPT_PATHS` line of `core/csrf.py` (RT4), the six `ROLE_PERMISSIONS[ctx.role]` reads and four `_tlp_rule` arguments (RT1: `ai/service_runs.py`, `evidence/share_policy.py`, `investigations/service.py`, `ioc_collections/export.py`, `notes/service.py`, `reports/service.py`), `infra/postgres/bootstrap.sh` (RT9), `app/main.py`, `app/models.py`, `auth/{models,schemas,router,sessions}.py`, `users/models.py`, `workers/{celery_app,tasks}.py`, compose files, `.env.example`, `package.json`, `infra/redis-broker/entrypoint.sh`, `infra/{identity,mail}/dev-seal-*.json`, `packages/contracts/**` (generated after phase 1, then after the group-B merge), `scripts/lane-test.sh`, `apps/web/lib/{api,nav,roles,audit-actions,http-errors}.ts`, the slot mounts and route shells, the frozen test files, and phase 1's own `tests/integration/test_step_up_core.py` and `tests/unit/test_access_log_filter.py`.
- **Group B merge (parent):**
  1. Merge the ten worktrees. Any conflict is a plan bug.
  2. Run the full API suite on the main stack.
  3. Run `pnpm gen:contracts` and check for no drift.
  4. Run `pnpm --filter web test typecheck`.
  5. Run the SSO login once end to end through `egress-proxy-test` → `idp-mock` (the lanes run phase 8 direct, phase 7 alone).
  6. Fix seams in the owning files, one commit per phase.
- **Group C: phase 12** (docs) after the merge.
- **Group D: phase 13 last.** It is the only phase allowed to touch other phases' files, and only for gate fixes.
- **One commit per phase.** The stack stays deployable after each: new routes answer 501 until their phase lands; login behaves as today until phase 5 (no factor can be enrolled); `check_org_access` is a no-op until phase 6; API keys are refused (`invalid_api_key`) until phase 9; `POST /members` keeps working until phase 3 replaces it in the same commit as invitations.

### Parallel execution on this host (the M5–M7 lane scheme, `scripts/lane-test.sh`; 4–8 GB free)

1. **One shared infra stack**, started by the parent after phase 1: `postgres`, `redis`, `redis-broker`, `minio` (+ init, `db-bootstrap`), `mailpit-test`. Everything else is stopped during group B (web, gateway, analyzers, enrich, analyst, report, retention, mail and egress workers).
2. **Worktrees** `..\cyber-wt\m11-b{n}` (`-b m11/b{n}` from the phase-1 commit), with `.env` copied in.
3. **API lanes:** phase n → lane n for n = 2..9 (lane 9 exists after M9 / M10; RT23).
   - Run with `scripts/lane-test.sh <lane> uv run pytest -q -p no:cacheprovider <own paths>`; the conftest migrates the lane DB to 0019.
   - Phase 2 also runs `--service mail-worker-test`; phase 7 runs `--service egress-proxy-test` for the tunnel test; phase 8 needs `idp-mock` (test profile, about 120 MB) started once by the parent before the lanes and left up.
   - At most three lane containers at once (`LANE_SLOTS=3`). Lanes never `up`, `down`, `build`, `restart` or `stop`.
4. **Heavy steps (the parent runs each alone):** the api image rebuild after phase 1 (new dependencies: `authlib`; test-only `pyotp`); the e2e in phase 13.
5. **Web lanes (phases 10, 11):** host `pnpm --filter web test -- <own paths>`, `typecheck`, `lint` against the phase-1 contracts and mocked fetch. No containers and no lane slot.
6. **Fallback** when worktrees misbehave on Windows: the M5 fallback (main tree, lane variables in the shell, `python -m compileall` before each run).

## Definition of done

- **Invitations:** an admin invites by email; the invitee receives a Mailpit message (dev) and joins through the link, signed in as that email or by registering with it; the token is single-use, expires, dies on resend and revoke, and never appears in a log, URL path or query; the create answer is identical for registered and unknown emails; direct add answers 410; `invite_only` refuses an uninvited registration and a fresh install gets its first owner only through `identity:admin bootstrap-owner` (RT12).
- **Mail:** every mail goes through `email_outbox`; the mail worker connects as `cyberlab_mail` and can read nothing but the outbox (RT9); the sealed token is NULL after sending; retries and the sweep work; no test sends mail outside `capture` or `mailpit-test` (guard test); prod refuses `capture`.
- **MFA:** enrollment (verified email, non-SSO session: RT8, RT2), login challenge, recovery codes and disable work; a code is accepted at most once (concurrent test); the per-challenge, per-user and 100-failure limits hold; secrets are sealed at rest and the identity private key exists only in the api role; operator reset works and is audited and mailed.
- **Step-up:** every action of `StepUpAction` refuses without a recent re-auth and passes after one, including the TLP downgrade through every route that can lower it; API keys can never pass; SSO step-up fails when the ID token's `auth_time` is stale (RT3).
- **Org policy:** `require_mfa` blocks password-only sessions of that org (and only that org) with `mfa_required`; `sso_enforced` blocks non-SSO sessions except owners with `otp` (audited).
- **SSO (unless cut, RT16):** an `idp-mock` user signs in, is JIT-provisioned only from a verified domain with `email_verified` (and a matching `hd` when present), keyed by (config, `iss`, `sub`); an SSO session of a user with a password reaches only its org and cannot change local account security (RT2); every hostile mode is refused (alg `none` / HS256, wrong `iss` / `aud` / `azp` / nonce, expired, replayed or unbound state, mix-up `iss`, unverified email, foreign domain, unknown `kid` after one refetch); the callback query is absent from logs; the API has no route to the internet except through `egress-proxy`, which refuses non-443 ports and non-global addresses.
- **Sessions and recovery:** pre-M11 sessions survive the deploy through the backfill (RT7); a user lists and revokes sessions (the revoked one's access token dies at once); password reset revokes every session and keeps MFA; the forgot and login routes answer identically, in status and timing class, for every account state (RT5, RT6).
- **API keys (unless cut):** a key works on its org's allowed routes only, never on another org, a non-org route or a step-up action, and every in-service permission check sees role ∩ scopes (RT1); revocation and expiry are immediate; CSRF is skipped only for cookie-less bearer requests; the key never appears in logs, in browser storage or in the React Query cache.
- **Security:** every new org route is in the IDOR enumerator (plus the foreign-API-key pass); every new tenant table is in RLS coverage; the tenant-session guard lists the two new vetted sites; the env checks prove the mail worker and egress proxy hold only their own secrets (`scripts/check-identity-env.mjs`).
- **Gate:** `pnpm verify:prod` is green; the e2e covers invite → accept, MFA enroll → login with a code, a step-up prompt on a provider key change, SSO login through `idp-mock`, session revoke, and an API key used from the e2e runner.
- **Docs:** ARCHITECTURE (identity section), API (auth, errors, new routes, bearer keys), DATABASE (tables, the §11 `api_keys` mapping), DEPLOYMENT (SMTP relay, Mailpit dev only, seal keys, egress proxy, IdP setup, `REGISTRATION_MODE`, runbooks), THREAT_MODEL (M11 section, M1 gaps closed or narrowed), TESTING, ROADMAP, PRD and README updated.

## Out of scope

- **WebAuthn / passkeys** (M11.1; py_webauthn evaluated), SMS or email OTP as a second factor, "remember this device".
- **SAML**, **SCIM** provisioning and deprovisioning, multiple IdPs per org, IdP-initiated login, group-to-role mapping, Entra multi-tenant (`common`) issuers.
- **Org-admin MFA reset or impersonation**, account deletion and GDPR export, email address change (needs a double-confirmation flow; recorded for later).
- **OAuth for third parties** (CyberLab as an authorization server), personal (user-bound) API keys, key IP allowlists, mTLS clients.
- **Retention of identity tables** (`email_outbox`, `user_action_tokens`, `auth_events`): the M7 retention worker is not extended in M11.
- **A real SMTP relay test** (prod relay is configured by the operator; only Mailpit is exercised), DKIM / SPF / DMARC (the relay's job, documented).

## Open risks

- **Lock-out:** `require_mfa`, `sso_enforced` or a broken IdP can lock an org out. Bounded by owner break-glass with `otp`, the step-up on policy changes, the policy refusing `sso_enforced` until one SSO login of the acting owner succeeded, and the operator script; documented.
- **IdP trust:** a misconfigured or hostile IdP that asserts `email_verified` for any address can provision users only inside its own org and only for its verified domains; it cannot link an account of another org's domain. A domain that changes hands keeps working until the next operator re-check (weekly cron).
- **Cookie behaviour across browsers** after the SSO redirect (`Lax` state, `Strict` session): covered by the Playwright Chromium e2e only; Firefox / Safari are a manual check recorded in phase 13.
- **API compromise** reads every TOTP secret and the IdP client secrets (they are opened in the API by design); recorded, KMS / HSM later. The proxy limits what such a compromise reaches to public hosts on 443 (RT28, RT29).
- **Org-controlled IdPs** can sign in as any member of their org who holds an identity there (that is what SSO means); RT2 confines such sessions to that org for users with a local password, but an SSO-provisioned user (no password) depends entirely on that IdP in every org that invited them. Documented.
- **Multi-org users with SSO** need one sign-in per org scope (an SSO session of org S does not reach their password-only orgs, RT2): product friction accepted; the org switcher explains it.
- **Mail deliverability and at-least-once delivery:** a crash between SMTP success and the status update re-sends one mail; invitations still accept once (the token is single-use).
- **DoS on the MFA limiter:** an attacker knowing a password can burn a victim's per-user MFA attempts; the victim still has recovery codes and the window is 15 min; the 100-failure lock needs the password first.
- **Contract drift:** the frontend builds against stubs. Any schema change after phase 1 is a parent broadcast, and the merge checks for drift.
