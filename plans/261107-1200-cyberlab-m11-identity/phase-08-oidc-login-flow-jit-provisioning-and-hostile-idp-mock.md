---
phase: 8
title: "OIDC login flow JIT provisioning and hostile IdP mock"
status: pending
priority: P2
effort: "21h"
dependencies: [1]
---

# Phase 8: OIDC login flow, JIT provisioning and the hostile IdP mock (group B, 2g, lane 8; OIDC cut line 2, RT16)

## Overview
The SSO login itself: home realm discovery, the authorization code flow with PKCE, a strict ID-token validator, account resolution by (`iss`, `sub`), guarded JIT provisioning and linking, SSO sessions, SSO step-up, and an in-house `idp-mock` with hostile modes for the tests. Design: plan.md "SSO" and research §2, §4.7.

**Owns:** `identity/sso/**` (`flow.py`, `state.py`, `id_token.py`, `jit.py`), `identity/router_sso.py`, `infra/idp-mock/**`, `tests/integration/test_sso_{login,hostile_idp,jit,link,state,step_up}.py`, `tests/unit/test_id_token.py`.

## Requirements
- **`idp-mock`** (`infra/idp-mock/server.py`, run with the api image's Python: PyJWT + cryptography available; test and e2e profiles; TLS with a CA generated at start into a shared tmpfs volume that only test clients trust):
  - endpoints: discovery, JWKS (an RSA-2048 and a P-256 key generated at start; rotation endpoint for tests), `/authorize` (auto-approves the configured test user, honours `prompt`, `max_age`, echoes `state`, adds `iss` to the redirect), `/token` (checks client auth and the PKCE verifier), `/dns-query` (a fake DoH for phase 7), a control endpoint `/_mode` (test-only, token-protected) selecting the next response's mode;
  - **hostile modes:** `alg_none`, `hs256_with_client_secret`, `wrong_iss`, `wrong_aud`, `aud_list_without_client`, `azp_mismatch`, `bad_nonce`, `expired`, `iat_future`, `unknown_kid`, `kid_rotated` (valid after one JWKS refetch), `missing_sub`, `email_unverified`, `email_other_domain`, `mixup_iss` (redirect `iss` of another issuer), `oversized_token`, `slow_token` (exceeds the timeout), `error_redirect` (`error=access_denied` with hostile `error_description`), `stale_auth_time` (ignores `prompt=login` / `max_age=0` and returns an old `auth_time`, RT3), `missing_auth_time`, `hd_mismatch` and `missing_hd` (RT10);
  - its CA reaches the api only through `IDENTITY_EXTRA_CA_FILE` (test / e2e profiles; refused when `ENV=prod`, RT24);
  - never part of the prod compose; refuses to start when `ENV=prod`.
- **Start** (`POST /auth/sso/start {email, next?, purpose?: login|step_up}`): public, 20 / min per IP; the email domain → `sso_domain_index` (enabled) → else `200 {redirect_url: null}` (password login; this reveals that a domain has no SSO on this platform, accepted); load the IdP config in the org's tenant session (vetted guard entry: org from the server-side index); build state: `state`, `nonce`, PKCE verifier (all `token_urlsafe(32)`), store in Redis `sso:state:<sha256(state)>` = `{org, idp_config_id, config_version, nonce, verifier, purpose, next (safe_next-validated), session_id for step_up}` with `SSO_STATE_TTL_S` (600); set `cl_sso` = a random binder whose sha256 is stored in the state; return the authorization URL (`response_type=code`, `scope=openid email profile`, `code_challenge_method=S256`, `prompt=login` + `max_age=0` for step-up, `login_hint=email`).
- **Callback** (`GET /auth/sso/callback`):
  - `error` → redirect `/login#sso_error=idp_denied` (fixed code; `error_description` never echoed);
  - `GETDEL` the state; missing → `sso_state_invalid`; the `cl_sso` binder must match (else `sso_state_unbound`); clear `cl_sso`;
  - if `iss` is present it must equal the config issuer (RFC 9207); absent → allowed only if the discovery document does not advertise `authorization_response_iss_parameter_supported`;
  - the config's `config_version` must equal the state's (a config change mid-flow fails);
  - token exchange through `egress_client()` with authlib's `AsyncOAuth2Client` (code, redirect URI exact, verifier, `client_secret_basic|post` from the unsealed secret), 10 s, response ≤ 64 KiB;
  - **ID token** (`id_token.py`, PyJWT): header `alg` ∈ {RS256, PS256, ES256} (anything else, including `none` and every HS*, refused before key lookup); `kid` required and present in the cached JWKS, else one `refresh_jwks_if_unknown_kid` then refuse; `iss` exact; `aud` contains `client_id` and, if multiple audiences, `azp == client_id`; `exp`, `iat` (≤ now + 60 s), leeway 60 s; `nonce` equals the state's (constant-time); `sub` non-empty ≤ 255; token ≤ 16 KiB; `hd`, when present, equals the email's domain, and for issuer `https://accounts.google.com` it is required (RT10); for `purpose=step_up`, `auth_time` is required and ≥ the state's creation time − 60 s (OIDC Core §3.1.2.1, RT3);
  - every failure → redirect `/login#sso_error=<fixed code>`, auth event `sso_failure` with the code only.
- **Account resolution** (`jit.py`), in the org's tenant session (the same vetted entry):
  1. `user_identities` by (`idp_config_id`, the config's current `issuer`, `sub`) → the user (must be active and `kind='human'`) (RT11);
  2. else, if `jit_enabled` is false and no identity → is there an existing member with that email whose email is verified? → link (below); else `sso_not_member`;
  3. email rules for 2 and 4: `email_verified` must be `true` (boolean, not the string) and the email domain must be a **verified domain of this org** (`sso_domain_index` org match), else `sso_email_not_eligible`;
  4. existing local user with that email: link only if the user is **already a member of this org** (else `sso_not_member`, whatever `jit_enabled` says: JIT creates new users only, RT2) and `users.email_verified_at` is set (else `sso_link_requires_verified_email`; both redirect codes, RT22); linking inserts `user_identities` (with `issuer`), audit `org.sso_identity_linked`, auth event `sso_linked`, mail `sso_account_linked`;
  5. no user: create (`kind='human'`, hash `!sso`, `email_verified_at=now()`, display name from `name` sanitized with `SafeName` rules, fallback the local part), identity row, membership with `jit_default_role` if JIT is on; audit `member.added {via: sso_jit}`;
  6. a user found through step 1 who is no longer a member: JIT on → add the membership (default role); JIT off → `sso_not_member`.
  Domain checks are exact matches (RT27).
- **Session:** `start_session(method=sso, amr=["sso"], sso_org_id=org)` (12 h cap; for a user with a usable password it reaches only this org and cannot change local account security, enforced by phases 5 and 6, RT2), `user_identities.last_login_at`, auth event `sso_login`; respond `303` to `/sso/complete#next=<safe next>` with the session cookies, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`.
- **SSO step-up:** `purpose=step_up` requires a session principal whose `sso_org_id` is the org; the authorization request sends `prompt=login` and `max_age=0`; the ID token must carry a fresh `auth_time` (above, RT3); on success `mark_step_up(state.session_id)` only if the resolved user is the session's user; redirect back to `next`.
- **Tests:** the happy path end to end (start → mock authorize → callback → `/auth/me`), cookies and headers on the callback, the access-log redaction (with the phase-1 filter), every hostile mode refused with its fixed code and no session, state replay, an unbound state (another browser's cookie), a config change mid-flow, JIT only for verified-domain verified emails, never admin / owner, link refused for an unverified local account and allowed for a verified one (with the mail), an identity of org A never signs into org B's IdP (same `sub`, different config), a deactivated user refused, step-up via SSO (and refused with `stale_auth_time` / `missing_auth_time`, RT3); `hd_mismatch` / `missing_hd` for the Google issuer refused (RT10); a local verified account that is not a member is never linked, even with JIT on (RT2); after an issuer change the old `sub` does not sign in (RT11); unit tests of the ID-token validator with crafted tokens (including an HS256 token signed with the client secret and a token with `alg` in lowercase).

## Implementation Steps
1. `idp-mock` with the happy path, then the hostile modes.
2. `state.py` and `start`; tests.
3. `id_token.py` with unit tests.
4. Callback, `jit.py`, sessions; integration tests (lane 8 talks to `idp-mock` directly; the tunnel run is the parent's merge step 5).
5. SSO step-up; tests.

## Success Criteria
- [ ] An `idp-mock` user signs in through the full code + PKCE flow and gets an SSO session of 12 h at most.
- [ ] Every hostile IdP mode, state replay or unbound state, and mix-up `iss` is refused with a fixed code and no session or user created.
- [ ] Users are keyed by (`iss`, `sub`); JIT and linking happen only for `email_verified` addresses of the org's verified domains, never above `analyst`, and never onto an unverified local account.
- [ ] SSO step-up marks only the initiating session.

## Risk Assessment
- **Real IdPs differ from the mock** (claims, `iss` parameter support, `amr` values): the optional interop procedure against Dex or Keycloak (phase 12 documents, phase 13 records run or not run).
- **Cookie behaviour after the cross-site redirect:** Chromium e2e in phase 13; other browsers manual.
- **authlib API drift:** pinned version; only `AsyncOAuth2Client.fetch_token` and PKCE helpers are used.
