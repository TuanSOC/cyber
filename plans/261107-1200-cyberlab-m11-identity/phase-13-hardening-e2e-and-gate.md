---
phase: 13
title: "Hardening e2e and gate"
status: pending
priority: P2
effort: "16h"
dependencies: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
---

# Phase 13: Hardening, e2e and the gate (group D, last)

## Overview
Prove the merged milestone end to end, close the cross-phase seams, and pass `pnpm verify:prod`. The only phase allowed to touch other phases' files, and only for gate fixes (one commit per fix, naming the owning phase).

**Owns:** `apps/web/e2e/identity*.spec.ts`, the e2e seed additions, `scripts/check-identity-env.mjs`, `tests/integration/test_identity_cross_phase.py`, gate fixes.

## Requirements
- **Cross-phase integration** (`test_identity_cross_phase.py`):
  - password reset of an enrolled user → the next login still asks for TOTP (phases 4 + 5);
  - an org with `require_mfa`: a password session gets `mfa_required`, enrolls, and the same session passes (phases 5 + 6);
  - an SSO session satisfies `sso_enforced` of its org and not of another org; SSO step-up passes a wired action (phases 6 + 8);
  - an invitation accepted by an SSO-provisioned user; JIT off requires the invitation (phases 3 + 8);
  - an API key on every step-up-wired route → `api_key_step_up_forbidden`; a key when the policy disables keys → `api_keys_disabled`; a narrowly scoped key fails every in-service check RT1 rewrote (phases 1, 6 + 9);
  - an SSO session of org A reaches org B only for an `!sso` user, never for a password user, and cannot enroll TOTP or revoke other sessions (phases 5, 6 + 8, RT2);
  - login and forgot for unknown, SSO-only, service and system accounts run the same code path (hasher calls, background job), RT5 / RT6;
  - every mail template actually sent through `mail-worker-test` to `mailpit-test` once (phases 2–9);
  - the SSO login through `egress-proxy-test` → `idp-mock` (phases 7 + 8).
- **Assertions on the scaffolding:** every `PENDING_ROUTES` of the three IDOR modules and `PENDING_ALLOWED` of the tenant-session guard are empty; the foreign-API-key enumerator pass is on; RLS coverage includes every new tenant table.
- **Env checks** (`scripts/check-identity-env.mjs`, wired into `verify`): runtime services only (the test profile excluded, as M7 RT27): only `api` holds `IDENTITY_SEAL_PRIVATE_KEYS_FILE`; `mail-worker`'s `DATABASE_URL` user is `cyberlab_mail` (RT9); `IDENTITY_EXTRA_CA_FILE` and `IDENTITY_ALLOW_PRIVATE_ISSUER_HOSTS` are absent from prod (RT24); only `mail-worker` holds `MAIL_SEAL_PRIVATE_KEYS_FILE` and SMTP credentials; `egress-proxy` holds no secret and no DB, Redis, broker or MinIO URL; the api is on no network with egress except through `idp`; `idp-mock` and Mailpit are absent from the prod compose.
- **e2e** (Playwright, Chromium, e2e profile with Mailpit and `idp-mock`):
  1. an owner invites a new email → the test reads the link from Mailpit's REST API → registers through it → lands in the org;
  2. the new user enrolls TOTP (the test computes codes from the secret shown) → logs out → logs in with a code;
  3. the owner changes a TI provider key → the step-up dialog appears → code → saved;
  4. SSO (unless cut, RT16): the owner configures the IdP (mock) and approves the domain with the operator script in the seed → a mock user signs in via SSO (JIT, viewer) → sees the org;
  5. sessions page: revoke the other session → that browser context is signed out on its next request;
  6. API key: create → the e2e runner calls a read route with `Authorization: Bearer` → revoke → 401.
- **Manual checks recorded** in the phase notes: Firefox and Safari SSO cookie behaviour (or "not run"), the optional interop check against Dex or Keycloak (or "not run"), the CSP with the QR library on the account page.
- **Gate:** `pnpm verify:prod` green; the full API suite, web tests, typecheck, lint, contracts drift, the e2e.

## Implementation Steps
1. Cross-phase tests; fix seams in the owning files.
2. Scaffolding assertions; env checks.
3. e2e specs and seed; run the e2e alone (heavy).
4. Manual checks; `pnpm verify:prod`; phase notes and plan status.

## Success Criteria
- [ ] Every cross-phase scenario passes; the scaffolding lists are empty.
- [ ] The env checks prove the secret placement and network isolation.
- [ ] The six e2e scenarios pass in the gate.
- [ ] `pnpm verify:prod` is green; manual checks are recorded as run or not run.

## Risk Assessment
- **Cut lines:** if phase 9 or OIDC (phases 7, 8) was cut, the matching scenarios, env checks and IDOR modules are recorded as cut, not failed.
- **e2e flakiness** around mail polling and TOTP step boundaries: poll Mailpit with a deadline; compute codes right after a step boundary when fewer than 5 s remain.
- **Memory on the host:** the e2e adds Mailpit (~30 MB), `idp-mock` (~120 MB), the mail worker and the proxy (~150 MB each); run it with only the infra stack, alone.
