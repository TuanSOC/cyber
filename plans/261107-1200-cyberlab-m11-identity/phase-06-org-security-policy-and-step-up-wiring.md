---
phase: 6
title: "Org security policy and step-up wiring"
status: pending
priority: P2
effort: "13h"
dependencies: [1]
---

# Phase 6: Org security policy and step-up wiring (group B, 2e, lane 6)

## Overview
Two things that sit on top of the phase-1 core: the per-org security policy (require MFA, enforce SSO, owner break-glass, API keys on/off, invitation domain allowlist) enforced on every org request by `check_org_access`, and the step-up calls in the M4–M7 services that change protected state. Design: plan.md "Step-up" and "SSO / Enforcement".

**Owns:** `identity/{policy,router_policy}.py`; the step-up call sites (one guarded call plus the import each) in `threat_intel/service_integrations.py`, `ai/service_providers.py`, `investigations/service.py`, `reports/service.py`, `evidence/share_policy.py`, `retention/{policy,service,holds}.py`; `tests/security/idor_cases_identity.py` (policy section); `tests/integration/test_security_policy.py`, `test_org_mfa_enforcement.py`, `test_sso_enforcement.py`, `test_step_up_wiring.py`.

## Requirements
- **Policy routes:** `GET /orgs/{org}/security-policy` (`org.read`; absent row → defaults); `PUT` (`security.manage`, step-up `security_policy_update`): `require_mfa`, `sso_enforced`, `owners_break_glass`, `api_keys_enabled`, `invite_domain_allowlist` (≤ 20 IDNA domains, normalized like TI domains, no special-use names).
  - Turning `require_mfa` on needs the acting owner to have `otp` in the session `amr` (`409 mfa_required_for_actor`), so an owner cannot lock themself out.
  - Turning `sso_enforced` on needs an enabled IdP with at least one verified domain and the acting owner's current session to be an SSO session of this org (`409 sso_not_ready`); or `owners_break_glass` true and the actor has `otp`.
  - Audit `org.security_policy_updated` with from / to; mail `new_owner_security_change` to every owner.
- **`check_org_access(session, org_id, principal)`** (called by `org_session` after the membership check; one read of `org_security_policies` joined with the membership query if phase 1 made it so, else a primary-key read):
  - API key principals: `api_keys_enabled` false → `403 api_keys_disabled`; MFA / SSO rules do not apply (keys have their own controls);
  - **SSO session scope** (RT2): a session whose `sso_org_id` is set and differs from `org_id`, of a user with a usable password (`principal.has_password`), → `403 sso_session_scope` (an org's IdP is controlled by that org's owners and must not open the member's other orgs); SSO-provisioned users (`!sso`) pass this rule;
  - `require_mfa` and `"otp"` ∉ `amr` and not (an SSO session **of this org**) → `403 mfa_required {enroll: true|false}` (enroll true when the user has no active factor; an SSO session of another org never satisfies it, RT2);
  - `sso_enforced` and `principal.sso_org_id != org_id` → if `owners_break_glass` and the role is owner and `"otp"` ∈ `amr` → allowed, audit `org.sso_break_glass` once per session (`core/audit_dedupe.once_per`); else `403 sso_required {sso_start: true}`;
  - the routes needed to fix the situation stay reachable: `/auth/*` (not org routes) and `GET /orgs/{org}` / `GET /orgs/{org}/security-policy`, which use `require(…, policy_exempt=True)` (phase 1, RT13; `check_org_access` never sees the route), so the web can explain the block.
- **Step-up wiring** (each a `await stepup.require_recent_auth(ctx.session, ctx.user, action=…)` at the decision point, after validation and before the write):
  - TI `PUT /integrations/{provider}` when `api_key` is set, `DELETE …/key` → `provider_key_change`;
  - AI `PUT /ai/providers/{provider}` when `api_key` is set, `DELETE …/key` → `provider_key_change`;
  - case PATCH lowering the TLP (the branch that requires `acknowledge_tlp_downgrade`) and turning `ai_excluded` / `ti_excluded` off → `tlp_downgrade` / `share_policy_release`;
  - reports: every `_tlp_rule` call that returns `downgraded` (`reports/service.py` 403, 483, 677, 848 at scout time: create, PATCH, finalize and the `wctx` path; phase 1 changed their argument to `ctx.permissions`, RT1) → `tlp_downgrade`;
  - evidence share policy PUT turning a flag off → `share_policy_release`;
  - retention policy PUT lowering any value or turning `enforce` on, `POST /retention/runs` in enforce mode, legal hold release → `retention_destructive` / `legal_hold_release`.
  Grep each module for every path that reaches the same write (for example finalize re-checking TLP) and list them in the phase notes; each gets a test.
- **Tests:** policy CRUD and its preconditions; an SSO session of org A on org B → `sso_session_scope` for a password user and allowed for an `!sso` user (RT2); an SSO session of org A does not satisfy `require_mfa` of org B; the two `policy_exempt` routes stay reachable under a block; MFA enforcement blocks a password-only session in org A but not in org B; enrolling and stepping up unblocks; SSO enforcement blocks password sessions, admits SSO sessions of that org only (seed `user_sessions.sso_org_id` with the helper), break-glass for owners with `otp` audited once; API keys refused when disabled (seed a key row with the helper; full key auth is phase 9, so this test uses a stub-resolved principal); every wired action refuses without step-up and passes with a fresh `step_up_at` and fails again after `STEP_UP_MAX_AGE_S` (time-travel helper); IDOR for the policy routes.

## Implementation Steps
1. Policy module, routes and preconditions; tests.
2. `check_org_access`; enforcement tests; measure the added cost on `require()` (one indexed read; record p50 / p95 on the lane).
3. Step-up wiring module by module, each with its test; the phase notes list every call site.

## Success Criteria
- [ ] `require_mfa` and `sso_enforced` are enforced per org on every org route, with the documented exemptions and owner break-glass, and an owner cannot lock themself out through the policy route.
- [ ] Every protected change in the M4–M7 modules requires a fresh step-up; the call-site list is complete (reviewed against a grep of the acknowledgement fields and key setters).
- [ ] The per-request cost of the policy check is one indexed read.

## Risk Assessment
- **Missed call sites** leave a sensitive change without step-up: the grep list and one test per site; the red team's seed question 6.
- **Editing six M4–M7 service files** in one phase: one-line, import-plus-call edits only; their own suites are re-run in the lane (`test_ti_*`, `test_ai_*`, `test_reports_*`, `test_retention_*` subsets that touch the edited functions).
