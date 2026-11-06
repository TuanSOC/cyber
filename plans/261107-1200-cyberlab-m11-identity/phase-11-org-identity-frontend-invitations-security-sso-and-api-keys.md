---
phase: 11
title: "Org identity frontend invitations security SSO and API keys"
status: pending
priority: P2
effort: "13h"
dependencies: [1]
---

# Phase 11: Org identity frontend: invitations, security policy, SSO and API keys (group B, 2j, web only)

## Overview
The org-admin side: invitations on the members page, the Security settings tab (policy, SSO configuration, domains) and the API keys tab. Built against the phase-1 contracts with mocked fetch.

**Owns:** `components/members/**` (except the removed `add-member-dialog.tsx`), the members settings page, `components/{invitations,org-security,sso,api-keys}/**`, `app/(app)/o/[orgId]/settings/{security,api-keys}/**`, `lib/{invitations,org-security,sso-admin,api-keys}.ts` (+ tests).

## Requirements
- **Members page:** `invite-dialog.tsx` (email, role; owner role only for owners; admin / owner roles go through the step-up dialog); `invitations-card.tsx` (pending with expiry and last sent, resend, revoke; accepted / revoked / expired in a collapsed history); member rows label service accounts as "API key", link to the API keys tab and show no role or remove controls (`service_account_member`, RT14); role change and removal handle `step_up_required` through the global dialog.
- **Security tab** (`security.manage` to edit, `org.read` to view):
  - policy: require MFA (explains `mfa_required_for_actor`), enforce SSO (disabled with the reason until `sso_not_ready` conditions are met), owner break-glass, API keys enabled, invitation domain allowlist;
  - SSO (hidden if OIDC is cut, RT16): issuer, client id, client secret (write-only, "•••• last4"), client auth method, JIT on/off and default role (viewer / analyst), status of the metadata (fetched at, algorithms), refresh metadata, the redirect URI to register at the IdP (copy), remove secret;
  - domains: add, the TXT record name and value with copy buttons, verify (with fixed failure messages), status, remove.
- **API keys tab** (`security.manage`): list (prefix, name, role, scopes, expiry, last used, status), create dialog (name, role, scopes checkboxes limited by role, expiry 30 / 90 / 180 / 365 days) → the key shown **once** in a dialog with copy, a warning, and the `curl` example with a placeholder (never the key itself in the example), cleared from state on close; revoke with confirmation. Hidden when the org policy disables keys (with a link to the policy).
- **Secrets:** the client secret field and the created key follow the phase-10 storage rules (component state only, the lint rule extended to `components/{sso,api-keys}/**`, a storage-spy test).
- **Tests:** invite and step-up path, resend / revoke, role-gated controls (owner vs admin vs analyst views), SSO form validation and the write-only secret, domain TXT display and verify outcomes, API key create shown once and cleared, scope checkboxes constrained by role, every fixed error code mapped.

## Implementation Steps
1. `lib/*` wrappers with tests.
2. Members page invitations.
3. Security tab (policy, SSO, domains).
4. API keys tab (skip if phase 9 is cut; the tab then stays hidden).

## Success Criteria
- [ ] Admins invite, resend and revoke; owners manage policy, SSO, domains and API keys; other roles see read-only or nothing, as the permissions say.
- [ ] Write-only secrets and one-time keys never reach storage, the query cache or a URL.
- [ ] `pnpm --filter web lint typecheck test` is green on the owned files.

## Risk Assessment
- **Lock-out by UI:** the policy controls show the preconditions before enabling and rely on the API's refusals (phase 6) as the source of truth.
