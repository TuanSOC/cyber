---
phase: 3
title: "Invitations email verification and registration modes"
status: complete
priority: P2
effort: "14h"
dependencies: [1]
---

# Phase 3: Invitations, email verification and registration modes (group B, 2b, lane 3)

## Overview
Members join only by consent: an admin invites an email, the invitee accepts through a single-use, expiring link. This closes the M1 gaps "members added without consent" and "add-member enumeration". Email verification and the `invite_only` registration mode come with it. Design: plan.md "Invitations".

**Owns:** `app/modules/invitations/**` (after the stubs, incl. `admin_bootstrap.py`, RT12), `organizations/{members,router,repository}.py` (`count_owners`, RT14), `identity/{email_verify,router_email}.py`, `tests/security/idor_cases_invitations.py`, `tests/integration/test_invitations_{create,accept,register,enumeration}.py`, `test_email_verify.py`, `test_registration_mode.py`, `test_members_hardening.py` (updated).

## Requirements
- **Create** (`POST /orgs/{org}/invitations {email, role}`): `members.manage`; lock the org and re-read the actor's role (the `members.py` pattern); `_ensure_may_manage` for owner roles; **step-up** (`StepUpAction.member_elevate`) when the role is admin or owner; email validated (`EmailStr`, special-use domains refused as today); optional `invite_domain_allowlist` from `org_security_policies` (`422 invite_domain_not_allowed`); a pending invitation for the same email is revoked in the same transaction; token 256-bit, sha256 in `org_invitations` and `invitation_index`; `email_outbox` row (`invite`, params: org name, inviter display name, role, expiry; secret: the token); audit `invitation.created` (email domain only in details, not the full address? **decision:** the full email, like `member.added` details hold the user id; audit is org-internal); publish after commit; response `201 InvitationOut` (no token). Same response and timing class whether the email is registered (no user lookup at all on this path).
- **Limits:** 30 / 10 min per actor, 100 / day per actor across orgs (RT20), 200 / day per org.
- **List / resend / revoke:** `GET` (pending, accepted, revoked, expired; `members.read`); resend rotates the token and expiry (3 per invitation per day), new outbox row; revoke sets `revoked_*`; audits `invitation.resent`, `invitation.revoked`.
- **Inspect** (`POST /invitations/inspect {token}`): public, 20 / 10 min per IP; lookup through `invitation_index` with no org context, then the tenant session for that org (vetted guard entry) to read the display fields; one `404 invitation_invalid` for every failure.
- **Accept** (`POST /invitations/accept {token}`, signed in, session principal only): atomic consume (`UPDATE … WHERE token_hash=:h AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now() RETURNING`) in the org's tenant session; email mismatch → `409 invitation_email_mismatch` without consuming; already a member → consumed, membership unchanged, `200`; else insert the membership (role from the invitation), `users.email_verified_at = coalesce(…, now())`, audits `invitation.accepted` and `member.added {via: invitation}`, auth event `invitation_accepted`.
- **Register with invitation** (`register_with_invitation`, called by `auth/service.register`): consume + user + membership in one transaction; no org created, no owned-org check; emails must match; works in both registration modes.
- **Registration mode:** `invite_only` → register without a valid token → `403 registration_closed` before any lookup (phase 1 enforces it in `auth/service.register`; the response does not say whether the email exists). **No automatic bootstrap rule** (RT12: on a fresh internet-facing install the first registrant would win it and lock the operator out).
- **Bootstrap** (`invitations/admin_bootstrap.py`, `pnpm identity:admin bootstrap-owner --email <e> --org-name <n> --yes`, one-off api container): creates the org (`created_by` = the M7 system user, `kind='system'`) and an owner invitation (`invited_by` = the system user), prints the `{PUBLIC_BASE_URL}/register#t=…` link once (never logged), audit `invitation.created {via: operator}`; refuses if the email already has an account (the operator then invites from an existing owner). Tests: the link registers an owner with no other org; a second run for the same org refuses while an owner exists.
- **Direct add removed:** `POST /orgs/{org}/members` → `410 members_direct_add_removed`; `members.add_member` deleted; `test_members_hardening.py` and `test_orgs_members.py` cases move to invitations.
- **Member role changes and removal** gain step-up (`member_elevate` for a change to admin / owner, `member_remove` for removal) in `members.py`, and refuse a target whose user is `kind='service'` (`409 service_account_member`: keys are revoked on the API keys tab); `repo.count_owners` counts `kind='human'` members only (RT14).
- **Email verification** (`identity/email_verify.py`, `router_email.py`): `POST /auth/email/verify-request` (signed in; 3 / hour; `user_action_tokens` purpose `email_verify`, 24 h; outbox `email_verify`); `POST /auth/email/verify {token}` (**signed in as the token's user**, RT8: a JS-executing link scanner or a forwarded link cannot verify an account it is not signed into; another user's token → `404 token_invalid` without consuming it; consumes; sets `email_verified_at` only if the token's `email` still equals the user's email; auth event `email_verified`; `404 token_invalid` otherwise); `MeOut.user.email_verified` exposed (phase-1 schema).
- **Enumeration tests** (`test_invitations_enumeration.py`): create for a registered vs an unknown email gives the same status, body shape and no extra query (assert the SQL count with an event listener); inspect gives the same 404 for unknown / used / revoked / expired; register in `invite_only` gives the same 403 for existing and new emails.
- **IDOR:** every invitation org route in `idor_cases_invitations.py` (another org's invitation id → 404).
- **Accept by a service account** (its email is `.invalid`, so it can never hold a session) needs no extra rule; the accept path still checks `kind='human'` (defence in depth).

## Implementation Steps
1. Service and repository for create / list / resend / revoke, with the outbox call; tests.
2. Inspect and accept with the vetted tenant session; tests (single-use under two concurrent accepts, expiry, mismatch, already member).
3. Register with invitation and the registration mode; tests.
4. Remove direct add; step-up and the service-account refusal in role change and removal; update the members tests.
4a. The `bootstrap-owner` operator command; tests.
5. Email verification routes; tests; enumeration suite; IDOR module.

## Success Criteria
- [x] An invitation is accepted once, only by the invited email, only before expiry and only if not revoked or rotated; concurrent accepts produce one membership.
- [x] Creating, inspecting and registering reveal nothing about whether an email is registered (enumeration suite).
- [x] Direct add answers 410; owner and admin invitations and elevations require step-up.
- [x] `invite_only` refuses uninvited registration; an invitation registration creates no org.
- [x] Email verification sets `email_verified_at` only for the address the token was sent to, and only in a session of that user (RT8).
- [x] A fresh install gets its first owner only through `bootstrap-owner` (RT12); service accounts can be neither re-roled nor removed through the members routes (RT14).

## Risk Assessment
- **Breaking existing tests and the e2e** that add members directly: phase 1 migrated the callers; this phase re-runs `test_orgs_members.py`, `test_members_hardening.py`, `test_rbac.py` and the IDOR suite.
- **Mail outage blocks onboarding:** the invitation still exists; resend works once mail is back; admins see `last_sent_at` and the outbox status (phase 11).
