---
phase: 12
title: "Docs threat model and identity runbooks"
status: pending
priority: P2
effort: "8h"
dependencies: [2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
---

# Phase 12: Docs, threat model and identity runbooks (group C, after the group-B merge)

## Overview
Document what M11 built, honestly, with the residuals. Re-check every claim against the merged code before writing it.

**Owns:** `docs/{ARCHITECTURE,API,DATABASE,DEPLOYMENT,THREAT_MODEL,TESTING,ROADMAP,PRD}.md`, `README.md`.

## Requirements
- **ARCHITECTURE:** an "Identity and access (M11)" section: modules (`identity`, `invitations`, `mail`, `api_keys`, `egress_proxy`), the login / MFA / step-up / SSO / invitation / API-key flows (one sequence diagram for SSO, one for invitations), networks `mail` and `idp`, the request lifecycle update (principal, `check_org_access`), boundaries.
- **API:** the cookie table (+ `cl_mfa`, `cl_sso`), bearer keys and the CSRF rule, the new error codes in the status table, every new route with its permission and limits, `202` login, the removed direct-add route (410), `security.manage` in the roles paragraph.
- **DATABASE:** the new tables and columns, grants, system lookups; the §11 mapping: `api_keys` is now the platform-key table, provider keys stay in `*_provider_configs`.
- **DEPLOYMENT:**
  - SMTP relay settings, TLS requirement, `MAIL_FROM`, SPF / DKIM / DMARC as the relay's job; Mailpit is dev / test only and its UI binds to localhost;
  - the two new seal key pairs (generation, rotation by kid, backup with the other secrets), prod refusals;
  - `REGISTRATION_MODE` (prod default `invite_only`, with an upgrade note for existing installs) and the first owner through `pnpm identity:admin bootstrap-owner` (no automatic first-registration rule, RT12);
  - the `cyberlab_mail` DB role (RT9) and NTP on the host (TOTP and step-up ages, RT21);
  - the egress proxy (what it allows, how to put Smokescreen or a corporate proxy in its place);
  - IdP setup recipes (Entra single-tenant issuer, Google Workspace, Okta, Keycloak): redirect URI, scopes, `email_verified` behaviour per IdP;
  - runbooks: first owner (`identity:admin bootstrap-owner`), an SSO user blocked by a squatted unverified local account (password reset by the mailbox owner, then an invitation and a sign-in to link, RT2 / RT8), lost MFA (`identity:admin reset-mfa`), domain approval and the weekly `recheck-domains` cron, revoking every session of a user, rotating `JWT_SECRET` after an incident (logs everyone out), API key leak response.
- **THREAT_MODEL:** assets (TOTP secrets, IdP client secrets, recovery codes, invitation / reset tokens, API keys, the outbox); boundaries 13–15 (mail worker ↔ SMTP, egress proxy ↔ internet, IdP ↔ API); an "M11: identity" STRIDE table (account takeover by credential stuffing, MFA bypass and replay, recovery abuse, invitation hijack and enumeration, login CSRF and session fixation, SSO mix-up / nOAuth / pre-account-takeover / hostile or org-controlled IdP (session scope, RT2) / shared Google issuer (`hd`, RT10) / issuer change (RT11), step-up bypass (incl. stale `auth_time`, RT3), API-key scope bypass in services (RT1), timing enumeration on login and forgot (RT5, RT6), API key leak and misuse, CSRF via bearer, outbox token leak, egress abuse), each with the test names; M1 known gaps updated: "No email verification, no MFA" (closed: MFA, verification, invite-only), "added without consent" (closed), "add-member enumeration" (closed), "register 409 reveals emails" (narrowed by `invite_only`; open in `open` mode), "special-use domains revisit with SSO" (kept: verified domains are public DNS names); residuals (an org's IdP can sign in as its SSO-provisioned members in every org that invited them, RT2; API compromise reads TOTP and IdP secrets; proxy reaches any public host on 443; no SCIM, 12 h SSO cap; at-least-once mail; MFA limiter DoS; DoH trust; approximate public-suffix list; identity tables outside retention; backups contain the outbox and sealed secrets).
- **TESTING:** the new suites, the hostile IdP modes, the enumeration suite, the mail guard, how to run the optional interop check against Dex or Keycloak (manual, recorded).
- **ROADMAP / PRD / README:** M11 row; "Later" loses invitations / MFA / SSO / platform keys and gains WebAuthn (M11.1), SAML, SCIM, email change; README feature list and caveats.

## Implementation Steps
1. Re-read the merged code paths and the phase notes; list each claim with its test.
2. Write the sections; cross-link.
3. Review against plan.md Definition of done.

## Success Criteria
- [ ] Every M11 behaviour and residual is documented with the test that proves it or the reason it is a residual.
- [ ] The M1 known-gaps table reflects what M11 closed, narrowed or kept.
- [ ] Runbooks exist for lost MFA, domain approval and re-check, session revocation, JWT secret rotation and an API key leak.

## Risk Assessment
- **Overclaiming** (for example "phishing-resistant MFA": TOTP is not): the review in step 3 checks the wording against the research report.
