---
phase: 10
title: "Identity frontend auth flows and account security"
status: pending
priority: P2
effort: "18h"
dependencies: [1]
---

# Phase 10: Identity frontend: auth flows and account security (group B, 2i, web only)

## Overview
Every user-facing identity page: login with the MFA step and "Sign in with SSO", registration with an invitation, the invitation page, forgot / reset password, email verification, the SSO completion page, the global step-up dialog, and the account security page (password, MFA with QR and recovery codes, sessions, security log). Built against the phase-1 contracts with mocked fetch.

**Owns:** `components/auth/**`, `app/(auth)/**`, `components/step-up/**` (after the slot), `components/account/**`, `app/(app)/account/**`, `components/shell/account-link.tsx` (slot), `lib/{identity,mfa,sessions}.ts` (+ tests).

## Requirements
- **Login** (`(auth)/login`): email + password; on `202` switch to the code step (6-digit input with `autocomplete="one-time-code"`, inputmode numeric, a "use a recovery code" toggle, remaining-attempts text from errors, a device-clock hint after two failures); "Sign in with SSO" asks for the email and calls `POST /auth/sso/start`; a `null` redirect falls back to the password form with a neutral message; `#sso_error=<code>` shows a fixed message per code (never server text); `mfa_challenge_invalid` returns to the password step.
- **Register** (`(auth)/register`): reads `#t=` from the fragment when coming from an invitation (`/register#t=…`), shows the inviting org (inspect), pre-fills and locks the email field, sends `invitation_token`; `registration_closed` shows "registration is by invitation only".
- **Invite** (`(auth)/invite`): reads `#t=`, removes the fragment from the address bar (`history.replaceState`) after reading it, inspects; signed-in → "Join <org> as <role>" (accept; a mismatch explains which email the invitation is for, masked); signed-out → links to login (`next` back to the invite page with the fragment kept in memory only) and register.
- **Forgot / reset / verify-email** pages: fragments read and cleared the same way; neutral success texts ("if an account exists…"). The verify-email page never auto-submits: it asks the user to sign in (keeping the token in memory) and then shows a "Verify" button (RT8); `email_verification_required` on MFA setup links to "send verification email".
- **SSO complete** (`(auth)/sso/complete`): reads `#next=`, validates it with `safeNext`, clears the query cache, loads `/auth/me`, navigates.
- **Step-up dialog** (`components/step-up/step-up-dialog.tsx`): listens to `STEP_UP_EVENT` from `lib/api.ts`; shows the action name (from a fixed label map of `StepUpAction`), then the method from `methods`: TOTP code / recovery code / password / "Continue with SSO" (opens `sso/start` with `purpose=step_up` in the same tab with `next` = current page, accepting that the original request is not retried); resolves the promise on `204`, rejects on cancel; one dialog at a time (queued requests share it).
- **Account** (`(app)/account`, `account/security`), reachable from the header link (not org-scoped):
  - profile (email, verified badge, "send verification email");
  - password change (current + new; step-up handled by the dialog);
  - MFA: status (enrollment disabled with the reason when the email is unverified or the session is an SSO session of a password user: `email_verification_required`, `local_reauth_required`, RT8, RT2); setup flow (QR rendered in the browser from `otpauth_uri` with a pinned MIT QR library producing SVG elements, plus the base32 secret in a copyable field; confirm code; recovery codes shown once with copy and download-as-.txt, and a checkbox "I saved them" before closing); regenerate codes; disable;
  - sessions table (UA summary, IP, created / last seen, method, MFA badge, "this device"), revoke one, revoke others;
  - security log (last 50 events, fixed labels per event type).
- **Secrets in the browser:** the `otpauth_uri`, secret and recovery codes live only in component state; never in React Query cache (use `useMutation` results without `queryClient.setQueryData`), `localStorage`, `sessionStorage`, IndexedDB or the URL; the dialog clears state on close. A unit test spies on the Storage APIs during the setup flow; an ESLint `no-restricted-globals` / `no-restricted-properties` rule for `localStorage` / `sessionStorage` under `components/{account,auth,step-up}/**`.
- **CSP:** no inline scripts or styles beyond the existing policy; the QR library must not need `unsafe-eval`; verified by the existing CSP test and a manual check in phase 13.
- **Tests** (vitest + Testing Library, mocked fetch): the login MFA step (202 → code → me), recovery code path, SSO start and fallback, `sso_error` mapping, invite page (signed in / out, mismatch), fragment clearing, step-up dialog retry and cancel, QR render, storage spy, sessions revoke, every fixed error code has a message (incl. `sso_session_scope`, `local_reauth_required`, `email_verification_required`, RT22); `sso_session_scope` on an org page offers "sign in with password" (RT2).

## Implementation Steps
1. `lib/{identity,mfa,sessions}.ts` typed wrappers with tests.
2. Login, register, invite, forgot, reset, verify, SSO complete.
3. Step-up dialog.
4. Account pages; QR library choice (licence, size, no network) recorded in the phase notes.
5. Storage lint rule and tests.

## Success Criteria
- [ ] Every identity flow of plan.md has a page that works against the frozen contracts (mocked) and shows fixed, non-echoing error messages.
- [ ] Tokens in fragments are read once and removed from the address bar; nothing secret reaches browser storage, the query cache or a URL.
- [ ] The step-up dialog retries the original request once after a successful re-auth.
- [ ] `pnpm --filter web lint typecheck test` is green on the owned files.

## Risk Assessment
- **Contract drift** with the API phases: build only against the phase-1 schemas; the merge regenerates contracts.
- **Step-up via SSO loses the original request:** accepted; the dialog says the action must be repeated after returning.
