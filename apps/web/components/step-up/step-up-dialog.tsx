"use client";

/**
 * M11 slot (phase 10 implements it): the global step-up dialog, mounted once in the app
 * layout. It will listen for `STEP_UP_EVENT` (lib/api.ts), call `event.preventDefault()` to
 * take the prompt, ask for a TOTP code, a recovery code or the password (or start the SSO
 * re-authentication) as `methods` allows, `POST /api/v1/auth/step-up`, then `settle(true)`
 * (the request is retried once) or `settle(false)` on cancel. Until then nobody takes the
 * prompt and the caller sees the original `step_up_required` error.
 */
export function StepUpDialog() {
  return null;
}
