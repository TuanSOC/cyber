import { ApiError } from "@/lib/api";

/**
 * Plain-language messages for API error codes the UI explains instead of showing the server
 * message (M7). Phases 8 and 9 use them; new codes are added here by the parent only.
 */
export const HTTP_ERROR_TEXT: Readonly<Record<string, string>> = {
  evidence_purged:
    "The evidence bytes were deleted by the retention policy. Its hashes and chain of custody are kept.",
  legal_hold_active: "A legal hold covers this data, so it cannot be changed or deleted.",
  policy_floor: "A retention period is below the minimum this platform allows.",
  retention_acknowledgement_required:
    "Enforcing retention deletes data. Confirm that you understand before turning it on.",
  search_query_invalid: "Search terms must be 2 to 256 characters long.",
  // M8: memory forensics.
  memory_image_too_large: "The memory image is larger than this platform accepts.",
  memory_image_empty: "An empty file cannot be analyzed as a memory image.",
  memory_sensitivity_restricted:
    "This evidence is a restricted memory image. An administrator must release it before AI or threat-intel use is allowed.",
  memory_sensitivity_released: "This memory evidence was already released.",
  acknowledgement_required: "Confirm that you understand what releasing this memory image allows.",
  insufficient_storage: "The platform does not have enough free space for this upload right now. Try again later.",
  // M9: disk forensics and the evidence-level sensitivity (disk images and derived evidence).
  disk_image_too_large: "A disk image segment is larger than this platform accepts.",
  disk_image_set_too_large: "The disk image segments together are larger than this platform accepts.",
  disk_segments_invalid: "The segments must be 1 to 64 distinct evidence items of this case, including this one.",
  disk_image_empty: "An empty file cannot be analyzed as a disk image.",
  evidence_sensitivity_restricted:
    "This evidence is restricted (TLP:RED). An administrator must release it before AI or threat-intel use is allowed.",
  evidence_sensitivity_released: "This evidence was already released.",
  disk_export_not_allowed:
    "This file cannot be exported (deleted, not a regular file, too large, not allocated, or a protected secret store).",
  disk_export_not_ready: "The exported file is not ready yet.",
  disk_export_already_promoted: "The exported file was already added to the case.",
  disk_export_expired: "The exported file expired. Export it again.",
  // M10: reverse engineering.
  static_analysis_required:
    "Run a full static analysis of this file first: reverse engineering starts from a static analysis that identified a PE or ELF program.",
  re_sample_too_large: "The file is larger than the reverse engineering analyzer accepts.",
  unsupported_architecture: "Only x86 and x86-64 programs can be reverse engineered.",
  unsupported_managed_code: ".NET (managed) programs cannot be reverse engineered here.",
  profile_unavailable: "This reverse engineering profile is not available on this platform.",
  function_not_found: "No function starts at this address in this analysis.",
  too_many_active_jobs:
    "Another heavy analysis (memory, disk or reverse engineering) is running on this platform. Try again in a few minutes.",
  // M11: identity and access.
  ambiguous_credentials: "Send either a session or an API key, not both.",
  invalid_api_key: "The API key is invalid, expired or revoked.",
  token_invalid: "This link is invalid or has expired. Ask for a new one.",
  registration_closed: "Registration needs an invitation. Ask an organization owner to invite you.",
  local_reauth_required: "Sign in with your password (not single sign-on) to change your account security.",
  email_verification_required: "Verify your email address first.",
  mfa_challenge_invalid: "The sign-in step expired. Sign in again.",
  mfa_code_invalid: "That code is not valid. Check your authenticator app and try again.",
  mfa_locked: "Two-factor authentication is locked after too many failed codes. Use a recovery code.",
  mfa_required: "This organization requires two-factor authentication. Turn it on in your account security.",
  mfa_required_by_org: "An organization you belong to requires two-factor authentication, so it cannot be turned off.",
  mfa_required_for_actor: "Turn on two-factor authentication before changing this setting.",
  step_up_required: "Confirm your identity to continue.",
  api_key_step_up_forbidden: "API keys cannot perform this action.",
  step_up_via_sso: "Confirm your identity through your organization's single sign-on.",
  invitation_invalid: "This invitation is invalid, already used or expired.",
  invitation_email_mismatch: "This invitation was sent to a different email address.",
  invite_domain_not_allowed: "This organization only invites addresses of its allowed domains.",
  members_direct_add_removed: "Members join through invitations.",
  service_account_member: "API key service accounts are managed on the API keys tab.",
  sso_required: "This organization requires single sign-on. Sign in through your identity provider.",
  sso_session_scope: "Your single sign-on session covers another organization. Sign in with your password to open this one.",
  sso_not_member: "You need an invitation to this organization before signing in with single sign-on.",
  sso_link_requires_verified_email: "Verify your email address before linking single sign-on.",
  sso_unavailable: "Single sign-on is not available right now. Try again later.",
  sso_not_ready: "Sign in once with single sign-on before enforcing it.",
  secret_required_for_new_issuer: "A new issuer needs its client secret.",
  issuer_invalid: "The issuer must be a public https URL.",
  domain_claimed: "This domain is verified by another organization.",
  domain_not_verified: "The verification record was not found. DNS changes can take a while to appear.",
  api_keys_disabled: "API keys are turned off for this organization (security policy).",
  api_key_limit_reached: "This organization has the maximum number of API keys. Revoke one first.",
};

/** M11: the fixed `#sso_error=` codes of the SSO callback redirect (never IdP text). */
export const SSO_ERROR_TEXT: Readonly<Record<string, string>> = {
  idp_denied: "The identity provider did not sign you in.",
  sso_state_invalid: "The sign-in link expired. Start again.",
  sso_state_unbound: "The sign-in started in another browser. Start again here.",
  sso_email_not_eligible: "Your email address cannot sign in with this identity provider.",
  sso_token_invalid: "The identity provider's answer could not be verified.",
  sso_unavailable: "Single sign-on is not available right now. Try again later.",
  sso_not_member: "You need an invitation to this organization first.",
  sso_link_requires_verified_email: "Verify your email address (sign in with your password) before using single sign-on.",
};

/** The message for an error code, or null when the code has no specific text. */
export function httpErrorText(code: string): string | null {
  return Object.hasOwn(HTTP_ERROR_TEXT, code) ? HTTP_ERROR_TEXT[code] : null;
}

/** `httpErrorText` for an `ApiError`, else null. */
export function apiErrorText(error: unknown): string | null {
  return error instanceof ApiError ? httpErrorText(error.code) : null;
}
