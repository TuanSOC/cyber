"""Identity and access error codes (M11 phase 1, FROZEN).

Every code the M11 routes answer, with its status; phases 2-9 raise these classes and never
invent new codes without a parent decision (the web maps them in `lib/http-errors.ts`). The SSO
callback never answers JSON: it redirects to `/login#sso_error=<code>` with one of
`SSO_REDIRECT_CODES` (RT22), never echoing IdP text.
"""

from app.core.errors import AppError, Conflict, Forbidden, Gone, NotFound, Unauthorized


class BadRequest(AppError):
    status_code = 400
    code = "bad_request"
    message = "Bad request"


class Unprocessable(AppError):
    status_code = 422
    code = "unprocessable"
    message = "The request cannot be processed"


# --- credentials and sessions ---------------------------------------------------------------


class AmbiguousCredentials(BadRequest):
    code = "ambiguous_credentials"
    message = "Send either a session cookie or an API key, not both"


class InvalidApiKey(Unauthorized):
    code = "invalid_api_key"
    message = "Invalid API key"


class TokenInvalid(BadRequest):
    code = "token_invalid"
    message = "The link is invalid or has expired"


class RegistrationClosed(Forbidden):
    code = "registration_closed"
    message = "Registration needs an invitation"


class LocalReauthRequired(Forbidden):
    """RT2: an SSO session of a user with a local password cannot change local security."""

    code = "local_reauth_required"
    message = "Sign in with your password to change account security"


class EmailVerificationRequired(Forbidden):
    code = "email_verification_required"
    message = "Verify your email address first"


# --- MFA and step-up -------------------------------------------------------------------------


class MfaChallengeInvalid(Unauthorized):
    code = "mfa_challenge_invalid"
    message = "The sign-in challenge expired, sign in again"


class MfaCodeInvalid(Unauthorized):
    code = "mfa_code_invalid"
    message = "Invalid code"


class MfaLocked(Forbidden):
    code = "mfa_locked"
    message = "Two-factor authentication is locked; use a recovery code"


class MfaRequired(Forbidden):
    """403 on org routes of an org with `require_mfa` (the login 202 carries a body flag)."""

    code = "mfa_required"
    message = "This organization requires two-factor authentication"


class MfaRequiredByOrg(Conflict):
    code = "mfa_required_by_org"
    message = "An organization you belong to requires two-factor authentication"


class MfaRequiredForActor(Forbidden):
    code = "mfa_required_for_actor"
    message = "Enable two-factor authentication before changing this setting"


class StepUpRequired(Forbidden):
    """`extra`: `action` (a `StepUpAction`) and `methods` (`totp`, `recovery_code`,
    `password` or `sso`)."""

    code = "step_up_required"
    message = "Confirm your identity to continue"


class ApiKeyStepUpForbidden(Forbidden):
    code = "api_key_step_up_forbidden"
    message = "API keys cannot perform this action"


class StepUpViaSso(Conflict):
    code = "step_up_via_sso"
    message = "Confirm your identity through your identity provider"


# --- invitations and members -----------------------------------------------------------------


class InvitationInvalid(NotFound):
    """One code for unknown, used, revoked and expired invitations."""

    code = "invitation_invalid"
    message = "This invitation is invalid or has expired"


class InvitationEmailMismatch(Conflict):
    code = "invitation_email_mismatch"
    message = "This invitation was sent to another email address"


class InviteDomainNotAllowed(Unprocessable):
    code = "invite_domain_not_allowed"
    message = "This organization only invites addresses of its allowed domains"


class MembersDirectAddRemoved(Gone):
    code = "members_direct_add_removed"
    message = "Members join through invitations"


class ServiceAccountMember(Conflict):
    code = "service_account_member"
    message = "API key service accounts are managed on the API keys tab"


# --- org policy and SSO ----------------------------------------------------------------------


class SsoRequired(Forbidden):
    code = "sso_required"
    message = "This organization requires single sign-on"


class SsoSessionScope(Forbidden):
    """RT2: an SSO session of org S, of a user with a usable password, reaches org S only."""

    code = "sso_session_scope"
    message = "Sign in with your password to open this organization"


class SsoNotMember(Forbidden):
    code = "sso_not_member"
    message = "You need an invitation to this organization"


class SsoLinkRequiresVerifiedEmail(Forbidden):
    code = "sso_link_requires_verified_email"
    message = "Verify your email address before linking single sign-on"


class SsoUnavailable(AppError):
    status_code = 503
    code = "sso_unavailable"
    message = "Single sign-on is not available right now"


class SsoNotReady(Conflict):
    code = "sso_not_ready"
    message = "Sign in once with single sign-on before enforcing it"


class SecretRequiredForNewIssuer(Unprocessable):
    code = "secret_required_for_new_issuer"
    message = "A new issuer needs its client secret"


class IssuerInvalid(Unprocessable):
    code = "issuer_invalid"
    message = "The issuer must be a public https URL"


class DomainClaimed(Conflict):
    code = "domain_claimed"
    message = "This domain is verified by another organization"


class DomainNotVerified(Conflict):
    code = "domain_not_verified"
    message = "The domain verification record was not found"


# --- API keys --------------------------------------------------------------------------------


class ApiKeysDisabled(Forbidden):
    code = "api_keys_disabled"
    message = "API keys are disabled for this organization"


class ApiKeyLimitReached(Conflict):
    code = "api_key_limit_reached"
    message = "This organization has the maximum number of API keys"


ERROR_CODES: frozenset[str] = frozenset(
    {
        "ambiguous_credentials",
        "invalid_api_key",
        "token_invalid",
        "registration_closed",
        "local_reauth_required",
        "email_verification_required",
        "mfa_challenge_invalid",
        "mfa_code_invalid",
        "mfa_locked",
        "mfa_required",
        "mfa_required_by_org",
        "mfa_required_for_actor",
        "step_up_required",
        "api_key_step_up_forbidden",
        "step_up_via_sso",
        "invitation_invalid",
        "invitation_email_mismatch",
        "invite_domain_not_allowed",
        "members_direct_add_removed",
        "service_account_member",
        "sso_required",
        "sso_session_scope",
        "sso_not_member",
        "sso_link_requires_verified_email",
        "sso_unavailable",
        "sso_not_ready",
        "secret_required_for_new_issuer",
        "issuer_invalid",
        "domain_claimed",
        "domain_not_verified",
        "api_keys_disabled",
        "api_key_limit_reached",
    }
)
# The fixed `#sso_error=` values of the callback redirect (RT22).
SSO_REDIRECT_CODES: tuple[str, ...] = (
    "idp_denied",
    "sso_state_invalid",
    "sso_state_unbound",
    "sso_email_not_eligible",
    "sso_token_invalid",
    "sso_unavailable",
    "sso_not_member",
    "sso_link_requires_verified_email",
)
