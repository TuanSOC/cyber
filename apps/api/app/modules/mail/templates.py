"""Mail templates and their parameters (M11 phase 1, FROZEN; rendering is phase 2).

Plain text only (decision): no HTML, no remote images, no tracking. Subjects are fixed strings.
`params` are non-secret and validated by the template's model (`extra="forbid"`, names through
`SafeName`); the one secret of a template (its link token) travels sealed, never in `params`.
Phase 2 renders names quoted and replaces a link-like name (`://`, `www.`, a dotted host-like
token) with a neutral label (RT20).
"""

import enum
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.core.validation import SafeName
from app.modules.organizations.models import MemberRole

Name = Annotated[SafeName, Field(min_length=1, max_length=120)]


class MailTemplate(enum.StrEnum):
    INVITE = "invite"
    EMAIL_VERIFY = "email_verify"
    PASSWORD_RESET = "password_reset"
    PASSWORD_CHANGED = "password_changed"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    MFA_LOCKED = "mfa_locked"
    RECOVERY_CODE_USED = "recovery_code_used"
    MFA_RESET_BY_OPERATOR = "mfa_reset_by_operator"
    SSO_ACCOUNT_LINKED = "sso_account_linked"
    API_KEY_CREATED = "api_key_created"
    NEW_OWNER_SECURITY_CHANGE = "new_owner_security_change"


class _Params(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class InviteParams(_Params):
    org_name: Name
    inviter_name: Name
    role: MemberRole
    expires_at: datetime


class UserParams(_Params):
    """Account notices addressed to the user by display name."""

    display_name: Name


class RecoveryCodeUsedParams(UserParams):
    remaining: int = Field(ge=0, le=10)


class SsoLinkedParams(UserParams):
    org_name: Name
    issuer_host: str = Field(min_length=1, max_length=253, pattern=r"^[a-z0-9.-]+$")


class ApiKeyCreatedParams(_Params):
    org_name: Name
    key_name: Name
    creator_name: Name
    role: Literal["analyst", "viewer"]
    expires_at: datetime


class SecurityChangeParams(_Params):
    org_name: Name
    actor_name: Name
    change: Literal["security_policy", "sso_config", "domain", "api_keys"]


TEMPLATE_PARAMS: dict[MailTemplate, type[_Params]] = {
    MailTemplate.INVITE: InviteParams,
    MailTemplate.EMAIL_VERIFY: UserParams,
    MailTemplate.PASSWORD_RESET: UserParams,
    MailTemplate.PASSWORD_CHANGED: UserParams,
    MailTemplate.MFA_ENABLED: UserParams,
    MailTemplate.MFA_DISABLED: UserParams,
    MailTemplate.MFA_LOCKED: UserParams,
    MailTemplate.RECOVERY_CODE_USED: RecoveryCodeUsedParams,
    MailTemplate.MFA_RESET_BY_OPERATOR: UserParams,
    MailTemplate.SSO_ACCOUNT_LINKED: SsoLinkedParams,
    MailTemplate.API_KEY_CREATED: ApiKeyCreatedParams,
    MailTemplate.NEW_OWNER_SECURITY_CHANGE: SecurityChangeParams,
}

# Templates whose body carries a link token (sealed; required) and the web route it opens.
# The token goes in the URL fragment (`#t=`): never in a log, a query or a Referer.
LINK_PATHS: dict[MailTemplate, str] = {
    MailTemplate.INVITE: "/invite",
    MailTemplate.EMAIL_VERIFY: "/verify-email",
    MailTemplate.PASSWORD_RESET: "/reset-password",
}

SUBJECTS: dict[MailTemplate, str] = {
    MailTemplate.INVITE: "You are invited to an organization on CyberLab",
    MailTemplate.EMAIL_VERIFY: "Verify your CyberLab email address",
    MailTemplate.PASSWORD_RESET: "Reset your CyberLab password",
    MailTemplate.PASSWORD_CHANGED: "Your CyberLab password was changed",
    MailTemplate.MFA_ENABLED: "Two-factor authentication enabled",
    MailTemplate.MFA_DISABLED: "Two-factor authentication disabled",
    MailTemplate.MFA_LOCKED: "Two-factor authentication locked",
    MailTemplate.RECOVERY_CODE_USED: "A recovery code was used",
    MailTemplate.MFA_RESET_BY_OPERATOR: "Two-factor authentication was reset",
    MailTemplate.SSO_ACCOUNT_LINKED: "Single sign-on linked to your account",
    MailTemplate.API_KEY_CREATED: "A new API key was created",
    MailTemplate.NEW_OWNER_SECURITY_CHANGE: "Organization security settings changed",
}

MAX_PARAMS_BYTES = 4096
