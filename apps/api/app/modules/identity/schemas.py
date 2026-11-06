"""Request and response schemas of every M11 route (phase 1, FROZEN).

Inputs and outputs are separate models (no `-Input` / `-Output` component splits). Secrets
(`client_secret`, the TOTP secret, recovery codes, a new API key) appear only in the one
response that creates them, with `Cache-Control: no-store`.
"""

import re
import uuid
from datetime import datetime
from typing import Literal, Self

from pydantic import BaseModel, EmailStr, Field, model_validator

from app.core.pagination import Page
from app.core.validation import SafeName
from app.modules.auth.schemas import PASSWORD_MAX, PASSWORD_MIN, TOKEN_PATTERN
from app.modules.organizations.models import MemberRole

TOTP_CODE_PATTERN = r"^[0-9]{6}$"
# 16 Crockford base32 characters, optionally grouped `XXXX-XXXX-XXXX-XXXX` (normalized
# server-side: uppercase, spaces and hyphens removed, I/L -> 1, O -> 0; RT26).
RECOVERY_CODE_PATTERN = r"^[0-9A-Za-z \-]{16,24}$"
DOMAIN_PATTERN = r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$"
NEXT_PATTERN = r"^/[A-Za-z0-9/_\-.~%?=&]{0,511}$"
_DOMAIN = re.compile(DOMAIN_PATTERN)

StepUpMethod = Literal["totp", "recovery_code", "password", "sso"]
ApiKeyScope = Literal[
    "org.read", "investigation.read", "investigation.write", "evidence.read", "evidence.write"
]


class TokenIn(BaseModel):
    token: str = Field(pattern=TOKEN_PATTERN)


# --- email verification (phase 3) -------------------------------------------------------------


class EmailVerifyIn(TokenIn):
    """Signed in as the token's user (RT8); the page never auto-submits."""


# --- invitations (phase 3) ---------------------------------------------------------------------


class InvitationCreate(BaseModel):
    email: EmailStr
    role: MemberRole


class InvitationOut(BaseModel):
    id: uuid.UUID
    email: str
    role: MemberRole
    status: Literal["pending", "accepted", "revoked", "expired"]
    invited_by: uuid.UUID | None
    invited_by_name: str | None
    created_at: datetime
    expires_at: datetime
    last_sent_at: datetime
    resend_count: int
    # The newest outbox row of this invitation: `pending`, `sent` or `failed` (RT19).
    mail_status: Literal["pending", "sending", "sent", "failed"] | None


class InvitationPage(Page[InvitationOut]):
    pass


class InvitationInspectIn(TokenIn):
    pass


class InvitationInspectOut(BaseModel):
    organization_name: str
    role: MemberRole
    inviter_name: str
    email_masked: str  # j***@example.com
    expires_at: datetime


class InvitationAcceptIn(TokenIn):
    pass


class InvitationAcceptOut(BaseModel):
    organization_id: uuid.UUID
    role: MemberRole
    already_member: bool


# --- recovery, password (phase 4) ---------------------------------------------------------------


class PasswordForgotIn(BaseModel):
    email: EmailStr


class PasswordResetIn(BaseModel):
    token: str = Field(pattern=TOKEN_PATTERN)
    new_password: str = Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)


class PasswordChangeIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=PASSWORD_MAX)
    new_password: str = Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)


# --- sessions and the personal security log (phase 4) ----------------------------------------


class SessionOut(BaseModel):
    id: uuid.UUID
    method: Literal["password", "sso"]
    amr: list[str]
    sso_organization_id: uuid.UUID | None
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    ip: str | None
    user_agent: str | None  # coarse: "Firefox on Windows"
    current: bool


class SessionList(BaseModel):
    items: list[SessionOut]


class AuthEventOut(BaseModel):
    id: uuid.UUID
    event: str
    occurred_at: datetime
    ip: str | None
    user_agent: str | None


class AuthEventList(BaseModel):
    items: list[AuthEventOut]


# --- MFA and step-up (phase 5) -------------------------------------------------------------------


class CodeOrRecoveryIn(BaseModel):
    """Exactly one of `code` (TOTP) or `recovery_code`."""

    code: str | None = Field(default=None, pattern=TOTP_CODE_PATTERN)
    recovery_code: str | None = Field(default=None, pattern=RECOVERY_CODE_PATTERN)

    @model_validator(mode="after")
    def _exactly_one(self) -> Self:
        if (self.code is None) == (self.recovery_code is None):
            raise ValueError("send exactly one of code or recovery_code")
        return self


class MfaVerifyIn(CodeOrRecoveryIn):
    pass


class StepUpIn(BaseModel):
    """Exactly one of `code`, `recovery_code` or `password` (as `step_up_required.methods`
    lists; SSO sessions step up through `POST /auth/sso/start {purpose: step_up}`)."""

    code: str | None = Field(default=None, pattern=TOTP_CODE_PATTERN)
    recovery_code: str | None = Field(default=None, pattern=RECOVERY_CODE_PATTERN)
    password: str | None = Field(default=None, min_length=1, max_length=PASSWORD_MAX)

    @model_validator(mode="after")
    def _exactly_one(self) -> Self:
        if sum(v is not None for v in (self.code, self.recovery_code, self.password)) != 1:
            raise ValueError("send exactly one of code, recovery_code or password")
        return self


class MfaStatusOut(BaseModel):
    totp: Literal["none", "pending", "active", "locked"]
    confirmed_at: datetime | None
    recovery_codes_remaining: int
    email_verified: bool
    required_by_orgs: list[uuid.UUID]


class TotpSetupOut(BaseModel):
    otpauth_uri: str
    secret: str


class TotpConfirmIn(BaseModel):
    code: str = Field(pattern=TOTP_CODE_PATTERN)


class TotpDisableIn(CodeOrRecoveryIn):
    pass


class RecoveryCodesOut(BaseModel):
    codes: list[str]  # shown once


# --- org security policy (phase 6) ------------------------------------------------------------


class SecurityPolicyOut(BaseModel):
    require_mfa: bool
    sso_enforced: bool
    owners_break_glass: bool
    api_keys_enabled: bool
    invite_domain_allowlist: list[str]
    updated_by: uuid.UUID | None
    updated_at: datetime | None


class SecurityPolicyUpdate(BaseModel):
    require_mfa: bool
    sso_enforced: bool
    owners_break_glass: bool
    api_keys_enabled: bool
    invite_domain_allowlist: list[str] = Field(max_length=20)

    @model_validator(mode="after")
    def _domains(self) -> Self:
        if any(not _DOMAIN.fullmatch(d) or len(d) > 253 for d in self.invite_domain_allowlist):
            raise ValueError("invite_domain_allowlist holds lowercase IDNA (punycode) domains")
        return self


# --- SSO administration (phase 7) ---------------------------------------------------------------


class SsoConfigOut(BaseModel):
    configured: bool
    issuer: str | None
    client_id: str | None
    client_auth: Literal["client_secret_basic", "client_secret_post"] | None
    scopes: str | None
    secret_last4: str | None  # write-only secret: the last 4 only
    enabled: bool
    jit_enabled: bool
    jit_default_role: Literal["viewer", "analyst"] | None
    metadata_fetched_at: datetime | None
    config_version: int | None
    redirect_uri: str


class SsoConfigUpdate(BaseModel):
    issuer: str = Field(min_length=9, max_length=512)
    client_id: str = Field(min_length=1, max_length=255)
    # Omitted: keep the stored secret (refused for a new issuer:
    # `secret_required_for_new_issuer`).
    client_secret: str | None = Field(default=None, min_length=8, max_length=256)
    client_auth: Literal["client_secret_basic", "client_secret_post"] = "client_secret_basic"
    scopes: str = Field(default="openid email profile", max_length=200)
    enabled: bool = False
    jit_enabled: bool = False
    jit_default_role: Literal["viewer", "analyst"] = "viewer"


class DomainOut(BaseModel):
    id: uuid.UUID
    domain: str
    status: Literal["pending", "verified", "failed", "removed"]
    method: Literal["dns", "operator"] | None
    txt_name: str  # _cyberlab-challenge.<domain>
    txt_value: str
    created_at: datetime
    verified_at: datetime | None
    last_checked_at: datetime | None


class DomainList(BaseModel):
    items: list[DomainOut]


class DomainCreate(BaseModel):
    domain: str = Field(min_length=3, max_length=253)


# --- SSO login (phase 8) --------------------------------------------------------------------------


class SsoStartIn(BaseModel):
    email: EmailStr
    next: str | None = Field(default=None, pattern=NEXT_PATTERN)
    purpose: Literal["login", "step_up"] = "login"


class SsoStartOut(BaseModel):
    redirect_url: str


# --- platform API keys (phase 9) ------------------------------------------------------------------


class ApiKeyOut(BaseModel):
    id: uuid.UUID
    name: str
    public_id: str
    role: Literal["analyst", "viewer"]
    scopes: list[ApiKeyScope]
    status: Literal["active", "expired", "revoked"]
    created_by: uuid.UUID
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None
    last_used_ip: str | None
    revoked_at: datetime | None


class ApiKeyList(BaseModel):
    items: list[ApiKeyOut]


class ApiKeyCreate(BaseModel):
    name: SafeName = Field(min_length=1, max_length=100)
    role: Literal["analyst", "viewer"]
    scopes: list[ApiKeyScope] = Field(min_length=1, max_length=5)
    expires_in_days: int = Field(ge=1, le=365)

    @model_validator(mode="after")
    def _unique_scopes(self) -> Self:
        if len(set(self.scopes)) != len(self.scopes):
            raise ValueError("scopes must be unique")
        return self


class ApiKeyCreated(BaseModel):
    key: ApiKeyOut
    secret: str  # `clk_…`, shown once (Cache-Control: no-store)
