import uuid
from typing import Literal, Self

from pydantic import BaseModel, EmailStr, Field, model_validator

from app.core.validation import SafeName
from app.modules.organizations.models import MemberRole
from app.modules.users.schemas import UserOut

PASSWORD_MIN = 12
PASSWORD_MAX = 128


# M11: invitation and action tokens are `secrets.token_urlsafe(32)` (43 characters).
TOKEN_PATTERN = r"^[A-Za-z0-9_-]{43}$"


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)
    display_name: SafeName = Field(min_length=1, max_length=100)
    # Required without an invitation (a new org is created); ignored with one (M11 phase 3:
    # the user joins the invitation's org, no new org).
    organization_name: SafeName | None = Field(default=None, min_length=2, max_length=120)
    invitation_token: str | None = Field(default=None, pattern=TOKEN_PATTERN)

    @model_validator(mode="after")
    def _password_not_email(self) -> Self:
        if self.password.strip().lower() == str(self.email).lower():
            raise ValueError("password must not equal the email address")
        return self

    @model_validator(mode="after")
    def _org_or_invitation(self) -> Self:
        if self.invitation_token is None and self.organization_name is None:
            raise ValueError("organization_name is required without an invitation")
        return self


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=PASSWORD_MAX)


class MembershipOut(BaseModel):
    organization_id: uuid.UUID
    organization_name: str
    role: MemberRole


class MeOut(BaseModel):
    user: UserOut
    memberships: list[MembershipOut]


class MfaChallengeOut(BaseModel):
    """`202` of `POST /auth/login` when the account has an active second factor (M11 phase 5):
    no session yet; the `cl_mfa` challenge cookie and a CSRF token are set, and
    `POST /auth/mfa/verify` completes the sign-in."""

    mfa_required: Literal[True] = True
    methods: list[Literal["totp", "recovery_code"]]
