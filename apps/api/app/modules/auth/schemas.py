import uuid
from typing import Self

from pydantic import BaseModel, EmailStr, Field, model_validator

from app.core.validation import SafeName
from app.modules.organizations.models import MemberRole
from app.modules.users.schemas import UserOut

PASSWORD_MIN = 12
PASSWORD_MAX = 128


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)
    display_name: SafeName = Field(min_length=1, max_length=100)
    organization_name: SafeName = Field(min_length=2, max_length=120)

    @model_validator(mode="after")
    def _password_not_email(self) -> Self:
        if self.password.strip().lower() == str(self.email).lower():
            raise ValueError("password must not equal the email address")
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
