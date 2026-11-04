import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.core.pagination import Page
from app.core.validation import SafeName
from app.modules.organizations.models import MemberRole


class OrgOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    created_at: datetime


class MyOrgOut(OrgOut):
    """An org as seen by the caller, including the caller's role in it."""

    role: MemberRole


class MyOrgPage(Page[MyOrgOut]):
    pass


class OrgCreate(BaseModel):
    name: SafeName = Field(min_length=2, max_length=120)


class OrgUpdate(BaseModel):
    name: SafeName = Field(min_length=2, max_length=120)


class StorageOut(BaseModel):
    """Evidence storage of the org: active + archived evidence against its quota."""

    used_bytes: int
    quota_bytes: int
    evidence_count: int


class MemberOut(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    email: str
    display_name: str
    role: MemberRole
    created_at: datetime


class MemberPage(Page[MemberOut]):
    pass


class MemberAdd(BaseModel):
    email: EmailStr
    role: MemberRole


class MemberUpdate(BaseModel):
    role: MemberRole
