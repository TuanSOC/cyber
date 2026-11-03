import enum
import uuid

from sqlalchemy import ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, CreatedAt, Timestamps, UUIDPk, pg_enum


class MemberRole(enum.StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Organization(UUIDPk, Timestamps, Base):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(120))
    slug: Mapped[str] = mapped_column(String(80), unique=True)
    next_case_number: Mapped[int] = mapped_column(server_default="1", default=1)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))


class OrganizationMember(UUIDPk, CreatedAt, Base):
    __tablename__ = "organization_members"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id"),
        Index(None, "user_id"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    role: Mapped[MemberRole] = mapped_column(pg_enum(MemberRole, "member_role"))
