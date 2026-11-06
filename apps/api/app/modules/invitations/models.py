"""Invitation tables (migration 0019, M11 phase 1, FROZEN; phase 3 implements the flows).

- `org_invitations` (tenant, FORCE RLS): the token is stored as sha256 only; one pending
  invitation per (org, email) (a re-invite revokes the previous one in the same transaction);
  resend rotates `token_hash` and `expires_at`. Status is computed: accepted, revoked, expired
  (DB `now()`), else pending.
- `invitation_index` (system lookup, `analysis_job_index` policy): token hash -> org, so the
  public inspect and the accept route find the org before opening its tenant session (the
  vetted `tenant_session_guard` entry of `invitations/service.py`).
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, ForeignKeyConstraint, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import CHAR, CITEXT
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, UUIDPk, pg_enum
from app.modules.organizations.models import MemberRole


class InvitationStatus(enum.StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REVOKED = "revoked"
    EXPIRED = "expired"


class OrgInvitation(UUIDPk, Base):
    __tablename__ = "org_invitations"
    __table_args__ = (UniqueConstraint("id", "organization_id"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    email: Mapped[str] = mapped_column(CITEXT)
    role: Mapped[MemberRole] = mapped_column(pg_enum(MemberRole, "member_role"))
    token_hash: Mapped[str] = mapped_column(CHAR(64), unique=True)
    invited_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime]
    accepted_at: Mapped[datetime | None]
    accepted_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    revoked_at: Mapped[datetime | None]
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    resend_count: Mapped[int] = mapped_column(server_default="0", default=0)
    last_sent_at: Mapped[datetime] = mapped_column(server_default=func.now())


class InvitationIndex(Base):
    __tablename__ = "invitation_index"
    __table_args__ = (
        ForeignKeyConstraint(
            ["invitation_id", "organization_id"],
            ["org_invitations.id", "org_invitations.organization_id"],
            name="fk_invitation_index_invitation_id_org_invitations",
            ondelete="CASCADE",
        ),
    )

    invitation_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    token_hash: Mapped[str] = mapped_column(CHAR(64), unique=True)
    expires_at: Mapped[datetime]
