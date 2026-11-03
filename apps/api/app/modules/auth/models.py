import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import CITEXT, INET
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, CreatedAt, UUIDPk, pg_enum


class RevokedReason(enum.StrEnum):
    ROTATED = "rotated"
    LOGOUT = "logout"
    REUSE = "reuse"


class AuthEventType(enum.StrEnum):
    REGISTER = "register"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    REFRESH_REUSE_DETECTED = "refresh_reuse_detected"


class RefreshToken(UUIDPk, CreatedAt, Base):
    """Opaque refresh token, stored as sha256. User-scoped (no RLS)."""

    __tablename__ = "refresh_tokens"
    __table_args__ = (Index(None, "family_id"), Index(None, "user_id"))

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    family_id: Mapped[uuid.UUID]
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
    revoked_reason: Mapped[RevokedReason | None] = mapped_column(
        pg_enum(RevokedReason, "refresh_revoked_reason")
    )
    # Deferred so rotation can point the old row at the successor before inserting it.
    replaced_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("refresh_tokens.id", deferrable=True, initially="DEFERRED")
    )
    ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(512))


class AuthEvent(UUIDPk, Base):
    """Append-only authentication log. Not tenant-scoped (no RLS); no read API in M1."""

    __tablename__ = "auth_events"
    __table_args__ = (Index(None, "user_id", "occurred_at"),)

    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    email_attempted: Mapped[str | None] = mapped_column(CITEXT)
    event: Mapped[AuthEventType] = mapped_column(pg_enum(AuthEventType, "auth_event_type"))
    occurred_at: Mapped[datetime] = mapped_column(server_default=func.now())
    ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(512))
    details: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)
