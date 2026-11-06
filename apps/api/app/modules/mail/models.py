"""The mail outbox (migration 0019, M11 phase 1, FROZEN).

A system table (no RLS): `context_org_id` is audit context only, never tenant data. The API
inserts (`mail.outbox.enqueue`, in the caller's transaction); the mail worker (DB role
`cyberlab_mail`, RT9) claims a row (`pending -> sending`, `claimed_at`), sends it, then sets
`sent` and NULLs the sealed columns; failures carry a fixed `last_error` code (RT19).
`params` is non-secret (validated by the template's model, <= 4 KiB); the one secret (a link
token) is sealed for the mail worker (`cyberlab.mail.v1`). `captured` (<= 16 KiB) is written by
`MAIL_TRANSPORT=capture` only (test profile).
"""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import BYTEA, CITEXT, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, UUIDPk


class OutboxStatus(enum.StrEnum):
    PENDING = "pending"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"


class OutboxError(enum.StrEnum):
    SMTP_TRANSIENT = "smtp_transient"
    SMTP_PERMANENT = "smtp_permanent"
    RENDER_REFUSED = "render_refused"
    UNSEAL_FAILED = "unseal_failed"
    MAIL_DISABLED = "mail_disabled"
    MAX_ATTEMPTS = "max_attempts"


class EmailOutbox(UUIDPk, Base):
    __tablename__ = "email_outbox"

    template: Mapped[str] = mapped_column(Text)
    to_email: Mapped[str] = mapped_column(CITEXT)
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default="{}", default=dict)
    secret_kid: Mapped[str | None] = mapped_column(String(64))
    secret_key_version: Mapped[int | None]
    secret_epk: Mapped[bytes | None] = mapped_column(BYTEA)
    secret_nonce: Mapped[bytes | None] = mapped_column(BYTEA)
    secret_ct: Mapped[bytes | None] = mapped_column(BYTEA)
    status: Mapped[str] = mapped_column(
        Text, server_default="pending", default=OutboxStatus.PENDING.value
    )
    attempts: Mapped[int] = mapped_column(server_default="0", default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(server_default=func.now())
    claimed_at: Mapped[datetime | None]
    sent_at: Mapped[datetime | None]
    last_error: Mapped[str | None] = mapped_column(Text)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    context_org_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("organizations.id"))
    captured: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
