"""Platform API keys (migration 0019, M11 phase 1, FROZEN; phase 9 implements the flows).

`api_keys` (tenant, FORCE RLS): one row per key, each with its own service account
(`users.kind = 'service'`, a membership with the key's role). The key is
`clk_<public_id>_<secret>`; only sha256 of the secret is stored. `scopes` is a subset of
`API_KEY_SCOPES`; the effective permissions are role permissions ∩ scopes (RT1).
"""

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY, CHAR, INET
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, UUIDPk

API_KEY_ROLES = ("analyst", "viewer")
API_KEY_SCOPES = (
    "org.read",
    "investigation.read",
    "investigation.write",
    "evidence.read",
    "evidence.write",
)


class ApiKey(UUIDPk, Base):
    __tablename__ = "api_keys"
    __table_args__ = (UniqueConstraint("id", "organization_id"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    service_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), unique=True)
    name: Mapped[str] = mapped_column(String(100))
    public_id: Mapped[str] = mapped_column(CHAR(12), unique=True)
    secret_hash: Mapped[str] = mapped_column(CHAR(64))
    role: Mapped[str] = mapped_column(Text)
    scopes: Mapped[list[str]] = mapped_column(ARRAY(Text))
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime]
    last_used_at: Mapped[datetime | None]
    last_used_ip: Mapped[str | None] = mapped_column(INET)
    revoked_at: Mapped[datetime | None]
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
