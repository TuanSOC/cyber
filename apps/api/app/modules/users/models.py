import enum
from datetime import datetime

from sqlalchemy import CheckConstraint, String, Text
from sqlalchemy.dialects.postgresql import CITEXT
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, Timestamps, UUIDPk

# A stored hash starting with this marker never verifies (M7 system user, M11 SSO-only
# users `!sso`, service accounts `!service`); `core.security.verify_password` still runs the
# dummy hash for it (RT5).
UNUSABLE_HASH_PREFIX = "!"


class UserKind(enum.StrEnum):
    """M11 (migration 0019): `service` = the service account of one platform API key (never
    signs in), `system` = the M7 retention user."""

    HUMAN = "human"
    SERVICE = "service"
    SYSTEM = "system"


class User(UUIDPk, Timestamps, Base):
    """Global identity (not tenant-scoped, no RLS)."""

    __tablename__ = "users"
    __table_args__ = (CheckConstraint("kind IN ('human', 'service', 'system')", name="kind"),)

    email: Mapped[str] = mapped_column(CITEXT, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(100))
    is_active: Mapped[bool] = mapped_column(server_default="true", default=True)
    # M11 (0019). Text plus a check (not a PG enum): a kind is never added by a migration race.
    kind: Mapped[str] = mapped_column(Text, server_default="human", default=UserKind.HUMAN.value)
    email_verified_at: Mapped[datetime | None]
    password_changed_at: Mapped[datetime | None]

    @property
    def has_password(self) -> bool:
        """A usable local password (SSO-only, service and system accounts have none)."""
        return bool(self.password_hash) and not self.password_hash.startswith(UNUSABLE_HASH_PREFIX)
