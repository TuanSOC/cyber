from sqlalchemy import String
from sqlalchemy.dialects.postgresql import CITEXT
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, Timestamps, UUIDPk


class User(UUIDPk, Timestamps, Base):
    """Global identity (not tenant-scoped, no RLS)."""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(CITEXT, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(100))
    is_active: Mapped[bool] = mapped_column(server_default="true", default=True)
