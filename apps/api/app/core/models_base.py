import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Enum, MetaData, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map = {
        dict[str, Any]: JSONB(none_as_null=True),
        datetime: DateTime(timezone=True),
    }


def pg_enum(enum_cls: type[enum.Enum], name: str) -> Enum:
    """Postgres ENUM storing the members' lowercase values (not their names)."""
    return Enum(enum_cls, name=name, values_callable=lambda e: [m.value for m in e])


class UUIDPk:
    # Client-side default so ids are known before flush; server default for raw SQL inserts.
    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=func.gen_random_uuid()
    )


class CreatedAt:
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Timestamps(CreatedAt):
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    # Fetch updated_at via RETURNING on flush, so it is loaded (not expired) when the
    # response is built after the tenant_session block has committed.
    __mapper_args__ = {"eager_defaults": True}
