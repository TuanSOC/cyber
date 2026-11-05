"""IOC collections of a case (migration 0012, M6 phase 1, FROZEN).

- `ioc_collections`: a named set per case (name unique per case, case-insensitive).
- `ioc_collection_items`: normalized IOCs (`ioc_type`, `value_norm`, `ioc_key` = the M4
  `compute_ioc_key`, so items join `ti_results`), from a job IOC (`job_id` + `ioc_id`) or
  entered manually. Unique per (collection, ioc_key) among items not removed; a removed item
  is soft-removed once (`ioc_collection_item_guard`) and a re-add is a new row.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, UUIDPk

COLLECTION_NAME_MAX_CHARS = 120
COLLECTION_DESCRIPTION_MAX_CHARS = 2_000
ITEM_VALUE_MAX_CHARS = 2_048
ITEM_NOTE_MAX_CHARS = 500
ITEM_SOURCES = ("job_ioc", "manual")


class IocCollection(UUIDPk, Base):
    __tablename__ = "ioc_collections"
    __table_args__ = (
        ForeignKeyConstraint(
            ["investigation_id", "organization_id"],
            ["investigations.id", "investigations.organization_id"],
        ),
        UniqueConstraint("id", "organization_id"),
        Index(
            "ux_ioc_collections_investigation_id_lower_name",
            "investigation_id",
            text("lower(name)"),
            unique=True,
        ),
        CheckConstraint(
            f"char_length(name) BETWEEN 1 AND {COLLECTION_NAME_MAX_CHARS}", name="name_length"
        ),
        CheckConstraint(
            f"char_length(description) <= {COLLECTION_DESCRIPTION_MAX_CHARS}",
            name="description_length",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    investigation_id: Mapped[uuid.UUID]
    name: Mapped[str] = mapped_column(String(COLLECTION_NAME_MAX_CHARS))
    description: Mapped[str] = mapped_column(Text, server_default="", default="")
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    archived_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    __mapper_args__ = {"eager_defaults": True}


class IocCollectionItem(UUIDPk, Base):
    __tablename__ = "ioc_collection_items"
    __table_args__ = (
        ForeignKeyConstraint(
            ["collection_id", "organization_id"],
            ["ioc_collections.id", "ioc_collections.organization_id"],
        ),
        ForeignKeyConstraint(
            ["job_id", "organization_id"],
            ["analysis_jobs.id", "analysis_jobs.organization_id"],
        ),
        Index(
            "ux_ioc_collection_items_collection_id_ioc_key",
            "collection_id",
            "ioc_key",
            unique=True,
            postgresql_where=text("removed_at IS NULL"),
        ),
        Index(None, "organization_id", "ioc_key"),
        CheckConstraint("ioc_key ~ '^[0-9a-f]{64}$'", name="ioc_key"),
        CheckConstraint(
            f"char_length(value_norm) BETWEEN 1 AND {ITEM_VALUE_MAX_CHARS}", name="value_length"
        ),
        CheckConstraint("ioc_type ~ '^[a-z][a-z0-9_]{0,31}$'", name="ioc_type"),
        CheckConstraint(
            "source IN ('job_ioc', 'manual')", name="source"
        ),
        CheckConstraint("(job_id IS NULL) = (ioc_id IS NULL)", name="job_ioc_pair"),
        CheckConstraint("(source = 'job_ioc') = (ioc_id IS NOT NULL)", name="source_matches"),
        CheckConstraint(
            f"note IS NULL OR char_length(note) <= {ITEM_NOTE_MAX_CHARS}", name="note_length"
        ),
        CheckConstraint("(removed_at IS NULL) = (removed_by IS NULL)", name="removed_pair"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    collection_id: Mapped[uuid.UUID]
    ioc_type: Mapped[str] = mapped_column(String(32))
    value_norm: Mapped[str] = mapped_column(String(ITEM_VALUE_MAX_CHARS))
    ioc_key: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(16))
    job_id: Mapped[uuid.UUID | None]
    ioc_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("iocs.id"))
    note: Mapped[str | None] = mapped_column(Text)
    added_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    added_at: Mapped[datetime] = mapped_column(server_default=func.now())
    removed_at: Mapped[datetime | None]
    removed_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
