"""Analyst notes (migration 0012, M6 phase 1, FROZEN).

- `analyst_notes`: the logical note of a case: creator, `current_version`, `pinned`,
  `include_in_reports`, soft delete. A guard trigger keeps `current_version` monotonic, sets
  the delete fields once, and keeps the identity columns immutable.
- `analyst_note_versions`: every body / refs edit as a new row (append-only, also for the
  owner). A deleted note keeps its versions, so the history stays readable (§10).
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    PrimaryKeyConstraint,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, UUIDPk

NOTE_BODY_MAX_CHARS = 20_000
NOTE_MAX_REFS = 20
NOTE_REFS_MAX_BYTES = 16 * 1024
NOTE_REF_KINDS = (
    "finding",
    "alert",
    "ioc",
    "evidence",
    "job",
    "timeline",
    "capability",
    "signature",
)


class AnalystNote(UUIDPk, Base):
    __tablename__ = "analyst_notes"
    __table_args__ = (
        ForeignKeyConstraint(
            ["investigation_id", "organization_id"],
            ["investigations.id", "investigations.organization_id"],
        ),
        UniqueConstraint("id", "organization_id"),
        Index(None, "investigation_id", "created_at"),
        CheckConstraint("current_version >= 1", name="current_version_positive"),
        CheckConstraint("(deleted_at IS NULL) = (deleted_by IS NULL)", name="deleted_pair"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    investigation_id: Mapped[uuid.UUID]
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    current_version: Mapped[int] = mapped_column(Integer, server_default="1", default=1)
    pinned: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)
    include_in_reports: Mapped[bool] = mapped_column(
        Boolean, server_default="false", default=False
    )
    deleted_at: Mapped[datetime | None]
    deleted_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    __mapper_args__ = {"eager_defaults": True}


class AnalystNoteVersion(Base):
    __tablename__ = "analyst_note_versions"
    __table_args__ = (
        PrimaryKeyConstraint("note_id", "version"),
        ForeignKeyConstraint(
            ["note_id", "organization_id"],
            ["analyst_notes.id", "analyst_notes.organization_id"],
        ),
        Index(None, "organization_id"),
        CheckConstraint("version >= 1", name="version_positive"),
        CheckConstraint(
            f"char_length(body) BETWEEN 1 AND {NOTE_BODY_MAX_CHARS}", name="body_length"
        ),
        CheckConstraint(
            f"jsonb_typeof(refs) = 'array' AND jsonb_array_length(refs) <= {NOTE_MAX_REFS} "
            f"AND octet_length(refs::text) <= {NOTE_REFS_MAX_BYTES}",
            name="refs",
        ),
    )

    note_id: Mapped[uuid.UUID]
    version: Mapped[int] = mapped_column(Integer)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    body: Mapped[str] = mapped_column(Text)
    # [{kind, ref_id, job_id?}], re-checked in the case scope on write.
    refs: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, server_default="[]", default=list)
    author_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
