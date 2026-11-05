"""Analyst-confirmed ATT&CK mappings of a case (migration 0012, M6 phase 1, FROZEN).

One row per (case, technique): `confirmed | suspected | rejected`, a plain-text rationale and
up to 32 source refs (capability / finding / AI run descriptors). Suggestions are never
written here automatically; an analyst request creates every row.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, UUIDPk

MAPPING_STATUSES = ("confirmed", "suspected", "rejected")
RATIONALE_MAX_CHARS = 2_000
MAX_SOURCES = 32
SOURCES_MAX_BYTES = 16 * 1024
TECHNIQUE_PATTERN = r"^T\d{4}(\.\d{3})?$"


class CaseAttackMapping(UUIDPk, Base):
    __tablename__ = "case_attack_mappings"
    __table_args__ = (
        ForeignKeyConstraint(
            ["investigation_id", "organization_id"],
            ["investigations.id", "investigations.organization_id"],
        ),
        UniqueConstraint("id", "organization_id"),
        UniqueConstraint("investigation_id", "technique_id"),
        Index(None, "organization_id"),
        CheckConstraint(f"technique_id ~ '{TECHNIQUE_PATTERN}'", name="technique_id"),
        CheckConstraint("status IN ('confirmed', 'suspected', 'rejected')", name="status"),
        CheckConstraint(
            f"char_length(rationale) <= {RATIONALE_MAX_CHARS}", name="rationale_length"
        ),
        CheckConstraint(
            f"jsonb_typeof(sources) = 'array' AND jsonb_array_length(sources) <= {MAX_SOURCES} "
            f"AND octet_length(sources::text) <= {SOURCES_MAX_BYTES}",
            name="sources",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    investigation_id: Mapped[uuid.UUID]
    technique_id: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16))
    rationale: Mapped[str] = mapped_column(Text, server_default="", default="")
    sources: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, server_default="[]", default=list)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    updated_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    __mapper_args__ = {"eager_defaults": True}
