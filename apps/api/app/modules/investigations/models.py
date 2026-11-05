import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, Timestamps, UUIDPk, pg_enum


class InvestigationStatus(enum.StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"
    ARCHIVED = "archived"


class Severity(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# TLP 2.0 labels (FIRST), least to most restrictive; the order lives in
# `cyberlab_jobs.report.TLP_ORDER` (M6, migration 0012). Text with a CHECK, as in M4/M5.
TLP_VALUES = ("clear", "green", "amber", "amber_strict", "red")
STATUS_VALUES = tuple(s.value for s in InvestigationStatus)
STATUS_REASON_MAX_CHARS = 500


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class Investigation(UUIDPk, Timestamps, Base):
    __tablename__ = "investigations"
    __table_args__ = (
        UniqueConstraint("organization_id", "case_number"),
        # Target for composite FKs that pin child rows to the same tenant.
        UniqueConstraint("id", "organization_id"),
        Index(None, "organization_id", "created_at"),
        CheckConstraint(_in("tlp", TLP_VALUES), name="tlp"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    case_number: Mapped[int]
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, server_default="", default="")
    status: Mapped[InvestigationStatus] = mapped_column(
        pg_enum(InvestigationStatus, "investigation_status"),
        server_default=InvestigationStatus.OPEN.value,
        default=InvestigationStatus.OPEN,
    )
    severity: Mapped[Severity] = mapped_column(pg_enum(Severity, "severity"))
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    # M6: TLP 2.0 marking and the share policy flags (TLP:RED implies both, computed).
    tlp: Mapped[str] = mapped_column(String(16), server_default="amber", default="amber")
    ai_excluded: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)
    ti_excluded: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)


class InvestigationStatusEvent(UUIDPk, Base):
    """One status change of a case (append-only, M6): feeds the case timeline and reports."""

    __tablename__ = "investigation_status_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["investigation_id", "organization_id"],
            ["investigations.id", "investigations.organization_id"],
        ),
        Index(None, "investigation_id", "occurred_at"),
        CheckConstraint(
            f"from_status IS NULL OR {_in('from_status', STATUS_VALUES)}", name="from_status"
        ),
        CheckConstraint(_in("to_status", STATUS_VALUES), name="to_status"),
        CheckConstraint(
            f"reason IS NULL OR char_length(reason) BETWEEN 1 AND {STATUS_REASON_MAX_CHARS}",
            name="reason_length",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    investigation_id: Mapped[uuid.UUID]
    from_status: Mapped[str | None] = mapped_column(String(16))
    to_status: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str | None] = mapped_column(Text)
    actor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    occurred_at: Mapped[datetime] = mapped_column(server_default=func.now())


class EvidenceSharePolicy(Base):
    """Per-evidence "do not send to AI / TI" flags (M6). A separate table, so the
    `evidence_immutable` trigger of the evidence row is never touched."""

    __tablename__ = "evidence_share_policies"
    __table_args__ = (
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"], ["evidence.id", "evidence.organization_id"]
        ),
        Index(None, "organization_id"),
    )

    evidence_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    ai_excluded: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)
    ti_excluded: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)
    updated_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    __mapper_args__ = {"eager_defaults": True}
