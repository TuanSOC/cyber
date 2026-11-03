import enum
import uuid

from sqlalchemy import ForeignKey, Index, String, Text, UniqueConstraint
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


class Investigation(UUIDPk, Timestamps, Base):
    __tablename__ = "investigations"
    __table_args__ = (
        UniqueConstraint("organization_id", "case_number"),
        # Target for composite FKs that pin child rows to the same tenant.
        UniqueConstraint("id", "organization_id"),
        Index(None, "organization_id", "created_at"),
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
