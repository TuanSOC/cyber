import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, UUIDPk, pg_enum


class EvidenceStatus(enum.StrEnum):
    ACTIVE = "active"
    ARCHIVED = "archived"


class HashAlgorithm(enum.StrEnum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class CustodyAction(enum.StrEnum):
    UPLOADED = "uploaded"
    DOWNLOADED = "downloaded"
    VERIFIED_OK = "verified_ok"
    VERIFIED_MISMATCH = "verified_mismatch"
    ARCHIVED = "archived"
    ANALYSIS_REQUESTED = "analysis_requested"
    ANALYZED = "analyzed"
    # M7 (migration 0014, RT12): the retention worker purged the bytes (actor: the retention
    # system user); `sent_to_sandbox` is reserved for dynamic analysis (not enabled).
    PURGED = "purged"
    SENT_TO_SANDBOX = "sent_to_sandbox"
    # M9 (migration 0017, phase 10): a file export of a disk job was requested / promoted to
    # derived evidence (on every source segment), and the derivation on the new evidence.
    EXPORT_REQUESTED = "export_requested"
    EXPORT_PROMOTED = "export_promoted"
    DERIVED_FROM = "derived_from"


class Evidence(UUIDPk, Base):
    """Evidence metadata. Storage location and identity columns are immutable (DB trigger)."""

    __tablename__ = "evidence"
    __table_args__ = (
        # Evidence must belong to an investigation of the same tenant.
        ForeignKeyConstraint(
            ["investigation_id", "organization_id"],
            ["investigations.id", "investigations.organization_id"],
        ),
        UniqueConstraint("id", "organization_id"),
        Index(None, "investigation_id"),
        Index(None, "organization_id", "uploaded_at"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    investigation_id: Mapped[uuid.UUID]
    original_filename: Mapped[str] = mapped_column(String(255))
    detected_mime: Mapped[str] = mapped_column(String(255))
    detected_description: Mapped[str] = mapped_column(String(512))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    storage_bucket: Mapped[str] = mapped_column(String(63))
    storage_key: Mapped[str] = mapped_column(String(255), unique=True)
    storage_version_id: Mapped[str] = mapped_column(String(255))
    status: Mapped[EvidenceStatus] = mapped_column(
        pg_enum(EvidenceStatus, "evidence_status"),
        server_default=EvidenceStatus.ACTIVE.value,
        default=EvidenceStatus.ACTIVE,
    )
    description: Mapped[str] = mapped_column(Text, server_default="", default="")
    uploaded_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    uploaded_at: Mapped[datetime] = mapped_column(server_default=func.now())
    # M7 (0014; phase 6 fills them at INSERT): the extension family the filename declares and
    # whether it disagrees with libmagic / the magic routing. Write-once (`evidence_immutable`);
    # NULL on evidence uploaded before M7.
    declared_type: Mapped[str | None] = mapped_column(String(32))
    type_mismatch: Mapped[bool | None]


class EvidenceHash(UUIDPk, Base):
    __tablename__ = "evidence_hashes"
    __table_args__ = (
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"], ["evidence.id", "evidence.organization_id"]
        ),
        UniqueConstraint("evidence_id", "algorithm"),
        Index(None, "organization_id"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    evidence_id: Mapped[uuid.UUID]
    algorithm: Mapped[HashAlgorithm] = mapped_column(pg_enum(HashAlgorithm, "hash_algorithm"))
    value: Mapped[str] = mapped_column(String(128))
    computed_at: Mapped[datetime] = mapped_column(server_default=func.now())


class EvidenceCustodyEvent(UUIDPk, Base):
    __tablename__ = "evidence_custody_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"], ["evidence.id", "evidence.organization_id"]
        ),
        Index(None, "evidence_id", "occurred_at"),
        Index(None, "organization_id"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    evidence_id: Mapped[uuid.UUID]
    action: Mapped[CustodyAction] = mapped_column(pg_enum(CustodyAction, "custody_action"))
    actor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    occurred_at: Mapped[datetime] = mapped_column(server_default=func.now())
    ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(512))
    details: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)
