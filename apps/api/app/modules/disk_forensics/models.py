"""Persisted disk forensics results, segment sets and file exports (migration 0017, M9 phase 1,
FROZEN).

Same rules as the pcap / static / memory result tables: written once by the trusted disk
ingest worker in the transaction that marks the job succeeded (or, for `disk_images` and
`disk_partitions`, fails it with a diagnostic stream), SELECT/INSERT only for the app role,
same-tenant composite FK to the job (ON DELETE CASCADE). Findings, IOCs and the timeline share
`analysis_findings`, `iocs` and `analysis_timeline` with every analyzer (the §11
`forensic_artifacts` of a disk job are `disk_files`, `disk_events` and `disk_partitions`).

Addresses and sector numbers are unsigned 64-bit in the contract, so they are NUMERIC(20, 0).
`disk_events.file_id` and `disk_exports.file_id` are soft references (retention deletes the
listing per job).
"""

import enum
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base
from app.modules.pcap_analysis.models import _job_fk, _JobRow

# The two bulk tables (retention DELETE; id, organization_id, job_id on each).
BULK_TABLES = ("disk_files", "disk_events")
TENANT_TABLES = (
    "analysis_job_segments",
    "disk_images",
    "disk_partitions",
    *BULK_TABLES,
    "disk_exports",
)


class DiskExportState(enum.StrEnum):
    PENDING = "pending"
    READY = "ready"
    FAILED = "failed"
    PROMOTED = "promoted"
    EXPIRED = "expired"


class AnalysisJobSegment(Base):
    """One evidence item of a disk job's ordered segment set (ordinal 0 is the job's
    `evidence_id`). Insert-only; every segment is in the job's investigation (trigger)."""

    __tablename__ = "analysis_job_segments"
    __table_args__ = (
        _job_fk(),
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"], ["evidence.id", "evidence.organization_id"]
        ),
        UniqueConstraint("job_id", "evidence_id"),
        Index(None, "evidence_id"),
        Index(None, "organization_id"),
        CheckConstraint("ordinal BETWEEN 0 AND 63", name="ordinal"),
    )

    job_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    ordinal: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    evidence_id: Mapped[uuid.UUID]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class DiskImage(Base):
    """One per disk job that produced a result (full or diagnostic): the image facts, the
    worker-reported media hash status (RT17), and the per-stage status."""

    __tablename__ = "disk_images"
    __table_args__ = (
        _job_fk(),
        Index(None, "organization_id"),
        CheckConstraint("format IN ('raw', 'split_raw', 'ewf')", name="format"),
        CheckConstraint("engine IN ('tsk')", name="engine"),
        CheckConstraint("timeline_engine IN ('plaso', 'replay', 'none')", name="timeline_engine"),
    )

    job_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    format: Mapped[str] = mapped_column(String(16))
    segments: Mapped[int] = mapped_column(SmallInteger)
    media_size: Mapped[Decimal] = mapped_column(Numeric(20, 0))
    sector_size: Mapped[int] = mapped_column(Integer)
    media_sha256: Mapped[str | None] = mapped_column(String(64))
    ewf_md5: Mapped[str | None] = mapped_column(String(32))
    ewf_sha1: Mapped[str | None] = mapped_column(String(40))
    media_hash_status: Mapped[str | None] = mapped_column(String(16))
    ewf_meta: Mapped[dict[str, Any]] = mapped_column(server_default="{}")
    volume_system: Mapped[str | None] = mapped_column(String(16))
    stages: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, server_default="[]")
    counts: Mapped[dict[str, Any]] = mapped_column(server_default="{}")
    tool_versions: Mapped[dict[str, Any]] = mapped_column(server_default="{}")
    hashsets: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, server_default="[]")
    engine: Mapped[str] = mapped_column(String(16))
    timeline_engine: Mapped[str] = mapped_column(String(16))
    truncated: Mapped[bool] = mapped_column(Boolean, server_default="false")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class DiskPartition(_JobRow, Base):
    __tablename__ = "disk_partitions"
    __table_args__ = (
        _job_fk(),
        UniqueConstraint("job_id", "index"),
        CheckConstraint('"index" BETWEEN 0 AND 127', name="index"),
    )

    index: Mapped[int] = mapped_column(SmallInteger)
    start_sector: Mapped[Decimal] = mapped_column(Numeric(20, 0))
    length_sectors: Mapped[Decimal] = mapped_column(Numeric(20, 0))
    description: Mapped[str | None] = mapped_column(Text)
    vs_flags: Mapped[str] = mapped_column(String(16))
    fs_type: Mapped[str | None] = mapped_column(String(16))
    fs_status: Mapped[str] = mapped_column(String(16))
    fs_label: Mapped[str | None] = mapped_column(Text)
    fs_uuid: Mapped[str | None] = mapped_column(Text)
    block_size: Mapped[int | None] = mapped_column(Integer)
    os: Mapped[str] = mapped_column(String(16))
    os_name: Mapped[str | None] = mapped_column(Text)
    error_code: Mapped[str | None] = mapped_column(String(64))
    counts: Mapped[dict[str, Any]] = mapped_column(server_default="{}")


class DiskFile(_JobRow, Base):
    """One directory entry (one name per row; a hard-linked inode has one row per name)."""

    __tablename__ = "disk_files"
    __table_args__ = (
        _job_fk(),
        Index(
            "ix_disk_files_job_id_partition_index_parent_addr_id",
            "job_id",
            "partition_index",
            "parent_addr",
            "id",
        ),
        Index(
            "ix_disk_files_job_id_partition_index_meta_addr",
            "job_id",
            "partition_index",
            "meta_addr",
        ),
        Index("ix_disk_files_job_id_sha256", "job_id", "sha256"),
        Index("ix_disk_files_job_id_mtime_id", "job_id", "mtime", "id"),
        Index("ix_disk_files_job_id_atime_id", "job_id", "atime", "id"),
        Index("ix_disk_files_job_id_ctime_id", "job_id", "ctime", "id"),
        Index("ix_disk_files_job_id_crtime_id", "job_id", "crtime", "id"),
        Index(
            "ix_disk_files_job_id_flags",
            "job_id",
            "flags",
            postgresql_where=text("flags <> 1"),
        ),
        CheckConstraint("flags BETWEEN 0 AND 127", name="flags"),
    )

    partition_index: Mapped[int] = mapped_column(SmallInteger)
    meta_addr: Mapped[Decimal] = mapped_column(Numeric(20, 0))
    meta_seq: Mapped[int | None] = mapped_column(BigInteger)
    stream: Mapped[str | None] = mapped_column(Text)
    path: Mapped[str] = mapped_column(Text)
    parent_addr: Mapped[Decimal | None] = mapped_column(Numeric(20, 0))
    name: Mapped[str] = mapped_column(Text)
    ext: Mapped[str | None] = mapped_column(String(32))
    type: Mapped[str] = mapped_column(String(8))
    flags: Mapped[int] = mapped_column(SmallInteger)
    size: Mapped[int | None] = mapped_column(BigInteger)
    mode: Mapped[int | None] = mapped_column(Integer)
    uid: Mapped[int | None] = mapped_column(BigInteger)
    gid: Mapped[int | None] = mapped_column(BigInteger)
    mtime: Mapped[datetime | None]
    atime: Mapped[datetime | None]
    ctime: Mapped[datetime | None]
    crtime: Mapped[datetime | None]
    time_basis: Mapped[str] = mapped_column(String(16), server_default="utc")
    magic: Mapped[str | None] = mapped_column(String(16))
    hash_status: Mapped[str | None] = mapped_column(String(16))
    md5: Mapped[str | None] = mapped_column(String(32))
    sha1: Mapped[str | None] = mapped_column(String(40))
    sha256: Mapped[str | None] = mapped_column(String(64))
    known: Mapped[str | None] = mapped_column(String(8))
    known_set: Mapped[str | None] = mapped_column(String(64))
    yara_rules: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default="{}")


class DiskEvent(_JobRow, Base):
    __tablename__ = "disk_events"
    __table_args__ = (
        _job_fk(),
        Index("ix_disk_events_job_id_ts_id", "job_id", "ts", "id"),
        Index("ix_disk_events_job_id_artifact_ts_id", "job_id", "artifact", "ts", "id"),
    )

    ts: Mapped[datetime]
    ts_desc: Mapped[str] = mapped_column(String(64))
    artifact: Mapped[str] = mapped_column(String(32))
    parser: Mapped[str] = mapped_column(String(64))
    data_type: Mapped[str] = mapped_column(String(64))
    partition_index: Mapped[int] = mapped_column(SmallInteger)
    path: Mapped[str] = mapped_column(Text)
    file_id: Mapped[uuid.UUID | None]  # soft reference to disk_files.id
    ordinal: Mapped[int] = mapped_column(BigInteger)
    message: Mapped[str] = mapped_column(Text)
    attributes: Mapped[dict[str, Any]] = mapped_column(server_default="{}")


class DiskExport(Base):
    """One allocated file copied out of an image by an `extract` job (phase 10); promoted to
    derived evidence through the evidence pipeline. Forward-only states (trigger)."""

    __tablename__ = "disk_exports"
    __table_args__ = (
        ForeignKeyConstraint(
            ["export_job_id", "organization_id"],
            ["analysis_jobs.id", "analysis_jobs.organization_id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["source_job_id", "organization_id"],
            ["analysis_jobs.id", "analysis_jobs.organization_id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"], ["evidence.id", "evidence.organization_id"]
        ),
        UniqueConstraint("id", "organization_id"),
        Index(None, "source_job_id", "created_at"),
        Index(None, "export_job_id"),
        Index(None, "state", "created_at"),
        Index(None, "organization_id"),
        CheckConstraint(
            "state IN ('pending', 'ready', 'failed', 'promoted', 'expired')", name="state"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, server_default=func.gen_random_uuid()
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    export_job_id: Mapped[uuid.UUID]
    source_job_id: Mapped[uuid.UUID]
    file_id: Mapped[uuid.UUID]  # soft reference to disk_files.id
    path: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(16), server_default=DiskExportState.PENDING.value)
    object_key: Mapped[str | None] = mapped_column(Text)
    object_version_id: Mapped[str | None] = mapped_column(String(255))
    size: Mapped[int | None] = mapped_column(BigInteger)
    worker_sha256: Mapped[str | None] = mapped_column(String(64))
    evidence_id: Mapped[uuid.UUID | None]
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    promoted_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    promoted_at: Mapped[datetime | None]
    error_code: Mapped[str | None] = mapped_column(String(64))
    object_deleted_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
