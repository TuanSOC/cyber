"""Persisted memory forensics results and the per-evidence memory sensitivity (migration 0016,
M8 phase 1, FROZEN).

Same rules as the pcap / static result tables: written once by the trusted ingest worker in
the transaction that marks the job succeeded (or, for `memory_images`, fails it
`symbols_missing`), SELECT/INSERT only for the app role, same-tenant composite FK to the job
(ON DELETE CASCADE). Findings, IOCs and the timeline share `analysis_findings`, `iocs` and
`analysis_timeline` with every analyzer (the §11 `memory_findings` are `analysis_findings`
of a memory job; the §11 `forensic_artifacts` are `memory_artifacts`).

Addresses are unsigned 64-bit in the contract, so they are NUMERIC(20, 0).
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
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base
from app.modules.pcap_analysis.models import _in, _job_fk, _JobRow

ARTIFACT_TYPES = (
    "module",
    "service",
    "hive",
    "userassist",
    "ldr_unlinked",
    "bash",
    "open_file",
    "syscall_hook",
    "hidden_module",
)
# memory_processes.sources bitmask.
SOURCE_BITS = {"pslist": 1, "psscan": 2, "pstree": 4}
# The four bulk tables (retention DELETE; RT23: id, organization_id, job_id on each).
BULK_TABLES = ("memory_processes", "memory_connections", "memory_injections", "memory_artifacts")


class SensitivityState(enum.StrEnum):
    RESTRICTED = "restricted"
    RELEASED = "released"


class MemoryImage(Base):
    """One per memory job that produced a result (full or diagnostic): the image facts, the
    symbols outcome (with the requirement when missing) and the per-plugin status."""

    __tablename__ = "memory_images"
    __table_args__ = (
        _job_fk(),
        Index(None, "organization_id"),
        CheckConstraint("os IN ('windows', 'linux')", name="os"),
        CheckConstraint("engine IN ('volatility3', 'replay')", name="engine"),
        CheckConstraint("symbols_status IN ('resolved', 'missing')", name="symbols_status"),
    )

    job_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    os: Mapped[str] = mapped_column(String(16))
    arch: Mapped[str | None] = mapped_column(String(8))
    layer: Mapped[str | None] = mapped_column(String(64))
    engine: Mapped[str] = mapped_column(String(16))
    nt_build: Mapped[str | None] = mapped_column(String(64))
    kernel_banner: Mapped[str | None] = mapped_column(Text)
    pdb_name: Mapped[str | None] = mapped_column(String(32))
    pdb_guid: Mapped[str | None] = mapped_column(String(32))
    pdb_age: Mapped[int | None] = mapped_column(Integer)
    system_time: Mapped[datetime | None]
    symbols_status: Mapped[str] = mapped_column(String(16))
    isf_sha256: Mapped[str | None] = mapped_column(String(64))
    volatility_version: Mapped[str | None] = mapped_column(String(64))
    plugins: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, server_default="[]")
    counts: Mapped[dict[str, Any]] = mapped_column(server_default="{}")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class MemoryProcess(_JobRow, Base):
    __tablename__ = "memory_processes"
    __table_args__ = (
        _job_fk(),
        Index("ix_memory_processes_job_id_ppid", "job_id", "ppid"),
        CheckConstraint("sources BETWEEN 1 AND 7", name="sources"),
    )

    pid: Mapped[int] = mapped_column(BigInteger)
    ppid: Mapped[int | None] = mapped_column(BigInteger)
    name: Mapped[str] = mapped_column(String(64))
    offset: Mapped[Decimal | None] = mapped_column(Numeric(20, 0))
    create_time: Mapped[datetime | None]
    exit_time: Mapped[datetime | None]
    threads: Mapped[int | None] = mapped_column(BigInteger)
    handles: Mapped[int | None] = mapped_column(BigInteger)
    session_id: Mapped[int | None] = mapped_column(BigInteger)
    wow64: Mapped[bool | None] = mapped_column(Boolean)
    sources: Mapped[int] = mapped_column(SmallInteger)
    cmdline: Mapped[str | None] = mapped_column(Text)
    image_path: Mapped[str | None] = mapped_column(Text)


class MemoryConnection(_JobRow, Base):
    __tablename__ = "memory_connections"
    __table_args__ = (
        _job_fk(),
        Index("ix_memory_connections_job_id_pid", "job_id", "pid"),
        CheckConstraint(_in("proto", ("tcp", "udp", "raw", "unix", "other")), name="proto"),
    )

    proto: Mapped[str] = mapped_column(String(8))
    local_addr: Mapped[str | None] = mapped_column(INET)
    local_port: Mapped[int | None] = mapped_column(Integer)
    remote_addr: Mapped[str | None] = mapped_column(INET)
    remote_port: Mapped[int | None] = mapped_column(Integer)
    state: Mapped[str | None] = mapped_column(String(16))
    pid: Mapped[int | None] = mapped_column(BigInteger)
    owner: Mapped[str | None] = mapped_column(String(64))
    created: Mapped[datetime | None]
    offset: Mapped[Decimal | None] = mapped_column(Numeric(20, 0))


class MemoryInjection(_JobRow, Base):
    __tablename__ = "memory_injections"
    __table_args__ = (_job_fk(), Index("ix_memory_injections_job_id_pid", "job_id", "pid"))

    pid: Mapped[int] = mapped_column(BigInteger)
    process: Mapped[str | None] = mapped_column(String(64))
    start: Mapped[Decimal] = mapped_column(Numeric(20, 0))
    end: Mapped[Decimal] = mapped_column(Numeric(20, 0))
    protection: Mapped[str | None] = mapped_column(String(64))
    tag: Mapped[str | None] = mapped_column(String(16))
    private: Mapped[bool | None] = mapped_column(Boolean)
    commit_charge: Mapped[int | None] = mapped_column(BigInteger)
    has_pe: Mapped[bool] = mapped_column(Boolean, server_default="false")
    head_hex: Mapped[str] = mapped_column(String(128), server_default="")
    disasm: Mapped[str | None] = mapped_column(Text)


class MemoryArtifact(_JobRow, Base):
    __tablename__ = "memory_artifacts"
    __table_args__ = (
        _job_fk(),
        Index("ix_memory_artifacts_job_id_type_id", "job_id", "type", "id"),
        CheckConstraint(_in("type", ARTIFACT_TYPES), name="type"),
    )

    type: Mapped[str] = mapped_column(String(16))
    pid: Mapped[int | None] = mapped_column(BigInteger)
    attributes: Mapped[dict[str, Any]] = mapped_column(server_default="{}")


class MemorySensitivity(Base):
    """TLP:RED-by-default marker of evidence that is (or was analyzed as) a memory image.

    Inserted `restricted` by the upload (`kind=memory`) or the first memory job
    (`apply_memory_default`, phase 8), together with the M6 share policy flags; released once
    by an admin (`restricted -> released`, trigger). Never deleted.
    """

    __tablename__ = "memory_sensitivity"
    __table_args__ = (
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"], ["evidence.id", "evidence.organization_id"]
        ),
        Index(None, "organization_id"),
        CheckConstraint("state IN ('restricted', 'released')", name="state"),
    )

    evidence_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    state: Mapped[str] = mapped_column(
        String(16), server_default=SensitivityState.RESTRICTED.value
    )
    defaulted_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    defaulted_at: Mapped[datetime] = mapped_column(server_default=func.now())
    released_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    released_at: Mapped[datetime | None]
    release_reason: Mapped[str | None] = mapped_column(Text)
