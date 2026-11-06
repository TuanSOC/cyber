"""Persisted reverse-engineering results (migration 0018, M10 phase 1, FROZEN).

Same rules as the other analyzers' result tables: written once by the trusted ingest worker in
the transaction that marks the job succeeded (or, for `re_programs`, fails it with a
diagnostic stream), SELECT/INSERT only for the app role, same-tenant composite FK to the job
(ON DELETE CASCADE). Findings and IOCs share `analysis_findings` and `iocs` with every
analyzer. Decompiled code is never copied into findings, reports, the search index or the
timeline (plan "Storage of large outputs").

Addresses are unsigned 64-bit in the contract, so they are NUMERIC(20, 0). Function entries
are engine virtual addresses; `re_function_capabilities.file_va` is the joined file virtual
address (RT8).
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
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base
from app.modules.pcap_analysis.models import _job_fk, _JobRow

# The bulk tables (retention DELETE; id, organization_id, job_id on each).
BULK_TABLES = (
    "re_functions",
    "re_call_edges",
    "re_imports",
    "re_import_refs",
    "re_strings",
    "re_string_refs",
    "re_decompilations",
    "re_function_capabilities",
)
TENANT_TABLES = ("re_programs", *BULK_TABLES)


class FunctionDecompileStatus(enum.StrEnum):
    """`re_functions.decompile_status`: the contract's `DecompileStatus` plus `not_selected`
    (the function was not on the decompile list, or the profile is `quick`)."""

    OK = "ok"
    TIMEOUT = "timeout"
    FAILED = "failed"
    TRUNCATED = "truncated"
    SKIPPED_BUDGET = "skipped_budget"
    NOT_SELECTED = "not_selected"


def _address(*, nullable: bool = False) -> Mapped[Any]:
    return mapped_column(Numeric(20, 0), nullable=nullable)


class ReProgram(Base):
    """One per RE job that produced a result (full or diagnostic)."""

    __tablename__ = "re_programs"
    __table_args__ = (
        _job_fk(),
        Index(None, "organization_id"),
        CheckConstraint("format IN ('pe', 'elf')", name="format"),
        CheckConstraint("arch IN ('x86', 'x86_64', 'other')", name="arch"),
        CheckConstraint("engine IN ('ghidra', 'radare2', 'replay')", name="engine"),
        CheckConstraint("code_kind IN ('pseudo_c', 'disasm')", name="code_kind"),
    )

    job_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    format: Mapped[str] = mapped_column(String(8))
    arch: Mapped[str] = mapped_column(String(16))
    machine: Mapped[str | None] = mapped_column(String(64))
    bits: Mapped[int] = mapped_column(SmallInteger)
    endianness: Mapped[str] = mapped_column(String(8))
    language_id: Mapped[str | None] = mapped_column(String(64))
    compiler_spec: Mapped[str | None] = mapped_column(String(32))
    image_base: Mapped[Decimal] = _address()
    preferred_base: Mapped[Decimal] = _address()  # RT8
    entry: Mapped[Decimal | None] = _address(nullable=True)
    analysis_status: Mapped[str] = mapped_column(String(16))
    peak_memory_bytes: Mapped[int | None] = mapped_column(BigInteger)  # cgroup (RT14)
    engine: Mapped[str] = mapped_column(String(16))
    engine_version: Mapped[str | None] = mapped_column(String(32))
    code_kind: Mapped[str] = mapped_column(String(16))
    stages: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, server_default="[]")
    counts: Mapped[dict[str, Any]] = mapped_column(server_default="{}")
    truncated: Mapped[dict[str, Any]] = mapped_column(server_default="{}")
    tool_versions: Mapped[dict[str, Any]] = mapped_column(server_default="{}")
    audit: Mapped[dict[str, Any]] = mapped_column(server_default="{}")
    jvm_args: Mapped[list[str]] = mapped_column(JSONB, server_default="[]")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class ReFunction(_JobRow, Base):
    __tablename__ = "re_functions"
    __table_args__ = (
        _job_fk(),
        UniqueConstraint("job_id", "entry"),
        Index(None, "job_id", "name"),
        Index(None, "job_id", "priority_rank"),
    )

    entry: Mapped[Decimal] = _address()
    rva: Mapped[Decimal] = _address()
    name: Mapped[str] = mapped_column(String(255))
    name_source: Mapped[str] = mapped_column(String(16))
    size: Mapped[int] = mapped_column(BigInteger)
    body: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, server_default="[]")
    body_truncated: Mapped[bool] = mapped_column(Boolean, server_default="false")
    is_thunk: Mapped[bool] = mapped_column(Boolean, server_default="false")
    is_external: Mapped[bool] = mapped_column(Boolean, server_default="false")
    is_library: Mapped[bool] = mapped_column(Boolean, server_default="false")
    signature: Mapped[str | None] = mapped_column(String(512))
    calling_convention: Mapped[str | None] = mapped_column(String(32))
    instructions: Mapped[int] = mapped_column(BigInteger)
    callers: Mapped[int] = mapped_column(BigInteger)
    callees: Mapped[int] = mapped_column(BigInteger)
    decompile_status: Mapped[str] = mapped_column(String(16))
    priority_rank: Mapped[int | None] = mapped_column(Integer)


class ReCallEdge(_JobRow, Base):
    __tablename__ = "re_call_edges"
    __table_args__ = (
        _job_fk(),
        UniqueConstraint("job_id", "caller_entry", "callee_entry"),
        Index(None, "job_id", "callee_entry"),
    )

    caller_entry: Mapped[Decimal] = _address()
    callee_entry: Mapped[Decimal] = _address()
    sites: Mapped[int] = mapped_column(BigInteger)


class ReImport(_JobRow, Base):
    __tablename__ = "re_imports"
    __table_args__ = (
        _job_fk(),
        UniqueConstraint("id", "organization_id"),
        Index(None, "job_id", "library", "name"),
    )

    library: Mapped[str] = mapped_column(String(128))
    name: Mapped[str | None] = mapped_column(String(255))
    ordinal: Mapped[int | None] = mapped_column(Integer)
    address: Mapped[Decimal | None] = _address(nullable=True)


class ReImportRef(_JobRow, Base):
    __tablename__ = "re_import_refs"
    __table_args__ = (
        _job_fk(),
        ForeignKeyConstraint(
            ["import_id", "organization_id"],
            ["re_imports.id", "re_imports.organization_id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("import_id", "function_entry"),
        Index(None, "job_id", "function_entry"),
    )

    import_id: Mapped[uuid.UUID]
    function_entry: Mapped[Decimal] = _address()
    count: Mapped[int] = mapped_column(BigInteger)


class ReString(_JobRow, Base):
    __tablename__ = "re_strings"
    __table_args__ = (
        _job_fk(),
        UniqueConstraint("id", "organization_id"),
        Index(None, "job_id", "address"),
    )

    address: Mapped[Decimal] = _address()
    encoding: Mapped[str] = mapped_column(String(8))
    value: Mapped[str] = mapped_column(String(1024))
    length: Mapped[int] = mapped_column(BigInteger)


class ReStringRef(_JobRow, Base):
    __tablename__ = "re_string_refs"
    __table_args__ = (
        _job_fk(),
        ForeignKeyConstraint(
            ["string_id", "organization_id"],
            ["re_strings.id", "re_strings.organization_id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("string_id", "function_entry"),
        Index(None, "job_id", "function_entry"),
    )

    string_id: Mapped[uuid.UUID]
    function_entry: Mapped[Decimal] = _address()
    count: Mapped[int] = mapped_column(BigInteger)


class ReDecompilation(_JobRow, Base):
    __tablename__ = "re_decompilations"
    __table_args__ = (_job_fk(), UniqueConstraint("job_id", "function_entry"))

    function_entry: Mapped[Decimal] = _address()
    status: Mapped[str] = mapped_column(String(16))
    code_kind: Mapped[str] = mapped_column(String(16))
    code: Mapped[str | None] = mapped_column(Text)  # <= 65 536 octets (0018 check)
    lines: Mapped[int] = mapped_column(Integer)
    code_sha256: Mapped[str | None] = mapped_column(String(64))
    truncated_bytes: Mapped[int] = mapped_column(BigInteger, server_default="0")
    duration_ms: Mapped[int] = mapped_column(BigInteger, server_default="0")


class ReFunctionCapability(_JobRow, Base):
    """A capa capability of the source static job located in this function (RT8 join)."""

    __tablename__ = "re_function_capabilities"
    __table_args__ = (
        # The conventional names would exceed Postgres' 63-character identifier limit.
        ForeignKeyConstraint(
            ["job_id", "organization_id"],
            ["analysis_jobs.id", "analysis_jobs.organization_id"],
            ondelete="CASCADE",
            name="fk_re_function_capabilities_job_id_analysis_jobs",
        ),
        ForeignKeyConstraint(
            ["capability_id", "organization_id"],
            ["malware_capabilities.id", "malware_capabilities.organization_id"],
            ondelete="CASCADE",
            name="fk_re_function_capabilities_capability_id_malware_capabilities",
        ),
        UniqueConstraint("job_id", "capability_id", "function_entry"),
        Index(None, "capability_id"),
        Index(None, "job_id", "function_entry"),
    )

    function_entry: Mapped[Decimal] = _address()
    capability_id: Mapped[uuid.UUID]
    file_va: Mapped[Decimal] = _address()


RESULT_TABLES = (
    ReProgram,
    ReFunction,
    ReCallEdge,
    ReImport,
    ReImportRef,
    ReString,
    ReStringRef,
    ReDecompilation,
    ReFunctionCapability,
)
