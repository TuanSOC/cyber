"""Persisted static analysis results (one set of rows per succeeded `static` job).

Same rules as the pcap result tables: written once by the trusted ingest worker in the
transaction that marks the job succeeded, SELECT/INSERT only for the app role, same-tenant
composite FK to the job (ON DELETE CASCADE). Findings and IOCs share `analysis_findings`
and `iocs` with every analyzer (the §11 `malware_findings` is `analysis_findings` of a job
whose analyzer is `static`).

Addresses (RVAs / VAs) are unsigned 64-bit in the contract, so they are NUMERIC(20, 0):
a bigint cannot hold the upper half.
"""

from decimal import Decimal
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Double,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base
from app.modules.pcap_analysis.models import _in, _job_fk, _JobRow

FILE_FORMATS = ("pe", "elf", "other")
STRING_ENCODINGS = ("ascii", "utf16le", "floss_decoded", "floss_stack", "floss_tight")
SIGNATURE_ENGINES = ("clamav", "yara")


def _address() -> Mapped[Decimal]:
    return mapped_column(Numeric(20, 0))


class MalwareSample(_JobRow, Base):
    """The analyzed file as the analyzer saw it. Its sha256 and size equal the evidence
    record (ingest refuses the result otherwise); ssdeep and the PE hashes in `pe` are
    analyzer-derived."""

    __tablename__ = "malware_samples"
    __table_args__ = (
        _job_fk(),
        UniqueConstraint("job_id"),  # exactly one per job
        CheckConstraint(_in("file_format", FILE_FORMATS), name="file_format"),
    )

    size: Mapped[int] = mapped_column(BigInteger)
    md5: Mapped[str] = mapped_column(String(32))
    sha1: Mapped[str] = mapped_column(String(40))
    sha256: Mapped[str] = mapped_column(String(64))
    ssdeep: Mapped[str | None] = mapped_column(String(128))
    file_type: Mapped[str | None] = mapped_column(String(255))
    mime: Mapped[str | None] = mapped_column(String(128))
    entropy: Mapped[float] = mapped_column(Double)
    file_format: Mapped[str] = mapped_column(String(8))
    pe: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    elf: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class MalwareSection(_JobRow, Base):
    __tablename__ = "malware_sections"
    __table_args__ = (_job_fk(), Index("ix_malware_sections_job_id_index", "job_id", "index"))

    index: Mapped[int] = mapped_column(BigInteger)
    name: Mapped[str] = mapped_column(String(64))
    virtual_address: Mapped[Decimal] = _address()
    virtual_size: Mapped[int] = mapped_column(BigInteger)
    raw_size: Mapped[int] = mapped_column(BigInteger)
    entropy: Mapped[float] = mapped_column(Double)
    flags: Mapped[list[str]] = mapped_column(JSONB)


class MalwareImport(_JobRow, Base):
    __tablename__ = "malware_imports"
    __table_args__ = (
        _job_fk(),
        Index("ix_malware_imports_job_id_library", "job_id", "library"),
    )

    library: Mapped[str] = mapped_column(String(255))
    function: Mapped[str | None] = mapped_column(String(255))
    ordinal: Mapped[int | None] = mapped_column(Integer)


class MalwareExport(_JobRow, Base):
    __tablename__ = "malware_exports"
    __table_args__ = (_job_fk(), Index("ix_malware_exports_job_id_ordinal", "job_id", "ordinal"))

    name: Mapped[str | None] = mapped_column(String(255))
    ordinal: Mapped[int] = mapped_column(BigInteger)  # unsigned 32-bit in the contract
    address: Mapped[Decimal] = _address()


class MalwareResource(_JobRow, Base):
    __tablename__ = "malware_resources"
    __table_args__ = (_job_fk(), Index("ix_malware_resources_job_id_type", "job_id", "type"))

    type: Mapped[str] = mapped_column(String(64))
    name: Mapped[str | None] = mapped_column(String(255))
    language: Mapped[str | None] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(BigInteger)
    entropy: Mapped[float] = mapped_column(Double)
    sha256: Mapped[str | None] = mapped_column(String(64))


class MalwareString(_JobRow, Base):
    __tablename__ = "malware_strings"
    __table_args__ = (
        _job_fk(),
        Index("ix_malware_strings_job_id_encoding", "job_id", "encoding"),
        CheckConstraint(_in("encoding", STRING_ENCODINGS), name="encoding"),
    )

    value: Mapped[str] = mapped_column(String(512))
    encoding: Mapped[str] = mapped_column(String(16))
    offset: Mapped[int | None] = mapped_column(BigInteger)


class MalwareSignatureMatch(_JobRow, Base):
    """An engine signature/rule matched (name verbatim from the engine; not a verdict)."""

    __tablename__ = "malware_signature_matches"
    __table_args__ = (
        # The conventional name would exceed Postgres' 63-character identifier limit.
        ForeignKeyConstraint(
            ["job_id", "organization_id"],
            ["analysis_jobs.id", "analysis_jobs.organization_id"],
            ondelete="CASCADE",
            name="fk_malware_signature_matches_job_id_analysis_jobs",
        ),
        Index("ix_malware_signature_matches_job_id_engine", "job_id", "engine"),
        CheckConstraint(_in("engine", SIGNATURE_ENGINES), name="engine"),
    )

    engine: Mapped[str] = mapped_column(String(8))
    name: Mapped[str] = mapped_column(String(255))
    namespace: Mapped[str | None] = mapped_column(String(128))
    tags: Mapped[list[str]] = mapped_column(JSONB)
    meta: Mapped[dict[str, Any]]


class MalwareCapability(_JobRow, Base):
    """A capa rule match: a static capability, not observed behaviour."""

    __tablename__ = "malware_capabilities"
    __table_args__ = (
        _job_fk(),
        Index("ix_malware_capabilities_job_id_namespace", "job_id", "namespace"),
    )

    name: Mapped[str] = mapped_column(String(255))
    namespace: Mapped[str | None] = mapped_column(String(255))
    attack: Mapped[list[str]] = mapped_column(JSONB)
    mbc: Mapped[list[str]] = mapped_column(JSONB)
    matches: Mapped[int] = mapped_column(BigInteger)


RESULT_TABLES = (
    MalwareSample,
    MalwareSection,
    MalwareImport,
    MalwareExport,
    MalwareResource,
    MalwareString,
    MalwareSignatureMatch,
    MalwareCapability,
)
