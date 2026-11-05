"""Persisted PCAP analysis results (one set of rows per succeeded job).

Rows are written once, by the trusted ingest worker, in the same transaction that marks the
job succeeded; the app role may only SELECT and INSERT them. They disappear only with their
job (ON DELETE CASCADE, owner-side). `flow_ref` is deliberately not a foreign key: it may
name a flow the analyzer dropped because of its caps.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Double,
    ForeignKeyConstraint,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base

SEVERITIES = ("info", "low", "medium", "high")
RECORD_KINDS = ("dns", "http", "tls")
FLOW_PROTOS = ("tcp", "udp", "icmp", "other")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _job_fk() -> ForeignKeyConstraint:
    # Same-tenant guarantee: a row can only point at a job of its own organization.
    return ForeignKeyConstraint(
        ["job_id", "organization_id"],
        ["analysis_jobs.id", "analysis_jobs.organization_id"],
        ondelete="CASCADE",
    )


class _JobRow:
    # Server-side ids only: bulk inserts send no per-row Python defaults.
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, server_default=func.gen_random_uuid())
    organization_id: Mapped[uuid.UUID]
    job_id: Mapped[uuid.UUID]


class _Endpoints:
    ts: Mapped[datetime]
    src_ip: Mapped[str | None] = mapped_column(INET)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_ip: Mapped[str | None] = mapped_column(INET)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    flow_ref: Mapped[str | None] = mapped_column(String(64))


def _endpoint_indexes(table: str) -> tuple[Index, ...]:
    return (
        Index(f"ix_{table}_job_id_ts", "job_id", "ts"),
        Index(f"ix_{table}_job_id_src_ip", "job_id", "src_ip"),
        Index(f"ix_{table}_job_id_dst_ip", "job_id", "dst_ip"),
    )


class NetworkFlow(_JobRow, _Endpoints, Base):
    __tablename__ = "network_flows"
    __table_args__ = (
        _job_fk(),
        *_endpoint_indexes("network_flows"),
        Index("ix_network_flows_job_id_total_bytes", "job_id", "total_bytes"),
        # The port filter matches either side (src_port = p OR dst_port = p): BitmapOr.
        Index("ix_network_flows_job_id_src_port", "job_id", "src_port"),
        Index("ix_network_flows_job_id_dst_port", "job_id", "dst_port"),
        CheckConstraint(_in("proto", FLOW_PROTOS), name="proto"),
    )

    proto: Mapped[str] = mapped_column(String(8))
    service: Mapped[str | None] = mapped_column(String(64))
    duration_s: Mapped[float | None] = mapped_column(Double)
    orig_bytes: Mapped[int] = mapped_column(BigInteger)
    resp_bytes: Mapped[int] = mapped_column(BigInteger)
    # orig + resp, clamped to bigint (each side alone may already be near the maximum).
    total_bytes: Mapped[int] = mapped_column(BigInteger)
    orig_pkts: Mapped[int] = mapped_column(BigInteger)
    resp_pkts: Mapped[int] = mapped_column(BigInteger)
    conn_state: Mapped[str | None] = mapped_column(String(16))
    community_id: Mapped[str | None] = mapped_column(String(64))


class NetworkRecord(_JobRow, _Endpoints, Base):
    """DNS / HTTP / TLS transactions: common columns + the kind's fields in `details`."""

    __tablename__ = "network_records"
    __table_args__ = (
        _job_fk(),
        *_endpoint_indexes("network_records"),
        Index("ix_network_records_job_id_kind_ts", "job_id", "kind", "ts"),
        CheckConstraint(_in("kind", RECORD_KINDS), name="kind"),
    )

    kind: Mapped[str] = mapped_column(String(8))
    summary: Mapped[str] = mapped_column(Text)
    details: Mapped[dict[str, Any]]


class NetworkAlert(_JobRow, _Endpoints, Base):
    __tablename__ = "network_alerts"
    __table_args__ = (
        _job_fk(),
        *_endpoint_indexes("network_alerts"),
        Index("ix_network_alerts_job_id_severity", "job_id", "severity"),
        CheckConstraint("severity BETWEEN 1 AND 4", name="severity"),
    )

    proto: Mapped[str | None] = mapped_column(String(16))
    signature_id: Mapped[int] = mapped_column(BigInteger)
    rev: Mapped[int] = mapped_column(Integer)
    signature: Mapped[str] = mapped_column(String(512))
    category: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[int] = mapped_column(SmallInteger)
    community_id: Mapped[str | None] = mapped_column(String(64))


class AnalysisFinding(_JobRow, _Endpoints, Base):
    """A heuristic observation with its evidence; never a maliciousness verdict."""

    __tablename__ = "analysis_findings"
    __table_args__ = (
        _job_fk(),
        *_endpoint_indexes("analysis_findings"),
        UniqueConstraint("job_id", "finding_id"),
        Index("ix_analysis_findings_job_id_severity", "job_id", "severity"),
        Index("ix_analysis_findings_job_id_type", "job_id", "type"),
        CheckConstraint(_in("severity", SEVERITIES), name="severity"),
    )

    finding_id: Mapped[uuid.UUID]
    type: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(8))
    confidence: Mapped[float] = mapped_column(Double)
    detection_method: Mapped[str] = mapped_column(String(128))
    last_seen: Mapped[datetime | None]
    protocol: Mapped[str | None] = mapped_column(String(16))
    evidence_refs: Mapped[list[str]] = mapped_column(JSONB)
    attributes: Mapped[dict[str, Any]]


class Ioc(_JobRow, Base):
    """An observable seen in the capture (no enrichment, no verdict)."""

    __tablename__ = "iocs"
    __table_args__ = (
        _job_fk(),
        # Parent of the same-org composite FK of `ioc_collection_items` (0013, M6 review L4).
        UniqueConstraint("id", "organization_id"),
        # md5(value): values may exceed the btree entry size limit; exact duplicates are
        # refused by ingest validation before this index is ever reached.
        Index("uq_iocs_job_id_type_value", "job_id", "type", func.md5("value"), unique=True),
    )

    type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(Text)
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    count: Mapped[int] = mapped_column(BigInteger)
    source: Mapped[str] = mapped_column(String(16))


# The IOC list order (most frequent first), served straight from the index.
Index("ix_iocs_job_id_count", Ioc.job_id, Ioc.count.desc(), Ioc.first_seen, Ioc.id)


class TimelineEntry(_JobRow, Base):
    __tablename__ = "analysis_timeline"
    __table_args__ = (
        _job_fk(),
        Index("ix_analysis_timeline_job_id_ts", "job_id", "ts"),
        CheckConstraint(f"severity IS NULL OR {_in('severity', SEVERITIES)}", name="severity"),
    )

    ts: Mapped[datetime]
    event: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str | None] = mapped_column(String(8))
    ref: Mapped[str | None] = mapped_column(String(64))
    src_ip: Mapped[str | None] = mapped_column(INET)
    dst_ip: Mapped[str | None] = mapped_column(INET)


RESULT_TABLES = (NetworkFlow, NetworkRecord, NetworkAlert, AnalysisFinding, Ioc, TimelineEntry)
