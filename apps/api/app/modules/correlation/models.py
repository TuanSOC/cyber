"""Deterministic correlation keys (migration 0014, M7 phase 1, FROZEN).

- `correlation_keys`: one row per (job, kind, key). `key` is the `ioc_key` that M6's
  `ioc_collections.normalize.normalize_item` returns (RT8), so it joins `ti_results.ioc_key`
  and `ioc_collection_items.ioc_key` byte for byte. Sources: `iocs`, `malware_samples` hashes
  and `evidence_hashes` sha256. Never purged (RT9): no DELETE grant for anyone.
- `correlation_job_state`: a job's keys were indexed (the indexer's "pending" test).
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, UUIDPk

# The M4 `IocType` values plus the pcap-only types `normalize_item` keys with `opaque_key`.
CORRELATION_KINDS = (
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "email",
    "md5",
    "sha1",
    "sha256",
    "ja3",
    "ja3s",
    "cert_sha256",
)
SOURCE_TABLES = ("iocs", "malware_samples", "evidence_hashes")
VALUE_MAX_CHARS = 2048


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class CorrelationKey(UUIDPk, Base):
    __tablename__ = "correlation_keys"
    __table_args__ = (
        ForeignKeyConstraint(
            ["investigation_id", "organization_id"],
            ["investigations.id", "investigations.organization_id"],
        ),
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"], ["evidence.id", "evidence.organization_id"]
        ),
        ForeignKeyConstraint(
            ["job_id", "organization_id"], ["analysis_jobs.id", "analysis_jobs.organization_id"]
        ),
        UniqueConstraint("job_id", "kind", "key"),
        Index(None, "organization_id", "kind", "key"),
        Index(None, "investigation_id"),
        # Trigram GIN on value_norm: `ix_correlation_keys_value_norm_trgm` (raw SQL in 0014).
        CheckConstraint(_in("kind", CORRELATION_KINDS), name="kind"),
        CheckConstraint("key ~ '^[0-9a-f]{64}$'", name="key"),
        CheckConstraint("char_length(value_norm) BETWEEN 1 AND 2048", name="value_length"),
        CheckConstraint(_in("source_table", SOURCE_TABLES), name="source_table"),
        CheckConstraint("char_length(source_id) BETWEEN 1 AND 64", name="source_id_length"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    investigation_id: Mapped[uuid.UUID]
    evidence_id: Mapped[uuid.UUID]
    job_id: Mapped[uuid.UUID]
    kind: Mapped[str] = mapped_column(String(16))
    key: Mapped[str] = mapped_column(String(64))
    value_norm: Mapped[str] = mapped_column(String(2048))
    source_table: Mapped[str] = mapped_column(String(32))
    source_id: Mapped[str] = mapped_column(String(64))
    first_seen: Mapped[datetime | None]
    last_seen: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class CorrelationJobState(Base):
    __tablename__ = "correlation_job_state"
    __table_args__ = (
        ForeignKeyConstraint(
            ["job_id", "organization_id"], ["analysis_jobs.id", "analysis_jobs.organization_id"]
        ),
        Index(None, "organization_id"),
        CheckConstraint("keys >= 0", name="keys_non_negative"),
    )

    job_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    indexed_at: Mapped[datetime] = mapped_column(server_default=func.now())
    keys: Mapped[int] = mapped_column(Integer, server_default="0", default=0)
    truncated: Mapped[bool] = mapped_column(server_default="false", default=False)
