"""Threat intel tables (migration 0009, frozen in M4 phase 1; 0010 hardens two grants/FKs).

- `ti_provider_configs`: one row per (org, provider); the sealed key columns are written by
  the API (seal only) and opened by the enrich worker only. `key_version` is monotonic (DB
  trigger, RT18).
- `ti_org_settings`: per-org TI settings (excluded domain suffixes).
- `ti_enrichment_runs`: one enrichment request; status graph enforced by a DB trigger.
- `ti_run_items`: the frozen plan of a run, one row per eligible (IOC, provider) pair (RT9).
- `ti_run_index`: system lookup (run -> org, scheduling, lease), like `analysis_job_index`.
- `ti_results`: append-only provider answers; also the per-org cache (newest unexpired row).

Statuses are text with CHECK constraints (no Postgres enums: new values need no ALTER TYPE).
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Double,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    PrimaryKeyConstraint,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, UUIDPk
from app.modules.threat_intel.catalog import PROVIDER_NAMES

IOC_TYPES = ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email")
VERIFY_STATUSES = ("unverified", "valid", "invalid", "error")
RUN_SCOPES = ("manual", "job")
RUN_STATUSES = ("queued", "running", "waiting", "completed", "partial", "failed")
RUN_ACTIVE = ("queued", "running", "waiting")
RUN_FINAL = ("completed", "partial", "failed")
ITEM_STATES = ("pending", "done", "cached", "abandoned")
ITEM_REASONS = ("rate_limited", "quota_exhausted", "deadline", "auth_failed")
RESULT_STATUSES = ("ok", "not_found", "error", "auth_failed")
SUMMARY_MAX_BYTES = 16 * 1024
MAX_VALUE_CHARS = 2048
MAX_EXCLUDED_SUFFIXES = 50


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _jsonb_max(column: str) -> str:
    return f"{column} IS NULL OR octet_length({column}::text) <= {SUMMARY_MAX_BYTES}"


SEALED = ("key_kid", "key_epk", "key_nonce", "key_ct", "key_last4")


class TiProviderConfig(UUIDPk, Base):
    __tablename__ = "ti_provider_configs"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider"),
        CheckConstraint(_in("provider", PROVIDER_NAMES), name="provider"),
        CheckConstraint("(base_url IS NOT NULL) = (provider = 'misp')", name="base_url_iff_misp"),
        CheckConstraint(
            " AND ".join(f"{c} IS NULL" for c in SEALED)
            + " OR "
            + " AND ".join(f"{c} IS NOT NULL" for c in SEALED),
            name="sealed_all_or_none",
        ),
        CheckConstraint("key_last4 IS NULL OR char_length(key_last4) = 4", name="key_last4"),
        CheckConstraint(
            "key_epk IS NULL OR (octet_length(key_epk) = 32 AND octet_length(key_nonce) = 12)",
            name="sealed_sizes",
        ),
        CheckConstraint("key_ct IS NULL OR key_version >= 1", name="sealed_version"),
        CheckConstraint("key_version >= 0", name="key_version_non_negative"),
        CheckConstraint("NOT enabled OR terms_ack_at IS NOT NULL", name="enabled_needs_terms"),
        CheckConstraint("NOT enabled OR key_ct IS NOT NULL", name="enabled_needs_key"),
        CheckConstraint(_in("verify_status", VERIFY_STATUSES), name="verify_status"),
        CheckConstraint("jsonb_typeof(limits) = 'object'", name="limits_object"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    provider: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)
    # MISP only: the normalized https base URL the key is bound to (in the seal AAD).
    base_url: Mapped[str | None] = mapped_column(String(512))
    key_kid: Mapped[str | None] = mapped_column(String(64))
    key_version: Mapped[int] = mapped_column(Integer, server_default="0", default=0)
    key_epk: Mapped[bytes | None] = mapped_column(LargeBinary)
    key_nonce: Mapped[bytes | None] = mapped_column(LargeBinary)
    key_ct: Mapped[bytes | None] = mapped_column(LargeBinary)
    key_last4: Mapped[str | None] = mapped_column(String(4))
    verify_status: Mapped[str] = mapped_column(
        String(16), server_default="unverified", default="unverified"
    )
    verified_at: Mapped[datetime | None]
    last_error_code: Mapped[str | None] = mapped_column(String(64))
    # Org-lowered limits ({per_minute, per_day}); never above the settings ceilings.
    limits: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)
    terms_ack_at: Mapped[datetime | None]
    terms_ack_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    __mapper_args__ = {"eager_defaults": True}


class TiOrgSettings(Base):
    __tablename__ = "ti_org_settings"
    __table_args__ = (
        CheckConstraint(
            "jsonb_typeof(excluded_suffixes) = 'array' AND "
            f"jsonb_array_length(excluded_suffixes) <= {MAX_EXCLUDED_SUFFIXES}",
            name="excluded_suffixes",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id"), primary_key=True
    )
    excluded_suffixes: Mapped[list[str]] = mapped_column(JSONB, server_default="[]", default=list)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class TiEnrichmentRun(UUIDPk, Base):
    __tablename__ = "ti_enrichment_runs"
    __table_args__ = (
        UniqueConstraint("id", "organization_id"),
        ForeignKeyConstraint(
            ["job_id", "organization_id"], ["analysis_jobs.id", "analysis_jobs.organization_id"]
        ),
        CheckConstraint(_in("scope", RUN_SCOPES), name="scope"),
        CheckConstraint("(job_id IS NOT NULL) = (scope = 'job')", name="job_id_iff_job_scope"),
        CheckConstraint(_in("status", RUN_STATUSES), name="status"),
        CheckConstraint("jsonb_typeof(providers) = 'array'", name="providers_array"),
        CheckConstraint(_jsonb_max("summary"), name="summary_size"),
        Index(None, "organization_id", "created_at"),
        Index(None, "job_id", "created_at"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    scope: Mapped[str] = mapped_column(String(8))
    job_id: Mapped[uuid.UUID | None]
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    providers: Mapped[list[str]] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(String(16), server_default="queued", default="queued")
    summary: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)
    deadline_at: Mapped[datetime]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]


class TiRunIndex(Base):
    """System lookup (run -> org, scheduling, lease) for the enrich worker, `ti.resume` and
    the fallback reaper. Holds no tenant data; same RLS pattern as `analysis_job_index`."""

    __tablename__ = "ti_run_index"
    __table_args__ = (
        # Composite (migration 0010, review L8): an index row can only name its run's org.
        ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["ti_enrichment_runs.id", "ti_enrichment_runs.organization_id"],
            ondelete="CASCADE",
        ),
        CheckConstraint(_in("status", RUN_STATUSES), name="status"),
        Index(None, "status", "resume_at"),
    )

    run_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    status: Mapped[str] = mapped_column(String(16))
    resume_at: Mapped[datetime | None]
    deadline_at: Mapped[datetime]
    dispatched_at: Mapped[datetime | None]
    lease_until: Mapped[datetime | None]
    lease_owner: Mapped[str | None] = mapped_column(String(64))


class TiResult(UUIDPk, Base):
    """One provider answer (append-only). Rate-limit, quota and deadline outcomes are item
    states, never rows here."""

    __tablename__ = "ti_results"
    __table_args__ = (
        UniqueConstraint("id", "organization_id"),
        UniqueConstraint("run_id", "provider", "ioc_key"),
        ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["ti_enrichment_runs.id", "ti_enrichment_runs.organization_id"],
        ),
        CheckConstraint(_in("provider", PROVIDER_NAMES), name="provider"),
        CheckConstraint(_in("ioc_type", IOC_TYPES), name="ioc_type"),
        CheckConstraint(_in("status", RESULT_STATUSES), name="status"),
        CheckConstraint("char_length(ioc_key) = 64", name="ioc_key"),
        CheckConstraint(_jsonb_max("summary"), name="summary_size"),
        CheckConstraint("NOT found OR status = 'ok'", name="found_only_ok"),
        CheckConstraint(
            "(expires_at IS NULL) = (status IN ('error', 'auth_failed'))",
            name="expires_iff_cacheable",
        ),
        CheckConstraint("permalink IS NULL OR permalink LIKE 'https://%'", name="permalink_https"),
        Index(
            "ix_ti_results_organization_id_ioc_key_provider_fetched_at",
            "organization_id",
            "ioc_key",
            "provider",
            text("fetched_at DESC"),
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    run_id: Mapped[uuid.UUID]
    provider: Mapped[str] = mapped_column(String(32))
    ioc_type: Mapped[str] = mapped_column(String(8))
    value_norm: Mapped[str] = mapped_column(String(MAX_VALUE_CHARS))
    ioc_key: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))
    found: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)
    detections: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    score: Mapped[float | None] = mapped_column(Double)
    score_scale: Mapped[str | None] = mapped_column(String(32))
    tags: Mapped[list[str]] = mapped_column(JSONB, server_default="[]", default=list)
    families: Mapped[list[str]] = mapped_column(JSONB, server_default="[]", default=list)
    attack_ids: Mapped[list[str]] = mapped_column(JSONB, server_default="[]", default=list)
    first_seen: Mapped[datetime | None]
    last_seen: Mapped[datetime | None]
    summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    permalink: Mapped[str | None] = mapped_column(String(2048))
    error_code: Mapped[str | None] = mapped_column(String(64))
    # Provider round trip of this answer (the run summary's p50/p95, the M4 metric).
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    fetched_at: Mapped[datetime] = mapped_column(server_default=func.now())
    # NULL for error statuses: they are never served from the cache.
    expires_at: Mapped[datetime | None]


class TiRunItem(Base):
    """One planned (IOC, provider) pair of a run (RT9). `result_id` is this run's row or the
    cached row it reused (RT10)."""

    __tablename__ = "ti_run_items"
    __table_args__ = (
        PrimaryKeyConstraint("run_id", "provider", "ioc_key"),
        ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["ti_enrichment_runs.id", "ti_enrichment_runs.organization_id"],
        ),
        ForeignKeyConstraint(
            ["result_id", "organization_id"], ["ti_results.id", "ti_results.organization_id"]
        ),
        CheckConstraint(_in("provider", PROVIDER_NAMES), name="provider"),
        CheckConstraint(_in("ioc_type", IOC_TYPES), name="ioc_type"),
        CheckConstraint(_in("state", ITEM_STATES), name="state"),
        CheckConstraint(f"reason IS NULL OR {_in('reason', ITEM_REASONS)}", name="reason"),
        CheckConstraint(
            "(reason IS NOT NULL) = (state = 'abandoned')", name="reason_iff_abandoned"
        ),
        CheckConstraint(
            "(result_id IS NOT NULL) = (state IN ('done', 'cached'))", name="result_iff_answered"
        ),
        CheckConstraint("char_length(ioc_key) = 64", name="ioc_key"),
        CheckConstraint("seq >= 0", name="seq_non_negative"),
        Index(None, "run_id", "state", "seq"),
    )

    run_id: Mapped[uuid.UUID]
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    seq: Mapped[int] = mapped_column(Integer)
    provider: Mapped[str] = mapped_column(String(32))
    ioc_type: Mapped[str] = mapped_column(String(8))
    value_norm: Mapped[str] = mapped_column(String(MAX_VALUE_CHARS))
    ioc_key: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(16), server_default="pending", default="pending")
    result_id: Mapped[uuid.UUID | None]
    reason: Mapped[str | None] = mapped_column(String(32))
