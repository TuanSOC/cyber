"""Retention, legal hold and purge (migration 0014, M7 phase 1, FROZEN).

- `org_retention_policies`: one row per org. Every `*_days` NULL = keep forever (the default).
  A lowered value waits in `pending_*` until `effective_at` (`RETENTION_POLICY_DELAY_DAYS`);
  turning `enforce` on waits in `pending_enforce` until `enforce_effective_at` (RT1). A raised
  value, or `enforce` off, applies at once. Floors: 30 days (DB check), and the closed-case
  floor is at least `EVIDENCE_LOCK_DAYS` (the API checks it: configuration).
- `retention_policy_index`: the system lookup of orgs with a policy (the sweep's org list,
  RT3), written by the API in the same transaction as every policy PUT.
- `legal_holds`: scope `org` or `investigation`; released once (`legal_hold_guard`). A hold
  released less than the delay ago still protects (RT1).
- `retention_runs`: one dry-run or enforce run (`trigger` schedule / manual); identity and
  final status immutable (`retention_run_guard`).
- `retention_run_items` and `evidence_purges` (the tombstone): append-only.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, UUIDPk

FLOOR_DAYS = 30
MAX_DAYS = 36500
HOLD_SCOPES = ("org", "investigation")
RUN_MODES = ("dry_run", "enforce")
RUN_TRIGGERS = ("schedule", "manual")
RUN_STATUSES = ("queued", "running", "completed", "partial", "failed")
RUN_FINAL = ("completed", "partial", "failed")
CATEGORIES = ("ti_results", "ai_runs", "closed_case")
ITEM_OUTCOMES = ("purged", "skipped_hold", "skipped_locked", "object_delete_failed", "kept_cited")
REASON_MAX_CHARS = 500
COUNTS_MAX_BYTES = 8 * 1024
SAMPLE_MAX_BYTES = 64 * 1024
POLICY_SNAPSHOT_MAX_BYTES = 4 * 1024


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _days(column: str) -> CheckConstraint:
    return CheckConstraint(
        f"{column} IS NULL OR {column} BETWEEN {FLOOR_DAYS} AND {MAX_DAYS}", name=column
    )


class OrgRetentionPolicy(Base):
    __tablename__ = "org_retention_policies"
    __table_args__ = (
        _days("ti_results_days"),
        _days("ai_runs_days"),
        _days("closed_case_days"),
        _days("pending_ti_results_days"),
        _days("pending_ai_runs_days"),
        _days("pending_closed_case_days"),
        CheckConstraint(
            "(effective_at IS NULL) = (pending_ti_results_days IS NULL AND "
            "pending_ai_runs_days IS NULL AND pending_closed_case_days IS NULL)",
            name="pending_pair",
        ),
        CheckConstraint(
            "pending_enforce = (enforce_effective_at IS NOT NULL)", name="enforce_pair"
        ),
        CheckConstraint("NOT (enforce AND pending_enforce)", name="enforce_pending_only_when_off"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id"), primary_key=True
    )
    ti_results_days: Mapped[int | None] = mapped_column(Integer)
    ai_runs_days: Mapped[int | None] = mapped_column(Integer)
    closed_case_days: Mapped[int | None] = mapped_column(Integer)
    pending_ti_results_days: Mapped[int | None] = mapped_column(Integer)
    pending_ai_runs_days: Mapped[int | None] = mapped_column(Integer)
    pending_closed_case_days: Mapped[int | None] = mapped_column(Integer)
    effective_at: Mapped[datetime | None]
    enforce: Mapped[bool] = mapped_column(server_default="false", default=False)
    pending_enforce: Mapped[bool] = mapped_column(server_default="false", default=False)
    enforce_effective_at: Mapped[datetime | None]
    updated_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    # Set by the `org_retention_policy_touch` trigger on every UPDATE.
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now())

    __mapper_args__ = {"eager_defaults": True}


class RetentionPolicyIndex(Base):
    """System lookup (the `analysis_job_index` pattern): ids and a timestamp only."""

    __tablename__ = "retention_policy_index"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id"), primary_key=True
    )
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now())


class LegalHold(UUIDPk, Base):
    __tablename__ = "legal_holds"
    __table_args__ = (
        ForeignKeyConstraint(
            ["investigation_id", "organization_id"],
            ["investigations.id", "investigations.organization_id"],
        ),
        UniqueConstraint("id", "organization_id"),
        Index(None, "organization_id", "released_at"),
        Index(None, "investigation_id"),
        CheckConstraint(_in("scope", HOLD_SCOPES), name="scope"),
        CheckConstraint("(scope = 'org') = (investigation_id IS NULL)", name="scope_target"),
        CheckConstraint("char_length(reason) BETWEEN 1 AND 500", name="reason_length"),
        CheckConstraint(
            "release_reason IS NULL OR char_length(release_reason) BETWEEN 1 AND 500",
            name="release_reason_length",
        ),
        CheckConstraint("(released_at IS NULL) = (released_by IS NULL)", name="released_pair"),
        CheckConstraint(
            "release_reason IS NULL OR released_at IS NOT NULL",
            name="release_reason_when_released",
        ),
        CheckConstraint(  # 0015
            "(s3_sync_cursor_at IS NULL) = (s3_sync_cursor_id IS NULL) "
            "AND (s3_sync_cursor_at IS NULL) = (s3_sync_pass_at IS NULL)",
            name="s3_sync_cursor",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    scope: Mapped[str] = mapped_column(String(16))
    investigation_id: Mapped[uuid.UUID | None]
    reason: Mapped[str] = mapped_column(Text)
    placed_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    placed_at: Mapped[datetime] = mapped_column(server_default=func.now())
    released_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    released_at: Mapped[datetime | None]
    release_reason: Mapped[str | None] = mapped_column(Text)
    # S3 legal-hold sync state, written by the retention worker only (RT5, 0015):
    # - s3_synced_at: the last COMPLETED pass (an ON pass: its start, the next incremental
    #   pass's lower bound; an OFF pass or a stamp-only release: its end);
    # - s3_full_synced_at: the first complete ON pass from the beginning finished;
    # - s3_sync_cursor_at / _id: the keyset cursor of the pass in progress, started at
    #   s3_sync_pass_at (all three NULL together).
    s3_synced_at: Mapped[datetime | None]
    s3_full_synced_at: Mapped[datetime | None]
    s3_sync_cursor_at: Mapped[datetime | None]
    s3_sync_cursor_id: Mapped[uuid.UUID | None]
    s3_sync_pass_at: Mapped[datetime | None]


class RetentionRun(UUIDPk, Base):
    __tablename__ = "retention_runs"
    __table_args__ = (
        UniqueConstraint("id", "organization_id"),
        Index(None, "organization_id", "created_at"),
        CheckConstraint(_in("mode", RUN_MODES), name="mode"),
        CheckConstraint(_in("trigger", RUN_TRIGGERS), name="trigger"),
        CheckConstraint(_in("status", RUN_STATUSES), name="status"),
        CheckConstraint(
            "(trigger = 'manual') = (requested_by IS NOT NULL)", name="manual_has_requester"
        ),
        CheckConstraint("error IS NULL OR error ~ '^[a-z][a-z0-9_]{0,63}$'", name="error"),
        CheckConstraint(
            "jsonb_typeof(policy) = 'object' AND octet_length(policy::text) <= 4096",
            name="policy",
        ),
        CheckConstraint(
            "jsonb_typeof(counts) = 'object' AND octet_length(counts::text) <= 8192",
            name="counts",
        ),
        CheckConstraint(
            "jsonb_typeof(sample) = 'array' AND octet_length(sample::text) <= 65536",
            name="sample",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    mode: Mapped[str] = mapped_column(String(16))
    trigger: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), server_default="queued", default="queued")
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    # The effective policy the run used (values and mode read from the DB only, RT1).
    policy: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default="{}", default=dict)
    counts: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default="{}", default=dict)
    sample: Mapped[list[Any]] = mapped_column(JSONB, server_default="[]", default=list)
    error: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]


class RetentionRunItem(UUIDPk, Base):
    """Append-only (`forbid_mutation`)."""

    __tablename__ = "retention_run_items"
    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["retention_runs.id", "retention_runs.organization_id"],
        ),
        ForeignKeyConstraint(
            ["job_id", "organization_id"],
            ["analysis_jobs.id", "analysis_jobs.organization_id"],
        ),
        Index(None, "run_id", "created_at"),
        Index(None, "organization_id"),
        CheckConstraint(_in("category", CATEGORIES), name="category"),
        CheckConstraint("ref_table ~ '^[a-z_]{1,64}$'", name="ref_table"),
        CheckConstraint("char_length(ref_id) BETWEEN 1 AND 64", name="ref_id_length"),
        CheckConstraint("rows >= 0", name="rows_non_negative"),
        CheckConstraint("bytes >= 0", name="bytes_non_negative"),
        CheckConstraint(_in("outcome", ITEM_OUTCOMES), name="outcome"),
        CheckConstraint("(object_key IS NULL) = (object_version_id IS NULL)", name="object_pair"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    run_id: Mapped[uuid.UUID]
    category: Mapped[str] = mapped_column(String(16))
    ref_table: Mapped[str] = mapped_column(String(64))
    ref_id: Mapped[str] = mapped_column(String(64))
    job_id: Mapped[uuid.UUID | None]
    rows: Mapped[int] = mapped_column(BigInteger, server_default="0", default=0)
    bytes: Mapped[int] = mapped_column(BigInteger, server_default="0", default=0)
    object_key: Mapped[str | None] = mapped_column(String(1024))
    object_version_id: Mapped[str | None] = mapped_column(String(255))
    outcome: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class EvidencePurge(Base):
    """The tombstone of purged evidence bytes (append-only). The evidence row itself, its
    hashes and its custody never change; download and verify answer 410."""

    __tablename__ = "evidence_purges"
    __table_args__ = (
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"], ["evidence.id", "evidence.organization_id"]
        ),
        ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["retention_runs.id", "retention_runs.organization_id"],
        ),
        Index(None, "organization_id", "purged_at"),
        CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="sha256"),
    )

    evidence_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    run_id: Mapped[uuid.UUID]
    object_version_id: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64))
    purged_at: Mapped[datetime] = mapped_column(server_default=func.now())
