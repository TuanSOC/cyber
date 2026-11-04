"""AI analyst tables (migration 0011, M5 phase 1, FROZEN; later schema needs go into 0012).

- `ai_provider_configs`: one row per (org, provider): model, sealed key (sealed by the API,
  opened by the analyst worker only), verify status, terms and paid-tier acknowledgements.
  `key_version` is monotonic (DB trigger) and the app role has no DELETE.
- `ai_org_settings`: opt-in switch with privacy acknowledgement, privacy toggles, budgets.
- `ai_runs`: one analysis (or incident child digest); status graph enforced by a trigger.
- `ai_run_index`: system lookup (run -> org, scheduling, lease, call count).
- `ai_run_inputs`: the frozen context exactly as sent + the pseudonym map (append-only).
- `ai_context_refs`: label -> row map of every stage (append-only).
- `ai_outputs` / `ai_citations`: the verified output and every checked citation (append-only).

Statuses are text with CHECK constraints (no Postgres enums), as in M4.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    PrimaryKeyConstraint,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.config import (
    AI_DEFAULT_DAILY_TOKEN_BUDGET,
    AI_DEFAULT_INCIDENT_TOKEN_CAP,
    AI_DEFAULT_RUN_TOKEN_CAP,
)
from app.core.models_base import Base, UUIDPk
from app.modules.ai.catalog import AI_PROVIDER_NAMES
from app.modules.ai.contracts import (
    AiRunStatus,
    AiScope,
    AiTask,
    CitationReason,
    CitationStatus,
    ClaimStatus,
    RefKind,
    VerifyStatus,
)

TASKS = tuple(t.value for t in AiTask)
SCOPES = tuple(s.value for s in AiScope)
RUN_STATUSES = tuple(s.value for s in AiRunStatus)
VERIFY_STATUSES = tuple(s.value for s in VerifyStatus)
REF_KINDS = tuple(k.value for k in RefKind)
CITATION_STATUSES = tuple(s.value for s in CitationStatus)
CLAIM_STATUSES = tuple(s.value for s in ClaimStatus)
CITATION_REASONS = tuple(r.value for r in CitationReason)
SECTIONS = (
    "observed",
    "interpretation",
    "hypotheses",
    "next_steps",
    "attack_techniques",
    "timeline",
)
STAGES = ("base", "reduce")
TARGET_KINDS = ("finding", "alert")
SEALED = ("key_kid", "key_epk", "key_nonce", "key_ct", "key_last4")
MAX_LIST_ENTRIES = 50
CONTEXT_STATS_MAX_BYTES = 16 * 1024
USAGE_MAX_BYTES = 2 * 1024
METRICS_MAX_BYTES = 4 * 1024
CONTEXT_MAX_BYTES = 512 * 1024
PSEUDONYM_MAP_MAX_BYTES = 64 * 1024
BODY_MAX_BYTES = 64 * 1024
VERIFICATION_MAX_BYTES = 32 * 1024
SHA256_PATTERN = "^[0-9a-f]{64}$"
MODEL_PATTERN = "^[a-z0-9][a-z0-9._-]{0,63}$"
LABEL_PATTERN = "^(J[0-9]{1,3}:)?[A-Z][0-9]{1,4}$"


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _jsonb_max(column: str, limit: int) -> str:
    return f"{column} IS NULL OR octet_length({column}::text) <= {limit}"


class AiProviderConfig(UUIDPk, Base):
    __tablename__ = "ai_provider_configs"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider"),
        CheckConstraint(_in("provider", AI_PROVIDER_NAMES), name="provider"),
        CheckConstraint(f"model IS NULL OR model ~ '{MODEL_PATTERN}'", name="model_pattern"),
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
        # A sealed key (or the dev platform key) is required to enable: checked in the app,
        # because the platform key has no sealed row.
        CheckConstraint("NOT enabled OR terms_ack_at IS NOT NULL", name="enabled_needs_terms"),
        CheckConstraint(
            "NOT enabled OR provider <> 'gemini' OR paid_tier_ack_at IS NOT NULL",
            name="gemini_enabled_needs_paid_tier",
        ),
        CheckConstraint(_in("verify_status", VERIFY_STATUSES), name="verify_status"),
        CheckConstraint("jsonb_typeof(limits) = 'object'", name="limits_object"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    provider: Mapped[str] = mapped_column(String(16))
    enabled: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)
    # None: the catalog default model.
    model: Mapped[str | None] = mapped_column(String(64))
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
    # Org-lowered limits ({per_minute}); never above the catalog / AI_CEILINGS ceilings.
    limits: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)
    terms_ack_at: Mapped[datetime | None]
    terms_ack_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    # Gemini only: the admin attests the key is a paid-tier key (RT5).
    paid_tier_ack_at: Mapped[datetime | None]
    paid_tier_ack_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    __mapper_args__ = {"eager_defaults": True}


class AiOrgSettings(Base):
    __tablename__ = "ai_org_settings"
    __table_args__ = (
        CheckConstraint(
            "NOT ai_enabled OR privacy_ack_at IS NOT NULL", name="enabled_needs_privacy"
        ),
        CheckConstraint(
            f"default_provider IS NULL OR {_in('default_provider', AI_PROVIDER_NAMES)}",
            name="default_provider",
        ),
        CheckConstraint(
            "jsonb_typeof(internal_cidrs) = 'array' AND "
            f"jsonb_array_length(internal_cidrs) <= {MAX_LIST_ENTRIES}",
            name="internal_cidrs",
        ),
        CheckConstraint(
            "jsonb_typeof(internal_suffixes) = 'array' AND "
            f"jsonb_array_length(internal_suffixes) <= {MAX_LIST_ENTRIES}",
            name="internal_suffixes",
        ),
        CheckConstraint(
            "daily_token_budget > 0 AND run_token_cap > 0 AND incident_token_cap > 0",
            name="budgets_positive",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id"), primary_key=True
    )
    ai_enabled: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)
    privacy_ack_at: Mapped[datetime | None]
    privacy_ack_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    default_provider: Mapped[str | None] = mapped_column(String(16))
    pseudonymize_internal: Mapped[bool] = mapped_column(
        Boolean, server_default="true", default=True
    )
    internal_cidrs: Mapped[list[str]] = mapped_column(JSONB, server_default="[]", default=list)
    internal_suffixes: Mapped[list[str]] = mapped_column(JSONB, server_default="[]", default=list)
    include_strings: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)
    include_ti: Mapped[bool] = mapped_column(Boolean, server_default="true", default=True)
    include_case_text: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)
    daily_token_budget: Mapped[int] = mapped_column(
        BigInteger,
        server_default=str(AI_DEFAULT_DAILY_TOKEN_BUDGET),
        default=AI_DEFAULT_DAILY_TOKEN_BUDGET,
    )
    run_token_cap: Mapped[int] = mapped_column(
        BigInteger, server_default=str(AI_DEFAULT_RUN_TOKEN_CAP), default=AI_DEFAULT_RUN_TOKEN_CAP
    )
    incident_token_cap: Mapped[int] = mapped_column(
        BigInteger,
        server_default=str(AI_DEFAULT_INCIDENT_TOKEN_CAP),
        default=AI_DEFAULT_INCIDENT_TOKEN_CAP,
    )
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class AiRun(UUIDPk, Base):
    __tablename__ = "ai_runs"
    __table_args__ = (
        UniqueConstraint("id", "organization_id"),
        ForeignKeyConstraint(
            ["job_id", "organization_id"], ["analysis_jobs.id", "analysis_jobs.organization_id"]
        ),
        ForeignKeyConstraint(
            ["investigation_id", "organization_id"],
            ["investigations.id", "investigations.organization_id"],
        ),
        ForeignKeyConstraint(
            ["parent_run_id", "organization_id"], ["ai_runs.id", "ai_runs.organization_id"]
        ),
        ForeignKeyConstraint(
            ["supersedes_run_id", "organization_id"], ["ai_runs.id", "ai_runs.organization_id"]
        ),
        CheckConstraint(_in("task", TASKS), name="task"),
        CheckConstraint(_in("scope", SCOPES), name="scope"),
        CheckConstraint(_in("status", RUN_STATUSES), name="status"),
        CheckConstraint(_in("provider", AI_PROVIDER_NAMES), name="provider"),
        CheckConstraint("(job_id IS NOT NULL) = (scope = 'job')", name="job_id_iff_job_scope"),
        CheckConstraint(
            "(investigation_id IS NOT NULL) = (scope = 'investigation')",
            name="investigation_id_iff_investigation_scope",
        ),
        CheckConstraint(
            "(parent_run_id IS NOT NULL) = (task = 'job_digest')", name="parent_iff_job_digest"
        ),
        CheckConstraint(
            f"(target_id IS NULL) = (target_kind IS NULL) AND "
            f"(target_kind IS NULL OR {_in('target_kind', TARGET_KINDS)})",
            name="target",
        ),
        CheckConstraint(f"context_sha256 ~ '{SHA256_PATTERN}'", name="context_sha256"),
        CheckConstraint(f"model ~ '{MODEL_PATTERN}'", name="model_pattern"),
        CheckConstraint(_jsonb_max("context_stats", CONTEXT_STATS_MAX_BYTES), name="stats_size"),
        CheckConstraint(_jsonb_max("usage", USAGE_MAX_BYTES), name="usage_size"),
        CheckConstraint(_jsonb_max("metrics", METRICS_MAX_BYTES), name="metrics_size"),
        CheckConstraint("cost_micros IS NULL OR cost_micros >= 0", name="cost_non_negative"),
        Index(None, "organization_id", "created_at"),
        Index(None, "job_id", "created_at"),
        Index(None, "investigation_id", "created_at"),
        Index(None, "parent_run_id"),
        # Dedupe lookups (phase 7) and digest reuse (phase 2).
        Index(None, "organization_id", "context_sha256"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    task: Mapped[str] = mapped_column(String(32))
    scope: Mapped[str] = mapped_column(String(16))
    job_id: Mapped[uuid.UUID | None]
    investigation_id: Mapped[uuid.UUID | None]
    target_kind: Mapped[str | None] = mapped_column(String(16))
    target_id: Mapped[uuid.UUID | None]
    parent_run_id: Mapped[uuid.UUID | None]
    provider: Mapped[str] = mapped_column(String(16))
    model: Mapped[str] = mapped_column(String(64))
    prompt_version: Mapped[str] = mapped_column(String(32))
    output_schema: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), server_default="queued", default="queued")
    error_code: Mapped[str | None] = mapped_column(String(32))
    served_model: Mapped[str | None] = mapped_column(String(64))
    context_sha256: Mapped[str] = mapped_column(String(64))
    context_stats: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)
    usage: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)
    metrics: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)
    cost_micros: Mapped[int | None] = mapped_column(BigInteger)
    price_version: Mapped[str | None] = mapped_column(String(32))
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    supersedes_run_id: Mapped[uuid.UUID | None]
    deadline_at: Mapped[datetime]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]


class AiRunIndex(Base):
    """System lookup (run -> org, scheduling, lease, provider calls made) for the analyst
    worker, `ai.resume` and the fallback reaper. Holds no tenant data (the `ti_run_index`
    pattern: a system session sees every row, a tenant session only its own org's)."""

    __tablename__ = "ai_run_index"
    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["ai_runs.id", "ai_runs.organization_id"],
            ondelete="CASCADE",
        ),
        CheckConstraint(_in("status", RUN_STATUSES), name="status"),
        CheckConstraint("attempts >= 0", name="attempts_non_negative"),
        CheckConstraint("calls >= 0", name="calls_non_negative"),
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
    # Overload backoff steps taken (phase 2).
    attempts: Mapped[int] = mapped_column(Integer, server_default="0", default=0)
    # Provider calls made, counted before each call (cap AI_MAX_CALLS_PER_RUN, RT2).
    calls: Mapped[int] = mapped_column(Integer, server_default="0", default=0)


class AiRunInput(Base):
    """The frozen context of one stage exactly as sent (append-only). `pseudonym_map` is
    never sent and never read by the worker (RT26: code review + test)."""

    __tablename__ = "ai_run_inputs"
    __table_args__ = (
        PrimaryKeyConstraint("run_id", "stage"),
        ForeignKeyConstraint(
            ["run_id", "organization_id"], ["ai_runs.id", "ai_runs.organization_id"]
        ),
        CheckConstraint(_in("stage", STAGES), name="stage"),
        CheckConstraint(f"context_sha256 ~ '{SHA256_PATTERN}'", name="context_sha256"),
        CheckConstraint(_jsonb_max("context", CONTEXT_MAX_BYTES), name="context_size"),
        CheckConstraint(
            "jsonb_typeof(pseudonym_map) = 'object' AND "
            f"octet_length(pseudonym_map::text) <= {PSEUDONYM_MAP_MAX_BYTES}",
            name="pseudonym_map",
        ),
    )

    run_id: Mapped[uuid.UUID]
    stage: Mapped[str] = mapped_column(String(8))
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    # FrozenContext.model_dump(mode="json") minus pseudonym_map.
    context: Mapped[dict[str, Any]] = mapped_column(JSONB)
    context_sha256: Mapped[str] = mapped_column(String(64))
    pseudonym_map: Mapped[dict[str, str]] = mapped_column(JSONB, server_default="{}", default=dict)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class AiContextRef(Base):
    """Label -> row of every stage (append-only). Index (org, kind, ref_id) answers M6's
    "which outputs cite X"."""

    __tablename__ = "ai_context_refs"
    __table_args__ = (
        PrimaryKeyConstraint("run_id", "label"),
        ForeignKeyConstraint(
            ["run_id", "organization_id"], ["ai_runs.id", "ai_runs.organization_id"]
        ),
        ForeignKeyConstraint(
            ["job_id", "organization_id"], ["analysis_jobs.id", "analysis_jobs.organization_id"]
        ),
        CheckConstraint(_in("stage", STAGES), name="stage"),
        CheckConstraint(_in("kind", REF_KINDS), name="kind"),
        CheckConstraint(f"label ~ '{LABEL_PATTERN}'", name="label"),
        CheckConstraint(f"fields_sha256 ~ '{SHA256_PATTERN}'", name="fields_sha256"),
        Index(None, "organization_id", "kind", "ref_id"),
    )

    run_id: Mapped[uuid.UUID]
    label: Mapped[str] = mapped_column(String(16))
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    stage: Mapped[str] = mapped_column(String(8))
    kind: Mapped[str] = mapped_column(String(16))
    ref_table: Mapped[str] = mapped_column(String(64))
    # The row id as text: a uuid, or the Zeek uid for flows (keyed with job_id, RT16).
    ref_id: Mapped[str] = mapped_column(String(128))
    job_id: Mapped[uuid.UUID | None]
    fields_sha256: Mapped[str] = mapped_column(String(64))


class AiOutput(UUIDPk, Base):
    """The validated, sanitized output of a run (append-only; raw model text is never
    stored). `verification` is a `contracts.OutputVerification`, `flags` a list of
    `OutputFlag` values."""

    __tablename__ = "ai_outputs"
    __table_args__ = (
        UniqueConstraint("id", "organization_id"),
        UniqueConstraint("run_id"),
        ForeignKeyConstraint(
            ["run_id", "organization_id"], ["ai_runs.id", "ai_runs.organization_id"]
        ),
        CheckConstraint(_jsonb_max("body", BODY_MAX_BYTES), name="body_size"),
        CheckConstraint(
            _jsonb_max("verification", VERIFICATION_MAX_BYTES), name="verification_size"
        ),
        CheckConstraint("jsonb_typeof(flags) = 'array'", name="flags_array"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    run_id: Mapped[uuid.UUID]
    body: Mapped[dict[str, Any]] = mapped_column(JSONB)
    verification: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)
    flags: Mapped[list[str]] = mapped_column(JSONB, server_default="[]", default=list)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class AiCitation(UUIDPk, Base):
    """One checked citation of an output (append-only; a `contracts.CitationResult`)."""

    __tablename__ = "ai_citations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["output_id", "organization_id"], ["ai_outputs.id", "ai_outputs.organization_id"]
        ),
        ForeignKeyConstraint(
            ["run_id", "organization_id"], ["ai_runs.id", "ai_runs.organization_id"]
        ),
        CheckConstraint(_in("section", SECTIONS), name="section"),
        CheckConstraint(
            f"claim_status IS NULL OR {_in('claim_status', CLAIM_STATUSES)}", name="claim_status"
        ),
        CheckConstraint(_in("status", CITATION_STATUSES), name="status"),
        CheckConstraint(f"kind IS NULL OR {_in('kind', REF_KINDS)}", name="kind"),
        CheckConstraint(f"reason IS NULL OR {_in('reason', CITATION_REASONS)}", name="reason"),
        CheckConstraint("quote IS NULL OR char_length(quote) <= 256", name="quote_length"),
        Index(None, "output_id"),
        Index(None, "organization_id", "kind", "ref_id"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    output_id: Mapped[uuid.UUID]
    run_id: Mapped[uuid.UUID]
    claim_path: Mapped[str] = mapped_column(String(128))
    section: Mapped[str] = mapped_column(String(32))
    claim_id: Mapped[str | None] = mapped_column(String(32))
    # None for next_steps refs (they belong to no claim).
    claim_status: Mapped[str | None] = mapped_column(String(16))
    label: Mapped[str] = mapped_column(String(32))
    kind: Mapped[str | None] = mapped_column(String(16))
    ref_id: Mapped[str | None] = mapped_column(String(128))
    job_id: Mapped[uuid.UUID | None]
    status: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str | None] = mapped_column(String(32))
    field: Mapped[str | None] = mapped_column(String(64))
    quote: Mapped[str | None] = mapped_column(String(256))
    stale: Mapped[bool] = mapped_column(Boolean, server_default="false", default=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
