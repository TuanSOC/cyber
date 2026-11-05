"""Retention policy, preview, runs and legal hold schemas (M7 phase 1, FROZEN; phase 3
implements the routes).

Values are days. `None` = keep forever. The floors (30 days; closed cases at least
`EVIDENCE_LOCK_DAYS`) are checked by the service and answer `422 policy_floor`, so the schema
only bounds the type. A lowered value, turning `enforce` on and a hold release take effect
after `RETENTION_POLICY_DELAY_DAYS` (RT1): the policy shows them as `pending_*`.
"""

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.core.pagination import Page

Days = Annotated[int, Field(ge=1, le=36500)]
Category = Literal["ti_results", "ai_runs", "closed_case"]
RunMode = Literal["dry_run", "enforce"]
RunTrigger = Literal["schedule", "manual"]
RunStatus = Literal["queued", "running", "completed", "partial", "failed"]
ItemOutcome = Literal[
    "purged", "skipped_hold", "skipped_locked", "object_delete_failed", "kept_cited"
]
HoldScope = Literal["org", "investigation"]
# `pending`: the API committed the hold and published `retention.sync_holds`; the retention
# worker mirrors it as S3 legal holds (RT5). `synced`: the worker's last sync covered it.
S3Sync = Literal["pending", "synced"]
# Plain text, no NUL; surrounding whitespace stripped first (a blank reason is refused).
HoldReason = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=500, pattern=r"^[^\x00]*$"),
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RetentionValues(BaseModel):
    ti_results_days: int | None
    ai_runs_days: int | None
    closed_case_days: int | None


class RetentionPolicyIn(_Strict):
    """PUT replaces the policy. Every value is required (null = keep forever)."""

    ti_results_days: Days | None
    ai_runs_days: Days | None
    closed_case_days: Days | None
    enforce: bool
    # Turning `enforce` on needs `true` here (`422 retention_acknowledgement_required`).
    acknowledge_destruction: bool | None = None


class RetentionPolicyOut(BaseModel):
    """The effective values now, what is pending and when it takes effect."""

    ti_results_days: int | None
    ai_runs_days: int | None
    closed_case_days: int | None
    pending_ti_results_days: int | None
    pending_ai_runs_days: int | None
    pending_closed_case_days: int | None
    effective_at: datetime | None
    enforce: bool
    pending_enforce: bool
    enforce_effective_at: datetime | None
    delay_days: int
    floors: RetentionValues
    updated_by: uuid.UUID | None
    updated_at: datetime | None


class RetentionPreviewIn(_Strict):
    """Preview a policy read-only (the shared selector `retention/select.py`). Omitted
    values preview the effective policy's value."""

    ti_results_days: Days | None = None
    ai_runs_days: Days | None = None
    closed_case_days: Days | None = None


class RetentionCategoryCount(BaseModel):
    candidates: int
    rows: int
    bytes: int
    kept_cited: int
    skipped_hold: int
    skipped_locked: int


class RetentionCandidateOut(BaseModel):
    category: Category
    ref_table: str
    ref_id: str
    job_id: uuid.UUID | None
    investigation_id: uuid.UUID | None
    rows: int
    bytes: int


class RetentionPreviewOut(BaseModel):
    generated_at: datetime
    policy: RetentionValues
    counts: dict[Category, RetentionCategoryCount]
    # A bounded sample of candidates (RETENTION_SAMPLE_LIMIT).
    sample: list[RetentionCandidateOut]
    truncated: bool
    holds_active: int


class RetentionRunCreate(_Strict):
    """A manual run. Its mode comes from the effective policy in the DB (RT1), never from
    the request: `dry_run: true` asks for a dry run even when `enforce` is effective."""

    dry_run: bool | None = None


class RetentionRunOut(BaseModel):
    id: uuid.UUID
    mode: RunMode
    trigger: RunTrigger
    status: RunStatus
    requested_by: uuid.UUID | None
    policy: RetentionValues | None
    counts: dict[Category, RetentionCategoryCount]
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class RetentionRunPage(Page[RetentionRunOut]):
    pass


class RetentionRunItemOut(BaseModel):
    """One purge decision (object keys and version ids stay internal)."""

    id: uuid.UUID
    category: Category
    ref_table: str
    ref_id: str
    job_id: uuid.UUID | None
    rows: int
    bytes: int
    outcome: ItemOutcome
    created_at: datetime


class RetentionRunDetail(RetentionRunOut):
    sample: list[RetentionCandidateOut]
    # The first items of the run (bounded); `items_total` counts all of them.
    items: list[RetentionRunItemOut]
    items_total: int


class LegalHoldCreate(_Strict):
    scope: HoldScope
    # Required for `investigation`, refused for `org` (422).
    investigation_id: uuid.UUID | None = None
    reason: HoldReason

    @field_validator("investigation_id", mode="before")
    @classmethod
    def _not_null(cls, value: object) -> object:
        # Optional (omit for an org hold), but explicit null is not a valid value.
        if value is None:
            raise ValueError("must not be null")
        return value


class LegalHoldRelease(_Strict):
    reason: HoldReason


class LegalHoldOut(BaseModel):
    id: uuid.UUID
    scope: HoldScope
    investigation_id: uuid.UUID | None
    case_ref: str | None
    reason: str
    placed_by: uuid.UUID
    placed_by_name: str
    placed_at: datetime
    released_by: uuid.UUID | None
    released_at: datetime | None
    release_reason: str | None
    # A released hold keeps protecting until released_at + RETENTION_POLICY_DELAY_DAYS (RT1).
    protects_until: datetime | None
    active: bool
    s3_sync: S3Sync
    s3_synced_at: datetime | None


class LegalHoldPage(Page[LegalHoldOut]):
    pass
