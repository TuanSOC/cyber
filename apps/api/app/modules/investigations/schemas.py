import uuid
from datetime import datetime
from typing import Annotated, Self

from cyberlab_jobs.report import TLP
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from app.core.pagination import Page
from app.core.validation import SafeName
from app.modules.investigations.models import InvestigationStatus, Severity

# Free text may contain newlines/tabs, never NUL (Postgres text cannot store it).
Description = Annotated[str, StringConstraints(max_length=10_000, pattern=r"^[^\x00]*$")]
Title = Annotated[SafeName, Field(min_length=3, max_length=200)]
# M6: the reason of a close / reopen / archive (plain text, no NUL). Surrounding whitespace
# is stripped first, so a whitespace-only reason is refused (422).
StatusReason = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=500, pattern=r"^[^\x00]*$"),
]


def case_ref(case_number: int) -> str:
    return f"CASE-{case_number:05d}"


class InvestigationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: Title
    description: Description = ""
    severity: Severity


class InvestigationUpdate(BaseModel):
    """M6 adds `tlp` (lowering it needs `org.update` and `acknowledge_tlp_downgrade`), the
    share-policy flags (turning one off needs `integrations.manage`) and `status_reason`
    (required to close, reopen or archive). Phase 2 implements the rules."""

    model_config = ConfigDict(extra="forbid")

    title: Title | None = None
    description: Description | None = None
    severity: Severity | None = None
    status: InvestigationStatus | None = None
    tlp: TLP | None = None
    ai_excluded: bool | None = None
    ti_excluded: bool | None = None
    status_reason: StatusReason | None = None
    # Optional like every other PATCH field (a `bool = False` default would make the generated
    # TS type require it on every edit); only `true` acknowledges a downgrade.
    acknowledge_tlp_downgrade: bool | None = None

    @field_validator(
        "title",
        "description",
        "severity",
        "status",
        "tlp",
        "ai_excluded",
        "ti_excluded",
        "status_reason",
        "acknowledge_tlp_downgrade",
        mode="before",
    )
    @classmethod
    def _not_null(cls, value: object) -> object:
        # Fields are optional (omit to keep), but explicit null is not a valid value.
        if value is None:
            raise ValueError("must not be null")
        return value

    @model_validator(mode="after")
    def _not_empty(self) -> Self:
        if not self.model_fields_set - {"acknowledge_tlp_downgrade", "status_reason"}:
            raise ValueError("at least one field must be provided")
        return self


class SharePolicyOut(BaseModel):
    """The case-level share policy (TLP:RED implies both blocks). Evidence-level flags are
    on the evidence (`EvidenceSharePolicyOut`)."""

    ai_blocked: bool
    ti_blocked: bool
    reasons: list[str]


class InvestigationOut(BaseModel):
    id: uuid.UUID
    case_number: int
    case_ref: str
    title: str
    description: str
    status: InvestigationStatus
    allowed_transitions: list[InvestigationStatus]
    severity: Severity
    created_by: uuid.UUID
    created_by_name: str
    evidence_count: int
    created_at: datetime
    updated_at: datetime
    # M6
    tlp: TLP
    ai_excluded: bool
    ti_excluded: bool
    share_policy: SharePolicyOut
    # M7: an active legal hold (case or org scope) covers this case (filled by phase 3).
    legal_hold: bool = False


class InvestigationPage(Page[InvestigationOut]):
    pass


class StatusEventOut(BaseModel):
    """One status change (M6). `reason` is shown to `investigation.read` holders."""

    id: uuid.UUID
    from_status: InvestigationStatus | None
    to_status: InvestigationStatus
    reason: str | None
    actor_id: uuid.UUID
    actor_name: str
    occurred_at: datetime


class StatusEventPage(BaseModel):
    items: list[StatusEventOut]
    next_cursor: str | None


class EvidenceSharePolicyIn(BaseModel):
    """`PUT /evidence/{id}/share-policy`: turning a flag off needs `integrations.manage`."""

    model_config = ConfigDict(extra="forbid")

    ai_excluded: bool
    ti_excluded: bool


class EvidenceSharePolicyOut(BaseModel):
    evidence_id: uuid.UUID
    ai_excluded: bool
    ti_excluded: bool
    # The effective policy of this evidence (its own flags plus its case's flags and TLP).
    effective: SharePolicyOut
    updated_by: uuid.UUID | None
    updated_at: datetime | None


class TimelineEntryOut(BaseModel):
    """One entry of the merged investigation timeline (M5). `ts_source` says which clock the
    time comes from: `recorded` (platform event), `capture` (the capture's clock) or
    `analysis_time` (a static finding, at its job's finish time). M6 (RT10): case events
    (`ref_kind` `note` / `status`) have no `evidence_id`."""

    ts: datetime
    ts_source: str
    kind: str
    title: str
    severity: str | None
    evidence_id: uuid.UUID | None
    job_id: uuid.UUID | None
    ref_kind: str
    ref_id: uuid.UUID


class InvestigationTimelinePage(BaseModel):
    items: list[TimelineEntryOut]
    next_cursor: str | None
