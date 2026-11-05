"""Report request and response models (M6 phase 1, FROZEN; routes in phases 3 and 4).

The draft (`ReportDraft`) holds the analyst sections (plain text, <= 20 000 characters each,
carried whole into the snapshot as `AnalystText`, RT9) and the selections; the whole draft is
<= 1 MiB of JSON, checked here (422) before the database check. The signed snapshot itself is
`cyberlab_jobs.report.ReportSnapshot` (the `content` route returns it as is).
"""

import json
import uuid
from datetime import datetime
from typing import Annotated, Any, Literal, Self

from cyberlab_jobs.report import TLP, Profile, RenderFormat
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from app.modules.reports.models import (
    CHANGE_NOTE_MAX_CHARS,
    DISTRIBUTION_MAX_CHARS,
    DRAFT_MAX_BYTES,
    TITLE_MAX_CHARS,
)

SECTION_MAX_CHARS = 20_000
MAX_AI_RUNS = 10
MAX_CITED_ROWS = 200
MAX_SELECTED_IDS = 200

SectionText = Annotated[str, StringConstraints(max_length=SECTION_MAX_CHARS, pattern=r"^[^\x00]*$")]
ReportTitle = Annotated[
    str,
    StringConstraints(
        min_length=1, max_length=TITLE_MAX_CHARS, strip_whitespace=True, pattern=r"^[^\x00]+$"
    ),
]
Distribution = Annotated[
    str, StringConstraints(max_length=DISTRIBUTION_MAX_CHARS, pattern=r"^[^\x00]*$")
]
ChangeNote = Annotated[
    str, StringConstraints(max_length=CHANGE_NOTE_MAX_CHARS, pattern=r"^[^\x00]*$")
]
Severity = Literal["info", "low", "medium", "high", "critical"]
ReportStatus = Literal["draft", "discarded"]
# M7: `purged` = the rendition was deleted by retention (re-render it from the signed snapshot).
RenderStatus = Literal["queued", "running", "succeeded", "failed", "purged"]
CitedKind = Literal[
    "finding",
    "alert",
    "ioc",
    "evidence",
    "job",
    "timeline",
    "capability",
    "signature",
    "flow",
    "record",
    "ti_result",
    "sample",
    "pe_summary",
    "string",
    "custody",
    "note",
]
RefId = Annotated[
    str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
]
TimelineKindName = Literal["custody", "job", "timeline", "alert", "finding", "note", "status"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DraftSections(_Strict):
    executive_summary: SectionText = ""
    scope: SectionText = ""
    methodology: SectionText = ""
    impact: SectionText = ""
    root_cause: SectionText = ""
    actions_taken: SectionText = ""
    recommendations: SectionText = ""
    lessons_learned: SectionText = ""


class SeveritySelection(_Strict):
    min_severity: Severity = "low"
    max: int = Field(default=500, ge=0, le=500)


class IocSelection(_Strict):
    case_iocs: bool = True
    collections: Annotated[list[uuid.UUID], Field(max_length=50)] = []
    max: int = Field(default=2000, ge=0, le=2000)


class AttackSelection(_Strict):
    statuses: Annotated[list[Literal["confirmed", "suspected"]], Field(max_length=2)] = [
        "confirmed"
    ]


class TimelineSelection(_Strict):
    kinds: Annotated[list[TimelineKindName], Field(max_length=7)] | None = None
    from_: datetime | None = Field(default=None, alias="from")
    to: datetime | None = None
    max: int = Field(default=1000, ge=0, le=1000)

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class CitedRowRef(_Strict):
    kind: CitedKind
    ref_id: RefId
    job_id: uuid.UUID | None = None


class DraftInclude(_Strict):
    evidence: bool = True
    custody: bool = True
    jobs: Literal["latest"] | Annotated[list[uuid.UUID], Field(max_length=MAX_SELECTED_IDS)] = (
        "latest"
    )
    findings: SeveritySelection = SeveritySelection()
    alerts: SeveritySelection = SeveritySelection()
    iocs: IocSelection = IocSelection()
    ti: bool = True
    attack: AttackSelection = AttackSelection()
    timeline: TimelineSelection = TimelineSelection()
    notes: Annotated[list[uuid.UUID], Field(max_length=MAX_SELECTED_IDS)] = []
    ai_runs: Annotated[list[uuid.UUID], Field(max_length=MAX_AI_RUNS)] = []
    cited_rows: Annotated[list[CitedRowRef], Field(max_length=MAX_CITED_ROWS)] = []


class ReportDraft(_Strict):
    """`reports.draft`. The whole JSON must fit DRAFT_MAX_BYTES (1 MiB, RT9)."""

    sections: DraftSections = DraftSections()
    include: DraftInclude = DraftInclude()

    @model_validator(mode="after")
    def _fits(self) -> Self:
        size = len(json.dumps(self.model_dump(mode="json", by_alias=True)).encode("utf-8"))
        if size > DRAFT_MAX_BYTES:
            raise ValueError(f"the draft is {size} bytes; at most {DRAFT_MAX_BYTES}")
        return self


class ReportCreate(_Strict):
    """`tlp` defaults to the case TLP; below it the downgrade rule applies (`org.update` +
    `acknowledge_tlp_downgrade`)."""

    title: ReportTitle
    template: Literal["incident_v1"] = "incident_v1"
    tlp: TLP | None = None
    profile: Profile = Profile.INTERNAL
    acknowledge_tlp_downgrade: bool = False


class ReportUpdate(_Strict):
    """Optimistic concurrency: `revision` must be the current one (`409 stale_draft`)."""

    revision: int = Field(ge=1)
    title: ReportTitle | None = None
    tlp: TLP | None = None
    profile: Profile | None = None
    distribution: Distribution | None = None
    draft: ReportDraft | None = None
    acknowledge_tlp_downgrade: bool = False


class ReportFinalize(_Strict):
    revision: int = Field(ge=1)
    change_note: ChangeNote | None = None
    # RT7: the case TLP may have been raised since the draft was written.
    acknowledge_tlp_downgrade: bool = False
    # RT8: required for the external profile.
    acknowledge_external_review: bool = False


class ReportVersionSummary(BaseModel):
    id: uuid.UUID
    version: int
    tlp: TLP
    profile: Profile
    snapshot_sha256: str
    snapshot_bytes: int
    kid: str
    change_note: str | None
    finalized_by: uuid.UUID
    finalized_by_name: str
    finalized_at: datetime


class ReportOut(BaseModel):
    id: uuid.UUID
    investigation_id: uuid.UUID
    case_ref: str
    title: str
    template: Literal["incident_v1"]
    tlp: TLP
    profile: Profile
    distribution: str | None
    status: ReportStatus
    revision: int
    latest_version: int
    latest: ReportVersionSummary | None
    created_by: uuid.UUID
    created_by_name: str
    created_at: datetime
    updated_at: datetime


class ReportPage(BaseModel):
    items: list[ReportOut]
    next_cursor: str | None


class ReportDetail(BaseModel):
    report: ReportOut
    draft: ReportDraft
    versions: list[ReportVersionSummary]


class SectionCount(BaseModel):
    included: int
    total: int


class ReportPreviewOut(BaseModel):
    """`POST …/preview`: the snapshot built in memory (nothing stored or audited), its size
    and render units against the budget (RT1)."""

    snapshot: dict[str, Any]
    section_counts: dict[str, SectionCount]
    snapshot_bytes: int
    max_snapshot_bytes: int
    render_units: int
    max_render_units: int
    section_units: dict[str, int]
    over_budget: bool


class RenderOut(BaseModel):
    id: uuid.UUID
    version_id: uuid.UUID
    format: RenderFormat
    status: RenderStatus
    error_code: str | None
    sha256: str | None
    bytes: int | None
    pages: int | None
    renderer_version: str | None
    requested_by: uuid.UUID
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class RenderCreate(_Strict):
    format: RenderFormat


class RenderList(BaseModel):
    items: list[RenderOut]


class ReportVersionDetail(BaseModel):
    """`snapshot_ok` re-hashes the stored object; `signature_valid` verifies the manifest
    with the version's kid. A mismatch is shown, never hidden (and audited)."""

    version: ReportVersionSummary
    report_id: uuid.UUID
    manifest: dict[str, Any]
    signature: str
    alg: Literal["Ed25519"] = "Ed25519"
    signature_valid: bool
    snapshot_ok: bool
    section_counts: dict[str, SectionCount]
    renders: list[RenderOut]


class ReportVersionList(BaseModel):
    items: list[ReportVersionSummary]


class ReportSignatureOut(BaseModel):
    """`GET …/signature` (served as `.sig.json`)."""

    manifest: dict[str, Any]
    signature: str
    kid: str
    alg: Literal["Ed25519"] = "Ed25519"


class CitingAiOutput(BaseModel):
    run_id: uuid.UUID
    task: str
    claims: int
    created_at: datetime


class CitingReportVersion(BaseModel):
    report_id: uuid.UUID
    version: int
    title: str
    cite_nos: list[int]
    finalized_at: datetime


class CitedByOut(BaseModel):
    """`GET /cited-by`: the AI outputs (verified citations only) and the report versions
    that cite one row."""

    kind: CitedKind
    ref_id: str
    ai_outputs: list[CitingAiOutput]
    report_versions: list[CitingReportVersion]


class SigningKeyOut(BaseModel):
    kid: str
    alg: Literal["Ed25519"] = "Ed25519"
    public_key: str  # base64 raw 32 bytes
    active: bool


class SigningKeysOut(BaseModel):
    """`GET /api/v1/report-signing-keys` (unauthenticated, RT22): verify an external PDF."""

    keys: list[SigningKeyOut]
