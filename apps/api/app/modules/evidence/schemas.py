import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress

from app.core.pagination import Page
from app.modules.evidence.models import CustodyAction, EvidenceStatus


class EvidenceSensitivityOut(BaseModel):
    """The evidence-level sensitivity (M9, RT2): `memory_sensitivity` rows of any source."""

    state: Literal["restricted", "released"]
    source: Literal["memory", "disk", "derived"]


class EvidenceSensitivityDetailOut(BaseModel):
    """`GET /evidence/{id}/sensitivity` (M9, RT2): the state and source of the evidence's
    sensitivity row; `state: none` (and `source: null`) when it was never marked."""

    evidence_id: uuid.UUID
    state: Literal["none", "restricted", "released"]
    source: Literal["memory", "disk", "derived"] | None = None
    defaulted_at: datetime | None = None
    released_at: datetime | None = None
    released_by_name: str | None = None
    release_reason: str | None = None


class SensitivityReleaseIn(BaseModel):
    """Admin release of restricted evidence (once, audited). `job_id` (a disk job whose
    segments include this evidence) releases every restricted segment of the job in one
    request (RT20). Derived evidence is never part of a batch."""

    model_config = ConfigDict(extra="forbid")

    acknowledge: bool = Field(
        description="Must be true: the evidence may hold passwords, keys and personal data."
    )
    reason: Annotated[str, Field(min_length=1, max_length=500)]
    job_id: uuid.UUID | None = None


class EvidenceOut(BaseModel):
    """Evidence metadata. Storage location/version are internal and never exposed."""

    id: uuid.UUID
    investigation_id: uuid.UUID
    original_filename: str
    detected_mime: str
    detected_description: str
    size_bytes: int
    status: EvidenceStatus
    description: str
    uploaded_by: uuid.UUID
    uploaded_by_name: str
    uploaded_at: datetime
    hashes: dict[str, str]
    # M6: the evidence share-policy flags (`evidence_share_policies`; filled by phase 2).
    ai_excluded: bool = False
    ti_excluded: bool = False
    # M7: when retention purged the bytes (tombstone; filled by phase 3, download and verify
    # then answer 410 `evidence_purged`), whether a legal hold covers the evidence's case or
    # org (phase 3), and the declared type vs the detected type (phase 6, NULL before M7).
    purged_at: datetime | None = None
    # Additive (M7 follow-up): the retention run that purged the bytes (with `purged_at`).
    # The run detail itself stays `audit.read`; the id alone reveals nothing more.
    purged_by_run_id: uuid.UUID | None = None
    legal_hold: bool = False
    declared_type: str | None = None
    type_mismatch: bool | None = None
    # M8: the memory sensitivity (`memory_sensitivity`, filled by phase 8): `restricted` (TLP:RED
    # by default, AI and TI excluded until an admin releases it), `released`, or null when the
    # evidence was never marked as a memory image.
    memory_sensitivity: Literal["restricted", "released"] | None = None
    # M9 (RT2): the sensitivity of any source (memory, disk, derived), beside M8's field
    # (which stays and is filled for `memory` rows only); null when never marked.
    sensitivity: EvidenceSensitivityOut | None = None
    # M9: the source evidence of a file exported from a disk image (derived evidence; filled
    # by phase 10 from `disk_exports`), null otherwise.
    derived_from: uuid.UUID | None = None


# `?kind=` of the upload route (M8): `memory` declares a memory image (its own size limit,
# restricted from the upload transaction, never analyzed automatically; RT3).
UploadKind = Literal["memory"]


class EvidencePage(Page[EvidenceOut]):
    pass


class CustodyEventOut(BaseModel):
    id: uuid.UUID
    action: CustodyAction
    actor_id: uuid.UUID
    actor_name: str
    occurred_at: datetime
    ip: IPvAnyAddress | None
    user_agent: str | None
    details: dict[str, Any]


class CustodyPage(Page[CustodyEventOut]):
    pass


class VerifyOut(BaseModel):
    result: Literal["ok", "mismatch", "missing"]
    expected: dict[str, str]
    actual: dict[str, str] | None
    size_bytes: int | None
