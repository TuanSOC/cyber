import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, IPvAnyAddress

from app.core.pagination import Page
from app.modules.evidence.models import CustodyAction, EvidenceStatus


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
    legal_hold: bool = False
    declared_type: str | None = None
    type_mismatch: bool | None = None


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
