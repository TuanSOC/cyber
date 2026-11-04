import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.core.pagination import Page
from app.modules.analysis.models import AnalysisStatus, Analyzer


class AnalysisCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analyzer: Analyzer = Analyzer.PCAP


class AnalysisJobOut(BaseModel):
    id: uuid.UUID
    evidence_id: uuid.UUID
    investigation_id: uuid.UUID
    evidence_filename: str
    analyzer: Analyzer
    status: AnalysisStatus
    error_code: str | None
    auto: bool
    requested_by: uuid.UUID
    requested_by_name: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    summary: dict[str, Any]


class AnalysisJobPage(Page[AnalysisJobOut]):
    pass
