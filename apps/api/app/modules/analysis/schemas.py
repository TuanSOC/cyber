import uuid
from datetime import datetime
from typing import Any, Self

from cyberlab_jobs.static import Profile
from pydantic import BaseModel, ConfigDict, model_validator

from app.core.pagination import Page
from app.modules.analysis.models import AnalysisStatus, Analyzer


class AnalysisCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analyzer: Analyzer = Analyzer.PCAP
    # Static only: `full` (every engine, the default) or `av` (ClamAV + YARA only).
    profile: Profile | None = None

    @model_validator(mode="after")
    def _profile_for_static_only(self) -> Self:
        if self.profile is not None and self.analyzer != Analyzer.STATIC:
            raise ValueError("profile applies to the static analyzer only")
        if self.analyzer == Analyzer.STATIC and self.profile is None:
            self.profile = Profile.FULL
        return self


class AnalysisJobOut(BaseModel):
    id: uuid.UUID
    evidence_id: uuid.UUID
    investigation_id: uuid.UUID
    evidence_filename: str
    analyzer: Analyzer
    profile: Profile | None
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
