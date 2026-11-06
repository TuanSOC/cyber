import uuid
from datetime import datetime
from typing import Any, Self

from cyberlab_jobs.memory import OsHint
from pydantic import BaseModel, ConfigDict, model_validator

from app.core.pagination import Page
from app.modules.analysis.models import (
    DEFAULT_PROFILE,
    PROFILES,
    AnalysisStatus,
    Analyzer,
    JobProfile,
)


class AnalysisCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analyzer: Analyzer = Analyzer.PCAP
    # Static: `full` (every engine, the default) or `av` (ClamAV + YARA only).
    # Memory (M8): `triage` (the default) or `full`. Pcap takes none.
    profile: JobProfile | None = None
    # Memory only (M8): which OS to try (`auto`, the default, tries both).
    os_hint: OsHint | None = None

    @model_validator(mode="after")
    def _profile_rules(self) -> Self:
        allowed = PROFILES[self.analyzer]
        if self.profile is not None and self.profile not in allowed:
            raise ValueError(f"profile {self.profile.value} does not apply to {self.analyzer}")
        if self.profile is None:
            self.profile = DEFAULT_PROFILE[self.analyzer]
        if self.analyzer == Analyzer.MEMORY:
            if self.os_hint is None:
                self.os_hint = OsHint.AUTO
        elif self.os_hint is not None:
            raise ValueError("os_hint applies to the memory analyzer only")
        return self


class AnalysisJobOut(BaseModel):
    id: uuid.UUID
    evidence_id: uuid.UUID
    investigation_id: uuid.UUID
    evidence_filename: str
    analyzer: Analyzer
    profile: JobProfile | None
    # Memory runs only (M8); null otherwise. Additive.
    os_hint: OsHint | None = None
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
