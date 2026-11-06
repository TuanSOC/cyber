import uuid
from datetime import datetime
from typing import Annotated, Any, Self

from cyberlab_jobs.disk import MAX_SEGMENTS
from cyberlab_jobs.memory import OsHint
from cyberlab_jobs.reverse import MAX_DECOMPILE_ADDRESSES
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.pagination import Page
from app.modules.analysis.models import (
    DEFAULT_PROFILE,
    REQUESTABLE_PROFILES,
    AnalysisStatus,
    Analyzer,
    JobProfile,
)


HexAddressIn = Annotated[str, Field(pattern=r"^0x[0-9a-fA-F]{1,16}$", examples=["0x401000"])]


class AnalysisCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analyzer: Analyzer = Analyzer.PCAP
    # Static: `full` (every engine, the default) or `av` (ClamAV + YARA only).
    # Memory (M8): `triage` (the default) or `full`. Pcap takes none.
    profile: JobProfile | None = None
    # Memory and disk (M8 / M9): which OS to try (`auto`, the default, tries both).
    os_hint: OsHint | None = None
    # Disk only (M9): the ordered segment set (evidence ids of the same investigation, 1..64;
    # this evidence must be one of them). Required for disk, refused otherwise.
    segments: list[uuid.UUID] | None = Field(default=None, min_length=1, max_length=MAX_SEGMENTS)
    # Reverse engineering only (M10): `quick` (radare2, when enabled) or `full` (the default).
    # The static `full` job of this evidence to start from (default: the latest succeeded one
    # that identified a PE / ELF file), and for `full` up to 64 addresses (`0x…`, engine
    # virtual addresses) to decompile first (RT10: "Decompile this function").
    source_job_id: uuid.UUID | None = None
    decompile_addresses: list[HexAddressIn] | None = Field(
        default=None, max_length=MAX_DECOMPILE_ADDRESSES
    )

    @model_validator(mode="after")
    def _profile_rules(self) -> Self:
        allowed = REQUESTABLE_PROFILES[self.analyzer]
        if self.profile is not None and self.profile not in allowed:
            raise ValueError(f"profile {self.profile.value} does not apply to {self.analyzer}")
        if self.profile is None:
            self.profile = DEFAULT_PROFILE[self.analyzer]
        if self.analyzer in (Analyzer.MEMORY, Analyzer.DISK):
            if self.os_hint is None:
                self.os_hint = OsHint.AUTO
        elif self.os_hint is not None:
            raise ValueError("os_hint applies to the memory and disk analyzers only")
        if self.analyzer == Analyzer.DISK:
            if self.segments is None:
                raise ValueError("a disk analysis names its ordered segments")
            if len(set(self.segments)) != len(self.segments):
                raise ValueError("a segment is listed twice")
        elif self.segments is not None:
            raise ValueError("segments apply to the disk analyzer only")
        if self.analyzer == Analyzer.REVERSE:
            addresses = self.decompile_address_values()
            if len(set(addresses)) != len(addresses):
                raise ValueError("an address is listed twice")
            if addresses and self.profile != JobProfile.FULL:
                raise ValueError("decompile_addresses apply to the full profile only")
        elif self.source_job_id is not None or self.decompile_addresses is not None:
            raise ValueError("source_job_id and decompile_addresses apply to reverse only")
        return self

    def decompile_address_values(self) -> list[int]:
        return [int(a, 16) for a in self.decompile_addresses or []]


class AnalysisJobOut(BaseModel):
    id: uuid.UUID
    evidence_id: uuid.UUID
    investigation_id: uuid.UUID
    evidence_filename: str
    analyzer: Analyzer
    profile: JobProfile | None
    # Memory and disk runs (M8 / M9); null otherwise. Additive.
    os_hint: OsHint | None = None
    # Reverse engineering runs (M10): the static job it started from; null otherwise.
    source_job_id: uuid.UUID | None = None
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
