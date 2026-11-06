import enum
import uuid
from collections.abc import Mapping
from datetime import datetime
from types import MappingProxyType
from typing import Any

from cyberlab_jobs.disk import DiskProfile
from cyberlab_jobs.memory import MemoryProfile, OsHint
from cyberlab_jobs.static import Profile
from sqlalchemy import (
    Enum,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, UUIDPk, pg_enum


class Analyzer(enum.StrEnum):
    PCAP = "pcap"
    STATIC = "static"
    MEMORY = "memory"  # M8 (migration 0016)
    DISK = "disk"  # M9 (migration 0017)


class JobProfile(enum.StrEnum):
    """What a run was asked to do: static `full` / `av` (0006), memory `triage` / `full`
    (0016), disk `triage` / `full` / `extract` (0017); NULL for pcap. One column for every
    analyzer, so `full` and `triage` are shared."""

    FULL = "full"
    AV = "av"
    TRIAGE = "triage"
    EXTRACT = "extract"  # a disk file export job (M9 phase 10), never requested directly


# The profiles each analyzer takes (the 0016 checks agree; test_analyzer_exhaustive).
PROFILES: Mapping[Analyzer, frozenset[JobProfile]] = MappingProxyType(
    {
        Analyzer.PCAP: frozenset(),
        Analyzer.STATIC: frozenset(JobProfile(p.value) for p in Profile),
        Analyzer.MEMORY: frozenset(JobProfile(p.value) for p in MemoryProfile),
        Analyzer.DISK: frozenset(JobProfile(p.value) for p in DiskProfile),
    }
)
# The profiles an analyst may request through `POST /evidence/{id}/analyses` (`extract` jobs
# are created by the file-export route, phase 10).
REQUESTABLE_PROFILES: Mapping[Analyzer, frozenset[JobProfile]] = MappingProxyType(
    {
        **PROFILES,
        Analyzer.DISK: frozenset({JobProfile.TRIAGE, JobProfile.FULL}),
    }
)
DEFAULT_PROFILE: Mapping[Analyzer, JobProfile | None] = MappingProxyType(
    {
        Analyzer.PCAP: None,
        Analyzer.STATIC: JobProfile.FULL,
        Analyzer.MEMORY: JobProfile.TRIAGE,
        Analyzer.DISK: JobProfile.TRIAGE,
    }
)
# The web route segment of each analyzer's job page (`/o/{org}/{route}/{job}`): every deep
# link the API builds goes through this map (RT1: no two-way "else" sends memory to pcap).
ANALYZER_ROUTES: Mapping[Analyzer, str] = MappingProxyType(
    {
        Analyzer.PCAP: "pcap",
        Analyzer.STATIC: "malware",
        Analyzer.MEMORY: "memory",
        Analyzer.DISK: "forensics",
    }
)
ANALYZER_TITLES: Mapping[Analyzer, str] = MappingProxyType(
    {
        Analyzer.PCAP: "PCAP analysis",
        Analyzer.STATIC: "Static analysis",
        Analyzer.MEMORY: "Memory analysis",
        Analyzer.DISK: "Disk analysis",
    }
)


def analyzer_route(analyzer: str | None) -> str | None:
    """The route segment of a stored analyzer value; None for an unknown one."""
    try:
        return ANALYZER_ROUTES[Analyzer(analyzer)] if analyzer is not None else None
    except ValueError:
        return None


class AnalysisStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


# Stored as text with a CHECK (not a Postgres enum): new profiles need no ALTER TYPE.
PROFILE = Enum(
    JobProfile,
    native_enum=False,
    create_constraint=False,
    length=16,
    values_callable=lambda e: [m.value for m in e],
)

OS_HINT = Enum(
    OsHint,
    native_enum=False,
    create_constraint=False,
    length=16,
    values_callable=lambda e: [m.value for m in e],
)

ACTIVE = (AnalysisStatus.QUEUED, AnalysisStatus.RUNNING)
TERMINAL = (AnalysisStatus.SUCCEEDED, AnalysisStatus.FAILED)


class AnalysisJob(UUIDPk, Base):
    """One analyzer run over one evidence version. Terminal states are final (DB trigger)."""

    __tablename__ = "analysis_jobs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"], ["evidence.id", "evidence.organization_id"]
        ),
        UniqueConstraint("id", "organization_id"),
        Index(None, "organization_id", "created_at"),
        Index(None, "evidence_id", "created_at"),
        # At most one active run per evidence and analyzer.
        Index(
            "uq_analysis_jobs_active",
            "evidence_id",
            "analyzer",
            unique=True,
            postgresql_where=text("status IN ('queued', 'running')"),
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    evidence_id: Mapped[uuid.UUID]
    analyzer: Mapped[Analyzer] = mapped_column(pg_enum(Analyzer, "analyzer"))
    # Static (`full` / `av`) and memory (`triage` / `full`) runs; NULL for pcap (DB checks).
    profile: Mapped[JobProfile | None] = mapped_column(PROFILE)
    # Memory runs only (`auto` / `windows` / `linux`), NULL otherwise (0016 check); write-once.
    os_hint: Mapped[OsHint | None] = mapped_column(OS_HINT)
    status: Mapped[AnalysisStatus] = mapped_column(
        pg_enum(AnalysisStatus, "analysis_status"),
        server_default=AnalysisStatus.QUEUED.value,
        default=AnalysisStatus.QUEUED,
    )
    error_code: Mapped[str | None] = mapped_column(String(64))
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    auto: Mapped[bool] = mapped_column(server_default="false", default=False)
    ingest_token_sha256: Mapped[str] = mapped_column(String(64))
    worker_version: Mapped[str | None] = mapped_column(String(255))
    result_version_id: Mapped[str | None] = mapped_column(String(255))
    summary: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]


class AnalysisJobIndex(Base):
    """Non-tenant lookup (job -> org, status, deadline) for the ingest worker and reaper.

    Holds no tenant data. It lets system code find which org a job belongs to before
    opening a tenant session for it; it is updated in the same transaction as the job.
    """

    __tablename__ = "analysis_job_index"
    __table_args__ = (
        Index(None, "status", "deadline_at"),
        Index(None, "analyzer", "status"),
    )

    job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analysis_jobs.id", ondelete="CASCADE"), primary_key=True
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    # Routing data, not tenant data: lets the global per-analyzer cap count without RLS.
    analyzer: Mapped[Analyzer] = mapped_column(pg_enum(Analyzer, "analyzer"))
    status: Mapped[AnalysisStatus] = mapped_column(pg_enum(AnalysisStatus, "analysis_status"))
    deadline_at: Mapped[datetime]
