"""Imports every model so Base.metadata is complete (Alembic autogenerate, tests)."""

from app.core.models_base import Base
from app.modules.analysis.models import AnalysisJob, AnalysisJobIndex
from app.modules.audit.models import AuditLog
from app.modules.auth.models import AuthEvent, RefreshToken
from app.modules.evidence.models import Evidence, EvidenceCustodyEvent, EvidenceHash
from app.modules.investigations.models import Investigation
from app.modules.organizations.models import Organization, OrganizationMember
from app.modules.pcap_analysis.models import (
    AnalysisFinding,
    Ioc,
    NetworkAlert,
    NetworkFlow,
    NetworkRecord,
    TimelineEntry,
)
from app.modules.users.models import User

__all__ = [
    "AnalysisFinding",
    "AnalysisJob",
    "AnalysisJobIndex",
    "AuditLog",
    "AuthEvent",
    "Base",
    "Evidence",
    "EvidenceCustodyEvent",
    "EvidenceHash",
    "Investigation",
    "Ioc",
    "NetworkAlert",
    "NetworkFlow",
    "NetworkRecord",
    "Organization",
    "OrganizationMember",
    "RefreshToken",
    "TimelineEntry",
    "User",
]
