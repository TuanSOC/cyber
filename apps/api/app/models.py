"""Imports every model so Base.metadata is complete (Alembic autogenerate, tests)."""

from app.core.models_base import Base
from app.modules.ai.models import (
    AiCitation,
    AiContextRef,
    AiOrgSettings,
    AiOutput,
    AiProviderConfig,
    AiRun,
    AiRunIndex,
    AiRunInput,
)
from app.modules.analysis.models import AnalysisJob, AnalysisJobIndex
from app.modules.audit.models import AuditLog
from app.modules.auth.models import AuthEvent, RefreshToken
from app.modules.case_attack.models import CaseAttackMapping
from app.modules.evidence.models import Evidence, EvidenceCustodyEvent, EvidenceHash
from app.modules.investigations.models import (
    EvidenceSharePolicy,
    Investigation,
    InvestigationStatusEvent,
)
from app.modules.ioc_collections.models import IocCollection, IocCollectionItem
from app.modules.notes.models import AnalystNote, AnalystNoteVersion
from app.modules.organizations.models import Organization, OrganizationMember
from app.modules.pcap_analysis.models import (
    AnalysisFinding,
    Ioc,
    NetworkAlert,
    NetworkFlow,
    NetworkRecord,
    TimelineEntry,
)
from app.modules.reports.models import (
    Report,
    ReportCitation,
    ReportRender,
    ReportRenderIndex,
    ReportVersion,
)
from app.modules.static_analysis.models import (
    MalwareCapability,
    MalwareExport,
    MalwareImport,
    MalwareResource,
    MalwareSample,
    MalwareSection,
    MalwareSignatureMatch,
    MalwareString,
)
from app.modules.threat_intel.models import (
    TiEnrichmentRun,
    TiOrgSettings,
    TiProviderConfig,
    TiResult,
    TiRunIndex,
    TiRunItem,
)
from app.modules.users.models import User

__all__ = [
    "AiCitation",
    "AiContextRef",
    "AiOrgSettings",
    "AiOutput",
    "AiProviderConfig",
    "AiRun",
    "AiRunIndex",
    "AiRunInput",
    "AnalysisFinding",
    "AnalysisJob",
    "AnalysisJobIndex",
    "AnalystNote",
    "AnalystNoteVersion",
    "AuditLog",
    "AuthEvent",
    "Base",
    "CaseAttackMapping",
    "Evidence",
    "EvidenceCustodyEvent",
    "EvidenceHash",
    "EvidenceSharePolicy",
    "Investigation",
    "InvestigationStatusEvent",
    "Ioc",
    "IocCollection",
    "IocCollectionItem",
    "MalwareCapability",
    "MalwareExport",
    "MalwareImport",
    "MalwareResource",
    "MalwareSample",
    "MalwareSection",
    "MalwareSignatureMatch",
    "MalwareString",
    "NetworkAlert",
    "NetworkFlow",
    "NetworkRecord",
    "Organization",
    "OrganizationMember",
    "RefreshToken",
    "Report",
    "ReportCitation",
    "ReportRender",
    "ReportRenderIndex",
    "ReportVersion",
    "TiEnrichmentRun",
    "TiOrgSettings",
    "TiProviderConfig",
    "TiResult",
    "TiRunIndex",
    "TiRunItem",
    "TimelineEntry",
    "User",
]
