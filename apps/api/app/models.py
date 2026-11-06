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
from app.modules.api_keys.models import ApiKey
from app.modules.audit.models import AuditLog
from app.modules.auth.models import AuthEvent, RefreshToken
from app.modules.case_attack.models import CaseAttackMapping
from app.modules.correlation.models import CorrelationJobState, CorrelationKey
from app.modules.disk_forensics.models import (
    AnalysisJobSegment,
    DiskEvent,
    DiskExport,
    DiskFile,
    DiskImage,
    DiskPartition,
)
from app.modules.evidence.models import Evidence, EvidenceCustodyEvent, EvidenceHash
from app.modules.identity.models import (
    ActionToken,
    MfaFactor,
    OrgDomain,
    OrgIdpConfig,
    OrgSecurityPolicy,
    RecoveryCode,
    SsoDomainIndex,
    UserIdentity,
    UserSession,
)
from app.modules.invitations.models import InvitationIndex, OrgInvitation
from app.modules.investigations.models import (
    EvidenceSharePolicy,
    Investigation,
    InvestigationStatusEvent,
)
from app.modules.ioc_collections.models import IocCollection, IocCollectionItem
from app.modules.mail.models import EmailOutbox
from app.modules.memory_analysis.models import (
    MemoryArtifact,
    MemoryConnection,
    MemoryImage,
    MemoryInjection,
    MemoryProcess,
    MemorySensitivity,
)
from app.modules.notes.models import AnalystNote, AnalystNoteVersion
from app.modules.ops.models import JobOutcome
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
from app.modules.retention.models import (
    EvidencePurge,
    LegalHold,
    OrgRetentionPolicy,
    RetentionPolicyIndex,
    RetentionRun,
    RetentionRunItem,
)
from app.modules.reverse_engineering.models import (
    ReCallEdge,
    ReDecompilation,
    ReFunction,
    ReFunctionCapability,
    ReImport,
    ReImportRef,
    ReProgram,
    ReString,
    ReStringRef,
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
    # M11 (migration 0019)
    "ActionToken",
    "ApiKey",
    "EmailOutbox",
    "InvitationIndex",
    "MfaFactor",
    "OrgDomain",
    "OrgIdpConfig",
    "OrgInvitation",
    "OrgSecurityPolicy",
    "RecoveryCode",
    "SsoDomainIndex",
    "UserIdentity",
    "UserSession",
    "AnalysisJobSegment",
    "DiskEvent",
    "DiskExport",
    "DiskFile",
    "DiskImage",
    "DiskPartition",
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
    "CorrelationJobState",
    "CorrelationKey",
    "Evidence",
    "EvidenceCustodyEvent",
    "EvidenceHash",
    "EvidencePurge",
    "EvidenceSharePolicy",
    "Investigation",
    "InvestigationStatusEvent",
    "Ioc",
    "IocCollection",
    "IocCollectionItem",
    "JobOutcome",
    "LegalHold",
    "MalwareCapability",
    "MalwareExport",
    "MalwareImport",
    "MalwareResource",
    "MalwareSample",
    "MalwareSection",
    "MalwareSignatureMatch",
    "MalwareString",
    "MemoryArtifact",
    "MemoryConnection",
    "MemoryImage",
    "MemoryInjection",
    "MemoryProcess",
    "MemorySensitivity",
    "NetworkAlert",
    "NetworkFlow",
    "NetworkRecord",
    "OrgRetentionPolicy",
    "Organization",
    "OrganizationMember",
    "ReCallEdge",
    "ReDecompilation",
    "ReFunction",
    "ReFunctionCapability",
    "ReImport",
    "ReImportRef",
    "ReProgram",
    "ReString",
    "ReStringRef",
    "RefreshToken",
    "Report",
    "ReportCitation",
    "ReportRender",
    "ReportRenderIndex",
    "ReportVersion",
    "RetentionPolicyIndex",
    "RetentionRun",
    "RetentionRunItem",
    "TiEnrichmentRun",
    "TiOrgSettings",
    "TiProviderConfig",
    "TiResult",
    "TiRunIndex",
    "TiRunItem",
    "TimelineEntry",
    "User",
]
