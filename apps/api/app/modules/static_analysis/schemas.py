"""Read models of static analysis results and the versioned static report document."""

import enum
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from app.modules.analysis.models import AnalysisStatus, Analyzer
from app.modules.evidence.models import CustodyAction
from app.modules.pcap_analysis.schemas import CappedPage, FindingOut, IocOut


def _to_int(value: object) -> object:
    return int(value) if isinstance(value, Decimal) else value


# Unsigned 64-bit addresses are NUMERIC in the database (Decimal from the driver).
Address = Annotated[int, BeforeValidator(_to_int)]


class _Row(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class StringEncoding(enum.StrEnum):
    ASCII = "ascii"
    UTF16LE = "utf16le"
    FLOSS_DECODED = "floss_decoded"
    FLOSS_STACK = "floss_stack"
    FLOSS_TIGHT = "floss_tight"


class SignatureEngine(enum.StrEnum):
    CLAMAV = "clamav"
    YARA = "yara"


class PeOut(BaseModel):
    machine: str
    bits: int
    is_dll: bool
    subsystem: str | None
    compile_timestamp: int | None = Field(
        description="Raw TimeDateStamp as found in the header (often forged; shown as-is)."
    )
    entry_point: Address
    entry_section: str | None
    image_base: Address
    imphash: str | None = Field(description="Analyzer-derived.")
    rich_header_hash: str | None = Field(description="Analyzer-derived.")
    tls_callbacks: int
    has_authenticode: bool = Field(description="Presence only: the chain is not validated.")
    overlay_size: int
    characteristics: list[str]
    dll_characteristics: list[str]


class ElfOut(BaseModel):
    elf_class: int
    machine: str
    elf_type: str
    entry_point: Address
    interpreter: str | None
    needed: list[str]
    stripped: bool


class AnalyzerDerivedHashes(BaseModel):
    """Computed by the (untrusted) analyzer from the sample; never used as identity."""

    ssdeep: str | None
    imphash: str | None
    rich_header_hash: str | None


class SampleOut(BaseModel):
    """Sample facts. `size` and the md5/sha1/sha256 hashes are the evidence record's
    (computed at upload; ingest refuses a result whose sample differs)."""

    job_id: uuid.UUID
    evidence_id: uuid.UUID
    size: int
    md5: str | None
    sha1: str | None
    sha256: str
    file_type: str | None
    mime: str | None
    entropy: float
    file_format: Literal["pe", "elf", "other"]
    analyzer_derived: AnalyzerDerivedHashes
    pe: PeOut | None
    elf: ElfOut | None


class SectionOut(_Row):
    id: uuid.UUID
    index: int
    name: str
    virtual_address: Address
    virtual_size: int
    raw_size: int
    entropy: float
    flags: list[str]


class ImportOut(_Row):
    id: uuid.UUID
    library: str
    function: str | None
    ordinal: int | None


class ExportOut(_Row):
    id: uuid.UUID
    name: str | None
    ordinal: int
    address: Address


class ResourceOut(_Row):
    id: uuid.UUID
    type: str
    name: str | None
    language: str | None
    size: int
    entropy: float
    sha256: str | None


class StringOut(_Row):
    id: uuid.UUID
    value: str
    encoding: StringEncoding
    offset: int | None


class SignatureOut(_Row):
    """An engine signature/rule matched; the name is the engine's, verbatim."""

    id: uuid.UUID
    engine: SignatureEngine
    name: str
    namespace: str | None
    tags: list[str]
    meta: dict[str, Any]


class CapabilityOut(_Row):
    """A capa rule match: a static capability, not observed behaviour."""

    id: uuid.UUID
    name: str
    namespace: str | None
    attack: list[str]
    mbc: list[str]
    matches: int


class SectionPage(CappedPage[SectionOut]):
    pass


class ImportPage(CappedPage[ImportOut]):
    pass


class ExportPage(CappedPage[ExportOut]):
    pass


class ResourcePage(CappedPage[ResourceOut]):
    pass


class StringPage(CappedPage[StringOut]):
    pass


class SignaturePage(CappedPage[SignatureOut]):
    pass


class CapabilityPage(CappedPage[CapabilityOut]):
    pass


# --- report ------------------------------------------------------------------------------

REPORT_SCHEMA: Literal["cyberlab.report.static.v1"] = "cyberlab.report.static.v1"


class ReportList[T](BaseModel):
    items: list[T]
    total: int = Field(description="All rows of this kind for the job.")
    truncated: bool = Field(description="True when `items` holds fewer than `total`.")


class ReportFindings(ReportList[FindingOut]):
    pass


class ReportSignatures(ReportList[SignatureOut]):
    pass


class ReportCapabilities(ReportList[CapabilityOut]):
    pass


class ReportIocs(ReportList[IocOut]):
    pass


class ReportSections(ReportList[SectionOut]):
    pass


class ReportOrganization(BaseModel):
    id: uuid.UUID
    name: str


class ReportInvestigation(BaseModel):
    id: uuid.UUID
    case_ref: str
    title: str


class ReportEvidence(BaseModel):
    id: uuid.UUID
    filename: str
    size_bytes: int
    hashes: dict[str, str] = Field(description="Trusted: computed by the API at upload.")
    detected_mime: str
    uploaded_at: datetime
    uploaded_by: uuid.UUID
    uploaded_by_name: str


class ReportCustodyEvent(BaseModel):
    action: CustodyAction
    occurred_at: datetime
    actor_id: uuid.UUID
    actor_name: str


class ReportCustody(BaseModel):
    count: int = Field(description="Every custody event of the evidence.")
    recent: list[ReportCustodyEvent] = Field(description="The latest events, oldest first.")


class ReportAnalysis(BaseModel):
    job_id: uuid.UUID
    analyzer: Analyzer
    profile: str | None
    status: AnalysisStatus
    auto: bool
    requested_by: uuid.UUID
    requested_by_name: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    worker_version: str | None
    result_schema: str
    tool_versions: dict[str, str] = Field(
        description="Engine, signature database and rule versions reported by the analyzer."
    )
    engine_errors: list[str]
    truncated: dict[str, bool]
    counts: dict[str, int]


class ReportSample(BaseModel):
    """Trusted size and hashes (evidence record) plus the analyzer's file facts."""

    size: int
    md5: str | None
    sha1: str | None
    sha256: str
    file_type: str | None
    mime: str | None
    entropy: float
    file_format: Literal["pe", "elf", "other"]
    analyzer_derived: AnalyzerDerivedHashes


class LibraryCount(BaseModel):
    library: str
    imports: int


class NotableFunction(BaseModel):
    library: str
    function: str
    category: str


class ImportsSummary(BaseModel):
    total: int
    libraries: int
    top_libraries: list[LibraryCount]
    notable_functions: list[NotableFunction] = Field(
        description=(
            "Imported API names that often deserve a closer look (injection, anti-debugging, "
            "networking, ...). Common in benign software too: presence alone is no verdict."
        )
    )
    notable_truncated: bool


class StaticReport(BaseModel):
    """Summary-level, capped report of one succeeded static analysis (no string dump)."""

    # Always present in the document, so required in the published (response) schema.
    model_config = ConfigDict(json_schema_serialization_defaults_required=True)

    schema_: Literal["cyberlab.report.static.v1"] = Field(default=REPORT_SCHEMA, alias="schema")
    generated_at: datetime
    organization: ReportOrganization
    investigation: ReportInvestigation
    evidence: ReportEvidence
    custody: ReportCustody
    analysis: ReportAnalysis
    sample: ReportSample
    pe: PeOut | None
    elf: ElfOut | None
    findings: ReportFindings
    signatures: ReportSignatures
    capabilities: ReportCapabilities
    iocs: ReportIocs
    imports_summary: ImportsSummary
    sections: ReportSections
