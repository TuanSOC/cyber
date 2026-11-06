"""`static.v1`: static (never executed) analysis of one evidence file.

Same framing as `pcap.v1` (gzip NDJSON, header first, hashed trailer last) and the same
value bounds: every value is derived from an attacker-controlled sample.
Frozen at the end of M3 phase 1: change only together with the trusted ingest.
"""

import enum
import uuid
from typing import Annotated, Literal, Self

from pydantic import Field, TypeAdapter, model_validator

from cyberlab_jobs.base import ErrorCode, Sha256, ShortText, Strict, Token
from cyberlab_jobs.messages import PresignedPost, Url
from cyberlab_jobs.results import (
    NO_NUL,
    Count,
    FindingRecord,
    IocRecord,
    ResultTrailer,
    Text16,
    Text64,
    Text128,
    Text255,
    ToolVersions,
)

STATIC_SCHEMA = "static.v1"

Hex32 = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
Hex40 = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
Text512 = Annotated[str, Field(max_length=512, pattern=NO_NUL)]
Entropy = Annotated[float, Field(ge=0, le=8, allow_inf_nan=False)]
Address = Annotated[int, Field(ge=0, le=2**64 - 1)]  # RVAs / VAs (unsigned 64-bit)
MAX_CAPA_LOCATIONS = 32  # per capability (M10 phase 6 fills them)


class Profile(enum.StrEnum):
    FULL = "full"  # every engine
    AV = "av"  # ClamAV + YARA only (any non-executable upload)


class StaticLimits(Strict):
    max_bytes: int = Field(gt=0)
    timeout_s: int = Field(gt=0, le=6 * 3600)
    tool_timeout_s: int = Field(gt=0)
    max_sections: int = Field(gt=0, le=10_000)
    max_imports: int = Field(gt=0, le=100_000)
    max_exports: int = Field(gt=0, le=100_000)
    max_resources: int = Field(gt=0, le=100_000)
    max_strings: int = Field(gt=0, le=200_000)
    max_signature_matches: int = Field(gt=0, le=10_000)
    max_capabilities: int = Field(gt=0, le=10_000)
    max_findings: int = Field(gt=0, le=10_000)
    max_iocs: int = Field(gt=0, le=100_000)
    max_result_bytes: int = Field(gt=0, le=1024**3)

    @model_validator(mode="after")
    def _tool_within_job(self) -> Self:
        if self.tool_timeout_s >= self.timeout_s:
            raise ValueError("tool_timeout_s must be below timeout_s")
        return self


class StaticJobV1(Strict):
    """API -> static analyzer (queue `static`)."""

    schema_version: Literal["static.v1"] = STATIC_SCHEMA
    job_id: uuid.UUID
    organization_id: uuid.UUID
    evidence_id: uuid.UUID
    expected_sha256: Sha256
    size_bytes: int = Field(ge=0)
    evidence_url: Url
    result_post: PresignedPost
    ingest_token: Token
    profile: Profile
    limits: StaticLimits


# --- result lines ------------------------------------------------------------------------


class StaticResultHeader(Strict):
    kind: Literal["header"] = "header"
    schema_version: Literal["static.v1"] = STATIC_SCHEMA
    job_id: uuid.UUID
    profile: Profile
    file_format: Literal["pe", "elf", "other"]
    tool_versions: ToolVersions
    engine_errors: Annotated[list[ErrorCode], Field(max_length=32)] = []
    truncated: Annotated[dict[ShortText, bool], Field(max_length=32)] = {}
    # M10 (additive, RT18): the base address capa reported its locations against (vivisect's
    # view of the file); None for every stream written before M10.
    capa_base_address: Address | None = None


class SampleInfo(Strict):
    """Exactly one per result. Hashes must equal the evidence record (checked by ingest)."""

    kind: Literal["sample"] = "sample"
    size: Count
    md5: Hex32
    sha1: Hex40
    sha256: Sha256
    ssdeep: Text128 | None = None
    file_type: Text255 | None = None  # libmagic description
    mime: Text128 | None = None
    entropy: Entropy


class PeInfo(Strict):
    kind: Literal["pe"] = "pe"
    machine: Text16
    bits: Literal[32, 64]
    is_dll: bool
    subsystem: Text64 | None = None
    compile_timestamp: Count | None = None  # raw TimeDateStamp (often forged; shown as-is)
    entry_point: Address
    entry_section: Text64 | None = None
    image_base: Address
    imphash: Hex32 | None = None
    rich_header_hash: Hex32 | None = None
    tls_callbacks: Count = 0
    has_authenticode: bool = False  # presence only: the chain is not validated
    overlay_size: Count = 0
    characteristics: Annotated[list[Text64], Field(max_length=32)] = []
    dll_characteristics: Annotated[list[Text64], Field(max_length=32)] = []


class ElfInfo(Strict):
    kind: Literal["elf"] = "elf"
    elf_class: Literal[32, 64]
    machine: Text64
    elf_type: Text16
    entry_point: Address
    interpreter: Text255 | None = None
    needed: Annotated[list[Text255], Field(max_length=256)] = []
    stripped: bool


class SectionRecord(Strict):
    kind: Literal["section"] = "section"
    index: Count
    name: Text64
    virtual_address: Address
    virtual_size: Count
    raw_size: Count
    entropy: Entropy
    flags: Annotated[list[Text16], Field(max_length=16)] = []  # e.g. read, write, execute


class ImportRecord(Strict):
    kind: Literal["import"] = "import"
    library: Text255
    function: Text255 | None = None
    ordinal: Annotated[int, Field(ge=0, le=65535)] | None = None


class ExportRecord(Strict):
    kind: Literal["export"] = "export"
    name: Text255 | None = None
    ordinal: Annotated[int, Field(ge=0, le=2**32 - 1)]
    address: Address


class ResourceRecord(Strict):
    kind: Literal["resource"] = "resource"
    type: Text64
    name: Text255 | None = None
    language: Text64 | None = None
    size: Count
    entropy: Entropy
    sha256: Sha256 | None = None


class StringRecord(Strict):
    kind: Literal["string"] = "string"
    value: Text512
    encoding: Literal["ascii", "utf16le", "floss_decoded", "floss_stack", "floss_tight"]
    offset: Count | None = None


class SignatureMatch(Strict):
    """An engine signature/rule matched. Engine-supplied names are shown verbatim."""

    kind: Literal["signature_match"] = "signature_match"
    engine: Literal["clamav", "yara"]
    name: Text255
    namespace: Text128 | None = None
    tags: Annotated[list[Text64], Field(max_length=20)] = []
    meta: Annotated[dict[Text64, Text255], Field(max_length=20)] = {}


AttackId = Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]
MbcId = Annotated[str, Field(pattern=r"^[A-Z]{1,2}\d{4}(\.[a-z0-9]{3})?$")]


class CapabilityRecord(Strict):
    """capa rule match (static capability, not observed behaviour)."""

    kind: Literal["capability"] = "capability"
    name: Text255
    namespace: Text255 | None = None
    attack: Annotated[list[AttackId], Field(max_length=20)] = []
    mbc: Annotated[list[MbcId], Field(max_length=20)] = []
    matches: Count = 1
    # M10 (additive): absolute match addresses (at most 32, sorted, unique) so the RE ingest
    # can link a capability to the function containing it (file virtual addresses, RT8).
    locations: Annotated[list[Address], Field(max_length=MAX_CAPA_LOCATIONS)] = []

    @model_validator(mode="after")
    def _locations(self) -> Self:
        if self.locations != sorted(set(self.locations)):
            raise ValueError("capability locations are sorted and unique")
        return self


StaticRecordLine = Annotated[
    SampleInfo
    | PeInfo
    | ElfInfo
    | SectionRecord
    | ImportRecord
    | ExportRecord
    | ResourceRecord
    | StringRecord
    | SignatureMatch
    | CapabilityRecord
    | FindingRecord
    | IocRecord,
    Field(discriminator="kind"),
]
StaticAnyLine = Annotated[
    StaticResultHeader
    | SampleInfo
    | PeInfo
    | ElfInfo
    | SectionRecord
    | ImportRecord
    | ExportRecord
    | ResourceRecord
    | StringRecord
    | SignatureMatch
    | CapabilityRecord
    | FindingRecord
    | IocRecord
    | ResultTrailer,
    Field(discriminator="kind"),
]

STATIC_RECORD_ADAPTER: TypeAdapter[StaticRecordLine] = TypeAdapter(StaticRecordLine)
STATIC_LINE_ADAPTER: TypeAdapter[StaticAnyLine] = TypeAdapter(StaticAnyLine)

__all__ = [
    "MAX_CAPA_LOCATIONS",
    "STATIC_LINE_ADAPTER",
    "STATIC_RECORD_ADAPTER",
    "STATIC_SCHEMA",
    "CapabilityRecord",
    "ElfInfo",
    "ExportRecord",
    "ImportRecord",
    "PeInfo",
    "Profile",
    "ResourceRecord",
    "SampleInfo",
    "SectionRecord",
    "SignatureMatch",
    "StaticAnyLine",
    "StaticJobV1",
    "StaticLimits",
    "StaticRecordLine",
    "StaticResultHeader",
    "StringRecord",
    "Text512",
]
