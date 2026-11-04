import enum
import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from app.core.pagination import MAX_OFFSET, Page

# asyncpg returns inet values as ipaddress objects; the API speaks plain strings.
IpText = Annotated[str | None, BeforeValidator(lambda v: None if v is None else str(v))]


class _Row(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class FlowSort(enum.StrEnum):
    BYTES = "bytes"  # largest first
    TS = "ts"  # oldest first


class FlowProto(enum.StrEnum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"


class RecordKind(enum.StrEnum):
    DNS = "dns"
    HTTP = "http"
    TLS = "tls"


class FindingSeverity(enum.StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class IocType(enum.StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    JA3 = "ja3"
    JA3S = "ja3s"
    CERT_SHA256 = "cert_sha256"
    FILE_MD5 = "file_md5"
    FILE_SHA1 = "file_sha1"
    FILE_SHA256 = "file_sha256"


class _Endpoints(_Row):
    id: uuid.UUID
    ts: datetime
    src_ip: IpText
    src_port: int | None
    dst_ip: IpText
    dst_port: int | None
    flow_ref: str | None


class FlowOut(_Endpoints):
    proto: str
    service: str | None
    duration_s: float | None
    orig_bytes: int
    resp_bytes: int
    total_bytes: int
    orig_pkts: int
    resp_pkts: int
    conn_state: str | None
    community_id: str | None


class RecordOut(_Endpoints):
    kind: RecordKind
    summary: str
    details: dict[str, Any]


class AlertOut(_Endpoints):
    proto: str | None
    signature_id: int
    rev: int
    signature: str
    category: str | None
    severity: int
    community_id: str | None


class FindingOut(_Endpoints):
    finding_id: uuid.UUID
    type: str
    title: str
    description: str
    severity: FindingSeverity
    confidence: float
    detection_method: str
    last_seen: datetime | None
    protocol: str | None
    evidence_refs: list[str]
    attributes: dict[str, Any]


class IocOut(_Row):
    id: uuid.UUID
    type: IocType
    value: str
    first_seen: datetime
    last_seen: datetime
    count: int
    source: str


class TimelineOut(_Row):
    id: uuid.UUID
    ts: datetime
    event: str
    title: str
    severity: FindingSeverity | None
    ref: str | None
    src_ip: IpText
    dst_ip: IpText


TOTAL_CAP = MAX_OFFSET + 1


class CappedPage[T](Page[T]):
    total: int = Field(
        le=TOTAL_CAP,
        description=(
            f"Matching rows, counted up to {TOTAL_CAP}: {TOTAL_CAP} means at least that "
            f"many (offset is capped at {MAX_OFFSET})."
        ),
    )


class FlowPage(CappedPage[FlowOut]):
    pass


class RecordPage(CappedPage[RecordOut]):
    pass


class AlertPage(CappedPage[AlertOut]):
    pass


class FindingPage(CappedPage[FindingOut]):
    pass


class IocPage(CappedPage[IocOut]):
    pass


class TimelinePage(CappedPage[TimelineOut]):
    pass
