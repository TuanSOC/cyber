"""`pcap.v1` result stream: gzip NDJSON, one object per line, `kind` discriminates.

Line 1 is the header, the last line the trailer (line count + sha256 of every byte before
it), so a truncated or spliced stream is detectable before anything is written. Every value
here is derived from attacker-controlled packets: text is length-capped and NUL-free,
timestamps are timezone-aware and inside 1970..2100, counters fit a Postgres bigint,
floats are finite, IP addresses carry no IPv6 zone id.
"""

import uuid
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal

from pydantic import AfterValidator, AwareDatetime, BeforeValidator, Field, IPvAnyAddress, TypeAdapter

from cyberlab_jobs.base import ErrorCode, Sha256, ShortText, Strict
from cyberlab_jobs.capture import CaptureFormat

ToolVersions = Annotated[dict[ShortText, ShortText], Field(max_length=16)]

NO_NUL = r"^[^\x00]*$"
Text16 = Annotated[str, Field(max_length=16, pattern=NO_NUL)]
Text64 = Annotated[str, Field(max_length=64, pattern=NO_NUL)]
Text128 = Annotated[str, Field(max_length=128, pattern=NO_NUL)]
Text255 = Annotated[str, Field(max_length=255, pattern=NO_NUL)]
Text512 = Annotated[str, Field(max_length=512, pattern=NO_NUL)]
Text2048 = Annotated[str, Field(max_length=2048, pattern=NO_NUL)]
Port = Annotated[int, Field(ge=0, le=65535)]
Count = Annotated[int, Field(ge=0, le=2**63 - 1)]
Seconds = Annotated[float, Field(ge=0, le=1e9, allow_inf_nan=False)]

_EARLIEST = datetime(1970, 1, 1, tzinfo=UTC)
_LATEST = datetime(2100, 1, 1, tzinfo=UTC)


def _in_window(value: datetime) -> datetime:
    if not _EARLIEST <= value < _LATEST:
        raise ValueError("timestamp outside 1970..2100")
    return value.astimezone(UTC)


def _no_zone(value: IPv4Address | IPv6Address) -> IPv4Address | IPv6Address:
    if isinstance(value, IPv6Address) and value.scope_id:
        raise ValueError("IPv6 zone ids are not accepted")
    return value


Timestamp = Annotated[AwareDatetime, AfterValidator(_in_window)]
Ip = Annotated[IPvAnyAddress, AfterValidator(_no_zone)]


class ResultHeader(Strict):
    kind: Literal["header"] = "header"
    schema_version: Literal["pcap.v1"] = "pcap.v1"
    job_id: uuid.UUID
    capture_format: CaptureFormat
    tool_versions: ToolVersions
    engine_errors: Annotated[list[ErrorCode], Field(max_length=16)] = []
    truncated: Annotated[dict[ShortText, bool], Field(max_length=16)] = {}


class ProtocolStat(Strict):
    path: Text255  # e.g. "eth:ip:tcp:tls"
    frames: Count
    bytes: Count


class HostStat(Strict):
    ip: Ip
    bytes: Count
    packets: Count
    flows: Count


class PortStat(Strict):
    port: Port
    proto: Text16
    flows: Count
    bytes: Count


class CaptureStats(Strict):
    kind: Literal["stats"] = "stats"
    packets: Count
    bytes: Count
    first_ts: Timestamp | None
    last_ts: Timestamp | None
    duration_s: Seconds | None
    link_type: Text128 | None
    protocol_hierarchy: Annotated[list[ProtocolStat], Field(max_length=200)]
    top_sources: Annotated[list[HostStat], Field(max_length=20)]
    top_destinations: Annotated[list[HostStat], Field(max_length=20)]
    top_ports: Annotated[list[PortStat], Field(max_length=20)]
    counts: Annotated[dict[Text64, Count], Field(max_length=32)]


class _Endpoints(Strict):
    ts: Timestamp
    src_ip: Ip | None = None
    src_port: Port | None = None
    dst_ip: Ip | None = None
    dst_port: Port | None = None
    flow_ref: Text64 | None = None  # Zeek conn uid (may refer to a flow dropped by caps)


class FlowRecord(_Endpoints):
    kind: Literal["flow"] = "flow"
    proto: Literal["tcp", "udp", "icmp", "other"]
    service: Text64 | None = None
    duration_s: Seconds | None = None
    orig_bytes: Count = 0
    resp_bytes: Count = 0
    orig_pkts: Count = 0
    resp_pkts: Count = 0
    conn_state: Text16 | None = None
    community_id: Text64 | None = None


class DnsRecord(_Endpoints):
    kind: Literal["dns"] = "dns"
    query: Text255 | None = None
    qtype: Text16 | None = None
    rcode: Text64 | None = None
    answers: Annotated[list[Text255], Field(max_length=20)] = []
    ttls: Annotated[list[Seconds], Field(max_length=20)] = []


class HttpRecord(_Endpoints):
    kind: Literal["http"] = "http"
    method: Text16 | None = None
    host: Text255 | None = None
    uri: Text2048 | None = None
    status_code: Annotated[int, Field(ge=0, le=999)] | None = None
    user_agent: Text512 | None = None
    referrer: Text2048 | None = None
    resp_mime_types: Annotated[list[Text128], Field(max_length=8)] = []
    request_body_len: Count | None = None
    response_body_len: Count | None = None


class TlsRecord(_Endpoints):
    kind: Literal["tls"] = "tls"
    version: Text16 | None = None
    cipher: Text128 | None = None
    server_name: Text255 | None = None
    established: bool | None = None
    ja3: Text64 | None = None
    ja3s: Text64 | None = None
    cert_subject: Text512 | None = None
    cert_issuer: Text512 | None = None
    cert_not_before: Timestamp | None = None
    cert_not_after: Timestamp | None = None
    cert_sha256: Text64 | None = None  # Zeek x509 fingerprint of the leaf
    validation_status: Text128 | None = None
    self_signed: bool | None = None


class AlertRecord(_Endpoints):
    kind: Literal["alert"] = "alert"
    proto: Text16 | None = None
    signature_id: Annotated[int, Field(ge=0, le=2**63 - 1)]
    rev: Annotated[int, Field(ge=0, le=2**31 - 1)] = 0
    signature: Text512
    category: Text255 | None = None
    severity: Annotated[int, Field(ge=1, le=4)]
    community_id: Text64 | None = None


def _bounded_int(value: object) -> object:
    """Refuse out-of-range ints before the union could silently turn them into floats."""
    if isinstance(value, int) and not isinstance(value, bool) and not -(2**63) <= value < 2**63:
        raise ValueError("integer attribute outside the bigint range")
    return value


# bool first: pydantic would otherwise accept true/false as ints. Numbers are jsonb-safe
# (finite, bigint-bounded) so a validated stream can never fail at insert time.
Attribute = Annotated[
    bool
    | Annotated[int, Field(ge=-(2**63), le=2**63 - 1)]
    | Annotated[float, Field(allow_inf_nan=False)]
    | Annotated[str, Field(max_length=255, pattern=NO_NUL)],
    BeforeValidator(_bounded_int),
]


class FindingRecord(_Endpoints):
    """A heuristic observation with its evidence; never a maliciousness verdict."""

    kind: Literal["finding"] = "finding"
    finding_id: uuid.UUID
    type: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
    title: Text255
    description: Text2048
    severity: Literal["info", "low", "medium", "high"]
    confidence: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    # At most 32 + 1 + 64 + 1 + 4 = 102 chars (stored in a 128-char column).
    detection_method: Annotated[
        str, Field(max_length=128, pattern=r"^[a-z_]{1,32}:[a-z0-9_.\-]{1,64}@\d{1,4}$")
    ]
    last_seen: Timestamp | None = None
    protocol: Text16 | None = None
    evidence_refs: Annotated[list[Text64], Field(max_length=50)] = []
    attributes: Annotated[dict[Text64, Attribute], Field(max_length=20)] = {}


IocType = Literal[
    "ip", "domain", "url", "ja3", "ja3s", "cert_sha256", "file_md5", "file_sha1", "file_sha256"
]


class IocRecord(Strict):
    """An observable seen in the capture (enrichment happens later, never here)."""

    kind: Literal["ioc"] = "ioc"
    type: IocType
    value: Text2048
    first_seen: Timestamp
    last_seen: Timestamp
    count: Count
    source: Text16


class TimelineEvent(Strict):
    kind: Literal["timeline"] = "timeline"
    ts: Timestamp
    event: Literal["capture_start", "capture_end", "finding", "alert", "first_contact"]
    title: Text255
    severity: Literal["info", "low", "medium", "high"] | None = None
    ref: Text64 | None = None  # finding id, flow uid or alert sid
    src_ip: Ip | None = None
    dst_ip: Ip | None = None


class ResultTrailer(Strict):
    kind: Literal["trailer"] = "trailer"
    line_count: int = Field(ge=1)
    sha256: Sha256


RecordLine = Annotated[
    CaptureStats
    | FlowRecord
    | DnsRecord
    | HttpRecord
    | TlsRecord
    | AlertRecord
    | FindingRecord
    | IocRecord
    | TimelineEvent,
    Field(discriminator="kind"),
]
RECORD_ADAPTER: TypeAdapter[RecordLine] = TypeAdapter(RecordLine)

# Every line kind; ingest also checks the position (header first, trailer last).
AnyLine = Annotated[
    ResultHeader
    | CaptureStats
    | FlowRecord
    | DnsRecord
    | HttpRecord
    | TlsRecord
    | AlertRecord
    | FindingRecord
    | IocRecord
    | TimelineEvent
    | ResultTrailer,
    Field(discriminator="kind"),
]
LINE_ADAPTER: TypeAdapter[AnyLine] = TypeAdapter(AnyLine)
