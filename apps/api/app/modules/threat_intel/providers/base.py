"""The provider interface (frozen in M4 phase 1; only the parent changes it afterwards).

Shared by the API, `normalize.py` and the enrich worker: unlike the adapter modules, the
registry, `http.py` and `unseal.py`, this module may be imported anywhere (see
`tests/unit/test_ti_import_guard.py`). It holds types only: no I/O, no keys.
"""

import enum
import hashlib
import math
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Literal, Protocol, Self
from urllib.parse import urlsplit

from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field, model_validator

from app.modules.threat_intel.summaries import (
    Count,
    ProviderSummary,
    Text32,
    Text64,
    Timestamp,
    _attack_ids,
    _cap,
)

if TYPE_CHECKING:
    import httpx


class ProviderName(enum.StrEnum):
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    URLHAUS = "urlhaus"
    MALWAREBAZAAR = "malwarebazaar"
    OTX = "otx"
    MISP = "misp"
    MOCK = "mock"  # dev/test only (refused when ENV=prod)


class IocType(enum.StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"  # MISP and mock only; never sent to an external public provider


HASH_TYPES = frozenset({IocType.MD5, IocType.SHA1, IocType.SHA256})
IP_TYPES = frozenset({IocType.IPV4, IocType.IPV6})


class ResultStatus(enum.StrEnum):
    """What a provider said. Rate-limit, quota and deadline outcomes are run-item states,
    never results (the history shows only real provider answers)."""

    OK = "ok"
    NOT_FOUND = "not_found"
    ERROR = "error"
    AUTH_FAILED = "auth_failed"


class VerifyStatus(enum.StrEnum):
    UNVERIFIED = "unverified"
    VALID = "valid"
    INVALID = "invalid"
    ERROR = "error"


class ProviderErrorKind(enum.StrEnum):
    TIMEOUT = "timeout"
    TRANSPORT = "transport"
    OVERSIZE = "oversize"
    BAD_JSON = "bad_json"
    HTTP_5XX = "http_5xx"
    UNEXPECTED_STATUS = "unexpected_status"
    REDIRECT = "redirect"
    AUTH = "auth"
    RATE_LIMITED = "rate_limited"
    QUOTA_EXHAUSTED = "quota_exhausted"
    NOT_FOUND = "not_found"
    BAD_REQUEST = "bad_request"
    INVALID_INPUT = "invalid_input"
    PATH_NOT_ALLOWED = "path_not_allowed"
    MISP_URL_NOT_PUBLIC = "misp_url_not_public"


class ProviderError(Exception):
    """A mapped provider failure. Carries a kind and numbers only: never a response body,
    header or key (some providers echo the key in error bodies, RT11)."""

    def __init__(
        self,
        kind: ProviderErrorKind,
        *,
        http_status: int | None = None,
        retry_after_s: float | None = None,
    ) -> None:
        super().__init__(kind.value)
        self.kind = kind
        self.http_status = http_status
        self.retry_after_s = retry_after_s

    def __str__(self) -> str:
        return self.kind.value if self.http_status is None else f"{self.kind} ({self.http_status})"

    def __repr__(self) -> str:
        return f"ProviderError({self.kind.value!r}, http_status={self.http_status!r})"


def compute_ioc_key(ioc_type: IocType, value_norm: str) -> str:
    """sha256(type || 0x00 || value_norm): the join key between `iocs` and `ti_results`."""
    return hashlib.sha256(f"{ioc_type.value}\0{value_norm}".encode()).hexdigest()


@dataclass(frozen=True)
class IocRef:
    """One normalized, eligible indicator handed to an adapter."""

    ioc_type: IocType
    value_norm: str
    ioc_key: str

    @classmethod
    def of(cls, ioc_type: IocType, value_norm: str) -> Self:
        return cls(ioc_type, value_norm, compute_ioc_key(ioc_type, value_norm))


@dataclass(frozen=True)
class AllowedPath:
    """One request shape an adapter may send. `host=None` means the org's MISP host."""

    method: Literal["GET", "POST"]
    host: str | None
    path: re.Pattern[str]

    def matches(self, method: str, host: str, path: str) -> bool:
        return (
            method == self.method
            and (self.host is None or host == self.host)
            and self.path.fullmatch(path) is not None
        )


@dataclass(frozen=True)
class VerifyOutcome:
    status: Literal[VerifyStatus.VALID, VerifyStatus.INVALID, VerifyStatus.ERROR]
    error_code: str | None = None


def _https_permalink(value: str) -> str:
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or "@" in parts.netloc
        or any(ord(c) < 0x21 or ord(c) == 0x7F for c in value)
    ):
        raise ValueError("permalink must be an https URL without credentials")
    return value


Permalink = Annotated[str, Field(max_length=2048), AfterValidator(_https_permalink)]
FiniteFloat = Annotated[float, Field(allow_inf_nan=False)]


class Detections(BaseModel):
    """VirusTotal's own engine counts (shown attributed, never as our verdict)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    malicious: Count
    suspicious: Count
    total: Count


class ProviderResult(BaseModel):
    """The normalized, verdict-free outcome of one lookup (one `ti_results` row)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: ProviderName
    status: ResultStatus
    found: bool = False
    # Provider-native score; `score_scale` names its scale (e.g. `abuseipdb_confidence_0_100`).
    score: FiniteFloat | None = None
    score_scale: Text32 | None = None
    detections: Detections | None = None
    tags: Annotated[list[Text64], BeforeValidator(_cap(32))] = []
    families: Annotated[list[Text64], BeforeValidator(_cap(16))] = []
    attack_ids: Annotated[list[str], BeforeValidator(_attack_ids(32))] = []
    first_seen: Timestamp = None
    last_seen: Timestamp = None
    summary: ProviderSummary | None = None
    # Built from constants and the normalized value, or a provider URL on its own host.
    permalink: Permalink | None = None
    # A mapped code for error / auth_failed rows (never provider text).
    error_code: Text64 | None = None

    @model_validator(mode="after")
    def _coherent(self) -> Self:
        if self.summary is not None and self.summary.provider != self.provider.value:
            raise ValueError("summary belongs to another provider")
        if self.found and self.status is not ResultStatus.OK:
            raise ValueError("only an ok result can be found")
        if self.score is not None and not math.isfinite(self.score):
            raise ValueError("score must be finite")
        return self


class Provider(Protocol):
    """A lookup-only adapter. It never uploads, submits or downloads anything; every request
    must match one of `allowed_paths` (checked by the HTTP client on each request)."""

    @property
    def name(self) -> ProviderName: ...

    @property
    def supported_types(self) -> frozenset[IocType]: ...

    @property
    def allowed_paths(self) -> tuple[AllowedPath, ...]: ...

    async def lookup(self, client: "httpx.AsyncClient", ioc: IocRef) -> ProviderResult: ...

    async def verify(self, client: "httpx.AsyncClient") -> VerifyOutcome: ...


__all__ = [
    "HASH_TYPES",
    "IP_TYPES",
    "AllowedPath",
    "Detections",
    "IocRef",
    "IocType",
    "Provider",
    "ProviderError",
    "ProviderErrorKind",
    "ProviderName",
    "ProviderResult",
    "ResultStatus",
    "VerifyOutcome",
    "VerifyStatus",
    "compute_ioc_key",
]
