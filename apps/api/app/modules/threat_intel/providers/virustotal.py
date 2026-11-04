"""VirusTotal API v3 adapter (enrich worker only): object lookups, nothing else.

`GET /api/v3/{ip_addresses,domains,urls,files}/{id}` only. Uploads (`POST /files`), URL scans
(`POST /urls`), re-analyses (`/analyse`), downloads and `/users/{id}` (whose id may be the key
itself, RT11) can never match `ALLOWED_PATHS`. The key travels only in `x-apikey`, attached per
request by `http.KeyAuth`.

Errors come mapped from `http.fetch_json` without reading the body: 404 is a not-found result,
401/403 `auth`, 429 (`QuotaExceededError` and `TooManyRequestsError` alike) `rate_limited` with
no Retry-After, so the worker cools down to the next minute boundary. VirusTotal's daily-quota
429 body is identical to the per-minute one; the worker's own daily counter (catalog limits)
parks the provider until 00:00 UTC, and so do 3 consecutive 429s (`enrich.QUOTA_STRIKES`).
"""

import base64
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx
from pydantic import ValidationError

from app.modules.threat_intel.catalog import CATALOG
from app.modules.threat_intel.http import fetch_json
from app.modules.threat_intel.providers.base import (
    AllowedPath,
    Detections,
    IocRef,
    IocType,
    ProviderError,
    ProviderErrorKind,
    ProviderName,
    ProviderResult,
    ResultStatus,
    VerifyOutcome,
    VerifyStatus,
)
from app.modules.threat_intel.providers.registry import ProviderContext
from app.modules.threat_intel.summaries import (
    VirusTotalSummary,
    VtAnalysisStats,
    VtVotes,
    clean_text,
)

HOST = "www.virustotal.com"
API = f"https://{HOST}/api/v3"
GUI = f"https://{HOST}/gui"
SCORE_SCALE = "virustotal_reputation"
# sha256 of the public EICAR test file: verify is a plain lookup, never `/users/{id}` (RT11).
VERIFY_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

_HASH = r"(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})"
ALLOWED_PATHS = (
    AllowedPath("GET", HOST, re.compile(r"/api/v3/ip_addresses/[0-9A-Fa-f.:]{2,45}")),
    AllowedPath("GET", HOST, re.compile(r"/api/v3/domains/[A-Za-z0-9._-]{1,253}")),
    AllowedPath("GET", HOST, re.compile(r"/api/v3/urls/[A-Za-z0-9_-]{1,4096}")),
    AllowedPath("GET", HOST, re.compile(rf"/api/v3/files/{_HASH}")),
)

# IOC type -> (API collection, GUI object kind).
_OBJECTS: dict[IocType, tuple[str, str]] = {
    IocType.IPV4: ("ip_addresses", "ip-address"),
    IocType.IPV6: ("ip_addresses", "ip-address"),
    IocType.DOMAIN: ("domains", "domain"),
    IocType.URL: ("urls", "url"),
    IocType.MD5: ("files", "file"),
    IocType.SHA1: ("files", "file"),
    IocType.SHA256: ("files", "file"),
}
_STATS = ("malicious", "suspicious", "harmless", "undetected", "timeout")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MAX_COUNT = 10**12
# Epoch seconds accepted as timestamps (VirusTotal dates): 1990 .. 2100.
_EPOCH_RANGE = (631_152_000, 4_102_444_800)


def url_id(url: str) -> str:
    """VirusTotal's URL identifier: base64url of the URL without `=` padding."""
    return base64.urlsafe_b64encode(url.encode()).decode("ascii").rstrip("=")


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) <= _MAX_COUNT:
        return value
    return None


def _count(value: object) -> int | None:
    number = _int(value)
    return number if number is not None and number >= 0 else None


def _str(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return clean_text(value) or None


def _strs(values: object, limit: int) -> list[str]:
    out: list[str] = []
    for item in values if isinstance(values, list) else []:
        text = _str(item)
        if text is not None and text not in out:
            out.append(text)
            if len(out) >= limit:
                break
    return out


def _epoch(value: object) -> datetime | None:
    seconds = _int(value)
    if seconds is None or not _EPOCH_RANGE[0] <= seconds <= _EPOCH_RANGE[1]:
        return None
    return datetime.fromtimestamp(seconds, UTC)


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _families(attrs: dict[str, Any]) -> list[str]:
    """File: `popular_threat_name` values; URL: `threat_names`."""
    names = _list(_dict(attrs.get("popular_threat_classification")).get("popular_threat_name"))
    values = [item.get("value") for item in names if isinstance(item, dict)]
    return _strs([*values, *_list(attrs.get("threat_names"))], 16)


def _permalink(ioc: IocRef, gui: str, obj: dict[str, Any]) -> str | None:
    if ioc.ioc_type is IocType.URL:
        # The GUI keys URLs by VirusTotal's own sha256 of its canonical form.
        ident = obj.get("id")
        if not isinstance(ident, str) or not _SHA256.fullmatch(ident):
            return None
        return f"{GUI}/url/{ident}"
    return f"{GUI}/{gui}/{quote(ioc.value_norm, safe=':')}"


def _result(ioc: IocRef, gui: str, obj: dict[str, Any], attrs: dict[str, Any]) -> ProviderResult:
    raw_stats = attrs.get("last_analysis_stats")
    stats: VtAnalysisStats | None = None
    detections: Detections | None = None
    if isinstance(raw_stats, dict):
        stats = VtAnalysisStats(**{k: _count(raw_stats.get(k)) or 0 for k in _STATS})
        total = sum(n for n in map(_count, raw_stats.values()) if n is not None)
        detections = Detections(
            malicious=stats.malicious,
            suspicious=stats.suspicious,
            total=min(total, _MAX_COUNT),
        )
    raw_votes = attrs.get("total_votes")
    votes = (
        VtVotes(
            harmless=_count(raw_votes.get("harmless")) or 0,
            malicious=_count(raw_votes.get("malicious")) or 0,
        )
        if isinstance(raw_votes, dict)
        else None
    )
    classification = _dict(attrs.get("popular_threat_classification"))
    reputation = _int(attrs.get("reputation"))
    analysed = _epoch(attrs.get("last_analysis_date"))
    first = _epoch(attrs.get("first_submission_date"))
    last = _epoch(attrs.get("last_submission_date"))
    summary = VirusTotalSummary(
        last_analysis_stats=stats,
        reputation=reputation,
        total_votes=votes,
        tags=_strs(attrs.get("tags"), 20),
        last_analysis_date=analysed,
        first_submission_date=first,
        last_submission_date=last,
        suggested_threat_label=_str(classification.get("suggested_threat_label")),
        meaningful_name=_str(attrs.get("meaningful_name")),
        type_tag=_str(attrs.get("type_tag")),
        as_owner=_str(attrs.get("as_owner")),
        country=_str(attrs.get("country")),
    )
    return ProviderResult(
        provider=ProviderName.VIRUSTOTAL,
        status=ResultStatus.OK,
        found=True,
        score=reputation,
        score_scale=SCORE_SCALE if reputation is not None else None,
        detections=detections,
        tags=_strs(attrs.get("tags"), 32),
        families=_families(attrs),
        first_seen=first,
        last_seen=last or analysed,
        summary=summary,
        permalink=_permalink(ioc, gui, obj),
    )


class VirusTotalProvider:
    @property
    def name(self) -> ProviderName:
        return ProviderName.VIRUSTOTAL

    @property
    def supported_types(self) -> frozenset[IocType]:
        return CATALOG[ProviderName.VIRUSTOTAL].supported_types

    @property
    def allowed_paths(self) -> tuple[AllowedPath, ...]:
        return ALLOWED_PATHS

    async def lookup(self, client: httpx.AsyncClient, ioc: IocRef) -> ProviderResult:
        target = _OBJECTS.get(ioc.ioc_type)
        if target is None or ioc.ioc_type not in self.supported_types:
            raise ProviderError(ProviderErrorKind.INVALID_INPUT)
        collection, gui = target
        ident = url_id(ioc.value_norm) if ioc.ioc_type is IocType.URL else ioc.value_norm
        url = f"{API}/{collection}/{quote(ident, safe=':')}"
        response = await fetch_json(client, "GET", url, accept=(200, 404))
        if response.status == 404:
            return ProviderResult(provider=ProviderName.VIRUSTOTAL, status=ResultStatus.NOT_FOUND)
        obj = _dict(_dict(response.data).get("data"))
        attrs = obj.get("attributes")
        if not isinstance(attrs, dict):
            raise ProviderError(ProviderErrorKind.BAD_JSON, http_status=response.status)
        try:
            return _result(ioc, gui, obj, attrs)
        except (ValidationError, TypeError, ValueError):
            raise ProviderError(ProviderErrorKind.BAD_JSON, http_status=response.status) from None

    async def verify(self, client: httpx.AsyncClient) -> VerifyOutcome:
        try:
            await fetch_json(client, "GET", f"{API}/files/{VERIFY_SHA256}", accept=(200, 404))
        except ProviderError as exc:
            if exc.kind is ProviderErrorKind.AUTH:
                return VerifyOutcome(VerifyStatus.INVALID, "auth")
            return VerifyOutcome(VerifyStatus.ERROR, exc.kind.value)
        return VerifyOutcome(VerifyStatus.VALID)


def create(ctx: ProviderContext) -> VirusTotalProvider:
    return VirusTotalProvider()
