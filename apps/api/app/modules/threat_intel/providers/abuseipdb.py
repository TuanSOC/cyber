"""AbuseIPDB APIv2 adapter (enrich worker only): `GET /api/v2/check`, nothing else.

Reporting (`/report`, `/bulk-report`), `/clear-address`, `/blacklist` and `/check-block` can
never match `ALLOWED_PATHS`. The key travels only in the `Key` header (`http.KeyAuth`).

AbuseIPDB never answers "not found": a confidence score of 0 with 0 reports is `found=false`
(a `not_found` result, so it gets the short cache TTL), and the summary still keeps
`usageType`, `isp`, `isTor` and `isWhitelisted`. 422 maps to `invalid_input`, 429 to
`rate_limited` with its Retry-After (both by `http.fetch_json`, without reading the body).
"""

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
from app.modules.threat_intel.summaries import AbuseIpdbSummary, clean_text

HOST = "api.abuseipdb.com"
CHECK_URL = f"https://{HOST}/api/v2/check"
PERMALINK = "https://www.abuseipdb.com/check/"
SCORE_SCALE = "abuseipdb_confidence_0_100"
MAX_AGE_DAYS = "90"
# Documented to cost one check of the daily quota.
VERIFY_IP = "8.8.8.8"

ALLOWED_PATHS = (AllowedPath("GET", HOST, re.compile(r"/api/v2/check")),)

_MAX_COUNT = 10**12
_MAX_CATEGORIES = 30


def _int(value: object, low: int = 0, high: int = _MAX_COUNT) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high:
        return value
    return None


def _str(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return clean_text(value) or None


def _bool(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _iso(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _categories(reports: object) -> list[int]:
    """Distinct report category ids (verbose `reports[].categories`), in first-seen order."""
    out: list[int] = []
    for report in reports if isinstance(reports, list) else []:
        raw = report.get("categories") if isinstance(report, dict) else None
        for item in raw if isinstance(raw, list) else []:
            category = _int(item, 0, 255)
            if category is not None and category not in out:
                out.append(category)
                if len(out) >= _MAX_CATEGORIES:
                    return out
    return out


def _result(ioc: IocRef, data: dict[str, Any]) -> ProviderResult:
    score = _int(data.get("abuseConfidenceScore"), 0, 100)
    reports = _int(data.get("totalReports"))
    last_reported = _iso(data.get("lastReportedAt"))
    summary = AbuseIpdbSummary(
        abuse_confidence_score=score,
        total_reports=reports,
        num_distinct_users=_int(data.get("numDistinctUsers")),
        last_reported_at=last_reported,
        is_whitelisted=_bool(data.get("isWhitelisted")),
        is_tor=_bool(data.get("isTor")),
        usage_type=_str(data.get("usageType")),
        isp=_str(data.get("isp")),
        country_code=_str(data.get("countryCode")),
        categories=_categories(data.get("reports")),
    )
    found = bool(score) or bool(reports)
    return ProviderResult(
        provider=ProviderName.ABUSEIPDB,
        status=ResultStatus.OK if found else ResultStatus.NOT_FOUND,
        found=found,
        score=score,
        score_scale=SCORE_SCALE if score is not None else None,
        last_seen=last_reported,
        summary=summary,
        permalink=PERMALINK + quote(ioc.value_norm, safe=":"),
    )


class AbuseIpdbProvider:
    @property
    def name(self) -> ProviderName:
        return ProviderName.ABUSEIPDB

    @property
    def supported_types(self) -> frozenset[IocType]:
        return CATALOG[ProviderName.ABUSEIPDB].supported_types

    @property
    def allowed_paths(self) -> tuple[AllowedPath, ...]:
        return ALLOWED_PATHS

    async def lookup(self, client: httpx.AsyncClient, ioc: IocRef) -> ProviderResult:
        if ioc.ioc_type not in self.supported_types:
            raise ProviderError(ProviderErrorKind.INVALID_INPUT)
        params = {"ipAddress": ioc.value_norm, "maxAgeInDays": MAX_AGE_DAYS, "verbose": ""}
        response = await fetch_json(client, "GET", CHECK_URL, params=params)
        data = response.data.get("data") if isinstance(response.data, dict) else None
        if not isinstance(data, dict):
            raise ProviderError(ProviderErrorKind.BAD_JSON, http_status=response.status)
        try:
            return _result(ioc, data)
        except (ValidationError, TypeError, ValueError):
            raise ProviderError(ProviderErrorKind.BAD_JSON, http_status=response.status) from None

    async def verify(self, client: httpx.AsyncClient) -> VerifyOutcome:
        try:
            await fetch_json(
                client, "GET", CHECK_URL, params={"ipAddress": VERIFY_IP, "maxAgeInDays": "1"}
            )
        except ProviderError as exc:
            if exc.kind is ProviderErrorKind.AUTH:
                return VerifyOutcome(VerifyStatus.INVALID, "auth")
            return VerifyOutcome(VerifyStatus.ERROR, exc.kind.value)
        return VerifyOutcome(VerifyStatus.VALID)


def create(ctx: ProviderContext) -> AbuseIpdbProvider:
    return AbuseIpdbProvider()
