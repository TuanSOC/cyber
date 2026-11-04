"""abuse.ch adapters (enrich worker only): URLhaus and MalwareBazaar lookups, nothing else.

Both take the abuse.ch `Auth-Key` header (`http.KeyAuth`; one key, stored per provider) and
answer HTTP 200 with a `query_status` for most outcomes, so the status is checked, not only the
HTTP code:
- `ok` -> a result; URLhaus `no_results` / MalwareBazaar `hash_not_found` -> not found;
- a missing or unknown key (`no_api_key`, `unknown_auth_key`, ...) -> `auth`, like HTTP 401/403;
- `invalid_*`, `illegal_hash`, `no_hash_provided`, `http_post_expected` -> `bad_request`.
The status string is only compared, never stored or logged.

URLhaus: `POST /v1/url/`, `/v1/host/`, `/v1/payload/` only; `/v1/download/{sha256}/` and the
submission API can never match. MalwareBazaar serves lookups, sample downloads (`get_file`) and
uploads on the same `POST /api/v1/`, so besides the path allowlist the adapter only ever builds
the `get_info` form (`MALWAREBAZAAR_QUERIES`; anything else raises `PathNotAllowed`).

Permalinks: URLhaus' own `urlhaus_reference` only when it is `https:` on `urlhaus.abuse.ch`
(RT19); host and payload links are built from constants and the normalized value.
"""

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
from pydantic import ValidationError

from app.modules.threat_intel.catalog import CATALOG
from app.modules.threat_intel.http import PathNotAllowed, fetch_json
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
from app.modules.threat_intel.summaries import (
    MalwareBazaarSummary,
    UrlhausBlacklists,
    UrlhausSummary,
    clean_text,
)

URLHAUS_HOST = "urlhaus-api.abuse.ch"
URLHAUS_API = f"https://{URLHAUS_HOST}/v1"
URLHAUS_SITE_HOST = "urlhaus.abuse.ch"
URLHAUS_SITE = f"https://{URLHAUS_SITE_HOST}"
MALWAREBAZAAR_HOST = "mb-api.abuse.ch"
MALWAREBAZAAR_API = f"https://{MALWAREBAZAAR_HOST}/api/v1/"
MALWAREBAZAAR_SITE = "https://bazaar.abuse.ch/sample/"
# sha256 of the public EICAR test file: verify is a lookup of a constant, harmless hash.
VERIFY_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

URLHAUS_ALLOWED_PATHS = (
    AllowedPath("POST", URLHAUS_HOST, re.compile(r"/v1/(?:url|host|payload)/")),
)
MALWAREBAZAAR_ALLOWED_PATHS = (AllowedPath("POST", MALWAREBAZAAR_HOST, re.compile(r"/api/v1/")),)
# The only MalwareBazaar `query` this adapter sends (never `get_file` or an upload).
MALWAREBAZAAR_QUERIES = frozenset({"get_info"})

_AUTH_STATUSES = frozenset(
    {"no_api_key", "unknown_auth_key", "invalid_auth_key", "unknown_api_key", "invalid_api_key"}
)
_BAD_REQUEST_PREFIXES = ("invalid_", "illegal_", "no_", "unknown_")

# IOC type -> (URLhaus endpoint, form field).
_URLHAUS_QUERIES: dict[IocType, tuple[str, str]] = {
    IocType.URL: ("url", "url"),
    IocType.DOMAIN: ("host", "host"),
    IocType.IPV4: ("host", "host"),
    IocType.IPV6: ("host", "host"),
    IocType.MD5: ("payload", "md5_hash"),
    IocType.SHA256: ("payload", "sha256_hash"),
}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MAX_COUNT = 10**12


# --- shared ---------------------------------------------------------------------------------


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


def _dicts(value: object) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _count(value: object) -> int | None:
    """abuse.ch sends counts as strings ("3") or numbers."""
    if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 12:
        return int(value)
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _MAX_COUNT:
        return value
    return None


def _date(value: object) -> datetime | None:
    """`2026-10-30 12:34:56 UTC`, `2026-10-30 12:34:56` or `2026-10-30` (UTC)."""
    if not isinstance(value, str) or len(value) > 40:
        return None
    text = value.strip().removesuffix(" UTC")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def own_https(value: object, host: str) -> str | None:
    """A provider-supplied link, kept only if it is `https:` on the provider's own host."""
    if not isinstance(value, str) or len(value) > 2048:
        return None
    # ASCII only: a bidi override (U+202E) or other hidden Unicode never reaches a link.
    if not value.isascii() or any(ord(c) < 0x21 or ord(c) == 0x7F for c in value):
        return None
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme != "https" or "@" in parts.netloc or port not in (None, 443):
        return None
    return value if parts.hostname == host else None


def query_status_error(status: str) -> ProviderError:
    """The mapped error of a non-`ok`, non-not-found `query_status`."""
    if status in _AUTH_STATUSES:
        return ProviderError(ProviderErrorKind.AUTH)
    if status == "rate_limited":
        return ProviderError(ProviderErrorKind.RATE_LIMITED)
    if status == "http_post_expected" or status.startswith(_BAD_REQUEST_PREFIXES):
        return ProviderError(ProviderErrorKind.BAD_REQUEST)
    return ProviderError(ProviderErrorKind.UNEXPECTED_STATUS, http_status=200)


async def _query(
    client: httpx.AsyncClient, url: str, form: Mapping[str, str], not_found: str
) -> dict[str, Any] | None:
    """The body of an `ok` answer, None for the not-found status; raises otherwise."""
    response = await fetch_json(client, "POST", url, data=form)
    data = response.data
    status = data.get("query_status") if isinstance(data, dict) else None
    if not isinstance(data, dict) or not isinstance(status, str):
        raise ProviderError(ProviderErrorKind.BAD_JSON, http_status=response.status)
    if status == "ok":
        return data
    if status == not_found:
        return None
    raise query_status_error(status)


async def _verify(
    client: httpx.AsyncClient, url: str, form: Mapping[str, str], not_found: str
) -> VerifyOutcome:
    try:
        await _query(client, url, form, not_found)
    except ProviderError as exc:
        if exc.kind is ProviderErrorKind.AUTH:
            return VerifyOutcome(VerifyStatus.INVALID, "auth")
        return VerifyOutcome(VerifyStatus.ERROR, exc.kind.value)
    return VerifyOutcome(VerifyStatus.VALID)


# --- URLhaus --------------------------------------------------------------------------------


def _blacklists(value: object) -> UrlhausBlacklists | None:
    if not isinstance(value, dict):
        return None
    return UrlhausBlacklists(
        spamhaus_dbl=_str(value.get("spamhaus_dbl")), surbl=_str(value.get("surbl"))
    )


def _urlhaus_url(data: dict[str, Any]) -> ProviderResult:
    signatures = _strs([p.get("signature") for p in _dicts(data.get("payloads"))], 16)
    added = _date(data.get("date_added"))
    online = _date(data.get("last_online"))
    summary = UrlhausSummary(
        lookup="url",
        url_status=_str(data.get("url_status")),
        threat=_str(data.get("threat")),
        tags=_strs(data.get("tags"), 20),
        date_added=added,
        last_online=online,
        blacklists=_blacklists(data.get("blacklists")),
        signature=signatures[0] if signatures else None,
    )
    return ProviderResult(
        provider=ProviderName.URLHAUS,
        status=ResultStatus.OK,
        found=True,
        tags=_strs(data.get("tags"), 32),
        families=signatures,
        first_seen=added,
        last_seen=online,
        summary=summary,
        permalink=own_https(data.get("urlhaus_reference"), URLHAUS_SITE_HOST),
    )


def _urlhaus_host(ioc: IocRef, data: dict[str, Any]) -> ProviderResult:
    urls = _dicts(data.get("urls"))
    tags = _strs([tag for url in urls for tag in _strs(url.get("tags"), 32)], 32)
    threats = _strs([url.get("threat") for url in urls], 1)
    first = _date(data.get("firstseen"))
    summary = UrlhausSummary(
        lookup="host",
        threat=threats[0] if threats else None,
        tags=tags[:20],
        blacklists=_blacklists(data.get("blacklists")),
        url_count=_count(data.get("url_count")),
        first_seen=first,
    )
    return ProviderResult(
        provider=ProviderName.URLHAUS,
        status=ResultStatus.OK,
        found=True,
        tags=tags,
        first_seen=first,
        summary=summary,
        permalink=f"{URLHAUS_SITE}/host/{quote(ioc.value_norm, safe=':')}/",
    )


def _urlhaus_payload(ioc: IocRef, data: dict[str, Any]) -> ProviderResult:
    signature = _str(data.get("signature"))
    first = _date(data.get("firstseen"))
    last = _date(data.get("lastseen"))
    summary = UrlhausSummary(
        lookup="payload",
        url_count=_count(data.get("url_count")),
        first_seen=first,
        last_seen=last,
        signature=signature,
    )
    return ProviderResult(
        provider=ProviderName.URLHAUS,
        status=ResultStatus.OK,
        found=True,
        families=[signature] if signature else [],
        first_seen=first,
        last_seen=last,
        summary=summary,
        permalink=f"{URLHAUS_SITE}/browse.php?search={quote(ioc.value_norm, safe='')}",
    )


class UrlhausProvider:
    @property
    def name(self) -> ProviderName:
        return ProviderName.URLHAUS

    @property
    def supported_types(self) -> frozenset[IocType]:
        return CATALOG[ProviderName.URLHAUS].supported_types

    @property
    def allowed_paths(self) -> tuple[AllowedPath, ...]:
        return URLHAUS_ALLOWED_PATHS

    async def lookup(self, client: httpx.AsyncClient, ioc: IocRef) -> ProviderResult:
        target = _URLHAUS_QUERIES.get(ioc.ioc_type)
        if target is None or ioc.ioc_type not in self.supported_types:
            raise ProviderError(ProviderErrorKind.INVALID_INPUT)
        endpoint, field = target
        url = f"{URLHAUS_API}/{endpoint}/"
        data = await _query(client, url, {field: ioc.value_norm}, "no_results")
        if data is None:
            return ProviderResult(provider=ProviderName.URLHAUS, status=ResultStatus.NOT_FOUND)
        try:
            if endpoint == "url":
                return _urlhaus_url(data)
            if endpoint == "host":
                return _urlhaus_host(ioc, data)
            return _urlhaus_payload(ioc, data)
        except (ValidationError, TypeError, ValueError):
            raise ProviderError(ProviderErrorKind.BAD_JSON, http_status=200) from None

    async def verify(self, client: httpx.AsyncClient) -> VerifyOutcome:
        form = {"sha256_hash": VERIFY_SHA256}
        return await _verify(client, f"{URLHAUS_API}/payload/", form, "no_results")


# --- MalwareBazaar --------------------------------------------------------------------------


def malwarebazaar_form(query: str, value: str) -> dict[str, str]:
    """The only request body this adapter sends; anything but a lookup is refused."""
    if query not in MALWAREBAZAAR_QUERIES:
        raise PathNotAllowed()
    return {"query": query, "hash": value}


def _malwarebazaar_result(ioc: IocRef, data: dict[str, Any]) -> ProviderResult:
    rows = _dicts(data.get("data"))
    if not rows:
        raise ProviderError(ProviderErrorKind.BAD_JSON, http_status=200)
    row = rows[0]
    signature = _str(row.get("signature"))
    first = _date(row.get("first_seen"))
    last = _date(row.get("last_seen"))
    vendors = row.get("vendor_intel")
    summary = MalwareBazaarSummary(
        first_seen=first,
        last_seen=last,
        signature=signature,
        tags=_strs(row.get("tags"), 20),
        file_type=_str(row.get("file_type")),
        imphash=_str(row.get("imphash")),
        ssdeep=_str(row.get("ssdeep")),
        tlsh=_str(row.get("tlsh")),
        vendor_intel=_strs(list(vendors) if isinstance(vendors, dict) else [], 30),
    )
    sha256 = ioc.value_norm if ioc.ioc_type is IocType.SHA256 else row.get("sha256_hash")
    valid = isinstance(sha256, str) and _SHA256.fullmatch(sha256) is not None
    return ProviderResult(
        provider=ProviderName.MALWAREBAZAAR,
        status=ResultStatus.OK,
        found=True,
        tags=_strs(row.get("tags"), 32),
        families=[signature] if signature else [],
        first_seen=first,
        last_seen=last,
        summary=summary,
        permalink=f"{MALWAREBAZAAR_SITE}{sha256}/" if valid else None,
    )


class MalwareBazaarProvider:
    @property
    def name(self) -> ProviderName:
        return ProviderName.MALWAREBAZAAR

    @property
    def supported_types(self) -> frozenset[IocType]:
        return CATALOG[ProviderName.MALWAREBAZAAR].supported_types

    @property
    def allowed_paths(self) -> tuple[AllowedPath, ...]:
        return MALWAREBAZAAR_ALLOWED_PATHS

    async def lookup(self, client: httpx.AsyncClient, ioc: IocRef) -> ProviderResult:
        if ioc.ioc_type not in self.supported_types:
            raise ProviderError(ProviderErrorKind.INVALID_INPUT)
        form = malwarebazaar_form("get_info", ioc.value_norm)
        data = await _query(client, MALWAREBAZAAR_API, form, "hash_not_found")
        if data is None:
            return ProviderResult(
                provider=ProviderName.MALWAREBAZAAR, status=ResultStatus.NOT_FOUND
            )
        try:
            return _malwarebazaar_result(ioc, data)
        except (ValidationError, TypeError, ValueError):
            raise ProviderError(ProviderErrorKind.BAD_JSON, http_status=200) from None

    async def verify(self, client: httpx.AsyncClient) -> VerifyOutcome:
        form = malwarebazaar_form("get_info", VERIFY_SHA256)
        return await _verify(client, MALWAREBAZAAR_API, form, "hash_not_found")


def create_urlhaus(ctx: ProviderContext) -> UrlhausProvider:
    return UrlhausProvider()


def create_malwarebazaar(ctx: ProviderContext) -> MalwareBazaarProvider:
    return MalwareBazaarProvider()
