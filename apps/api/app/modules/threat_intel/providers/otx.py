"""AlienVault (LevelBlue) OTX DirectConnect v1 adapter (enrich worker only): lookups only.

`GET /api/v1/indicators/{IPv4,IPv6,domain,url,file}/{value}/general` and, for verify,
`GET /api/v1/user/me`. Pulse creation, subscriptions and file/URL submission can never match
`ALLOWED_PATHS`. The key travels only in `X-OTX-API-KEY` (`http.KeyAuth`).

Not found: HTTP 404, or the "quiet" 200 with `pulse_info.count == 0` and no reputation (the
summary keeps OTX's `validation` hints, e.g. an allowlisted domain). ATT&CK ids come from the
pulses and keep only well-formed T-ids (`summaries._attack_ids`).
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
from app.modules.threat_intel.summaries import OtxPulse, OtxSummary, OtxValidation, clean_text

HOST = "otx.alienvault.com"
API = f"https://{HOST}/api/v1"
SITE = f"https://{HOST}/indicator"
VERIFY_URL = f"{API}/user/me"

ALLOWED_PATHS = (
    AllowedPath(
        "GET", HOST, re.compile(r"/api/v1/indicators/(?:IPv4|IPv6|domain)/[A-Za-z0-9._:-]+/general")
    ),
    AllowedPath("GET", HOST, re.compile(r"/api/v1/indicators/url/[^?#]{1,6200}/general")),
    AllowedPath("GET", HOST, re.compile(r"/api/v1/indicators/file/[0-9a-f]{32,64}/general")),
    AllowedPath("GET", HOST, re.compile(r"/api/v1/user/me")),
)

# IOC type -> (API indicator section, web UI kind).
_KINDS: dict[IocType, tuple[str, str]] = {
    IocType.IPV4: ("IPv4", "ip"),
    IocType.IPV6: ("IPv6", "ip"),
    IocType.DOMAIN: ("domain", "domain"),
    IocType.URL: ("url", "url"),
    IocType.MD5: ("file", "file"),
    IocType.SHA1: ("file", "file"),
    IocType.SHA256: ("file", "file"),
}
_MAX_COUNT = 10**12
_TOP_PULSES = 10


def _dicts(value: object) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _int(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) <= _MAX_COUNT:
        return value
    return None


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


def _iso(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _names(items: object, *keys: str) -> list[Any]:
    """Pulse `malware_families` / `attack_ids`: objects (first of `keys`) or plain strings."""
    out: list[Any] = []
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict):
            out.append(next((item[k] for k in keys if isinstance(item.get(k), str)), None))
        else:
            out.append(item)
    return out


def _path_value(ioc: IocRef) -> str:
    if ioc.ioc_type is not IocType.URL:
        return quote(ioc.value_norm, safe=":")
    # OTX takes the URL as-is in the path. A dot segment would be resolved by the client and
    # turn the request into another endpoint, so such a URL is refused before sending.
    if any(segment in (".", "..") for segment in ioc.value_norm.split("/")):
        raise ProviderError(ProviderErrorKind.INVALID_INPUT)
    return quote(ioc.value_norm, safe=":/")


def _result(ioc: IocRef, ui_kind: str, data: dict[str, Any]) -> ProviderResult:
    info = data.get("pulse_info")
    info = info if isinstance(info, dict) else {}
    pulses = _dicts(info.get("pulses"))
    count = _int(info.get("count"))
    count = count if count is not None and count >= 0 else len(pulses)
    reputation = _int(data.get("reputation"))
    families = [_names(p.get("malware_families"), "display_name", "id") for p in pulses]
    attack_ids = [_names(p.get("attack_ids"), "id") for p in pulses]
    summary = OtxSummary(
        pulse_count=count,
        pulses=[
            OtxPulse(
                name=_str(p.get("name")) or "",
                tags=_strs(p.get("tags"), 8),
                malware_families=_strs(names, 4),
                attack_ids=ids,
                modified=_iso(p.get("modified")),
            )
            for p, names, ids in list(zip(pulses, families, attack_ids, strict=True))[:_TOP_PULSES]
        ],
        reputation=reputation,
        validation=[
            OtxValidation(
                source=_str(v.get("source")),
                name=_str(v.get("name")),
                message=_str(v.get("message")),
            )
            for v in _dicts(data.get("validation"))[:5]
        ],
    )
    if count == 0 and not reputation:
        # The quiet 200: OTX knows the indicator but no pulse mentions it.
        return ProviderResult(
            provider=ProviderName.OTX, status=ResultStatus.NOT_FOUND, summary=summary
        )
    created = [d for d in (_iso(p.get("created")) for p in pulses) if d is not None]
    modified = [d for d in (_iso(p.get("modified")) for p in pulses) if d is not None]
    return ProviderResult(
        provider=ProviderName.OTX,
        status=ResultStatus.OK,
        found=True,
        tags=_strs([tag for p in pulses for tag in _strs(p.get("tags"), 32)], 32),
        families=_strs([name for names in families for name in names], 16),
        attack_ids=[tid for ids in attack_ids for tid in ids if isinstance(tid, str)],
        first_seen=min(created, default=None),
        last_seen=max(modified, default=None),
        summary=summary,
        permalink=f"{SITE}/{ui_kind}/{quote(ioc.value_norm, safe='')}",
    )


class OtxProvider:
    @property
    def name(self) -> ProviderName:
        return ProviderName.OTX

    @property
    def supported_types(self) -> frozenset[IocType]:
        return CATALOG[ProviderName.OTX].supported_types

    @property
    def allowed_paths(self) -> tuple[AllowedPath, ...]:
        return ALLOWED_PATHS

    async def lookup(self, client: httpx.AsyncClient, ioc: IocRef) -> ProviderResult:
        kinds = _KINDS.get(ioc.ioc_type)
        if kinds is None or ioc.ioc_type not in self.supported_types:
            raise ProviderError(ProviderErrorKind.INVALID_INPUT)
        section, ui_kind = kinds
        url = f"{API}/indicators/{section}/{_path_value(ioc)}/general"
        response = await fetch_json(client, "GET", url, accept=(200, 404))
        if response.status == 404:
            return ProviderResult(provider=ProviderName.OTX, status=ResultStatus.NOT_FOUND)
        if not isinstance(response.data, dict):
            raise ProviderError(ProviderErrorKind.BAD_JSON, http_status=response.status)
        try:
            return _result(ioc, ui_kind, response.data)
        except (ValidationError, TypeError, ValueError):
            raise ProviderError(ProviderErrorKind.BAD_JSON, http_status=response.status) from None

    async def verify(self, client: httpx.AsyncClient) -> VerifyOutcome:
        try:
            await fetch_json(client, "GET", VERIFY_URL)
        except ProviderError as exc:
            if exc.kind is ProviderErrorKind.AUTH:
                return VerifyOutcome(VerifyStatus.INVALID, "auth")
            return VerifyOutcome(VerifyStatus.ERROR, exc.kind.value)
        return VerifyOutcome(VerifyStatus.VALID)


def create(ctx: ProviderContext) -> OtxProvider:
    return OtxProvider()
