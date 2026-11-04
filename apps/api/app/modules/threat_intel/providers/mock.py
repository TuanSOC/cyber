"""The `mock` provider (dev/test only): lookups against the local `ti-mock` sink.

It exercises the real path (sealed key -> worker -> httpx -> egress) without real keys. The
IOC value selects the sink's behaviour (`infra/ti-mock/server.py`); the behaviour names live
under `example.com`, which only this provider may receive (`normalize.eligible`).

Refused in prod: the catalog marks it `dev_only`, the registry never creates it when
`ENV=prod` or without `TI_MOCK_ENABLED`, `_prod_guards` refuses `TI_MOCK_ENABLED` in prod, and
importing this module in a prod process fails.
"""

import re
from urllib.parse import quote, urlsplit

import httpx
from pydantic import ValidationError

from app.core.config import get_settings
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
from app.modules.threat_intel.summaries import MockSummary

if not CATALOG[ProviderName.MOCK].dev_only or get_settings().env == "prod":
    raise ImportError("the mock threat-intel provider is refused when ENV=prod")

_TYPES = "|".join(t.value for t in IocType)


class MockProvider:
    def __init__(self, base_url: str) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("TI_MOCK_BASE_URL must be an http(s) URL")
        self._base = base_url.rstrip("/")
        host = parts.hostname
        self._allowed = (
            AllowedPath("GET", host, re.compile(rf"/v1/lookup/(?:{_TYPES})/[^/]{{1,6200}}")),
            AllowedPath("GET", host, re.compile(r"/v1/verify")),
        )

    @property
    def name(self) -> ProviderName:
        return ProviderName.MOCK

    @property
    def supported_types(self) -> frozenset[IocType]:
        return CATALOG[ProviderName.MOCK].supported_types

    @property
    def allowed_paths(self) -> tuple[AllowedPath, ...]:
        return self._allowed

    async def lookup(self, client: httpx.AsyncClient, ioc: IocRef) -> ProviderResult:
        url = f"{self._base}/v1/lookup/{ioc.ioc_type.value}/{quote(ioc.value_norm, safe='')}"
        response = await fetch_json(client, "GET", url, accept=(200, 404))
        if response.status == 404:
            return ProviderResult(provider=ProviderName.MOCK, status=ResultStatus.NOT_FOUND)
        data = response.data
        if not isinstance(data, dict):
            raise ProviderError(ProviderErrorKind.BAD_JSON, http_status=response.status)
        try:
            tags = data.get("tags") or []
            summary = MockSummary(
                behaviour=data.get("behaviour"),
                label=data.get("label"),
                hits=data.get("hits"),
                tags=tags,
            )
            return ProviderResult(
                provider=ProviderName.MOCK,
                status=ResultStatus.OK,
                found=bool(data.get("found")),
                score=data.get("hits"),
                score_scale="mock_hits",
                tags=tags,
                families=data.get("families") or [],
                attack_ids=data.get("attack_ids") or [],
                summary=summary,
            )
        except (ValidationError, TypeError, ValueError):
            raise ProviderError(ProviderErrorKind.BAD_JSON, http_status=response.status) from None

    async def verify(self, client: httpx.AsyncClient) -> VerifyOutcome:
        try:
            await fetch_json(client, "GET", f"{self._base}/v1/verify")
        except ProviderError as exc:
            if exc.kind is ProviderErrorKind.AUTH:
                return VerifyOutcome(VerifyStatus.INVALID, "auth")
            return VerifyOutcome(VerifyStatus.ERROR, exc.kind.value)
        return VerifyOutcome(VerifyStatus.VALID)


def create(ctx: ProviderContext) -> MockProvider:
    return MockProvider(ctx.settings.ti_mock_base_url)
