"""Public provider adapters against every case of `tests/fixtures/ti/manifest.json` (M4 phase 3).

One table-driven test per manifest case (VirusTotal, AbuseIPDB, URLhaus, MalwareBazaar, OTX):
the adapter is built through the registry, runs on the hardened `ti_client` over
`httpx.MockTransport`, and must
- send exactly the documented lookup request (method, path, query, form), on its allowlist;
- carry the sentinel key only in its auth header: never in the URL, body, other headers,
  request/client reprs, the result, the exception or captured logs (incl. key-echo bodies);
- map the response to the expected status or `ProviderError` kind;
- return strict, sanitized, size-capped summaries with https permalinks on provider hosts.
"""

import json
import logging
import unicodedata
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from pydantic import SecretStr

from app.core.config import get_settings
from app.modules.threat_intel.http import KeyAuth, path_allowed, ti_client
from app.modules.threat_intel.providers import registry
from app.modules.threat_intel.providers.base import (
    IocRef,
    IocType,
    Provider,
    ProviderError,
    ProviderErrorKind,
    ProviderName,
    ProviderResult,
    ResultStatus,
)
from app.modules.threat_intel.ratelimit import parse_retry_after
from app.modules.threat_intel.summaries import SUMMARY_MAX_BYTES, summary_size
from tests.ti_helpers import SENTINEL_KEY

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "ti"
MANIFEST: dict[str, Any] = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
PUBLIC = ("virustotal", "abuseipdb", "urlhaus", "malwarebazaar", "otx")
OVERSIZE_BYTES = 2 * 1024 * 1024 + 1

# Hosts a permalink may point at, per provider.
PERMALINK_HOSTS = {
    "virustotal": {"www.virustotal.com"},
    "abuseipdb": {"www.abuseipdb.com"},
    "urlhaus": {"urlhaus.abuse.ch"},
    "malwarebazaar": {"bazaar.abuse.ch"},
    "otx": {"otx.alienvault.com"},
}
IOC_TYPES = {
    "domain": IocType.DOMAIN,
    "url": IocType.URL,
    "file_md5": IocType.MD5,
    "file_sha1": IocType.SHA1,
    "file_sha256": IocType.SHA256,
}
# Manifest `expect` -> the adapter's ProviderError kind. VirusTotal's daily-quota 429 body is
# identical to the per-minute one (manifest note): the adapter reports `rate_limited` (no
# Retry-After: the worker cools down to the next minute) and the worker's own daily counter
# turns the provider to `quota_exhausted` until 00:00 UTC.
ERROR_KINDS = {
    "auth": ProviderErrorKind.AUTH,
    "rate_limited": ProviderErrorKind.RATE_LIMITED,
    "quota_exhausted": ProviderErrorKind.RATE_LIMITED,
    "unavailable": ProviderErrorKind.HTTP_5XX,
    "parse_error": ProviderErrorKind.BAD_JSON,
    "timeout": ProviderErrorKind.TIMEOUT,
    "oversize": ProviderErrorKind.OVERSIZE,
    "bad_request": ProviderErrorKind.BAD_REQUEST,
    "invalid_input": ProviderErrorKind.INVALID_INPUT,
}
FOUND = {"found", "found_sanitized", "found_capped", "found_reference_dropped"}
_DIRTY_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


def _cases() -> Iterator[Any]:
    for provider in PUBLIC:
        for name, case in MANIFEST["providers"][provider]["cases"].items():
            yield pytest.param(provider, case, id=f"{provider}-{name}")


def adapter_for(provider: str) -> Provider:
    name = ProviderName(provider)
    return registry.create(name, registry.ProviderContext(get_settings()))


def ioc_for(case: dict[str, Any]) -> IocRef:
    value: str = case["ioc_value"]
    if case["ioc_type"] == "ip":
        return IocRef.of(IocType.IPV6 if ":" in value else IocType.IPV4, value)
    return IocRef.of(IOC_TYPES[case["ioc_type"]], value)


async def _oversize_stream() -> AsyncIterator[bytes]:
    sent = 0
    while sent < OVERSIZE_BYTES:
        chunk = b"x" * min(65536, OVERSIZE_BYTES - sent)
        sent += len(chunk)
        yield chunk


class _Body(httpx.AsyncByteStream):
    def __init__(self, data: bytes) -> None:
        self._data = data

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self._data


class StreamedMock(httpx.AsyncBaseTransport):
    """`httpx.MockTransport` whose responses arrive as a stream, as from the network (a
    `Response(content=bytes)` built by a handler is already read into memory)."""

    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        self._handler = handler

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await request.aread()
        response = self._handler(request)
        try:
            body = response.content
        except httpx.ResponseNotRead:  # already a stream (the oversize case)
            response.request = request
            return response
        return httpx.Response(
            response.status_code, headers=response.headers, stream=_Body(body), request=request
        )


class Recorder:
    """Serves one manifest case and checks the request it receives."""

    def __init__(self, provider: str, case: dict[str, Any]) -> None:
        self.provider = provider
        self.case = case
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        expected = self.case["request"]
        assert request.method == expected["method"]
        path, _, query = expected["path"].partition("?")
        if not request.url.query:
            # A `?` inside a path value (OTX takes URLs in the path) is percent-encoded.
            path, query = expected["path"], ""
        assert request.url.path == path
        assert parse_qs(request.url.query.decode(), keep_blank_values=True) == parse_qs(
            query, keep_blank_values=True
        )
        if "form" in expected:
            form = parse_qs(request.content.decode(), keep_blank_values=True)
            assert form == {k: [v] for k, v in expected["form"].items()}
        else:
            assert request.content == b""
        expect = self.case["expect"]
        headers = dict(self.case.get("headers") or {})
        if expect == "timeout":
            raise httpx.ReadTimeout("simulated", request=request)
        if expect == "oversize":
            return httpx.Response(200, headers=headers, content=_oversize_stream())
        body = (FIXTURES / self.provider / self.case["file"]).read_bytes()
        return httpx.Response(self.case["http_status"], headers=headers, content=body)


def strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from strings(key)
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def assert_clean(result: ProviderResult) -> None:
    """Every stored string is sanitized text; links are server-checked https permalinks."""
    dumped = result.model_dump(mode="json")
    for text in strings(dumped):
        assert not any(unicodedata.category(c) in _DIRTY_CATEGORIES for c in text), text
        assert text == text.strip()
    for field in ("tags", "families", "attack_ids"):
        assert all(dumped[field]), field  # no empty entries
    assert len(result.tags) <= 32 and len(result.families) <= 16
    if result.summary is not None:
        assert summary_size(result.summary) <= SUMMARY_MAX_BYTES
    if result.permalink is not None:
        parts = urlsplit(result.permalink)
        assert parts.scheme == "https"
        assert parts.hostname in PERMALINK_HOSTS[result.provider.value]
    # What the worker stores round-trips through the strict model.
    assert ProviderResult.model_validate(dumped) == result


def assert_key_only_in_header(
    request: httpx.Request, header: str, client: httpx.AsyncClient
) -> None:
    assert request.headers[header] == SENTINEL_KEY
    for name, value in request.headers.items():
        if name.lower() != header.lower():
            assert SENTINEL_KEY not in value, name
    assert SENTINEL_KEY not in str(request.url)
    assert SENTINEL_KEY.encode() not in request.content
    assert SENTINEL_KEY not in repr(request) + repr(client) + repr(client.auth)
    assert header.lower() not in {name.lower() for name in client.headers}


@pytest.mark.parametrize(("provider", "case"), list(_cases()))
async def test_manifest_case(
    provider: str, case: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    caplog.set_level(logging.DEBUG, logger="httpx")
    caplog.set_level(logging.DEBUG, logger="httpcore")
    adapter = adapter_for(provider)
    header = registry.auth_header(ProviderName(provider))
    recorder = Recorder(provider, case)
    result: ProviderResult | None = None
    error: ProviderError | None = None
    async with ti_client(
        adapter,
        auth=KeyAuth(header, SecretStr(SENTINEL_KEY)),
        transport=StreamedMock(recorder),
    ) as client:
        try:
            result = await adapter.lookup(client, ioc_for(case))
        except ProviderError as exc:
            error = exc
        [request] = recorder.requests
        assert path_allowed(request, adapter.allowed_paths)
        assert_key_only_in_header(request, header, client)

    expect = case["expect"]
    if expect in ERROR_KINDS:
        assert result is None and error is not None, result
        assert error.kind is ERROR_KINDS[expect]
        assert SENTINEL_KEY not in str(error) + repr(error) + repr(error.__cause__)
        if error.kind is ProviderErrorKind.RATE_LIMITED:
            retry_after = (case.get("headers") or {}).get("Retry-After")
            assert error.retry_after_s == parse_retry_after(retry_after)
    else:
        assert error is None, error
        assert result is not None and result.provider.value == provider
        assert SENTINEL_KEY not in repr(result) + result.model_dump_json()
        assert_clean(result)
        if expect in FOUND:
            assert (result.status, result.found) == (ResultStatus.OK, True)
            assert result.summary is not None and result.summary.provider == provider
        else:
            assert expect == "not_found"
            assert (result.status, result.found) == (ResultStatus.NOT_FOUND, False)
        if expect == "found_reference_dropped":
            assert result.permalink is None or "evil" not in result.permalink
    assert SENTINEL_KEY not in caplog.text


def test_every_public_provider_case_is_covered() -> None:
    cases = list(_cases())
    assert len(cases) == sum(
        MANIFEST["providers"][p]["case_count"] for p in PUBLIC
    )  # 63 + 17 + 68 + 24 + 66
    expects = {param.values[1]["expect"] for param in cases}
    assert expects <= set(ERROR_KINDS) | FOUND | {"not_found"}
