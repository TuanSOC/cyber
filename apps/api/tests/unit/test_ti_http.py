"""The hardened provider HTTP client (M4 phase 2; RT11, RT19)."""

import asyncio
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from app.modules.threat_intel import http as ti_http
from app.modules.threat_intel.http import (
    KeyAuth,
    PathNotAllowed,
    PinnedHost,
    fetch_json,
    json_depth_exceeds,
    parse_json,
    path_allowed,
    ti_client,
)
from app.modules.threat_intel.providers.base import (
    AllowedPath,
    IocType,
    ProviderError,
    ProviderErrorKind,
    ProviderName,
)
from app.modules.threat_intel.ratelimit import parse_retry_after
from tests.ti_helpers import SENTINEL_KEY, SafeTransport

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "ti"
HOST = "api.provider.test"
URL = f"https://{HOST}/v1/lookup/domain/acme-corp.net"


class _Provider:
    name = ProviderName.MOCK
    supported_types = frozenset(IocType)
    allowed_paths = (
        AllowedPath("GET", HOST, re.compile(r"/v1/lookup/domain/[^/]+")),
        AllowedPath("POST", None, re.compile(r"/misp/attributes/restSearch")),
    )

    async def lookup(self, client: Any, ioc: Any) -> Any:
        raise NotImplementedError

    async def verify(self, client: Any) -> Any:
        raise NotImplementedError


def _client(handler: Any, **kwargs: Any) -> httpx.AsyncClient:
    return ti_client(
        _Provider(),
        auth=KeyAuth("x-apikey", SecretStr(SENTINEL_KEY)),
        transport=SafeTransport(handler),
        **kwargs,
    )


async def _fetch(handler: Any, url: str = URL, **kwargs: Any) -> Any:
    async with _client(handler) as client:
        return await fetch_json(client, "GET", url, **kwargs)


async def _error(handler: Any, url: str = URL, **kwargs: Any) -> ProviderError:
    with pytest.raises(ProviderError) as caught:
        await _fetch(handler, url, **kwargs)
    return caught.value


async def test_key_only_in_the_auth_header_and_never_in_reprs() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    auth = KeyAuth("x-apikey", SecretStr(SENTINEL_KEY))
    async with ti_client(_Provider(), auth=auth, transport=SafeTransport(handler)) as client:
        assert (await fetch_json(client, "GET", URL)).data == {"ok": True}
        assert SENTINEL_KEY not in repr(client)
        assert "x-apikey" not in {k.lower() for k in client.headers}
    [request] = seen
    assert request.headers["x-apikey"] == SENTINEL_KEY
    assert request.headers["user-agent"].startswith("CyberLab-TI/")
    assert SENTINEL_KEY not in str(request.url)
    for text in (repr(request), repr(auth), str(auth)):
        assert SENTINEL_KEY not in text
    error = ProviderError(ProviderErrorKind.AUTH, http_status=401)
    assert SENTINEL_KEY not in str(error) + repr(error)


async def test_error_bodies_are_never_read(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": f"bad key {SENTINEL_KEY}"})

    error = await _error(handler)
    assert (error.kind, error.http_status) == (ProviderErrorKind.AUTH, 401)
    assert SENTINEL_KEY not in str(error) + repr(error) + repr(error.__cause__)
    assert SENTINEL_KEY not in caplog.text


@pytest.mark.parametrize(
    ("status", "kind"),
    [
        (301, ProviderErrorKind.REDIRECT),
        (302, ProviderErrorKind.REDIRECT),
        (401, ProviderErrorKind.AUTH),
        (403, ProviderErrorKind.AUTH),
        (404, ProviderErrorKind.NOT_FOUND),
        (400, ProviderErrorKind.BAD_REQUEST),
        (422, ProviderErrorKind.INVALID_INPUT),
        (418, ProviderErrorKind.UNEXPECTED_STATUS),
        (500, ProviderErrorKind.HTTP_5XX),
        (503, ProviderErrorKind.HTTP_5XX),
    ],
)
async def test_status_mapping(status: int, kind: ProviderErrorKind) -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status, headers={"Location": f"https://{HOST}/elsewhere"})

    assert (await _error(handler)).kind is kind
    assert calls == 1  # redirects are never followed


async def test_accepted_statuses_are_parsed() -> None:
    response = await _fetch(lambda _: httpx.Response(404, json={"x": 1}), accept=(200, 404))
    assert (response.status, response.data) == (404, {"x": 1})


async def test_429_retry_after() -> None:
    error = await _error(lambda _: httpx.Response(429, headers={"Retry-After": "7"}))
    assert (error.kind, error.retry_after_s) == (ProviderErrorKind.RATE_LIMITED, 7.0)
    error = await _error(lambda _: httpx.Response(429))
    assert error.retry_after_s is None


async def test_unlisted_paths_are_refused_before_sending() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={})

    for url in (
        f"https://{HOST}/v1/upload",
        f"https://{HOST}/v1/lookup/domain/a/b",
        "https://other.test/v1/lookup/domain/x",
        f"http://{HOST}:8080/v1/lookup/ip/x",
        f"https://{HOST}/v1/lookup/domain/%2e%2e/admin",
    ):
        with pytest.raises(PathNotAllowed):
            await _fetch(handler, url)
    with pytest.raises(PathNotAllowed):
        async with _client(handler) as client:
            await fetch_json(client, "POST", URL)
    assert calls == 0


def test_org_host_paths() -> None:
    allowed = _Provider.allowed_paths
    request = httpx.Request("POST", "https://misp.acme-corp.net/misp/attributes/restSearch")
    assert path_allowed(request, allowed, org_host="misp.acme-corp.net")
    assert not path_allowed(request, allowed, org_host="other.acme-corp.net")
    assert not path_allowed(request, allowed)  # no org host: never
    pinned = httpx.Request(
        "POST",
        "https://203.0.113.7/misp/attributes/restSearch",
        headers={"Host": "misp.acme-corp.net"},
    )
    pin = PinnedHost("misp.acme-corp.net", "203.0.113.7")
    assert path_allowed(pinned, allowed, org_host="misp.acme-corp.net", pinned=pin)
    assert not path_allowed(pinned, allowed, org_host="misp.acme-corp.net")


async def test_body_cap() -> None:
    big = b'{"pad":"' + b"x" * (ti_http.MAX_BODY_BYTES + 10) + b'"}'
    # Declared length over the cap: refused before reading.
    error = await _error(lambda _: httpx.Response(200, content=big))
    assert error.kind is ProviderErrorKind.OVERSIZE

    async def stream() -> Any:
        for _ in range(20):
            yield b"x" * 65536

    error = await _error(lambda _: httpx.Response(200, content=stream()))
    assert error.kind is ProviderErrorKind.OVERSIZE
    # MISP's larger cap.
    ok = b'{"pad":"' + b"x" * (ti_http.MAX_BODY_BYTES + 10) + b'"}'
    response = await _fetch(
        lambda _: httpx.Response(200, content=ok), max_bytes=ti_http.MISP_MAX_BODY_BYTES
    )
    assert len(response.data["pad"]) == ti_http.MAX_BODY_BYTES + 10


async def test_trust_env_is_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "all_proxy"):
        monkeypatch.setenv(name, "http://proxy.invalid:3128")
    trusting = httpx.AsyncClient()
    assert trusting._mounts  # the environment would install a proxy...
    await trusting.aclose()
    # ...and a CA bundle (unreadable here: loading it would fail)...
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent.pem")
    client = ti_client(_Provider())  # ...but neither is used by the TI client
    try:
        assert client._mounts == {}
        assert client.follow_redirects is False
        assert client.timeout == httpx.Timeout(connect=3.0, read=10.0, write=10.0, pool=3.0)
    finally:
        await client.aclose()


async def test_timeouts() -> None:
    def read_timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    assert (await _error(read_timeout)).kind is ProviderErrorKind.TIMEOUT

    def connect_error(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    assert (await _error(connect_error)).kind is ProviderErrorKind.TRANSPORT


async def test_total_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ti_http, "TOTAL_TIMEOUT_S", 0.2)

    async def slow(_: httpx.Request) -> httpx.Response:
        await asyncio.sleep(1)
        return httpx.Response(200, json={})

    assert (await _error(slow)).kind is ProviderErrorKind.TIMEOUT


@pytest.mark.parametrize(
    "body",
    [
        b"[" * 3000 + b"]" * 3000,
        b'{"a":' * 65 + b"1" + b"}" * 65,
        b'{"n": NaN}',
        b'{"n": Infinity}',
        b'{"n": -Infinity}',
        b'{"n": 1e999}',
        b'{"n": ' + b"9" * 5000 + b"}",
        b'{"n": ' + b"9" * 41 + b"}",
        b'{"found": true, "label": "trunc',
        b"\xff\xfe\x00garbage",
        b"<html>not json</html>",
    ],
)
async def test_hostile_json_is_bad_json(body: bytes) -> None:
    error = await _error(lambda _: httpx.Response(200, content=body))
    assert error.kind is ProviderErrorKind.BAD_JSON


def test_fixture_deep_nesting_is_bad_json() -> None:
    for path in FIXTURES.glob("*/deep_nesting.txt"):
        with pytest.raises(ProviderError) as caught:
            parse_json(path.read_bytes())
        assert caught.value.kind is ProviderErrorKind.BAD_JSON
    for path in FIXTURES.glob("*/malformed.txt"):
        with pytest.raises(ProviderError):
            parse_json(path.read_bytes())


def test_every_json_fixture_parses() -> None:
    files = list(FIXTURES.glob("*/*.json"))
    assert files
    for path in files:
        assert parse_json(path.read_bytes()) == json.loads(path.read_bytes())


def test_depth_scanner_ignores_strings() -> None:
    deep_string = json.dumps({"s": "[" * 500 + '\\"{' * 100}).encode()
    assert not json_depth_exceeds(deep_string)
    assert parse_json(deep_string)["s"].startswith("[[[")
    assert not json_depth_exceeds(b"[" * 64 + b"]" * 64)
    assert json_depth_exceeds(b"[" * 65 + b"]" * 65)
    assert parse_json(b'{"big": 12345678901234567890, "f": 1.5}') == {
        "big": 12345678901234567890,
        "f": 1.5,
    }


def test_retry_after_forms() -> None:
    now = datetime(2026, 11, 5, 12, 0, 0, tzinfo=UTC)
    assert parse_retry_after("30") == 30.0
    assert parse_retry_after(" 0 ") == 1.0
    assert parse_retry_after("999999") == 3600.0
    assert parse_retry_after("99999999999999999999") == 3600.0
    future = format_datetime(now + timedelta(seconds=90), usegmt=True)
    assert parse_retry_after(future, now=now) == pytest.approx(90.0)
    past = format_datetime(now - timedelta(hours=1), usegmt=True)
    assert parse_retry_after(past, now=now) == 1.0
    far = format_datetime(now + timedelta(days=3), usegmt=True)
    assert parse_retry_after(far, now=now) == 3600.0
    for bad in (None, "", "soon", "-5", "1.5", "Wed, 99 Foo 2026", "x" * 100):
        assert parse_retry_after(bad, now=now) is None


def test_key_auth_header_names_are_checked() -> None:
    with pytest.raises(ValueError):
        KeyAuth("bad header\r\n", SecretStr("x" * 10))
