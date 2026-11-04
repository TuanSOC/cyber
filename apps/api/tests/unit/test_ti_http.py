"""The hardened provider HTTP client (M4 phase 2; RT11, RT19)."""

import asyncio
import gzip
import json
import logging
import re
import traceback
import tracemalloc
import zlib
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from typing import Any

import h11
import httpx
import pytest
from pydantic import SecretStr

from app.core.db import get_engine
from app.modules.threat_intel import http as ti_http
from app.modules.threat_intel.http import (
    KeyAuth,
    Origin,
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


def test_org_host_paths_compare_an_idn_in_punycode() -> None:
    # `httpx.URL.host` decodes a host starting with an IDN label to Unicode; the stored org
    # host is punycode.
    allowed = _Provider.allowed_paths
    idn = "xn--bcher-kva.net"
    request = httpx.Request("POST", f"https://{idn}/misp/attributes/restSearch")
    assert request.url.host == "bücher.net"  # Unicode form
    assert path_allowed(request, allowed, org_host=idn)
    assert not path_allowed(request, allowed, org_host="bücher.net")


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


@pytest.mark.parametrize(
    "value",
    ["²", "30²", "¹²", "٣٠", "３０", "Wed, ٠٥ Nov 2026 12:00:00 GMT", "٣"],
)
def test_retry_after_non_ascii_digits_are_malformed(value: str) -> None:
    # `str.isdigit()` is True for several of these but `int()` refuses them: never a crash.
    assert parse_retry_after(value) is None


async def test_429_with_unparsable_retry_after_gets_the_default_backoff() -> None:
    # Latin-1 `²` on the wire (httpx decodes header bytes as ASCII, UTF-8, then Latin-1).
    error = await _error(lambda _: httpx.Response(429, headers={"Retry-After": b"\xb2"}))
    assert (error.kind, error.retry_after_s) == (ProviderErrorKind.RATE_LIMITED, None)


def test_key_auth_header_names_are_checked() -> None:
    with pytest.raises(ValueError):
        KeyAuth("bad header\r\n", SecretStr("x" * 10))


# --- content codings: identity requested, compression bombs bounded -----------------------


def _gzip_bomb(inflated: int) -> bytes:
    """`inflated` zero bytes, gzip-compressed without ever holding them in memory."""
    packer = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    block = b"\0" * (1024 * 1024)
    parts = [packer.compress(block) for _ in range(inflated // len(block))]
    return b"".join([*parts, packer.flush()])


def _chunked(body: bytes, size: int = 16 * 1024) -> Any:
    async def stream() -> Any:
        for start in range(0, len(body), size):
            yield body[start : start + size]

    return stream()


async def test_requests_ask_for_an_identity_body() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={})

    await _fetch(handler)
    assert seen[0].headers["accept-encoding"] == "identity"


@pytest.mark.parametrize("coding", ["gzip", "x-gzip", "deflate", "raw-deflate", "identity"])
async def test_small_compressed_bodies_are_still_read(coding: str) -> None:
    body = json.dumps({"found": True, "pad": "x" * 5000}).encode()
    if coding in ("gzip", "x-gzip"):
        wire = gzip.compress(body)
    elif coding == "deflate":
        wire = zlib.compress(body)
    elif coding == "raw-deflate":
        packer = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS)
        wire = packer.compress(body) + packer.flush()
    else:
        wire = body
    header = "deflate" if coding == "raw-deflate" else coding

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=_chunked(wire, 7), headers={"Content-Encoding": header})

    assert (await _fetch(handler)).data["found"] is True


async def test_gzip_bomb_is_refused_with_bounded_memory() -> None:
    inflated = 256 * 1024 * 1024  # 256 MiB of zeros in ~250 KB of gzip
    bomb = _gzip_bomb(inflated)
    assert len(bomb) < ti_http.MAX_BODY_BYTES  # under the cap as sent

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=_chunked(bomb), headers={"Content-Encoding": "gzip"})

    tracemalloc.start()
    try:
        error = await _error(handler)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert error.kind is ProviderErrorKind.OVERSIZE
    assert error.__cause__ is None and error.__context__ is None
    # Bounded by the cap (plus the joined copy and one raw chunk), not by the bomb.
    assert peak < 4 * ti_http.MAX_BODY_BYTES, peak


def test_inflater_never_produces_more_than_the_cap_plus_one() -> None:
    bomb = _gzip_bomb(64 * 1024 * 1024)
    for chunk_size in (len(bomb), 1, 4096):
        inflater = ti_http._Inflater("gzip", 1000)
        produced = 0
        for start in range(0, len(bomb), chunk_size):
            produced += sum(len(p) for p in inflater.feed(bomb[start : start + chunk_size]))
            if inflater.over:
                break
        assert inflater.over
        assert produced == 1001


async def test_misp_cap_applies_to_the_inflated_size() -> None:
    body = b'{"pad":"' + b"x" * (ti_http.MAX_BODY_BYTES + 10) + b'"}'
    wire = gzip.compress(body)

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=_chunked(wire), headers={"Content-Encoding": "gzip"})

    assert (await _error(handler)).kind is ProviderErrorKind.OVERSIZE
    response = await _fetch(handler, max_bytes=ti_http.MISP_MAX_BODY_BYTES)
    assert len(response.data["pad"]) == ti_http.MAX_BODY_BYTES + 10


@pytest.mark.parametrize(
    "coding", ["br", "zstd", "compress", "gzip, gzip", "deflate, gzip", "gzip, br", "bogus"]
)
async def test_other_content_codings_are_refused(coding: str) -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200, content=_chunked(gzip.compress(b"{}")), headers={"Content-Encoding": coding}
        )

    error = await _error(handler)
    assert error.kind is ProviderErrorKind.BAD_JSON
    assert calls == 1


@pytest.mark.parametrize(
    "wire",
    [
        gzip.compress(b'{"a": 1}')[:-6],  # truncated
        gzip.compress(b'{"a": 1}') + b"trailing garbage",
        gzip.compress(b'{"a": 1}') + gzip.compress(b'{"b": 2}'),  # a second member
        b"\x1f\x8b\x08\x00not really gzip",
        b"plain text, not compressed",
    ],
)
async def test_corrupt_compressed_bodies_are_bad_json(wire: bytes) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=_chunked(wire, 5), headers={"Content-Encoding": "gzip"})

    error = await _error(handler)
    assert error.kind is ProviderErrorKind.BAD_JSON
    assert error.__cause__ is None and error.__context__ is None


async def test_non_ascii_content_length_is_ignored_not_a_crash() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=_chunked(b'{"ok": 1}'), headers={"Content-Length": b"\xb2"}
        )

    assert (await _fetch(handler)).data == {"ok": 1}


# --- origins: https on the expected port only ----------------------------------------------


async def test_scheme_and_port_are_enforced_before_sending() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={})

    for url in (
        f"http://{HOST}/v1/lookup/domain/acme-corp.net",
        f"http://{HOST}:443/v1/lookup/domain/acme-corp.net",
        f"https://{HOST}:8443/v1/lookup/domain/acme-corp.net",
        f"https://{HOST}:80/v1/lookup/domain/acme-corp.net",
        f"ws://{HOST}/v1/lookup/domain/acme-corp.net",
    ):
        with pytest.raises(PathNotAllowed):
            await _fetch(handler, url)
    assert calls == 0
    await _fetch(handler, f"https://{HOST}:443/v1/lookup/domain/acme-corp.net")
    assert calls == 1


def test_org_host_port_is_the_base_url_port() -> None:
    allowed = _Provider.allowed_paths
    path = "/misp/attributes/restSearch"
    org = "misp.acme-corp.net"

    def ok(url: str, **kwargs: Any) -> bool:
        return path_allowed(httpx.Request("POST", url), allowed, org_host=org, **kwargs)

    assert ok(f"https://{org}{path}")
    assert not ok(f"https://{org}:8443{path}")
    assert ok(f"https://{org}:8443{path}", org_port=8443)
    assert not ok(f"https://{org}{path}", org_port=8443)
    assert not ok(f"http://{org}:8443{path}", org_port=8443)
    pinned = httpx.Request("POST", f"https://203.0.113.7:8443{path}", headers={"Host": org})
    pin = PinnedHost(org, "203.0.113.7")
    assert path_allowed(pinned, allowed, org_host=org, org_port=8443, pinned=pin)
    assert not path_allowed(pinned, allowed, org_host=org, pinned=pin)
    # The dev origin never covers the org (MISP) entries.
    dev = Origin("http", org, 8080)
    assert not ok(f"http://{org}:8080{path}", dev_origin=dev)


class _MispLike(_Provider):
    name = ProviderName.MISP

    class base:  # noqa: N801 - mirrors `MispProvider.base` (a `ValidatedBase`)
        port = 8443


async def test_ti_client_takes_the_misp_port_from_the_adapter() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={})

    org = "misp.acme-corp.net"
    good = f"https://{org}:8443/misp/attributes/restSearch"
    async with ti_client(
        _MispLike(), transport=httpx.MockTransport(handler), org_host=org
    ) as client:
        await fetch_json(client, "POST", good)
        for bad in (f"https://{org}/misp/attributes/restSearch", good.replace("https", "http")):
            with pytest.raises(PathNotAllowed):
                await fetch_json(client, "POST", bad)
    assert seen == [good]


class _Real(_Provider):
    name = ProviderName.VIRUSTOTAL


async def test_plain_http_only_for_the_mock_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={})

    dev = f"http://{HOST}:8080"
    url = f"{dev}/v1/lookup/domain/acme-corp.net"

    async def get(provider: Any, target: str, base: str | None = dev) -> None:
        async with ti_client(
            provider, transport=httpx.MockTransport(handler), dev_base_url=base
        ) as client:
            await fetch_json(client, "GET", target)

    await get(_Provider(), url)  # the mock provider at its own base URL
    assert calls == 1
    for provider, target in (
        (_Provider(), f"http://{HOST}:8081/v1/lookup/domain/acme-corp.net"),
        (_Provider(), f"http://{HOST}/v1/lookup/domain/acme-corp.net"),
        (_Real(), url),  # never for a real provider
    ):
        with pytest.raises(PathNotAllowed):
            await get(provider, target)
    # Without an override, TI_MOCK_BASE_URL is the dev origin.
    settings = ti_http.get_settings()
    monkeypatch.setattr(
        ti_http,
        "get_settings",
        lambda: settings.model_copy(update={"ti_mock_base_url": dev}),
    )
    await get(_Provider(), url, base=None)
    assert calls == 2
    # ...and there is none in prod.
    monkeypatch.setattr(
        ti_http,
        "get_settings",
        lambda: settings.model_copy(update={"ti_mock_base_url": dev, "env": "prod"}),
    )
    with pytest.raises(PathNotAllowed):
        await get(_Provider(), url, base=None)
    assert calls == 2


# --- the key never reaches an exception ----------------------------------------------------


def _leaks(error: BaseException) -> bool:
    text = "".join(traceback.format_exception(error)) + repr(error) + str(error)
    return SENTINEL_KEY in text or SENTINEL_KEY[:12] in text


@pytest.mark.parametrize(
    "raise_",
    [
        lambda r: httpx.LocalProtocolError(f"Illegal header value {SENTINEL_KEY!r}", request=r),
        lambda r: h11.LocalProtocolError(f"Illegal header value {SENTINEL_KEY!r}"),
        lambda r: httpx.RemoteProtocolError(f"echo {SENTINEL_KEY}", request=r),
        lambda r: UnicodeEncodeError("ascii", SENTINEL_KEY + "é", 0, 1, "bad"),
    ],
)
async def test_protocol_errors_are_sanitized(raise_: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise raise_(request)

    error = await _error(handler)
    assert error.kind is ProviderErrorKind.TRANSPORT
    assert error.__cause__ is None and error.__context__ is None
    assert not _leaks(error)


class _RawAuth(httpx.Auth):
    """Puts a value into a header without KeyAuth's checks."""

    def __init__(self, value: str) -> None:
        self.value = value

    def auth_flow(self, request: httpx.Request) -> Any:
        request.headers["x-apikey"] = self.value
        yield request


class _Loopback(_Provider):
    allowed_paths = (AllowedPath("GET", "127.0.0.1", re.compile(r"/v1/lookup/domain/[^/]+")),)


async def test_h11_refusing_the_key_header_never_leaks_it() -> None:
    """Over a real httpcore/h11 connection: h11 quotes an illegal header value in its error
    message ("Illegal header value b'...'"); the mapped error carries none of it."""
    received: list[bytes] = []

    async def serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        received.append(await reader.read(65536))
        writer.close()

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    try:
        for value in (
            f"{SENTINEL_KEY}\r\nX-Injected: 1",
            f"{SENTINEL_KEY}\x00",
            f" {SENTINEL_KEY}\n",
        ):
            async with ti_client(
                _Loopback(),
                auth=_RawAuth(value),
                transport=httpx.AsyncHTTPTransport(retries=0),
                dev_base_url=base,
            ) as client:
                with pytest.raises(ProviderError) as caught:
                    await fetch_json(client, "GET", f"{base}/v1/lookup/domain/acme-corp.net")
            assert caught.value.kind is ProviderErrorKind.TRANSPORT
            assert caught.value.__cause__ is None and caught.value.__context__ is None
            assert not _leaks(caught.value)
    finally:
        server.close()
        await server.wait_closed()
    assert not any(SENTINEL_KEY.encode() in data for data in received)


@pytest.mark.parametrize(
    "key",
    [
        f" {SENTINEL_KEY}",
        f"{SENTINEL_KEY} ",
        f"{SENTINEL_KEY}\r\nX-Injected: 1",
        f"{SENTINEL_KEY}\n",
        f"{SENTINEL_KEY}\x00",
        f"{SENTINEL_KEY}\t",
        f"{SENTINEL_KEY}é",
        "",
    ],
)
def test_key_auth_refuses_unsafe_keys_without_quoting_them(key: str) -> None:
    with pytest.raises(ValueError) as caught:
        KeyAuth("x-apikey", SecretStr(key))
    assert not _leaks(caught.value)


def test_key_auth_accepts_inner_spaces() -> None:
    KeyAuth("Authorization", SecretStr(f"Token {SENTINEL_KEY}"))


def test_the_db_engine_hides_statement_parameters() -> None:
    # IOC values and file names must not reach Celery tracebacks through SQL errors.
    assert get_engine().sync_engine.hide_parameters is True
