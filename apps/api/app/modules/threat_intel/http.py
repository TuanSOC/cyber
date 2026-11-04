"""The hardened provider HTTP client (enrich worker only; see the import guard test).

One `httpx.AsyncClient` per provider and slice:
- `trust_env=False` (no proxy, netrc or CA env from the environment), `follow_redirects=False`,
  `verify=True`; timeouts 3 s connect / 10 s read and 20 s for the whole exchange; a fixed
  `User-Agent`;
- the key is attached per request by `KeyAuth`, an `httpx.Auth` whose `repr` is redacted. It is
  never put in `client.headers`: httpx masks only `Authorization` in header reprs (RT11);
- every request must match one of the adapter's `allowed_paths` (checked by a request event
  hook before anything is sent; `PathNotAllowed` otherwise). Paths are matched in their
  percent-encoded form, without the query string; the origin must be `https` on port 443
  (MISP: its base URL's port). The only exception is the dev/test `ti-mock` base URL
  (`TI_MOCK_BASE_URL`, never in prod), for the mock provider only;
- `fetch_json` sends `Accept-Encoding: identity` and streams the raw body under a byte cap
  (1 MiB, MISP 2 MiB). A server that compresses anyway gets gzip/deflate inflated
  incrementally with the cap applied to the inflated output (a compression bomb never grows
  past the cap plus one chunk); any other content coding is refused. It never reads an error
  body and maps every failure to a `ProviderError` kind whose `__cause__`/`__context__` are
  empty (an httpx/h11 protocol error can quote a header value: the key). JSON is parsed with
  a nesting-depth limit (CPython's `json` accepts thousands of levels), an integer-digit
  limit and no `NaN`/`Infinity` (RT19).

Nothing here logs a header, a body or a key; the `httpx`/`httpcore` loggers are set to WARNING.
"""

import asyncio
import json
import logging
import math
import re
import zlib
from collections.abc import Generator, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import h11
import httpcore
import httpx
from pydantic import SecretStr

from app.core.config import get_settings
from app.modules.threat_intel.providers.base import (
    AllowedPath,
    Provider,
    ProviderError,
    ProviderErrorKind,
    ProviderName,
)
from app.modules.threat_intel.ratelimit import parse_retry_after

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

VERSION = "0.4"
USER_AGENT = f"CyberLab-TI/{VERSION}"
TIMEOUT = httpx.Timeout(connect=3.0, read=10.0, write=10.0, pool=3.0)
TOTAL_TIMEOUT_S = 20.0
MAX_BODY_BYTES = 1024 * 1024
MISP_MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_INT_DIGITS = 40

_HEADER_NAME = re.compile(r"[A-Za-z0-9-]{1,64}")
MAX_KEY_CHARS = 4096
HTTPS_PORT = 443
_DEFAULT_PORTS = {"https": 443, "http": 80}


def _header_safe(value: str) -> bool:
    """Printable ASCII without surrounding whitespace: what h11 sends verbatim (anything
    else makes httpx/h11 raise an error whose message or attributes quote the value)."""
    return (
        0 < len(value) <= MAX_KEY_CHARS
        and value.isascii()
        and value.isprintable()
        and value == value.strip()
    )


class KeyAuth(httpx.Auth):
    """Adds the provider key header to each outgoing request. Its repr never shows the key,
    and a key that is not a safe header value is refused here, with a message without it."""

    requires_request_body = False
    requires_response_body = False

    def __init__(self, header: str, key: SecretStr) -> None:
        if not _HEADER_NAME.fullmatch(header):
            raise ValueError("bad auth header name")
        if not _header_safe(key.get_secret_value()):
            raise ValueError("bad api key: not a printable ASCII header value")
        self._header = header
        self._key = key

    @property
    def header(self) -> str:
        return self._header

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers[self._header] = self._key.get_secret_value()
        yield request

    def __repr__(self) -> str:
        return f"KeyAuth(header={self._header!r}, key=***)"

    __str__ = __repr__


class PathNotAllowed(ProviderError):
    """A request outside the adapter's allowlist (a bug, never sent)."""

    def __init__(self) -> None:
        super().__init__(ProviderErrorKind.PATH_NOT_ALLOWED)


@dataclass(frozen=True)
class PinnedHost:
    """MISP (phase 4): the request URL names the pinned IP; `Host`/SNI carry `hostname`."""

    hostname: str
    address: str


@dataclass(frozen=True)
class Origin:
    """The scheme, host and effective port of a URL."""

    scheme: str
    host: str
    port: int | None

    @classmethod
    def of(cls, url: "httpx.URL | str") -> "Origin":
        parsed = url if isinstance(url, httpx.URL) else httpx.URL(url)
        scheme = parsed.scheme.lower()
        port = parsed.port if parsed.port is not None else _DEFAULT_PORTS.get(scheme)
        # `raw_host`: the ASCII (punycode) form; `host` is Unicode for an IDN, while the
        # validated MISP host and the allowlists are ASCII.
        return cls(scheme, parsed.raw_host.decode("ascii").lower(), port)


def encoded_path(url: httpx.URL) -> str:
    return url.raw_path.split(b"?", 1)[0].decode("ascii", errors="replace")


def path_allowed(
    request: httpx.Request,
    allowed: Iterable[AllowedPath],
    *,
    org_host: str | None = None,
    org_port: int = HTTPS_PORT,
    pinned: PinnedHost | None = None,
    dev_origin: Origin | None = None,
) -> bool:
    """The request matches an allowed shape on an allowed origin: `https` on 443 for fixed
    hosts, `https` on `org_port` for the org (MISP) host, or exactly `dev_origin` (mock)."""
    origin = Origin.of(request.url)
    host = origin.host
    if pinned is not None and host == pinned.address:
        # A pinned request is allowed as the hostname it carries in `Host` (and SNI).
        header_host = request.headers.get("host", "").split(":")[0].lower()
        host = pinned.hostname if header_host == pinned.hostname else ""
    path = encoded_path(request.url)
    for entry in allowed:
        if entry.host is None and (org_host is None or host != org_host):
            continue
        expected_port = org_port if entry.host is None else HTTPS_PORT
        secure = origin.scheme == "https" and origin.port == expected_port
        dev = dev_origin is not None and entry.host is not None and origin == dev_origin
        if not (secure or dev):
            continue
        if entry.matches(request.method, host, path):
            return True
    return False


def _org_port(provider: Provider) -> int:
    """The MISP base URL's port (`ValidatedBase.port`), else 443."""
    port = getattr(getattr(provider, "base", None), "port", None)
    return port if isinstance(port, int) and not isinstance(port, bool) else HTTPS_PORT


def _dev_origin(provider: Provider, dev_base_url: str | None) -> Origin | None:
    """The `ti-mock` origin (plain http allowed): the mock provider only, never in prod."""
    if provider.name is not ProviderName.MOCK:
        return None
    settings = get_settings()
    if settings.env == "prod":
        return None
    try:
        return Origin.of(dev_base_url or settings.ti_mock_base_url)
    except (httpx.InvalidURL, ValueError, TypeError):
        return None


def ti_client(
    provider: Provider,
    *,
    auth: httpx.Auth | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    org_host: str | None = None,
    org_port: int | None = None,
    pinned: PinnedHost | None = None,
    verify: Any = True,
    dev_base_url: str | None = None,
) -> httpx.AsyncClient:
    """A client bound to `provider.allowed_paths`. `org_host` and `org_port` (by default the
    adapter's base URL port, else 443) are the MISP origin that `AllowedPath(host=None)`
    entries refer to. `dev_base_url` overrides `TI_MOCK_BASE_URL` for the mock provider."""
    allowed = tuple(provider.allowed_paths)
    port = org_port if org_port is not None else _org_port(provider)
    dev_origin = _dev_origin(provider, dev_base_url)

    async def guard(request: httpx.Request) -> None:
        if not path_allowed(
            request,
            allowed,
            org_host=org_host,
            org_port=port,
            pinned=pinned,
            dev_origin=dev_origin,
        ):
            raise PathNotAllowed()

    return httpx.AsyncClient(
        auth=auth,
        transport=transport,
        trust_env=False,
        follow_redirects=False,
        verify=verify,
        timeout=TIMEOUT,
        limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        },
        event_hooks={"request": [guard]},
    )


# --- JSON ----------------------------------------------------------------------------------

_STRUCTURAL = re.compile(rb'["\\\[\]{}]')


def json_depth_exceeds(body: bytes, limit: int = MAX_JSON_DEPTH) -> bool:
    """True if arrays/objects nest deeper than `limit` (strings and escapes skipped)."""
    depth = 0
    in_string = False
    skip_at = -1
    for match in _STRUCTURAL.finditer(body):
        pos = match.start()
        if pos == skip_at:
            continue
        char = body[pos]
        if in_string:
            if char == 0x5C:  # backslash: the next byte is escaped
                skip_at = pos + 1
            elif char == 0x22:
                in_string = False
            continue
        if char == 0x22:
            in_string = True
        elif char in (0x5B, 0x7B):
            depth += 1
            if depth > limit:
                return True
        elif char in (0x5D, 0x7D):
            depth -= 1
    return False


def _refuse_constant(_: str) -> Any:
    raise ValueError("non-finite number")


def _bounded_int(text: str) -> int:
    if len(text.lstrip("-")) > MAX_INT_DIGITS:
        raise ValueError("integer too long")
    return int(text)


def _finite_float(text: str) -> float:
    if len(text) > 64:
        raise ValueError("number too long")
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("non-finite number")
    return value


def parse_json(body: bytes) -> Any:
    """Strict JSON: any failure (syntax, depth, digits, NaN/Infinity, encoding) is `bad_json`."""
    if json_depth_exceeds(body):
        raise ProviderError(ProviderErrorKind.BAD_JSON)
    try:
        return json.loads(
            body,
            parse_constant=_refuse_constant,
            parse_int=_bounded_int,
            parse_float=_finite_float,
        )
    except (ValueError, RecursionError, TypeError, UnicodeDecodeError):
        raise ProviderError(ProviderErrorKind.BAD_JSON) from None


# --- requests ------------------------------------------------------------------------------


@dataclass(frozen=True)
class JsonResponse:
    status: int
    data: Any


def status_error(response: httpx.Response) -> ProviderError:
    """The mapped error of an unaccepted status. The body is never read."""
    status = response.status_code
    if 300 <= status < 400:
        return ProviderError(ProviderErrorKind.REDIRECT, http_status=status)
    if status in (401, 403):
        return ProviderError(ProviderErrorKind.AUTH, http_status=status)
    if status == 429:
        return ProviderError(
            ProviderErrorKind.RATE_LIMITED,
            http_status=status,
            retry_after_s=parse_retry_after(response.headers.get("retry-after")),
        )
    if status == 404:
        return ProviderError(ProviderErrorKind.NOT_FOUND, http_status=status)
    if status == 400:
        return ProviderError(ProviderErrorKind.BAD_REQUEST, http_status=status)
    if status == 422:
        return ProviderError(ProviderErrorKind.INVALID_INPUT, http_status=status)
    if status >= 500:
        return ProviderError(ProviderErrorKind.HTTP_5XX, http_status=status)
    return ProviderError(ProviderErrorKind.UNEXPECTED_STATUS, http_status=status)


_GZIP = "gzip"
_DEFLATE = "deflate"
_CODINGS = {"gzip": _GZIP, "x-gzip": _GZIP, "deflate": _DEFLATE}


class _Inflater:
    """Incremental gzip/deflate decoding whose total output never exceeds `limit + 1` bytes,
    however small the compressed input (`decompress(data, max_length)`)."""

    def __init__(self, coding: str, limit: int) -> None:
        self._coding = coding
        self._limit = limit
        self._produced = 0
        self._started = False
        # HTTP `deflate` is zlib-wrapped; raw deflate is tried too (as httpx does).
        self._obj = zlib.decompressobj(zlib.MAX_WBITS | 16 if coding == _GZIP else zlib.MAX_WBITS)

    @property
    def over(self) -> bool:
        return self._produced > self._limit

    def _budget(self) -> int:
        return self._limit + 1 - self._produced

    def feed(self, data: bytes) -> list[bytes]:
        """Inflate `data`; stops (with `over` set) once the output passes the limit.
        Raises `zlib.error` on corrupt input or bytes after the end of the stream."""
        out: list[bytes] = []
        pending = data
        while pending and not self.over:
            if self._obj.eof:
                raise zlib.error("data after the end of the compressed stream")
            try:
                piece = self._obj.decompress(pending, self._budget())
            except zlib.error:
                if self._started or self._coding != _DEFLATE:
                    raise
                self._obj = zlib.decompressobj(-zlib.MAX_WBITS)
                piece = self._obj.decompress(pending, self._budget())
            self._started = True
            self._produced += len(piece)
            out.append(piece)
            rest = self._obj.unconsumed_tail or self._obj.unused_data
            if not piece and len(rest) >= len(pending):
                raise zlib.error("no progress")
            pending = rest
        return out

    def finish(self) -> list[bytes]:
        if self.over:
            return []
        tail = self._obj.flush(self._budget())
        self._produced += len(tail)
        if not self._obj.eof:
            raise zlib.error("truncated compressed stream")
        return [tail]


def _content_coding(response: httpx.Response) -> str | None:
    """None for an identity body, else gzip/deflate. Anything else (brotli, zstd, stacked or
    unknown codings) is refused as `bad_json`: we asked for identity."""
    values = response.headers.get_list("content-encoding", split_commas=True)
    codings = [v.strip().lower() for v in values]
    codings = [c for c in codings if c not in ("", "identity")]
    if not codings:
        return None
    if len(codings) == 1 and codings[0] in _CODINGS:
        return _CODINGS[codings[0]]
    raise ProviderError(ProviderErrorKind.BAD_JSON, http_status=response.status_code)


async def _read_capped(response: httpx.Response, max_bytes: int) -> bytes:
    """The raw body under `max_bytes`, inflated (the cap applying to the inflated size) if
    the server compressed it despite `Accept-Encoding: identity`. Raises `ProviderError`
    only, never with a `__context__`."""
    status = response.status_code
    declared = response.headers.get("content-length", "").strip()
    if declared.isascii() and declared.isdigit() and int(declared) > max_bytes:
        # For a compressed body this is the compressed size: still more than we accept.
        raise ProviderError(ProviderErrorKind.OVERSIZE, http_status=status)
    coding = _content_coding(response)
    if response.is_stream_consumed:
        # An in-memory response (`httpx.MockTransport` in tests) was read, and decoded, when
        # it was built; a network response never is.
        if len(response.content) > max_bytes:
            raise ProviderError(ProviderErrorKind.OVERSIZE, http_status=status)
        return response.content
    inflater = _Inflater(coding, max_bytes) if coding is not None else None
    chunks: list[bytes] = []
    raw_size = 0
    corrupt = False
    async for raw in response.aiter_raw():
        raw_size += len(raw)
        if raw_size > max_bytes:
            raise ProviderError(ProviderErrorKind.OVERSIZE, http_status=status)
        if inflater is None:
            chunks.append(raw)
            continue
        try:
            chunks += inflater.feed(raw)
        except zlib.error:
            corrupt = True
            break
        if inflater.over:
            break
    if inflater is not None and not corrupt and not inflater.over:
        try:
            chunks += inflater.finish()
        except zlib.error:
            corrupt = True
    # Raised outside the `except` blocks: no zlib error as `__context__`.
    if corrupt:
        raise ProviderError(ProviderErrorKind.BAD_JSON, http_status=status)
    if inflater is not None and inflater.over:
        raise ProviderError(ProviderErrorKind.OVERSIZE, http_status=status)
    return b"".join(chunks)


async def fetch_json(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    accept: Iterable[int] = (200,),
    max_bytes: int = MAX_BODY_BYTES,
    params: Mapping[str, str] | None = None,
    data: Mapping[str, str] | None = None,
    json_body: Any = None,
    headers: Mapping[str, str] | None = None,
    extensions: Mapping[str, Any] | None = None,
) -> JsonResponse:
    """One request; the body of an accepted status parsed as strict JSON.

    Unaccepted statuses raise their mapped `ProviderError` without reading the body (some
    providers echo the key in error bodies, RT11). Transport failures, timeouts (including
    the 20 s total), oversize bodies and bad JSON raise too.
    """
    accepted = frozenset(accept)
    failure: ProviderErrorKind | None = None
    try:
        async with asyncio.timeout(TOTAL_TIMEOUT_S):
            async with client.stream(
                method,
                url,
                params=params,
                data=data,
                json=json_body,
                headers=headers,
                extensions=dict(extensions) if extensions else None,
            ) as response:
                if response.status_code not in accepted:
                    raise status_error(response)
                status = response.status_code
                body = await _read_capped(response, max_bytes)
    except ProviderError:
        raise
    except (TimeoutError, httpx.TimeoutException):
        failure = ProviderErrorKind.TIMEOUT
    except (httpx.HTTPError, httpcore.ProtocolError, h11.ProtocolError, UnicodeError):
        # A protocol or encoding error may quote a header value (the key) in its message or
        # attributes (`UnicodeEncodeError.object`): mapped to a bare kind and dropped.
        failure = ProviderErrorKind.TRANSPORT
    if failure is not None:
        # Raised outside the `except` block, so neither `__cause__` nor `__context__` keeps
        # the original exception (a traceback or an error reporter never walks into it).
        raise ProviderError(failure)
    if not body.strip():
        return JsonResponse(status, None)
    return JsonResponse(status, parse_json(body))


__all__ = [
    "MAX_BODY_BYTES",
    "MISP_MAX_BODY_BYTES",
    "USER_AGENT",
    "JsonResponse",
    "KeyAuth",
    "Origin",
    "PathNotAllowed",
    "PinnedHost",
    "fetch_json",
    "json_depth_exceeds",
    "parse_json",
    "path_allowed",
    "status_error",
    "ti_client",
]
