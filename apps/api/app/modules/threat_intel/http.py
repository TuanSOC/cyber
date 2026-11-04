"""The hardened provider HTTP client (enrich worker only; see the import guard test).

One `httpx.AsyncClient` per provider and slice:
- `trust_env=False` (no proxy, netrc or CA env from the environment), `follow_redirects=False`,
  `verify=True`; timeouts 3 s connect / 10 s read and 20 s for the whole exchange; a fixed
  `User-Agent`;
- the key is attached per request by `KeyAuth`, an `httpx.Auth` whose `repr` is redacted. It is
  never put in `client.headers`: httpx masks only `Authorization` in header reprs (RT11);
- every request must match one of the adapter's `allowed_paths` (checked by a request event
  hook before anything is sent; `PathNotAllowed` otherwise). Paths are matched in their
  percent-encoded form, without the query string;
- `fetch_json` streams the body under a byte cap (1 MiB, MISP 2 MiB), never reads an error
  body, and maps every failure to a `ProviderError` kind. JSON is parsed with a nesting-depth
  limit (CPython's `json` accepts thousands of levels), an integer-digit limit and no
  `NaN`/`Infinity` (RT19).

Nothing here logs a header, a body or a key; the `httpx`/`httpcore` loggers are set to WARNING.
"""

import asyncio
import json
import logging
import math
import re
from collections.abc import Generator, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx
from pydantic import SecretStr

from app.modules.threat_intel.providers.base import (
    AllowedPath,
    Provider,
    ProviderError,
    ProviderErrorKind,
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


class KeyAuth(httpx.Auth):
    """Adds the provider key header to each outgoing request. Its repr never shows the key."""

    requires_request_body = False
    requires_response_body = False

    def __init__(self, header: str, key: SecretStr) -> None:
        if not _HEADER_NAME.fullmatch(header):
            raise ValueError("bad auth header name")
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


def encoded_path(url: httpx.URL) -> str:
    return url.raw_path.split(b"?", 1)[0].decode("ascii", errors="replace")


def path_allowed(
    request: httpx.Request,
    allowed: Iterable[AllowedPath],
    *,
    org_host: str | None = None,
    pinned: PinnedHost | None = None,
) -> bool:
    host = request.url.host
    if pinned is not None and host == pinned.address:
        # A pinned request is allowed as the hostname it carries in `Host` (and SNI).
        header_host = request.headers.get("host", "").split(":")[0].lower()
        host = pinned.hostname if header_host == pinned.hostname else ""
    path = encoded_path(request.url)
    for entry in allowed:
        if entry.host is None and (org_host is None or host != org_host):
            continue
        if entry.matches(request.method, host, path):
            return True
    return False


def ti_client(
    provider: Provider,
    *,
    auth: httpx.Auth | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    org_host: str | None = None,
    pinned: PinnedHost | None = None,
    verify: Any = True,
) -> httpx.AsyncClient:
    """A client bound to `provider.allowed_paths`. `org_host` is the MISP host that
    `AllowedPath(host=None)` entries refer to."""
    allowed = tuple(provider.allowed_paths)

    async def guard(request: httpx.Request) -> None:
        if not path_allowed(request, allowed, org_host=org_host, pinned=pinned):
            raise PathNotAllowed()

    return httpx.AsyncClient(
        auth=auth,
        transport=transport,
        trust_env=False,
        follow_redirects=False,
        verify=verify,
        timeout=TIMEOUT,
        limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
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


async def _read_capped(response: httpx.Response, max_bytes: int) -> bytes:
    declared = response.headers.get("content-length")
    if declared is not None and declared.strip().isdigit() and int(declared) > max_bytes:
        raise ProviderError(ProviderErrorKind.OVERSIZE, http_status=response.status_code)
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        size += len(chunk)
        if size > max_bytes:
            raise ProviderError(ProviderErrorKind.OVERSIZE, http_status=response.status_code)
        chunks.append(chunk)
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
        raise ProviderError(ProviderErrorKind.TIMEOUT) from None
    except httpx.HTTPError:
        raise ProviderError(ProviderErrorKind.TRANSPORT) from None
    if not body.strip():
        return JsonResponse(status, None)
    return JsonResponse(status, parse_json(body))


__all__ = [
    "MAX_BODY_BYTES",
    "MISP_MAX_BODY_BYTES",
    "USER_AGENT",
    "JsonResponse",
    "KeyAuth",
    "PathNotAllowed",
    "PinnedHost",
    "fetch_json",
    "json_depth_exceeds",
    "parse_json",
    "path_allowed",
    "status_error",
    "ti_client",
]
