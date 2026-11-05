"""Egress HTTP clients of the LLM provider adapters (analyst worker only; import guard).

Cloned in spirit from `threat_intel/http.py` (never imported: the analyst may not import TI
modules). One client factory per provider:
- `anthropic_client()`: an `httpx2.AsyncClient` (the `anthropic` SDK's transport package,
  RT20) for `AsyncAnthropic(http_client=...)`;
- `gemini_client()`: an `httpx.AsyncClient` for `google-genai`
  (`HttpOptions.httpx_async_client`), plus `blocked_sync_client()` for the SDK's unused sync
  slot, which refuses every request;
- `mock_client()`: an `httpx.AsyncClient` to `ai-mock` (dev/test only, refused in prod), with
  the key attached per request by `KeyAuth`.

Every client has `trust_env=False` (no proxy, netrc or CA bundle from the environment),
`follow_redirects=False`, TLS verification on, bounded timeouts, and a request event hook that
allows only the provider's documented method + path shapes on exactly one origin (`https:443`
of the vendor host; the dev/test base URL override only outside prod). Paths are matched in
their percent-encoded form without the query string. A refused request raises
`RequestNotAllowed` before anything is sent. Tests pass `httpx2.MockTransport` /
`httpx.MockTransport` to the same factories, so fixture replays run through the real hooks.

`trace_call()` records, per call (a context variable), whether a request passed the hook and
was handed to the transport: `ProviderError.request_sent` (a timeout after that point may have
been billed, RT2). The Anthropic client also reports every received body chunk to the trace
(`on_activity`), so the adapter's idle timer is reset by any byte of the stream, SSE `ping`
keep-alives included (the SDK drops pings before its events reach the caller, and a long
adaptive-thinking pause may carry nothing else).

Nothing here logs a header, a body or a key; the `httpx`/`httpcore`/`httpx2`/`httpcore2`,
`anthropic` and `google_genai` loggers are set to WARNING.
"""

import logging
import re
from collections.abc import AsyncIterator, Callable, Generator, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Protocol, cast

import httpx
import httpx2
from pydantic import SecretStr

from app.core.config import Settings
from app.modules.ai.providers.errors import ProviderUnavailable, key_text

for _name in ("httpx", "httpcore", "httpx2", "httpcore2", "anthropic", "google_genai"):
    logging.getLogger(_name).setLevel(logging.WARNING)

VERSION = "0.1"
USER_AGENT = f"CyberLab-AI/{VERSION}"
ANTHROPIC_BASE_URL = "https://api.anthropic.com"
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com"
GEMINI_API_VERSION = "v1beta"
MOCK_TOTAL_TIMEOUT_S = 120.0
MOCK_MAX_BODY_BYTES = 2 * 1024 * 1024
MOCK_KEY_HEADER = "X-Mock-Key"
_DEFAULT_PORTS = {"https": 443, "http": 80}
_MODEL_ID = r"[A-Za-z0-9._-]{1,64}"


class RequestNotAllowed(Exception):
    """A request outside the client's allowlist (a bug or a hostile redirect), never sent."""

    def __init__(self) -> None:
        super().__init__("request_not_allowed")


# --- per-call trace ------------------------------------------------------------------------


@dataclass
class CallTrace:
    sent: bool = False
    # Called on every request sent and every response chunk received (the idle timer).
    on_activity: Callable[[], None] | None = None

    def touch(self) -> None:
        if self.on_activity is not None:
            self.on_activity()


_TRACE: ContextVar[CallTrace | None] = ContextVar("ai_call_trace", default=None)


@contextmanager
def trace_call() -> Iterator[CallTrace]:
    """Records whether a request of this call reached the transport (`trace.sent`)."""
    trace = CallTrace()
    token = _TRACE.set(trace)
    try:
        yield trace
    finally:
        _TRACE.reset(token)


def _mark_sent() -> None:
    trace = _TRACE.get()
    if trace is not None:
        trace.sent = True
        trace.touch()


def _touch() -> None:
    trace = _TRACE.get()
    if trace is not None:
        trace.touch()


class _ActivityStream(httpx2.AsyncByteStream):
    """A response body that reports each received chunk to the current call trace."""

    def __init__(self, inner: httpx2.AsyncByteStream) -> None:
        self._inner = inner

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._inner:
            _touch()
            yield chunk

    async def aclose(self) -> None:
        await self._inner.aclose()


async def _watch_body(response: httpx2.Response) -> None:
    _touch()
    response.stream = _ActivityStream(cast(httpx2.AsyncByteStream, response.stream))


# --- allowlist -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Origin:
    scheme: str
    host: str
    port: int | None


class _Url(Protocol):
    @property
    def scheme(self) -> str: ...

    @property
    def raw_host(self) -> bytes: ...

    @property
    def port(self) -> int | None: ...

    @property
    def raw_path(self) -> bytes: ...


def origin_of(url: _Url) -> Origin:
    scheme = url.scheme.lower()
    port = url.port if url.port is not None else _DEFAULT_PORTS.get(scheme)
    return Origin(scheme, url.raw_host.decode("ascii", errors="replace").lower(), port)


def encoded_path(url: _Url) -> str:
    return url.raw_path.split(b"?", 1)[0].decode("ascii", errors="replace")


@dataclass(frozen=True)
class Route:
    method: str
    path: re.Pattern[str]

    @classmethod
    def of(cls, method: str, path: str) -> "Route":
        return cls(method, re.compile(path))

    def matches(self, method: str, path: str) -> bool:
        return method == self.method and self.path.fullmatch(path) is not None


ANTHROPIC_ROUTES = (
    Route.of("POST", r"/v1/messages"),
    Route.of("POST", r"/v1/messages/count_tokens"),
    Route.of("GET", rf"/v1/models/{_MODEL_ID}"),
)
ANTHROPIC_LIST_ROUTE = Route.of("GET", r"/v1/models")
GEMINI_ROUTES = (
    Route.of("POST", rf"/{GEMINI_API_VERSION}/models/{_MODEL_ID}:generateContent"),
    Route.of("GET", rf"/{GEMINI_API_VERSION}/models/{_MODEL_ID}"),
)
GEMINI_LIST_ROUTE = Route.of("GET", rf"/{GEMINI_API_VERSION}/models")
MOCK_ROUTES = (
    Route.of("POST", r"/v1/analyze"),
    Route.of("POST", r"/v1/count_tokens"),
    Route.of("GET", r"/v1/verify"),
)


def allowed(method: str, url: _Url, origin: Origin, routes: tuple[Route, ...]) -> bool:
    if origin_of(url) != origin:
        return False
    path = encoded_path(url)
    return any(route.matches(method.upper(), path) for route in routes)


def _base_origin(url: str, *, allow_http: bool) -> Origin:
    """The origin of a base URL with no path, query or credentials."""
    parsed = httpx.URL(url)
    origin = origin_of(parsed)
    ok = (
        origin.scheme == "https" or (allow_http and origin.scheme == "http")
    ) and origin.host != ""
    if not ok or parsed.raw_path not in (b"", b"/") or parsed.userinfo or parsed.query:
        raise ValueError("bad AI provider base URL")
    return origin


def anthropic_base_url(settings: Settings) -> str:
    """The vendor URL, or the test-only `AI_ANTHROPIC_BASE_URL` (refused in prod)."""
    if settings.ai_anthropic_base_url and settings.env != "prod":
        return settings.ai_anthropic_base_url.rstrip("/")
    return ANTHROPIC_BASE_URL


def gemini_base_url(settings: Settings) -> str:
    """The vendor URL, or the test-only `AI_GEMINI_BASE_URL` (refused in prod)."""
    if settings.ai_gemini_base_url and settings.env != "prod":
        return settings.ai_gemini_base_url.rstrip("/")
    return GEMINI_BASE_URL


def mock_base_url(settings: Settings) -> str:
    if settings.env == "prod":
        raise ProviderUnavailable("prod_mock")
    return settings.ai_mock_base_url.rstrip("/")


# --- clients -------------------------------------------------------------------------------


def anthropic_client(
    settings: Settings,
    *,
    transport: httpx2.AsyncBaseTransport | None = None,
    allow_list_models: bool = False,
) -> httpx2.AsyncClient:
    """The `httpx2` client for `AsyncAnthropic`. Read timeout = the idle timeout
    (`AI_CALL_IDLE_TIMEOUT_S`): a stalled stream fails at the transport too. The SDK sets
    the key header itself (`X-Api-Key`); this client never holds it."""
    base = anthropic_base_url(settings)
    origin = _base_origin(base, allow_http=base != ANTHROPIC_BASE_URL)
    routes = ANTHROPIC_ROUTES + ((ANTHROPIC_LIST_ROUTE,) if allow_list_models else ())

    async def guard(request: httpx2.Request) -> None:
        if not allowed(request.method, request.url, origin, routes):
            raise RequestNotAllowed()
        _mark_sent()

    return httpx2.AsyncClient(
        transport=transport,
        trust_env=False,
        follow_redirects=False,
        verify=True,
        timeout=anthropic_timeout(settings),
        limits=httpx2.Limits(max_connections=4, max_keepalive_connections=2),
        headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"},
        event_hooks={"request": [guard], "response": [_watch_body]},
    )


def anthropic_timeout(settings: Settings) -> httpx2.Timeout:
    return httpx2.Timeout(
        connect=10.0, read=float(settings.ai_call_idle_timeout_s), write=30.0, pool=10.0
    )


def gemini_client(
    settings: Settings,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    allow_list_models: bool = False,
) -> httpx.AsyncClient:
    """The `httpx` client for `google-genai` (not streamed: the read timeout is the call
    timeout). The SDK sets the key header itself (`x-goog-api-key`)."""
    base = gemini_base_url(settings)
    origin = _base_origin(base, allow_http=base != GEMINI_BASE_URL)
    routes = GEMINI_ROUTES + ((GEMINI_LIST_ROUTE,) if allow_list_models else ())

    async def guard(request: httpx.Request) -> None:
        if not allowed(request.method, request.url, origin, routes):
            raise RequestNotAllowed()
        _mark_sent()

    return httpx.AsyncClient(
        transport=transport,
        trust_env=False,
        follow_redirects=False,
        verify=True,
        timeout=httpx.Timeout(
            connect=10.0, read=float(settings.ai_call_timeout_s), write=30.0, pool=10.0
        ),
        limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
        headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"},
        event_hooks={"request": [guard]},
    )


class _RefuseAll(httpx.BaseTransport):
    def handle_request(self, request: httpx.Request) -> httpx.Response:
        raise RequestNotAllowed()


def blocked_sync_client() -> httpx.Client:
    """`google-genai` builds a sync client too; the adapter never uses it, and it refuses
    every request instead of reaching the network with environment settings."""
    return httpx.Client(transport=_RefuseAll(), trust_env=False, follow_redirects=False)


class KeyAuth(httpx.Auth):
    """Adds `X-Mock-Key` per request. Never in `client.headers` (httpx masks only
    `Authorization` in header reprs); its repr is redacted; an unsafe key is refused here
    (`auth_failed`) without quoting it."""

    requires_request_body = False
    requires_response_body = False

    def __init__(self, key: SecretStr, header: str = MOCK_KEY_HEADER) -> None:
        key_text(key)
        self._header = header
        self._key = key

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers[self._header] = self._key.get_secret_value()
        yield request

    def __repr__(self) -> str:
        return f"KeyAuth(header={self._header!r}, key=***)"

    __str__ = __repr__


def mock_client(
    settings: Settings,
    *,
    key: SecretStr,
    transport: httpx.AsyncBaseTransport | None = None,
) -> httpx.AsyncClient:
    """The `ai-mock` client (`AI_MOCK_BASE_URL`, plain http allowed; refused in prod)."""
    base = mock_base_url(settings)
    origin = _base_origin(base, allow_http=True)

    async def guard(request: httpx.Request) -> None:
        if not allowed(request.method, request.url, origin, MOCK_ROUTES):
            raise RequestNotAllowed()
        _mark_sent()

    return httpx.AsyncClient(
        base_url=base,
        auth=KeyAuth(key),
        transport=transport,
        trust_env=False,
        follow_redirects=False,
        verify=True,
        timeout=httpx.Timeout(connect=5.0, read=MOCK_TOTAL_TIMEOUT_S, write=30.0, pool=5.0),
        limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        },
        event_hooks={"request": [guard]},
    )


class BodyTooLarge(Exception):
    def __init__(self) -> None:
        super().__init__("body_too_large")


async def read_capped(response: httpx.Response, max_bytes: int = MOCK_MAX_BODY_BYTES) -> bytes:
    """The identity-coded body under `max_bytes` (`BodyTooLarge` otherwise; any content
    coding is refused too: we asked for identity)."""
    declared = response.headers.get("content-length", "").strip()
    if declared.isascii() and declared.isdigit() and int(declared) > max_bytes:
        raise BodyTooLarge()
    coding = response.headers.get("content-encoding", "").strip().lower()
    if coding not in ("", "identity"):
        raise BodyTooLarge()
    if response.is_stream_consumed:
        # An in-memory response (`httpx.MockTransport`) was read when it was built.
        if len(response.content) > max_bytes:
            raise BodyTooLarge()
        return response.content
    chunks: list[bytes] = []
    size = 0
    async for raw in response.aiter_raw():
        size += len(raw)
        if size > max_bytes:
            raise BodyTooLarge()
        chunks.append(raw)
    return b"".join(chunks)


__all__ = [
    "ANTHROPIC_BASE_URL",
    "GEMINI_API_VERSION",
    "GEMINI_BASE_URL",
    "MOCK_MAX_BODY_BYTES",
    "MOCK_TOTAL_TIMEOUT_S",
    "USER_AGENT",
    "BodyTooLarge",
    "CallTrace",
    "KeyAuth",
    "Origin",
    "RequestNotAllowed",
    "Route",
    "allowed",
    "anthropic_base_url",
    "anthropic_client",
    "anthropic_timeout",
    "blocked_sync_client",
    "gemini_base_url",
    "gemini_client",
    "mock_base_url",
    "mock_client",
    "read_capped",
    "trace_call",
]
