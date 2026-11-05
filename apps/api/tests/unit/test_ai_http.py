"""The egress clients of the AI adapters (`app/modules/ai/http.py`) and the shared adapter
helpers (`providers/errors.py`), M5 phase 3.

- every client: `trust_env=False`, no redirects, and a request hook that allows only the
  documented method + path shapes on one origin, before anything is sent;
- the test-only base URL overrides apply outside prod only, and the mock is refused in prod;
- `KeyAuth` keeps the mock key out of reprs and `client.headers`;
- `trace_call` marks a call as sent only once a request passed the hook;
- strict JSON, `Retry-After` / protobuf durations, the body cap.

The replay helpers at the bottom are shared by the adapter test modules.
"""

import json
import logging
import traceback
from collections.abc import AsyncIterator, Callable, Iterable
from pathlib import Path
from typing import Any

import httpx
import httpx2
import pytest
from pydantic import SecretStr

from app.core.config import Settings
from app.modules.ai import http
from app.modules.ai.contracts import ProviderError, ProviderErrorKind, ProviderRequest
from app.modules.ai.providers import errors
from tests.ai_helpers import AI_SENTINEL_KEY

KEY = AI_SENTINEL_KEY
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "ai"
BASE: dict[str, Any] = {
    "database_url": "postgresql+asyncpg://cyberlab_app:s3cret@postgres/cyberlab",
    "redis_url": "redis://redis:6379/0",
    "jwt_secret": "x" * 48,
    "minio_endpoint": "minio:9000",
    "minio_access_key": "cyberlab-api",
    "minio_secret_key": "s3cret-minio",
    "broker_url": "redis://redis-broker:6379/1",
}
AI_DEFAULTS: dict[str, Any] = {
    "env": "test",
    "ai_enabled": True,
    "ai_mock_enabled": True,
    "ai_mock_base_url": "http://ai-mock:8080",
    "gemini_billing_enabled": False,
    "ai_anthropic_base_url": None,
    "ai_gemini_base_url": None,
    "ai_anthropic_effort": "medium",
    "ai_call_timeout_s": 300,
    "ai_call_idle_timeout_s": 60,
    "ai_platform_key_file": None,
    "ai_platform_provider": None,
}
SDK_LOGGERS = ("anthropic", "httpx", "httpcore", "httpx2", "httpcore2", "google_genai")


def make_settings(**overrides: Any) -> Settings:
    return Settings(**BASE, **{**AI_DEFAULTS, **overrides})


def prod(settings: Settings) -> Settings:
    """A prod view of `settings` (the prod validators would refuse the dev-only values)."""
    return settings.model_copy(update={"env": "prod"})


# --- allowlists ----------------------------------------------------------------------------


def _hook(client: httpx.AsyncClient | httpx2.AsyncClient) -> Callable[[Any], Any]:
    hooks = client.event_hooks["request"]
    assert len(hooks) == 1
    return hooks[0]


async def _passes(client: httpx.AsyncClient | httpx2.AsyncClient, method: str, url: str) -> bool:
    lib = httpx2 if isinstance(client, httpx2.AsyncClient) else httpx
    try:
        await _hook(client)(lib.Request(method, url))
    except http.RequestNotAllowed:
        return False
    return True


ANTHROPIC_OK = [
    ("POST", "https://api.anthropic.com/v1/messages"),
    ("POST", "https://api.anthropic.com/v1/messages/count_tokens"),
    ("GET", "https://api.anthropic.com/v1/models/claude-sonnet-5"),
    ("GET", "https://api.anthropic.com:443/v1/models/claude-opus-5-5"),
    ("POST", "https://api.anthropic.com/v1/messages?stream=true"),
]
ANTHROPIC_REFUSED = [
    ("GET", "https://api.anthropic.com/v1/messages"),
    ("POST", "https://api.anthropic.com/v1/messages/batches"),
    ("POST", "https://api.anthropic.com/v1/complete"),
    ("GET", "https://api.anthropic.com/v1/models"),
    ("GET", "https://api.anthropic.com/v1/models/../files"),
    ("GET", "https://api.anthropic.com/v1/models/a%2Fb"),
    ("POST", "http://api.anthropic.com/v1/messages"),
    ("POST", "https://api.anthropic.com:8443/v1/messages"),
    ("POST", "https://api.anthropic.com.evil.example/v1/messages"),
    ("POST", "https://evil.example/v1/messages"),
    ("DELETE", "https://api.anthropic.com/v1/models/claude-sonnet-5"),
]


@pytest.mark.parametrize(("method", "url"), ANTHROPIC_OK)
async def test_anthropic_client_allows_the_documented_calls(method: str, url: str) -> None:
    client = http.anthropic_client(make_settings())
    try:
        assert await _passes(client, method, url)
    finally:
        await client.aclose()


@pytest.mark.parametrize(("method", "url"), ANTHROPIC_REFUSED)
async def test_anthropic_client_refuses_everything_else(method: str, url: str) -> None:
    client = http.anthropic_client(make_settings())
    try:
        assert not await _passes(client, method, url)
    finally:
        await client.aclose()


async def test_the_models_list_is_allowed_for_the_check_script_only() -> None:
    client = http.anthropic_client(make_settings(), allow_list_models=True)
    gclient = http.gemini_client(make_settings(), allow_list_models=True)
    try:
        assert await _passes(client, "GET", "https://api.anthropic.com/v1/models?limit=100")
        assert await _passes(
            gclient, "GET", "https://generativelanguage.googleapis.com/v1beta/models?pageSize=50"
        )
    finally:
        await client.aclose()
        await gclient.aclose()


GEMINI = "https://generativelanguage.googleapis.com"


@pytest.mark.parametrize(
    ("method", "url", "ok"),
    [
        ("POST", f"{GEMINI}/v1beta/models/gemini-3.8-flash:generateContent", True),
        ("GET", f"{GEMINI}/v1beta/models/gemini-3.8-flash", True),
        ("POST", f"{GEMINI}/v1beta/models/gemini-3.8-flash:streamGenerateContent", False),
        ("POST", f"{GEMINI}/v1beta/models/gemini-3.8-flash:countTokens", False),
        ("POST", f"{GEMINI}/v1beta/interactions", False),
        ("POST", f"{GEMINI}/upload/v1beta/files", False),
        ("GET", f"{GEMINI}/v1beta/models", False),
        ("POST", f"{GEMINI}/v1/models/gemini-3.8-flash:generateContent", False),
        (
            "POST",
            "https://generativelanguage.mtls.googleapis.com/v1beta/models/x:generateContent",
            False,
        ),
        ("POST", "http://generativelanguage.googleapis.com/v1beta/models/x:generateContent", False),
    ],
)
async def test_gemini_client_allowlist(method: str, url: str, ok: bool) -> None:
    client = http.gemini_client(make_settings())
    try:
        assert await _passes(client, method, url) is ok
    finally:
        await client.aclose()


@pytest.mark.parametrize(
    ("method", "path", "ok"),
    [
        ("POST", "/v1/analyze", True),
        ("POST", "/v1/count_tokens", True),
        ("GET", "/v1/verify", True),
        ("GET", "/_last", False),
        ("GET", "/health", False),
        ("GET", "/v1/analyze", False),
        ("POST", "/v1/verify", False),
    ],
)
async def test_mock_client_allowlist(method: str, path: str, ok: bool) -> None:
    client = http.mock_client(make_settings(), key=SecretStr(KEY))
    try:
        assert await _passes(client, method, f"http://ai-mock:8080{path}") is ok
        assert not await _passes(client, method, f"http://ai-mock:8081{path}")
        assert not await _passes(client, method, f"https://ai-mock{path}")
        assert not await _passes(client, method, f"http://evil.example:8080{path}")
    finally:
        await client.aclose()


async def test_every_client_ignores_the_environment_and_redirects() -> None:
    settings = make_settings()
    clients: list[httpx.AsyncClient | httpx2.AsyncClient] = [
        http.anthropic_client(settings),
        http.gemini_client(settings),
        http.mock_client(settings, key=SecretStr(KEY)),
    ]
    try:
        for client in clients:
            assert client.trust_env is False
            assert client.follow_redirects is False
    finally:
        for client in clients:
            await client.aclose()


async def test_base_url_overrides_apply_outside_prod_only() -> None:
    settings = make_settings(
        ai_anthropic_base_url="http://replay:8080", ai_gemini_base_url="http://replay:8081/"
    )
    assert http.anthropic_base_url(settings) == "http://replay:8080"
    assert http.gemini_base_url(settings) == "http://replay:8081"
    client = http.anthropic_client(settings)
    try:
        assert await _passes(client, "POST", "http://replay:8080/v1/messages")
        assert not await _passes(client, "POST", "https://api.anthropic.com/v1/messages")
    finally:
        await client.aclose()
    assert http.anthropic_base_url(prod(settings)) == http.ANTHROPIC_BASE_URL
    assert http.gemini_base_url(prod(settings)) == http.GEMINI_BASE_URL
    vendor = http.anthropic_client(prod(settings))
    try:
        # The vendor origin is https only, whatever the override said.
        assert not await _passes(vendor, "POST", "http://api.anthropic.com/v1/messages")
        assert await _passes(vendor, "POST", "https://api.anthropic.com/v1/messages")
    finally:
        await vendor.aclose()


@pytest.mark.parametrize(
    "url", ["http://replay:8080/prefix", "http://user:pw@replay:8080", "ftp://replay", "http://"]
)
def test_bad_base_urls_are_refused(url: str) -> None:
    with pytest.raises(ValueError, match="bad AI provider base URL"):
        http.anthropic_client(make_settings(ai_anthropic_base_url=url))


def test_the_mock_client_is_refused_in_prod() -> None:
    with pytest.raises(errors.ProviderUnavailable) as caught:
        http.mock_client(prod(make_settings()), key=SecretStr(KEY))
    assert caught.value.reason == "prod_mock"


async def test_key_auth_is_redacted_and_never_a_client_header() -> None:
    client = http.mock_client(make_settings(), key=SecretStr(KEY))
    try:
        assert KEY not in repr(client.auth)
        assert KEY not in str(client.auth)
        assert all(KEY not in value for value in client.headers.values())
        assert KEY not in repr(client.headers)
        request = client.build_request("GET", "/v1/verify")
        flow = client.auth.sync_auth_flow(request)  # type: ignore[union-attr]
        assert next(flow).headers[http.MOCK_KEY_HEADER] == KEY
    finally:
        await client.aclose()


@pytest.mark.parametrize("key", ["", "short", "bad key with spaces\n", "é" * 20, " padded-key-1 "])
def test_unsafe_keys_are_refused_without_quoting_them(key: str) -> None:
    with pytest.raises(ProviderError) as caught:
        http.KeyAuth(SecretStr(key))
    assert caught.value.kind is ProviderErrorKind.AUTH_FAILED
    assert key.strip() == "" or key.strip() not in str(caught.value)


async def test_trace_call_marks_only_requests_that_passed_the_guard() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={})

    client = http.anthropic_client(make_settings(), transport=httpx2.MockTransport(handler))
    try:
        with http.trace_call() as refused:
            with pytest.raises(http.RequestNotAllowed):
                await client.get("https://evil.example/v1/messages")
        assert refused.sent is False
        with http.trace_call() as sent:
            await client.post("https://api.anthropic.com/v1/messages", json={})
        assert sent.sent is True
        # Outside a trace nothing is recorded (and nothing fails).
        await client.post("https://api.anthropic.com/v1/messages", json={})
    finally:
        await client.aclose()


def test_the_blocked_sync_client_refuses_every_request() -> None:
    client = http.blocked_sync_client()
    try:
        assert client.trust_env is False
        with pytest.raises(http.RequestNotAllowed):
            client.get("https://generativelanguage.googleapis.com/v1beta/models")
    finally:
        client.close()


async def test_read_capped_refuses_oversize_and_encoded_bodies() -> None:
    small = httpx.Response(200, content=b"x" * 10)
    assert await http.read_capped(small, 10) == b"x" * 10
    with pytest.raises(http.BodyTooLarge):
        await http.read_capped(httpx.Response(200, content=b"x" * 11), 10)
    with pytest.raises(http.BodyTooLarge):
        await http.read_capped(httpx.Response(200, headers={"content-length": "999"}), 10)
    with pytest.raises(http.BodyTooLarge):
        await http.read_capped(
            httpx.Response(200, headers={"content-encoding": "br"}, content=b"{}"), 10
        )

    class Chunks(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            for _ in range(4):
                yield b"y" * 4

    with pytest.raises(http.BodyTooLarge):
        await http.read_capped(httpx.Response(200, stream=Chunks()), 10)
    assert await http.read_capped(httpx.Response(200, stream=Chunks()), 16) == b"y" * 16


# --- errors.py helpers ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("", None),
        ("17", 17.0),
        ("0.5", 0.5),
        ("-3", 0.0),
        ("999999", 3600.0),
        ("nan", None),
        ("inf", None),
        ("soon", None),
        ("Wed, 21 Oct 2015 07:28:00 GMT", 0.0),
        ("x" * 100, None),
    ],
)
def test_parse_retry_after(value: str | None, expected: float | None) -> None:
    assert errors.parse_retry_after(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [("31s", 31.0), ("1.5s", 1.5), ("0s", 0.0), ("99999s", 3600.0), ("31", None), (31, None)],
)
def test_parse_duration(value: object, expected: float | None) -> None:
    assert errors.parse_duration(value) == expected


@pytest.mark.parametrize(
    "text",
    [
        "[" * 65 + "]" * 65,
        '{"a": NaN}',
        '{"a": Infinity}',
        '{"a": ' + "9" * 41 + "}",
        "{'a': 1}",
        "",
        b"\xff\xfe",
    ],
)
def test_loads_strict_refuses(text: str | bytes) -> None:
    with pytest.raises(errors.JsonRejected) as caught:
        errors.loads_strict(text)
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_loads_strict_accepts_normal_json_and_strings_with_brackets() -> None:
    assert errors.loads_strict('{"a": "[[[[{{{{", "b": [1, 2.5]}') == {
        "a": "[[[[{{{{",
        "b": [1, 2.5],
    }
    assert errors.loads_strict("[" * 64 + "]" * 64) is not None


@pytest.mark.parametrize("text", [None, "", "  ", "[1, 2]", '"text"', "{bad", '{"a": NaN}'])
def test_parse_output_wants_one_json_object(text: str | None) -> None:
    with pytest.raises(ProviderError) as caught:
        errors.parse_output(text)
    assert caught.value.kind is ProviderErrorKind.INVALID_OUTPUT
    assert caught.value.request_sent is True
    assert caught.value.__context__ is None


@pytest.mark.parametrize(
    ("status", "kind"),
    [
        (429, ProviderErrorKind.RATE_LIMITED),
        (529, ProviderErrorKind.OVERLOADED),
        (401, ProviderErrorKind.AUTH_FAILED),
        (403, ProviderErrorKind.AUTH_FAILED),
        (413, ProviderErrorKind.CONTEXT_TOO_LARGE),
        (400, ProviderErrorKind.BAD_REQUEST),
        (404, ProviderErrorKind.BAD_REQUEST),
        (500, ProviderErrorKind.PROVIDER_ERROR),
        (503, ProviderErrorKind.PROVIDER_ERROR),
    ],
)
def test_kind_for_status(status: int, kind: ProviderErrorKind) -> None:
    assert errors.kind_for_status(status) is kind


def test_clip_keeps_printable_short_strings() -> None:
    assert errors.clip("cyber", 32) == "cyber"
    assert errors.clip("a‮b\x00c" * 20, 5) == "abcab"
    assert errors.clip(None, 5) is None
    assert errors.clip(17, 5) is None


# --- shared replay helpers (imported by the adapter test modules) ---------------------------


def load_fixture(provider: str, case: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(
        (FIXTURES / provider / f"{case}.json").read_text(encoding="utf-8")
    )
    return data


def fixture_cases(provider: str) -> list[str]:
    return sorted(p.stem for p in (FIXTURES / provider).glob("*.json"))


def body_of(response: dict[str, Any]) -> bytes:
    """The response body of a fixture (`sse` events, `json` or raw `text`); `{{KEY}}` is the
    sentinel key (a provider echoing the key in an error body)."""
    if "sse" in response:
        text = "".join(
            f"event: {event['type']}\ndata: {json.dumps(event)}\n\n" for event in response["sse"]
        )
    elif "json" in response:
        text = json.dumps(response["json"])
    else:
        text = response.get("text", "")
    return text.replace("{{KEY}}", KEY).encode()


def make_request(model: str, **overrides: Any) -> ProviderRequest:
    values: dict[str, Any] = {
        "model": model,
        "system": "You are a careful DFIR analyst. Canary c4n4ry.",
        "user": "Task: summarize_pcap.\n<<D>>\n[]\n<<D>>",
        "output_schema": {"type": "object"},
        "max_output_tokens": 16000,
        **overrides,
    }
    return ProviderRequest(**values)


def assert_no_key(*values: object) -> None:
    for value in values:
        assert KEY not in repr(value)
        assert KEY not in str(value)


def assert_clean_error(error: ProviderError) -> None:
    """No key, no cause or context chain, a fixed message (the kind)."""
    assert error.__cause__ is None
    assert error.__context__ is None
    assert str(error) == error.kind.value
    assert_no_key(error, error.args, vars(error))
    assert KEY not in "".join(traceback.format_exception(error))


def debug_logs(caplog: pytest.LogCaptureFixture) -> None:
    """Capture everything, SDK debug logs included (they must not carry the key either)."""
    caplog.set_level(logging.DEBUG)
    for name in SDK_LOGGERS:
        caplog.set_level(logging.DEBUG, logger=name)


def expect_matches(error: ProviderError, expect: dict[str, Any]) -> None:
    assert error.kind.value == expect["kind"]
    for field in ("category", "http_status", "retry_after_s", "request_sent"):
        if field in expect:
            assert getattr(error, field) == expect[field], field
    # A 200 that ends in a failure was billed: its usage rides on the error (`usage`);
    # HTTP-level failures without a response body carry none.
    assert "usage" in expect
    usage = error.usage.model_dump() if error.usage is not None else None
    assert usage == expect["usage"]


def paths(requests: Iterable[Any]) -> list[str]:
    return [f"{r.method} {r.url.path}" for r in requests]
