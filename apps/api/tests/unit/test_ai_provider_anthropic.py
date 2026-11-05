"""The Anthropic adapter against every replay fixture of `tests/fixtures/ai/anthropic/`
(M5 phase 3).

The fixtures (SSE event streams and JSON error bodies, hand-written from the documented
shapes) replay at the transport: `httpx2.MockTransport` behind the real `ai.http`
client and the real `AsyncAnthropic`, so the request shape is asserted on the wire:
- streamed `POST /v1/messages` only, with `output_config.format` (the Anthropic provider
  schema) and `effort`, a cached system block, one user message, `max_tokens`;
- never `temperature`, `top_p`, `tools`, `thinking`, `fallbacks`, a beta header or query;
- the key only in the auth header, never in reprs, errors, results or (debug) logs.
Plus the idle and total timeouts (RT2), the error mapping of transport failures, and
`count_tokens` / `verify`.
"""

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import anthropic
import httpx2
import pytest
from pydantic import SecretStr, ValidationError

from app.modules.ai.contracts import (
    LlmProvider,
    ProviderError,
    ProviderErrorKind,
    VerifyStatus,
)
from app.modules.ai.output_schema import AnalysisOutput, provider_json_schema
from app.modules.ai.providers.anthropic import AnthropicProvider, map_error
from tests.unit.test_ai_http import (
    KEY,
    assert_clean_error,
    assert_no_key,
    body_of,
    debug_logs,
    expect_matches,
    fixture_cases,
    load_fixture,
    make_request,
    make_settings,
)

MODEL = "claude-sonnet-5"
CASES = fixture_cases("anthropic")
FORBIDDEN_PARAMS = {
    "temperature",
    "top_p",
    "top_k",
    "tools",
    "tool_choice",
    "thinking",
    "fallbacks",
    "fallback",
    "stop_sequences",
    "container",
}


class Replay:
    """Records the requests and answers each with a fixture (or a callable)."""

    def __init__(self, response: dict[str, Any] | None = None) -> None:
        self.response = response
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        path = request.url.path
        if path.endswith("/count_tokens"):
            return httpx2.Response(200, json={"input_tokens": 2048})
        if path.startswith("/v1/models/"):
            return httpx2.Response(
                200,
                json={
                    "type": "model",
                    "id": path.rsplit("/", 1)[-1],
                    "display_name": "Claude",
                    "created_at": "2026-01-01T00:00:00Z",
                    "lifecycle": "active",
                },
            )
        assert self.response is not None
        return httpx2.Response(
            self.response["status"],
            headers=self.response.get("headers", {}),
            content=body_of(self.response),
        )


def provider_for(replay: Any, **settings: Any) -> AnthropicProvider:
    return AnthropicProvider(
        api_key=SecretStr(KEY),
        model=MODEL,
        settings=make_settings(**settings),
        transport=httpx2.MockTransport(replay),
    )


@pytest.mark.parametrize("case", CASES)
async def test_every_fixture_maps_to_its_typed_outcome(
    case: str, caplog: pytest.LogCaptureFixture
) -> None:
    debug_logs(caplog)
    fixture = load_fixture("anthropic", case)
    replay = Replay(fixture["response"])
    provider = provider_for(replay)
    model = MODEL if "opus" not in json.dumps(fixture["expect"]) else "claude-opus-5-5"
    expect = fixture["expect"]
    try:
        if "result" in expect:
            result = await provider.analyze(make_request(model))
            wanted = expect["result"]
            assert result.stop_reason == wanted["stop_reason"]
            assert result.served_model == wanted["served_model"]
            assert result.request_id == wanted["request_id"]
            assert result.usage.model_dump() == wanted["usage"]
            assert result.refusal_category is None
            if wanted["schema_valid"]:
                AnalysisOutput.model_validate(result.parsed)
            else:
                # Parsed JSON is returned; the worker's re-validation rejects it.
                with pytest.raises(ValidationError):
                    AnalysisOutput.model_validate(result.parsed)
            assert_no_key(result, result.model_dump_json())
        else:
            with pytest.raises(ProviderError) as caught:
                await provider.analyze(make_request(model))
            expect_matches(caught.value, expect)
            assert_clean_error(caught.value)
    finally:
        await provider.aclose()
    assert len(replay.requests) == 1
    assert_no_key(provider, provider.client, provider._http)
    assert KEY not in caplog.text


async def test_the_request_shape_on_the_wire() -> None:
    replay = Replay(load_fixture("anthropic", "ok")["response"])
    provider = provider_for(replay, ai_anthropic_effort="high")
    try:
        await provider.analyze(make_request(MODEL, max_output_tokens=12345))
    finally:
        await provider.aclose()
    (request,) = replay.requests
    assert request.method == "POST"
    assert str(request.url) == "https://api.anthropic.com/v1/messages"
    body = json.loads(request.content)
    assert FORBIDDEN_PARAMS.isdisjoint(body)
    assert body["model"] == MODEL
    assert body["stream"] is True
    assert body["max_tokens"] == 12345
    assert body["system"] == [
        {
            "type": "text",
            "text": "You are a careful DFIR analyst. Canary c4n4ry.",
            "cache_control": {"type": "ephemeral"},
        }
    ]
    assert body["messages"] == [
        {"role": "user", "content": "Task: summarize_pcap.\n<<D>>\n[]\n<<D>>"}
    ]
    assert body["output_config"] == {
        "format": {"type": "json_schema", "schema": provider_json_schema("anthropic")},
        "effort": "high",
    }
    headers = {k.lower(): v for k, v in request.headers.items()}
    assert not any(k.startswith("anthropic-beta") for k in headers)
    assert "beta" not in request.url.query.decode()
    # The key travels only in the auth header.
    holders = [k for k, v in headers.items() if KEY in v]
    assert holders in (["authorization"], ["x-api-key"])
    assert KEY not in str(request.url)
    assert KEY.encode() not in request.content


async def test_a_request_effort_overrides_the_setting() -> None:
    replay = Replay(load_fixture("anthropic", "ok")["response"])
    provider = provider_for(replay)
    try:
        await provider.analyze(make_request(MODEL, effort="low"))
        await provider.analyze(make_request(MODEL, effort="bogus"))
    finally:
        await provider.aclose()
    efforts = [json.loads(r.content)["output_config"]["effort"] for r in replay.requests]
    assert efforts == ["low", "medium"]


@pytest.mark.parametrize("model", ["claude-sonnet-5-5", "claude-opus-4-8", "", "mock-1"])
async def test_a_model_outside_the_allowlist_is_never_sent(model: str) -> None:
    replay = Replay(load_fixture("anthropic", "ok")["response"])
    provider = provider_for(replay)
    try:
        with pytest.raises(ProviderError) as caught:
            await provider.analyze(make_request(model))
        assert caught.value.kind is ProviderErrorKind.BAD_REQUEST
        assert caught.value.request_sent is False
    finally:
        await provider.aclose()
    assert replay.requests == []


class StallingStream(httpx2.AsyncByteStream):
    """Sends `message_start` and then nothing (a stalled stream)."""

    def __init__(self, first: bytes, stall_s: float) -> None:
        self.first = first
        self.stall_s = stall_s

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.first
        await asyncio.sleep(self.stall_s)
        yield b""


async def test_the_idle_timer_aborts_a_stalled_stream() -> None:
    events = load_fixture("anthropic", "ok")["response"]["sse"]
    first = f"event: message_start\ndata: {json.dumps(events[0])}\n\n".encode()

    def stall(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=StallingStream(first, 30),
        )

    provider = provider_for(stall, ai_call_idle_timeout_s=1)
    loop = asyncio.get_running_loop()
    started = loop.time()
    try:
        with pytest.raises(ProviderError) as caught:
            await provider.analyze(make_request(MODEL))
    finally:
        await provider.aclose()
    assert loop.time() - started < 10
    assert caught.value.kind is ProviderErrorKind.TIMEOUT
    assert caught.value.request_sent is True
    assert_clean_error(caught.value)


async def test_ping_keep_alives_reset_the_idle_timer() -> None:
    """A long adaptive-thinking pause carries only `ping` events, which the SDK drops: the
    idle timer must still see them (byte-level activity), or a healthy call would abort."""
    events = load_fixture("anthropic", "ok")["response"]["sse"]
    head = f"event: message_start\ndata: {json.dumps(events[0])}\n\n".encode()
    rest = "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events[1:])
    ping = b'event: ping\ndata: {"type": "ping"}\n\n'

    class KeepAlive(httpx2.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield head
            for _ in range(6):  # 2.4 s of pings only, with a 1 s idle timeout
                await asyncio.sleep(0.4)
                yield ping
            yield rest.encode()

    def answer(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200, headers={"content-type": "text/event-stream"}, stream=KeepAlive()
        )

    provider = provider_for(answer, ai_call_idle_timeout_s=1)
    try:
        result = await provider.analyze(make_request(MODEL))
    finally:
        await provider.aclose()
    assert result.stop_reason == "end_turn"


async def test_the_total_timeout_bounds_a_slow_but_alive_stream() -> None:
    events = load_fixture("anthropic", "ok")["response"]["sse"]
    body = "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events)

    class Drip(httpx2.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            for line in body.splitlines(keepends=True):
                await asyncio.sleep(0.2)
                yield line.encode()

    def drip(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, headers={"content-type": "text/event-stream"}, stream=Drip())

    provider = provider_for(drip, ai_call_idle_timeout_s=5)
    provider._total_s = 0.5
    try:
        with pytest.raises(ProviderError) as caught:
            await provider.analyze(make_request(MODEL))
    finally:
        await provider.aclose()
    assert caught.value.kind is ProviderErrorKind.TIMEOUT
    assert caught.value.request_sent is True


@pytest.mark.parametrize(
    ("raised", "kind", "sent"),
    [
        (httpx2.ConnectError("refused"), ProviderErrorKind.TRANSPORT, False),
        (httpx2.ConnectTimeout("slow dns"), ProviderErrorKind.TIMEOUT, False),
        (httpx2.ReadTimeout("idle"), ProviderErrorKind.TIMEOUT, True),
        (httpx2.RemoteProtocolError("peer closed"), ProviderErrorKind.TRANSPORT, True),
    ],
)
async def test_transport_failures(raised: Exception, kind: ProviderErrorKind, sent: bool) -> None:
    def fail(request: httpx2.Request) -> httpx2.Response:
        raise raised

    provider = provider_for(fail)
    try:
        with pytest.raises(ProviderError) as caught:
            await provider.analyze(make_request(MODEL))
    finally:
        await provider.aclose()
    assert caught.value.kind is kind
    assert caught.value.request_sent is sent
    assert_clean_error(caught.value)


async def test_a_request_outside_the_allowlist_never_leaves() -> None:
    replay = Replay(load_fixture("anthropic", "ok")["response"])
    provider = provider_for(replay)
    try:
        with pytest.raises(anthropic.APIConnectionError):
            # Bypassing the adapter: the client hook still refuses the beta namespace.
            await provider.client.post("/v1/messages/batches", cast_to=object, body={})
    finally:
        await provider.aclose()
    assert replay.requests == []
    mapped = map_error(
        anthropic.APIConnectionError(request=httpx2.Request("POST", "https://x")),
        request_sent=True,
    )
    assert mapped.kind is ProviderErrorKind.TRANSPORT


async def test_count_tokens_uses_the_same_shape_and_is_never_billed() -> None:
    replay = Replay()
    provider = provider_for(replay)
    try:
        assert await provider.count_tokens(make_request(MODEL)) == 2048
    finally:
        await provider.aclose()
    (request,) = replay.requests
    assert request.url.path == "/v1/messages/count_tokens"
    body = json.loads(request.content)
    assert FORBIDDEN_PARAMS.isdisjoint(body)
    assert body["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert body["output_config"]["format"]["schema"] == provider_json_schema("anthropic")
    assert "max_tokens" not in body and "stream" not in body

    limited = load_fixture("anthropic", "rate_limited_retry_after")["response"]

    def answer_429(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(429, headers=limited["headers"], content=body_of(limited))

    provider = provider_for(answer_429)
    try:
        with pytest.raises(ProviderError) as caught:
            await provider.count_tokens(make_request(MODEL))
    finally:
        await provider.aclose()
    assert caught.value.kind is ProviderErrorKind.RATE_LIMITED
    assert caught.value.request_sent is False


async def test_verify_retrieves_the_model() -> None:
    replay = Replay()
    provider = provider_for(replay)
    try:
        outcome = await provider.verify()
    finally:
        await provider.aclose()
    assert outcome.status is VerifyStatus.VALID
    assert [f"{r.method} {r.url.path}" for r in replay.requests] == [f"GET /v1/models/{MODEL}"]


@pytest.mark.parametrize(
    ("status", "body", "expected", "code"),
    [
        (
            401,
            {"type": "error", "error": {"type": "authentication_error"}},
            "invalid",
            "auth_failed",
        ),
        (403, {"type": "error", "error": {"type": "permission_error"}}, "invalid", "auth_failed"),
        (
            404,
            {"type": "error", "error": {"type": "not_found_error"}},
            "invalid",
            "model_not_found",
        ),
        (529, {"type": "error", "error": {"type": "overloaded_error"}}, "error", "overloaded"),
        (500, {"type": "error", "error": {"type": "api_error"}}, "error", "provider_error"),
    ],
)
async def test_verify_outcomes(status: int, body: dict[str, Any], expected: str, code: str) -> None:
    def answer(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(status, json=body)

    provider = provider_for(answer)
    try:
        outcome = await provider.verify()
    finally:
        await provider.aclose()
    assert outcome.status.value == expected
    assert outcome.error_code == code


async def test_the_adapter_is_an_llm_provider_with_a_redacted_repr() -> None:
    provider = provider_for(Replay())
    try:
        assert isinstance(provider, LlmProvider)
        assert provider.name == "anthropic"
        assert repr(provider) == "AnthropicProvider(model='claude-sonnet-5')"
        assert_no_key(provider, provider.client, provider._http, vars(provider).keys())
    finally:
        await provider.aclose()


def test_an_unsafe_key_is_refused_at_construction() -> None:
    with pytest.raises(ProviderError) as caught:
        AnthropicProvider(api_key=SecretStr("bad key\n"), model=MODEL, settings=make_settings())
    assert caught.value.kind is ProviderErrorKind.AUTH_FAILED
