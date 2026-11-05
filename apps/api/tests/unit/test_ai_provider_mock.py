"""The `ai-mock` adapter (M5 phase 3) against the frozen wire protocol (`contracts.py`).

- every fixture of `tests/fixtures/ai/mock/` replayed through `httpx.MockTransport` behind
  the real `ai.http.mock_client`;
- an in-test stdlib stub of the wire protocol on a real socket (phase-2 independent): the
  request body and `X-Mock-Key` on the wire, the 2 MiB body cap, the total timeout;
- the key never in reprs, errors, results or logs.
"""

import asyncio
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from app.modules.ai import http
from app.modules.ai.contracts import LlmProvider, ProviderError, ProviderErrorKind, VerifyStatus
from app.modules.ai.output_schema import AnalysisOutput, provider_json_schema
from app.modules.ai.providers.mock import MockProvider
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

MODEL = "mock-1"
CASES = fixture_cases("mock")


class Replay:
    def __init__(self, response: dict[str, Any] | None = None) -> None:
        self.response = response
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/v1/count_tokens":
            return httpx.Response(200, json={"input_tokens": 321})
        if request.url.path == "/v1/verify":
            return httpx.Response(200, json={"ok": True})
        assert self.response is not None
        return httpx.Response(
            self.response["status"],
            headers=self.response.get("headers", {}),
            content=body_of(self.response),
        )


def provider_for(replay: Any, **settings: Any) -> MockProvider:
    return MockProvider(
        api_key=SecretStr(KEY),
        model=MODEL,
        settings=make_settings(**settings),
        transport=httpx.MockTransport(replay),
    )


@pytest.mark.parametrize("case", CASES)
async def test_every_fixture_maps_to_its_typed_outcome(
    case: str, caplog: pytest.LogCaptureFixture
) -> None:
    debug_logs(caplog)
    fixture = load_fixture("mock", case)
    replay = Replay(fixture["response"])
    provider = provider_for(replay)
    expect = fixture["expect"]
    try:
        if "result" in expect:
            result = await provider.analyze(make_request(MODEL))
            wanted = expect["result"]
            assert result.stop_reason == wanted["stop_reason"]
            assert result.served_model == wanted["served_model"]
            assert result.request_id == wanted["request_id"]
            assert result.usage.model_dump() == wanted["usage"]
            if wanted["schema_valid"]:
                AnalysisOutput.model_validate(result.parsed)
            else:
                with pytest.raises(ValidationError):
                    AnalysisOutput.model_validate(result.parsed)
            assert_no_key(result, result.model_dump_json())
        else:
            with pytest.raises(ProviderError) as caught:
                await provider.analyze(make_request(MODEL))
            expect_matches(caught.value, expect)
            assert_clean_error(caught.value)
    finally:
        await provider.aclose()
    # Redirects are never followed: one request per call.
    assert len(replay.requests) == 1
    assert_no_key(provider)
    assert KEY not in caplog.text


async def test_count_tokens_and_verify() -> None:
    replay = Replay()
    provider = provider_for(replay)
    try:
        assert await provider.count_tokens(make_request(MODEL)) == 321
        assert (await provider.verify()).status is VerifyStatus.VALID
    finally:
        await provider.aclose()
    assert [f"{r.method} {r.url.path}" for r in replay.requests] == [
        "POST /v1/count_tokens",
        "GET /v1/verify",
    ]


@pytest.mark.parametrize(
    ("status", "body", "expected", "code"),
    [
        (401, {"error": "auth"}, "invalid", "auth_failed"),
        (500, {"error": "internal"}, "error", "provider_error"),
        (200, {"ok": False}, "error", "provider_error"),
    ],
)
async def test_verify_outcomes(status: int, body: dict[str, Any], expected: str, code: str) -> None:
    def answer(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=body)

    provider = provider_for(answer)
    try:
        outcome = await provider.verify()
    finally:
        await provider.aclose()
    assert outcome.status.value == expected
    assert outcome.error_code == code


async def test_count_tokens_failures_are_never_billed() -> None:
    def answer(request: httpx.Request) -> httpx.Response:
        return httpx.Response(529, json={"error": "overloaded"})

    provider = provider_for(answer)
    try:
        with pytest.raises(ProviderError) as caught:
            await provider.count_tokens(make_request(MODEL))
    finally:
        await provider.aclose()
    assert caught.value.kind is ProviderErrorKind.OVERLOADED
    assert caught.value.request_sent is False


@pytest.mark.parametrize(
    ("raised", "kind", "sent"),
    [
        (httpx.ConnectError("refused"), ProviderErrorKind.TRANSPORT, False),
        (httpx.ConnectTimeout("dns"), ProviderErrorKind.TIMEOUT, False),
        (httpx.ReadTimeout("slow"), ProviderErrorKind.TIMEOUT, True),
        (httpx.RemoteProtocolError("closed"), ProviderErrorKind.TRANSPORT, True),
    ],
)
async def test_transport_failures(raised: Exception, kind: ProviderErrorKind, sent: bool) -> None:
    def fail(request: httpx.Request) -> httpx.Response:
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


async def test_an_oversize_body_is_refused() -> None:
    big = b'{"output": "' + b"x" * http.MOCK_MAX_BODY_BYTES + b'"}'

    def answer(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=big)

    provider = provider_for(answer)
    try:
        with pytest.raises(ProviderError) as caught:
            await provider.analyze(make_request(MODEL))
    finally:
        await provider.aclose()
    assert caught.value.kind is ProviderErrorKind.PROVIDER_ERROR
    assert_clean_error(caught.value)


# --- a real socket: the in-test stdlib stub of the wire protocol ----------------------------


class Stub(BaseHTTPRequestHandler):
    """Minimal ai-mock wire protocol: echoes a schema-valid answer, or stalls / oversizes on
    `stub:slow` / `stub:big` in the user text."""

    seen: list[dict[str, Any]] = []

    def _send(self, status: int, data: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length))
        Stub.seen.append({"path": self.path, "key": self.headers.get("X-Mock-Key"), "body": body})
        if self.headers.get("X-Mock-Key") != KEY:
            self._send(401, b'{"error": "auth"}')
            return
        if "stub:slow" in body["user"]:
            threading.Event().wait(3)
        if "stub:big" in body["user"]:
            self._send(200, b'{"output": "' + b"y" * (http.MOCK_MAX_BODY_BYTES + 10) + b'"}')
            return
        answer = {
            "output": {"overall_confidence": {"level": "low", "rationale": "stub"}},
            "usage": {"input_tokens": 7, "output_tokens": 3},
            "stop_reason": "end_turn",
            "model": "mock-1",
        }
        self._send(200, json.dumps(answer).encode())

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


@pytest.fixture
def stub_url() -> Iterator[str]:
    Stub.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


async def test_a_real_exchange_carries_the_protocol_body_and_the_key(stub_url: str) -> None:
    provider = MockProvider(
        api_key=SecretStr(KEY), model=MODEL, settings=make_settings(ai_mock_base_url=stub_url)
    )
    try:
        result = await provider.analyze(make_request(MODEL, max_output_tokens=999))
    finally:
        await provider.aclose()
    assert result.parsed == {"overall_confidence": {"level": "low", "rationale": "stub"}}
    assert result.usage.input_tokens == 7
    (seen,) = Stub.seen
    assert seen["path"] == "/v1/analyze"
    assert seen["key"] == KEY
    assert seen["body"] == {
        "model": MODEL,
        "system": "You are a careful DFIR analyst. Canary c4n4ry.",
        "user": "Task: summarize_pcap.\n<<D>>\n[]\n<<D>>",
        "schema": provider_json_schema("mock"),
        "max_output_tokens": 999,
    }


async def test_a_wrong_key_is_auth_failed(stub_url: str) -> None:
    provider = MockProvider(
        api_key=SecretStr("another-key-0000"),
        model=MODEL,
        settings=make_settings(ai_mock_base_url=stub_url),
    )
    try:
        with pytest.raises(ProviderError) as caught:
            await provider.analyze(make_request(MODEL))
        assert (await provider.verify()).status is VerifyStatus.ERROR
    finally:
        await provider.aclose()
    assert caught.value.kind is ProviderErrorKind.AUTH_FAILED


async def test_a_slow_mock_times_out_after_the_request_was_sent(
    stub_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(http, "MOCK_TOTAL_TIMEOUT_S", 0.5)
    provider = MockProvider(
        api_key=SecretStr(KEY), model=MODEL, settings=make_settings(ai_mock_base_url=stub_url)
    )
    try:
        with pytest.raises(ProviderError) as caught:
            await provider.analyze(make_request(MODEL, user="evidence stub:slow"))
    finally:
        await provider.aclose()
    assert caught.value.kind is ProviderErrorKind.TIMEOUT
    assert caught.value.request_sent is True
    assert_clean_error(caught.value)


async def test_an_oversize_streamed_body_is_cut(stub_url: str) -> None:
    provider = MockProvider(
        api_key=SecretStr(KEY), model=MODEL, settings=make_settings(ai_mock_base_url=stub_url)
    )
    try:
        with pytest.raises(ProviderError) as caught:
            await provider.analyze(make_request(MODEL, user="evidence stub:big"))
    finally:
        await provider.aclose()
    assert caught.value.kind is ProviderErrorKind.PROVIDER_ERROR


async def test_nothing_is_sent_to_an_unreachable_mock() -> None:
    provider = MockProvider(
        api_key=SecretStr(KEY),
        model=MODEL,
        settings=make_settings(ai_mock_base_url="http://127.0.0.1:9"),
    )
    try:
        with pytest.raises(ProviderError) as caught:
            await asyncio.wait_for(provider.analyze(make_request(MODEL)), 20)
    finally:
        await provider.aclose()
    assert caught.value.kind is ProviderErrorKind.TRANSPORT
    assert caught.value.request_sent is False


async def test_the_adapter_is_an_llm_provider_with_a_redacted_repr() -> None:
    provider = provider_for(Replay())
    try:
        assert isinstance(provider, LlmProvider)
        assert provider.name == "mock"
        assert repr(provider) == "MockProvider(model='mock-1')"
        assert_no_key(provider, vars(provider))
    finally:
        await provider.aclose()
