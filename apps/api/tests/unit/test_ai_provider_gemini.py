"""The Gemini adapter against every replay fixture of `tests/fixtures/ai/gemini/` (M5 phase 3).

The fixtures (`generateContent` JSON and `google.rpc` error bodies, hand-written from the
documented shapes) replay at the transport: `httpx.MockTransport` behind the real `ai.http`
client and the real `google-genai` client. Asserted on the wire: one
`POST /v1beta/models/{model}:generateContent` with the system instruction, the JSON MIME
type, the Gemini provider schema and `maxOutputTokens`; no tools, no sampling parameters, no
safety overrides; the key only in `x-goog-api-key`.
"""

import json
from typing import Any

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from app.modules.ai.contracts import LlmProvider, ProviderError, ProviderErrorKind, VerifyStatus
from app.modules.ai.output_schema import AnalysisOutput, provider_json_schema
from app.modules.ai.providers.gemini import GeminiProvider
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

MODEL = "gemini-3.8-flash"
CASES = fixture_cases("gemini")
GENERATE = f"/v1beta/models/{MODEL}:generateContent"


class Replay:
    def __init__(self, response: dict[str, Any] | None = None) -> None:
        self.response = response
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "name": f"models/{MODEL}",
                    "displayName": "Gemini",
                    "inputTokenLimit": 1048576,
                    "outputTokenLimit": 65536,
                },
            )
        assert self.response is not None
        return httpx.Response(
            self.response["status"],
            headers=self.response.get("headers", {}),
            content=body_of(self.response),
        )


def provider_for(replay: Any, **settings: Any) -> GeminiProvider:
    return GeminiProvider(
        api_key=SecretStr(KEY),
        model=MODEL,
        settings=make_settings(gemini_billing_enabled=True, **settings),
        transport=httpx.MockTransport(replay),
    )


@pytest.mark.parametrize("case", CASES)
async def test_every_fixture_maps_to_its_typed_outcome(
    case: str, caplog: pytest.LogCaptureFixture
) -> None:
    debug_logs(caplog)
    fixture = load_fixture("gemini", case)
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
    # No SDK retry: exactly one request per call, whatever the status.
    assert len(replay.requests) == 1
    assert_no_key(provider, provider.client, provider._http)
    assert KEY not in caplog.text


async def test_the_request_shape_on_the_wire() -> None:
    replay = Replay(load_fixture("gemini", "ok")["response"])
    provider = provider_for(replay)
    try:
        await provider.analyze(make_request(MODEL, max_output_tokens=4096))
    finally:
        await provider.aclose()
    (request,) = replay.requests
    assert request.method == "POST"
    assert str(request.url) == f"https://generativelanguage.googleapis.com{GENERATE}"
    body = json.loads(request.content)
    assert set(body) == {"contents", "systemInstruction", "generationConfig"}
    assert body["generationConfig"] == {
        "maxOutputTokens": 4096,
        "responseMimeType": "application/json",
        "responseJsonSchema": provider_json_schema("gemini"),
    }
    assert body["systemInstruction"]["parts"] == [
        {"text": "You are a careful DFIR analyst. Canary c4n4ry."}
    ]
    assert body["contents"] == [
        {"role": "user", "parts": [{"text": "Task: summarize_pcap.\n<<D>>\n[]\n<<D>>"}]}
    ]
    headers = {k.lower(): v for k, v in request.headers.items()}
    assert [k for k, v in headers.items() if KEY in v] == ["x-goog-api-key"]
    assert KEY not in str(request.url)
    assert KEY.encode() not in request.content


@pytest.mark.parametrize("model", ["gemini-2.0-flash", "claude-sonnet-5", ""])
async def test_a_model_outside_the_allowlist_is_never_sent(model: str) -> None:
    replay = Replay(load_fixture("gemini", "ok")["response"])
    provider = provider_for(replay)
    try:
        with pytest.raises(ProviderError) as caught:
            await provider.analyze(make_request(model))
    finally:
        await provider.aclose()
    assert caught.value.kind is ProviderErrorKind.BAD_REQUEST
    assert replay.requests == []


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


async def test_count_tokens_is_not_used() -> None:
    replay = Replay()
    provider = provider_for(replay)
    try:
        assert await provider.count_tokens(make_request(MODEL)) is None
    finally:
        await provider.aclose()
    assert replay.requests == []


async def test_verify_gets_the_model() -> None:
    replay = Replay()
    provider = provider_for(replay)
    try:
        outcome = await provider.verify()
    finally:
        await provider.aclose()
    assert outcome.status is VerifyStatus.VALID
    assert [f"{r.method} {r.url.path}" for r in replay.requests] == [f"GET /v1beta/models/{MODEL}"]


@pytest.mark.parametrize(
    ("case", "expected", "code"),
    [
        ("auth_api_key_invalid", "invalid", "auth_failed"),
        ("permission_403", "invalid", "auth_failed"),
        ("rate_limited_no_hint", "error", "rate_limited"),
        ("server_500", "error", "provider_error"),
    ],
)
async def test_verify_outcomes(case: str, expected: str, code: str) -> None:
    response = load_fixture("gemini", case)["response"]

    def answer(request: httpx.Request) -> httpx.Response:
        return httpx.Response(response["status"], content=body_of(response))

    provider = provider_for(answer)
    try:
        outcome = await provider.verify()
    finally:
        await provider.aclose()
    assert outcome.status.value == expected
    assert outcome.error_code == code


async def test_verify_unknown_model() -> None:
    def answer(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404, json={"error": {"code": 404, "message": "not found", "status": "NOT_FOUND"}}
        )

    provider = provider_for(answer)
    try:
        outcome = await provider.verify()
    finally:
        await provider.aclose()
    assert outcome.status is VerifyStatus.INVALID
    assert outcome.error_code == "model_not_found"


async def test_environment_variables_cannot_redirect_the_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GOOGLE_GEMINI_BASE_URL", "https://evil.example/")
    monkeypatch.setenv("GOOGLE_GENAI_USE_VERTEXAI", "true")
    monkeypatch.setenv("GOOGLE_API_KEY", "env-key-must-not-be-used-0000")
    replay = Replay(load_fixture("gemini", "ok")["response"])
    provider = provider_for(replay)
    try:
        await provider.analyze(make_request(MODEL))
    finally:
        await provider.aclose()
    (request,) = replay.requests
    assert request.url.host == "generativelanguage.googleapis.com"
    assert request.headers["x-goog-api-key"] == KEY


async def test_the_adapter_is_an_llm_provider_with_a_redacted_repr() -> None:
    provider = provider_for(Replay())
    try:
        assert isinstance(provider, LlmProvider)
        assert provider.name == "gemini"
        assert repr(provider) == "GeminiProvider(model='gemini-3.8-flash')"
        assert_no_key(provider, provider.client, provider._http)
    finally:
        await provider.aclose()
