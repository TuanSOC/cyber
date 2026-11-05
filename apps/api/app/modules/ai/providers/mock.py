"""`ai-mock` adapter (M5 phase 3): plain `httpx` to the dev/test sink (`AI_MOCK_BASE_URL`).

The wire protocol is the frozen one in `contracts.py`. The client (`ai.http.mock_client`)
allows only `POST /v1/analyze`, `POST /v1/count_tokens` and `GET /v1/verify` on that origin,
attaches `X-Mock-Key` per request through a redacted `httpx.Auth`, has `trust_env=False`, no
redirects, a 120 s total, a 2 MiB body cap and strict JSON. Refused in prod (registry and
client).

Mapping by status, as for the vendors: 429 → `rate_limited` (`Retry-After`) or
`spend_limit` (body `{"error": "spend_limit"}`), 529 → `overloaded`, 401/403 →
`auth_failed`, 400 → `bad_request`, 5xx and any other status → `provider_error`. A 200 is
checked like a vendor answer: `stop_reason` first, then `output` (an object, or a string that
must be strict JSON; anything else → `invalid_output`, the worker's repair retry).
"""

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx
from pydantic import SecretStr

from app.core.config import Settings
from app.modules.ai import http
from app.modules.ai.contracts import (
    AiProviderName,
    ProviderError,
    ProviderErrorKind,
    ProviderRequest,
    ProviderResult,
    ProviderUsage,
    VerifyOutcome,
    VerifyStatus,
)
from app.modules.ai.output_schema import provider_json_schema
from app.modules.ai.providers.errors import (
    JsonRejected,
    clip,
    fail,
    kind_for_status,
    loads_strict,
    parse_output,
    parse_retry_after,
)

_STOP_KINDS = {
    "max_tokens": ProviderErrorKind.MAX_TOKENS,
    "model_context_window_exceeded": ProviderErrorKind.CONTEXT_TOO_LARGE,
}


@dataclass(frozen=True)
class _Reply:
    status: int
    data: Any  # the parsed JSON body; None when empty
    valid_json: bool
    retry_after: str | None


def _count(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def _status_error(reply: _Reply) -> ProviderError:
    status = reply.status
    if status == 429:
        if isinstance(reply.data, dict) and reply.data.get("error") == "spend_limit":
            return fail(ProviderErrorKind.SPEND_LIMIT, http_status=status, request_sent=True)
        return fail(
            ProviderErrorKind.RATE_LIMITED,
            http_status=status,
            retry_after_s=parse_retry_after(reply.retry_after),
            request_sent=True,
        )
    if status < 400:
        # 1xx/3xx (redirects are never followed) or a 2xx other than 200.
        return fail(ProviderErrorKind.PROVIDER_ERROR, http_status=status, request_sent=True)
    return fail(kind_for_status(status), http_status=status, request_sent=True)


class MockProvider:
    """`LlmProvider` for `ai-mock`. The key lives only in the client's redacted auth."""

    name = AiProviderName.MOCK.value

    def __init__(
        self,
        *,
        api_key: SecretStr,
        model: str,
        settings: Settings,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.model = model
        self._client = http.mock_client(settings, key=api_key, transport=transport)

    def __repr__(self) -> str:
        return f"MockProvider(model={self.model!r})"

    __str__ = __repr__

    @staticmethod
    def _body(request: ProviderRequest) -> dict[str, Any]:
        return {
            "model": request.model,
            "system": request.system,
            "user": request.user,
            "schema": provider_json_schema("mock"),
            "max_output_tokens": request.max_output_tokens,
        }

    async def _call(self, method: str, path: str, body: dict[str, Any] | None) -> _Reply:
        """One exchange. Raises `ProviderError` only, never with a context."""
        failure: ProviderError | None = None
        reply: _Reply | None = None
        with http.trace_call() as trace:
            try:
                async with asyncio.timeout(http.MOCK_TOTAL_TIMEOUT_S):
                    async with self._client.stream(method, path, json=body) as response:
                        raw = await http.read_capped(response)
                        status = response.status_code
                        retry_after = response.headers.get("retry-after")
                data: Any = None
                valid = True
                if raw.strip():
                    try:
                        data = loads_strict(raw)
                    except JsonRejected:
                        valid = False
                reply = _Reply(status, data, valid, retry_after)
            except http.BodyTooLarge:
                failure = fail(ProviderErrorKind.PROVIDER_ERROR, request_sent=True)
            except (TimeoutError, httpx.TimeoutException) as exc:
                sent = trace.sent and not isinstance(exc, httpx.ConnectTimeout)
                failure = fail(ProviderErrorKind.TIMEOUT, request_sent=sent)
            except (httpx.ConnectError, http.RequestNotAllowed):
                failure = fail(ProviderErrorKind.TRANSPORT, request_sent=False)
            except (httpx.HTTPError, UnicodeError):
                # A protocol or encoding error may quote a header value (the key).
                failure = fail(ProviderErrorKind.TRANSPORT, request_sent=trace.sent)
        if failure is not None:
            raise failure
        if reply is None:
            raise fail(ProviderErrorKind.PROVIDER_ERROR, request_sent=True)
        return reply

    async def analyze(self, request: ProviderRequest) -> ProviderResult:
        reply = await self._call("POST", "/v1/analyze", self._body(request))
        if reply.status != 200:
            raise _status_error(reply)
        data = reply.data
        if not reply.valid_json or not isinstance(data, dict):
            # A 200 whose body is not a JSON object: the answer is unusable (repairable).
            raise fail(ProviderErrorKind.INVALID_OUTPUT, request_sent=True)
        raw_usage = data.get("usage")
        counts = raw_usage if isinstance(raw_usage, dict) else {}
        # The mock answered, so a failure below is "billed" like a vendor's: carry the usage.
        usage = ProviderUsage(
            input_tokens=_count(counts.get("input_tokens")),
            output_tokens=_count(counts.get("output_tokens")),
        )
        stop = data.get("stop_reason")
        if stop == "refusal":
            category = clip(data.get("refusal_category"), 32)
            raise fail(ProviderErrorKind.REFUSED, category=category, request_sent=True, usage=usage)
        if isinstance(stop, str) and stop in _STOP_KINDS:
            raise fail(_STOP_KINDS[stop], request_sent=True, usage=usage)
        if stop != "end_turn":
            raise fail(ProviderErrorKind.PROVIDER_ERROR, request_sent=True, usage=usage)
        output = data.get("output")
        if isinstance(output, dict):
            parsed: dict[str, Any] = output
        else:
            parsed = parse_output(output if isinstance(output, str) else None, usage=usage)
        return ProviderResult(
            parsed=parsed,
            usage=usage,
            served_model=clip(data.get("model"), 64) or request.model,
            stop_reason="end_turn",
        )

    async def count_tokens(self, request: ProviderRequest) -> int | None:
        failure: ProviderError | None = None
        tokens: object = None
        try:
            reply = await self._call("POST", "/v1/count_tokens", self._body(request))
            if reply.status != 200:
                failure = _status_error(reply)
            elif isinstance(reply.data, dict):
                tokens = reply.data.get("input_tokens")
        except ProviderError as exc:
            failure = exc
        if failure is None:
            if isinstance(tokens, int) and not isinstance(tokens, bool) and tokens >= 0:
                return tokens
            failure = fail(ProviderErrorKind.PROVIDER_ERROR)
        failure.request_sent = False  # counting is never billed
        raise failure

    async def verify(self) -> VerifyOutcome:
        try:
            reply = await self._call("GET", "/v1/verify", None)
        except ProviderError as exc:
            return VerifyOutcome(status=VerifyStatus.ERROR, error_code=exc.kind.value)
        if reply.status == 200 and isinstance(reply.data, dict) and reply.data.get("ok") is True:
            return VerifyOutcome(status=VerifyStatus.VALID)
        kind = _status_error(reply).kind if reply.status != 200 else None
        if kind is ProviderErrorKind.AUTH_FAILED:
            return VerifyOutcome(status=VerifyStatus.INVALID, error_code=kind.value)
        code = (kind or ProviderErrorKind.PROVIDER_ERROR).value
        return VerifyOutcome(status=VerifyStatus.ERROR, error_code=code)

    async def aclose(self) -> None:
        await self._client.aclose()


__all__ = ["MockProvider"]
