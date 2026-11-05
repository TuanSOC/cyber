"""Anthropic adapter (M5 phase 3): the official `anthropic` SDK over the hardened `httpx2`
client of `ai.http`.

Call shape (plan "Anthropic call shape", RT2, RT10, RT19, RT24):
- `messages.stream(...)` + `get_final_message()`; `max_tokens` from the request
  (`AI_MAX_OUTPUT_TOKENS`); `system` is one text block with `cache_control: ephemeral`; one
  user message; `output_config = {format: json_schema(provider_json_schema("anthropic")),
  effort}`;
- never `temperature` / `top_p` (400 on these models), never `thinking` (adaptive is the
  default; Opus 5.5 rejects disabling it), no tools, no native citations, no `fallbacks`, no
  beta namespace;
- `max_retries=0`: the worker's limiter and resume own retries;
- an idle timer (`AI_CALL_IDLE_TIMEOUT_S`), reset by the request and by every received body
  chunk (SSE events and `ping` keep-alives, reported by `ai.http`), aborts a stalled stream,
  and `AI_CALL_TIMEOUT_S` bounds the whole call.

`stop_reason` is checked before parsing (refusal → `refused` with the open
`stop_details.category`, which may be null; `max_tokens`; `model_context_window_exceeded` →
`context_too_large`; `pause_turn` and any unknown value → `provider_error`). Errors are mapped
by SDK exception class (and the structured `error.type` of an in-stream error event), never by
message text, and re-raised without cause, context or body.
"""

import asyncio
from typing import Any, cast

import anthropic
import httpx2
from anthropic.types import Message, MessageParam, OutputConfigParam, TextBlockParam
from pydantic import SecretStr

from app.core.config import Settings
from app.modules.ai import http
from app.modules.ai.catalog import AI_CATALOG
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
    clip,
    fail,
    key_text,
    kind_for_status,
    parse_output,
    parse_retry_after,
)

SPEND_LIMIT_CODE = "enforced_spend_limit_reached"
_EFFORTS = frozenset({"low", "medium", "high", "xhigh", "max"})
# Structured `error.type` values of an in-stream SSE `error` event (HTTP status 200).
_STREAM_ERROR_KINDS = {
    "overloaded_error": ProviderErrorKind.OVERLOADED,
    "rate_limit_error": ProviderErrorKind.RATE_LIMITED,
    "authentication_error": ProviderErrorKind.AUTH_FAILED,
    "permission_error": ProviderErrorKind.AUTH_FAILED,
    "invalid_request_error": ProviderErrorKind.BAD_REQUEST,
    "request_too_large": ProviderErrorKind.CONTEXT_TOO_LARGE,
    "timeout_error": ProviderErrorKind.TIMEOUT,
}
_STOP_KINDS = {
    "max_tokens": ProviderErrorKind.MAX_TOKENS,
    "model_context_window_exceeded": ProviderErrorKind.CONTEXT_TOO_LARGE,
}
_OK_STOPS = frozenset({"end_turn", "stop_sequence"})


def _not_connected(exc: BaseException) -> bool:
    """The connection was never established: nothing reached the provider."""
    cause = exc.__cause__
    return isinstance(cause, httpx2.ConnectError | httpx2.ConnectTimeout | http.RequestNotAllowed)


def map_error(exc: BaseException, *, request_sent: bool) -> ProviderError:
    """The typed failure of an SDK / transport exception (by class, never by message)."""
    if isinstance(exc, ProviderError):
        return exc
    if isinstance(exc, anthropic.APIStatusError):
        status = exc.status_code if exc.status_code >= 400 else None
        if isinstance(exc, anthropic.RateLimitError):
            if exc.error_code == SPEND_LIMIT_CODE:
                return fail(ProviderErrorKind.SPEND_LIMIT, http_status=status, request_sent=True)
            return fail(
                ProviderErrorKind.RATE_LIMITED,
                http_status=status,
                retry_after_s=parse_retry_after(exc.response.headers.get("retry-after")),
                request_sent=True,
            )
        if isinstance(exc, anthropic.OverloadedError):
            return fail(ProviderErrorKind.OVERLOADED, http_status=status, request_sent=True)
        if isinstance(exc, anthropic.AuthenticationError | anthropic.PermissionDeniedError):
            return fail(ProviderErrorKind.AUTH_FAILED, http_status=status, request_sent=True)
        if isinstance(exc, anthropic.BadRequestError):
            return fail(ProviderErrorKind.BAD_REQUEST, http_status=status, request_sent=True)
        if status is None:
            # An SSE `error` event inside a 200 stream: its structured `error.type`.
            error_type = exc.type if isinstance(exc.type, str) else ""
            kind = _STREAM_ERROR_KINDS.get(error_type, ProviderErrorKind.PROVIDER_ERROR)
            return fail(kind, request_sent=True)
        return fail(kind_for_status(status), http_status=status, request_sent=True)
    if isinstance(exc, anthropic.APITimeoutError):
        return fail(
            ProviderErrorKind.TIMEOUT, request_sent=request_sent and not _not_connected(exc)
        )
    if isinstance(exc, anthropic.APIConnectionError):
        return fail(
            ProviderErrorKind.TRANSPORT, request_sent=request_sent and not _not_connected(exc)
        )
    if isinstance(exc, TimeoutError | httpx2.TimeoutException):
        return fail(ProviderErrorKind.TIMEOUT, request_sent=request_sent)
    if isinstance(exc, httpx2.HTTPError | http.RequestNotAllowed):
        return fail(ProviderErrorKind.TRANSPORT, request_sent=request_sent)
    # APIResponseValidationError, a malformed event stream, an SDK bug.
    return fail(ProviderErrorKind.PROVIDER_ERROR, request_sent=request_sent)


def _usage(message: Message) -> ProviderUsage:
    usage = message.usage
    return ProviderUsage(
        input_tokens=max(usage.input_tokens or 0, 0),
        output_tokens=max(usage.output_tokens or 0, 0),
        cache_read_tokens=max(usage.cache_read_input_tokens or 0, 0),
        cache_write_tokens=max(usage.cache_creation_input_tokens or 0, 0),
    )


def result_of(message: Message, request_id: str | None) -> ProviderResult:
    """The typed result of a final message: `stop_reason` first (RT19, RT24), then the JSON
    text block."""
    stop = message.stop_reason
    # The call was answered, so it was billed: every failure below carries the usage.
    usage = _usage(message)
    if stop == "refusal":
        details = message.stop_details
        category = details.category if details is not None else None
        raise fail(
            ProviderErrorKind.REFUSED, category=clip(category, 32), request_sent=True, usage=usage
        )
    if stop in _STOP_KINDS:
        raise fail(_STOP_KINDS[stop], request_sent=True, usage=usage)
    if stop not in _OK_STOPS:
        # pause_turn (server tools only; we have none), tool_use, None or a new value.
        raise fail(ProviderErrorKind.PROVIDER_ERROR, request_sent=True, usage=usage)
    text = next((block.text for block in message.content if block.type == "text"), None)
    parsed = parse_output(text, usage=usage)
    return ProviderResult(
        parsed=parsed,
        usage=usage,
        served_model=clip(message.model, 64) or "unknown",
        stop_reason=stop,
        request_id=clip(request_id, 128),
    )


class AnthropicProvider:
    """`LlmProvider` for Anthropic. The key lives only inside the SDK client; this object's
    repr names the model only."""

    name = AiProviderName.ANTHROPIC.value

    def __init__(
        self,
        *,
        api_key: SecretStr,
        model: str,
        settings: Settings,
        transport: httpx2.AsyncBaseTransport | None = None,
        allow_list_models: bool = False,
    ) -> None:
        key = key_text(api_key)
        self.model = model
        self._effort = settings.ai_anthropic_effort
        self._idle_s = float(settings.ai_call_idle_timeout_s)
        self._total_s = float(settings.ai_call_timeout_s)
        self._http = http.anthropic_client(
            settings, transport=transport, allow_list_models=allow_list_models
        )
        self._client = anthropic.AsyncAnthropic(
            api_key=key,
            base_url=http.anthropic_base_url(settings),
            max_retries=0,
            timeout=http.anthropic_timeout(settings),
            http_client=self._http,
            open_telemetry=False,
        )

    def __repr__(self) -> str:
        return f"AnthropicProvider(model={self.model!r})"

    __str__ = __repr__

    @property
    def client(self) -> anthropic.AsyncAnthropic:
        """The SDK client (for `scripts/check_ai_models.py`)."""
        return self._client

    def _model(self, request: ProviderRequest) -> str:
        if request.model not in AI_CATALOG[AiProviderName.ANTHROPIC].model_ids:
            raise fail(ProviderErrorKind.BAD_REQUEST)
        return request.model

    def _effort_of(self, request: ProviderRequest) -> Any:
        return request.effort if request.effort in _EFFORTS else self._effort

    def _shape(self, request: ProviderRequest) -> dict[str, Any]:
        """The request parameters shared by `analyze` and `count_tokens`."""
        system: list[TextBlockParam] = [
            {"type": "text", "text": request.system, "cache_control": {"type": "ephemeral"}}
        ]
        messages: list[MessageParam] = [{"role": "user", "content": request.user}]
        output_config: OutputConfigParam = {
            "format": {"type": "json_schema", "schema": provider_json_schema("anthropic")},
            "effort": self._effort_of(request),
        }
        return {
            "model": self._model(request),
            "system": system,
            "messages": messages,
            "output_config": output_config,
        }

    async def analyze(self, request: ProviderRequest) -> ProviderResult:
        params = self._shape(request)
        failure: ProviderError | None = None
        message: Message | None = None
        request_id: str | None = None
        loop = asyncio.get_running_loop()
        with http.trace_call() as trace:
            try:
                async with asyncio.timeout(self._total_s):
                    async with asyncio.timeout(self._idle_s) as idle:
                        # Every request sent and every body chunk received pushes it back.
                        trace.on_activity = lambda: idle.reschedule(loop.time() + self._idle_s)
                        try:
                            message, request_id = await self._stream(
                                params, request.max_output_tokens
                            )
                        finally:
                            trace.on_activity = None
            except Exception as exc:
                failure = map_error(exc, request_sent=trace.sent)
        if failure is not None:
            # Raised outside the `except` block: no SDK exception in `__context__`.
            raise failure
        if message is None:
            raise fail(ProviderErrorKind.PROVIDER_ERROR, request_sent=True)
        return result_of(message, request_id)

    async def _stream(self, params: dict[str, Any], max_tokens: int) -> tuple[Message, str | None]:
        async with self._client.messages.stream(max_tokens=max_tokens, **params) as stream:
            message = await stream.get_final_message()
            return cast(Message, message), stream.request_id

    async def count_tokens(self, request: ProviderRequest) -> int | None:
        params = self._shape(request)
        failure: ProviderError | None = None
        count = 0
        with http.trace_call():
            try:
                async with asyncio.timeout(self._total_s):
                    tokens = await self._client.messages.count_tokens(**params)
                count = tokens.input_tokens
            except Exception as exc:
                # Counting is free: nothing is billed whatever happened.
                failure = map_error(exc, request_sent=False)
        if failure is not None:
            failure.request_sent = False
            raise failure
        return max(int(count), 0)

    async def verify(self) -> VerifyOutcome:
        """`GET /v1/models/{model}`: proves the key and that the model is served."""
        failure: ProviderError | None = None
        not_found = False
        with http.trace_call():
            try:
                async with asyncio.timeout(self._total_s):
                    await self._client.models.retrieve(self.model)
            except anthropic.NotFoundError:
                not_found = True
            except Exception as exc:
                failure = map_error(exc, request_sent=False)
        if not_found:
            return VerifyOutcome(status=VerifyStatus.INVALID, error_code="model_not_found")
        if failure is None:
            return VerifyOutcome(status=VerifyStatus.VALID)
        if failure.kind is ProviderErrorKind.AUTH_FAILED:
            return VerifyOutcome(status=VerifyStatus.INVALID, error_code=failure.kind.value)
        return VerifyOutcome(status=VerifyStatus.ERROR, error_code=failure.kind.value)

    async def aclose(self) -> None:
        await self._client.close()
        await self._http.aclose()


__all__ = ["SPEND_LIMIT_CODE", "AnthropicProvider", "map_error", "result_of"]
