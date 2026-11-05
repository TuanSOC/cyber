"""Gemini adapter (M5 phase 3): `google-genai` (`client.aio.models.generate_content`) over the
hardened `httpx` client of `ai.http`.

- `config`: `system_instruction`, `response_mime_type="application/json"`,
  `response_json_schema=provider_json_schema("gemini")`, `max_output_tokens`; safety settings
  left at their defaults; no tools; the SDK's retries off (`retry_options=None`, the worker
  owns retries); `vertexai=False` and an explicit base URL, so no environment variable can
  redirect the call.
- Not streamed: the call is bounded by `AI_CALL_TIMEOUT_S` (transport read timeout and an
  asyncio total).
- Gated: the registry builds it only with `GEMINI_BILLING_ENABLED=true` (RT5; the per-org
  paid-tier attestation is checked by the routes and the worker).

Mapping (by HTTP status and the structured `error.status` / `google.rpc.ErrorInfo.reason`,
never by message text):
- 429 → `rate_limited` (`RetryInfo.retryDelay`, else `Retry-After`, else no hint: the worker
  backs off);
- 400 whose `ErrorInfo.reason` names a safety / prohibited-content block → `refused`;
  `API_KEY_INVALID` (Gemini answers 400 for a bad key) → `auth_failed`; other 400 →
  `bad_request`;
- 401 / 403 → `auth_failed`; 404 → `bad_request`; 503 → `overloaded`; 504 → `timeout`;
  other 5xx → `provider_error`;
- a 200 with `promptFeedback.blockReason`, or a candidate `finishReason` of SAFETY,
  PROHIBITED_CONTENT, BLOCKLIST, SPII or another block → `refused` (category = the reason,
  lower-cased); `MAX_TOKENS` → `max_tokens`; any other non-STOP reason → `provider_error`.
`count_tokens` returns None (the worker uses the context estimator).
"""

import asyncio
from typing import Any

import httpx
from google import genai
from google.genai import errors as genai_errors
from google.genai import types
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
    parse_duration,
    parse_output,
    parse_retry_after,
)

_REFUSAL_REASONS = frozenset(
    {
        "SAFETY",
        "PROHIBITED_CONTENT",
        "BLOCKLIST",
        "SPII",
        "IMAGE_SAFETY",
        "IMAGE_PROHIBITED_CONTENT",
    }
)
_AUTH_REASONS = frozenset({"API_KEY_INVALID", "API_KEY_SERVICE_BLOCKED", "PERMISSION_DENIED"})
_BLOCK_WORDS = ("SAFETY", "PROHIBITED", "BLOCK")
_RETRY_INFO = "type.googleapis.com/google.rpc.RetryInfo"
_ERROR_INFO = "type.googleapis.com/google.rpc.ErrorInfo"


def _enum_name(value: object) -> str | None:
    if value is None:
        return None
    raw = getattr(value, "value", value)
    return raw.upper() if isinstance(raw, str) else None


def _error_details(exc: genai_errors.APIError) -> list[dict[str, Any]]:
    body = exc.details
    error = body.get("error", body) if isinstance(body, dict) else None
    details = error.get("details") if isinstance(error, dict) else None
    if not isinstance(details, list):
        return []
    return [d for d in details if isinstance(d, dict)]


def _retry_after(exc: genai_errors.APIError) -> float | None:
    for detail in _error_details(exc):
        if detail.get("@type") == _RETRY_INFO:
            delay = parse_duration(detail.get("retryDelay"))
            if delay is not None:
                return delay
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", None)
    value = headers.get("retry-after") if headers is not None else None
    return parse_retry_after(value if isinstance(value, str) else None)


def _reasons(exc: genai_errors.APIError) -> list[str]:
    return [
        d["reason"].upper()
        for d in _error_details(exc)
        if d.get("@type") == _ERROR_INFO and isinstance(d.get("reason"), str)
    ]


def map_api_error(exc: genai_errors.APIError) -> ProviderError:
    code = exc.code if isinstance(exc.code, int) else 0
    status = code or None
    if code == 429:
        return fail(
            ProviderErrorKind.RATE_LIMITED,
            http_status=status,
            retry_after_s=_retry_after(exc),
            request_sent=True,
        )
    if code == 400:
        reasons = _reasons(exc)
        if any(r in _AUTH_REASONS for r in reasons):
            return fail(ProviderErrorKind.AUTH_FAILED, http_status=status, request_sent=True)
        blocked = next((r for r in reasons if any(w in r for w in _BLOCK_WORDS)), None)
        if blocked is not None:
            return fail(
                ProviderErrorKind.REFUSED,
                http_status=status,
                category=clip(blocked.lower(), 32),
                request_sent=True,
            )
        return fail(ProviderErrorKind.BAD_REQUEST, http_status=status, request_sent=True)
    if code == 503:
        return fail(ProviderErrorKind.OVERLOADED, http_status=status, request_sent=True)
    if code == 504:
        return fail(ProviderErrorKind.TIMEOUT, http_status=status, request_sent=True)
    if code == 404:
        return fail(ProviderErrorKind.BAD_REQUEST, http_status=status, request_sent=True)
    if code < 400:
        return fail(ProviderErrorKind.PROVIDER_ERROR, http_status=status, request_sent=True)
    return fail(kind_for_status(code), http_status=status, request_sent=True)


def map_error(exc: BaseException, *, request_sent: bool) -> ProviderError:
    if isinstance(exc, ProviderError):
        return exc
    if isinstance(exc, genai_errors.APIError):
        return map_api_error(exc)
    if isinstance(exc, TimeoutError | httpx.TimeoutException):
        not_connected = isinstance(exc, httpx.ConnectTimeout)
        return fail(ProviderErrorKind.TIMEOUT, request_sent=request_sent and not not_connected)
    if isinstance(exc, httpx.ConnectError | http.RequestNotAllowed):
        return fail(ProviderErrorKind.TRANSPORT, request_sent=False)
    if isinstance(exc, httpx.HTTPError):
        return fail(ProviderErrorKind.TRANSPORT, request_sent=request_sent)
    return fail(ProviderErrorKind.PROVIDER_ERROR, request_sent=request_sent)


def _usage(response: types.GenerateContentResponse) -> ProviderUsage:
    meta = response.usage_metadata
    if meta is None:
        return ProviderUsage()
    prompt = max(meta.prompt_token_count or 0, 0)
    cached = min(max(meta.cached_content_token_count or 0, 0), prompt)
    output = max(meta.candidates_token_count or 0, 0) + max(meta.thoughts_token_count or 0, 0)
    return ProviderUsage(
        input_tokens=prompt - cached, output_tokens=output, cache_read_tokens=cached
    )


def result_of(response: types.GenerateContentResponse, model: str) -> ProviderResult:
    # A 200 was billed (a blocked prompt still counts its input): failures carry the usage.
    usage = _usage(response)
    feedback = response.prompt_feedback
    blocked = _enum_name(feedback.block_reason) if feedback is not None else None
    if blocked and blocked != "BLOCKED_REASON_UNSPECIFIED":
        category = clip(blocked.lower(), 32)
        raise fail(ProviderErrorKind.REFUSED, category=category, request_sent=True, usage=usage)
    candidates = response.candidates or []
    if not candidates:
        raise fail(ProviderErrorKind.PROVIDER_ERROR, request_sent=True, usage=usage)
    candidate = candidates[0]
    reason = _enum_name(candidate.finish_reason) or "STOP"
    if reason == "MAX_TOKENS":
        raise fail(ProviderErrorKind.MAX_TOKENS, request_sent=True, usage=usage)
    if reason in _REFUSAL_REASONS:
        category = clip(reason.lower(), 32)
        raise fail(ProviderErrorKind.REFUSED, category=category, request_sent=True, usage=usage)
    if reason != "STOP":
        raise fail(ProviderErrorKind.PROVIDER_ERROR, request_sent=True, usage=usage)
    parts = candidate.content.parts if candidate.content is not None else None
    texts = [p.text for p in parts or [] if p.text is not None and not p.thought]
    parsed = parse_output("".join(texts) if texts else None, usage=usage)
    return ProviderResult(
        parsed=parsed,
        usage=usage,
        served_model=clip(response.model_version, 64) or model,
        stop_reason="stop",
        request_id=clip(response.response_id, 128),
    )


class GeminiProvider:
    """`LlmProvider` for Gemini. The key lives only inside the SDK client."""

    name = AiProviderName.GEMINI.value

    def __init__(
        self,
        *,
        api_key: SecretStr,
        model: str,
        settings: Settings,
        transport: httpx.AsyncBaseTransport | None = None,
        allow_list_models: bool = False,
    ) -> None:
        key = key_text(api_key)
        self.model = model
        self._total_s = float(settings.ai_call_timeout_s)
        self._http = http.gemini_client(
            settings, transport=transport, allow_list_models=allow_list_models
        )
        self._sync = http.blocked_sync_client()
        self._client = genai.Client(
            vertexai=False,
            api_key=key,
            http_options=types.HttpOptions(
                base_url=http.gemini_base_url(settings) + "/",
                api_version=http.GEMINI_API_VERSION,
                timeout=int(self._total_s * 1000),
                retry_options=None,
                httpx_async_client=self._http,
                httpx_client=self._sync,
            ),
        )

    def __repr__(self) -> str:
        return f"GeminiProvider(model={self.model!r})"

    __str__ = __repr__

    @property
    def client(self) -> genai.Client:
        """The SDK client (for `scripts/check_ai_models.py`)."""
        return self._client

    def _model(self, request: ProviderRequest) -> str:
        if request.model not in AI_CATALOG[AiProviderName.GEMINI].model_ids:
            raise fail(ProviderErrorKind.BAD_REQUEST)
        return request.model

    async def analyze(self, request: ProviderRequest) -> ProviderResult:
        model = self._model(request)
        config = types.GenerateContentConfig(
            system_instruction=request.system,
            response_mime_type="application/json",
            response_json_schema=provider_json_schema("gemini"),
            max_output_tokens=request.max_output_tokens,
        )
        failure: ProviderError | None = None
        response: types.GenerateContentResponse | None = None
        with http.trace_call() as trace:
            try:
                async with asyncio.timeout(self._total_s):
                    response = await self._client.aio.models.generate_content(
                        model=model, contents=request.user, config=config
                    )
            except Exception as exc:
                failure = map_error(exc, request_sent=trace.sent)
        if failure is not None:
            raise failure
        if response is None:
            raise fail(ProviderErrorKind.PROVIDER_ERROR, request_sent=True)
        return result_of(response, model)

    async def count_tokens(self, request: ProviderRequest) -> int | None:
        return None

    async def verify(self) -> VerifyOutcome:
        """`GET /v1beta/models/{model}`: proves the key and that the model is served."""
        failure: ProviderError | None = None
        with http.trace_call():
            try:
                async with asyncio.timeout(self._total_s):
                    await self._client.aio.models.get(model=self.model)
            except Exception as exc:
                failure = map_error(exc, request_sent=False)
        if failure is None:
            return VerifyOutcome(status=VerifyStatus.VALID)
        if failure.kind is ProviderErrorKind.AUTH_FAILED:
            return VerifyOutcome(status=VerifyStatus.INVALID, error_code=failure.kind.value)
        if failure.http_status == 404:
            return VerifyOutcome(status=VerifyStatus.INVALID, error_code="model_not_found")
        return VerifyOutcome(status=VerifyStatus.ERROR, error_code=failure.kind.value)

    async def aclose(self) -> None:
        await self._client.aio.aclose()
        await self._http.aclose()
        self._sync.close()


__all__ = ["GeminiProvider", "map_api_error", "map_error", "result_of"]
