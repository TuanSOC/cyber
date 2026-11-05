"""Shared helpers of the LLM provider adapters (M5 phase 3): typed failures, strict JSON.

Every adapter failure is a frozen `contracts.ProviderError` built here or in the adapter, and
always raised **outside** the `except` block that caught the SDK / transport exception, so it
carries neither `__cause__` nor `__context__`: an SDK error keeps the request, the response
body and sometimes header values, and a traceback or an error reporter must never walk into
them. Nothing here reads, logs or formats a key, a header or a body.

`ProviderUnavailable` is the registry's refusal (unknown provider, model outside the catalog
allowlist, operator-level availability); the worker maps it to
`failed/provider_unavailable` (`error_code`).
"""

import json
import math
import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Literal

from pydantic import SecretStr

from app.modules.ai.contracts import AiErrorCode, ProviderError, ProviderErrorKind, ProviderUsage

MAX_JSON_DEPTH = 64
MAX_INT_DIGITS = 40
RETRY_AFTER_MAX_S = 3600.0
# The sealed-key bounds (`core/sealbox.py` MIN/MAX_KEY_CHARS): printable ASCII only, so a key
# can never make an HTTP library raise an error that quotes it.
MIN_KEY_CHARS = 8
MAX_KEY_CHARS = 256

UnavailableCode = Literal[
    "unknown_provider",
    "model_not_allowed",
    "ai_disabled_platform",
    "prod_mock",
    "gemini_billing_required",
]


class ProviderUnavailable(ValueError):
    """The registry refuses to build an adapter. Fixed message: the reason code only."""

    error_code = AiErrorCode.PROVIDER_UNAVAILABLE

    def __init__(self, reason: UnavailableCode) -> None:
        super().__init__(reason)
        self.reason = reason


def fail(
    kind: ProviderErrorKind,
    *,
    http_status: int | None = None,
    retry_after_s: float | None = None,
    category: str | None = None,
    request_sent: bool = False,
    usage: ProviderUsage | None = None,
) -> ProviderError:
    """A `ProviderError` (raise it outside any `except` block). `usage` is set whenever the
    provider answered (a 200 that ends in a failure was still billed)."""
    return ProviderError(
        kind,
        http_status=http_status,
        retry_after_s=retry_after_s,
        category=category,
        request_sent=request_sent,
        usage=usage,
    )


def kind_for_status(status: int) -> ProviderErrorKind:
    """The generic mapping of an HTTP error status (the mock; fallbacks of the SDK adapters)."""
    if status == 429:
        return ProviderErrorKind.RATE_LIMITED
    if status == 529:
        return ProviderErrorKind.OVERLOADED
    if status in (401, 403):
        return ProviderErrorKind.AUTH_FAILED
    if status == 413:
        return ProviderErrorKind.CONTEXT_TOO_LARGE
    if 400 <= status < 500:
        return ProviderErrorKind.BAD_REQUEST
    return ProviderErrorKind.PROVIDER_ERROR


def key_text(key: SecretStr | None) -> str:
    """The key as a header-safe string, or `auth_failed` (no message, no value)."""
    value = key.get_secret_value() if key is not None else ""
    ok = (
        MIN_KEY_CHARS <= len(value) <= MAX_KEY_CHARS
        and value.isascii()
        and value.isprintable()
        and value == value.strip()
    )
    if not ok:
        raise fail(ProviderErrorKind.AUTH_FAILED)
    return value


def parse_retry_after(value: str | None) -> float | None:
    """`Retry-After` as seconds (delta-seconds or an HTTP date), clamped to 0..3600."""
    if value is None:
        return None
    text = value.strip()
    if not text or len(text) > 64:
        return None
    seconds: float | None
    try:
        seconds = float(text)
    except ValueError:
        try:
            when = parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        seconds = (when - datetime.now(UTC)).total_seconds()
    if not math.isfinite(seconds):
        return None
    return min(max(seconds, 0.0), RETRY_AFTER_MAX_S)


_DURATION = re.compile(r"^(\d{1,6})(?:\.(\d{1,9}))?s$")


def parse_duration(value: object) -> float | None:
    """A protobuf JSON duration (`"30s"`, `"1.5s"`), clamped like `parse_retry_after`."""
    if not isinstance(value, str):
        return None
    match = _DURATION.fullmatch(value.strip())
    if match is None:
        return None
    seconds = float(f"{match.group(1)}.{match.group(2) or '0'}")
    return min(seconds, RETRY_AFTER_MAX_S)


# --- strict JSON ---------------------------------------------------------------------------

_STRUCTURAL = re.compile(r'["\\\[\]{}]')


class JsonRejected(ValueError):
    """Strict JSON refused (syntax, depth, digits, NaN/Infinity). Fixed message."""

    def __init__(self) -> None:
        super().__init__("json_rejected")


def _depth_exceeds(text: str, limit: int) -> bool:
    depth = 0
    in_string = False
    skip_at = -1
    for match in _STRUCTURAL.finditer(text):
        pos = match.start()
        if pos == skip_at:
            continue
        char = text[pos]
        if in_string:
            if char == "\\":
                skip_at = pos + 1
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > limit:
                return True
        elif char in "]}":
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


def loads_strict(data: str | bytes) -> Any:
    """Strict JSON: a nesting-depth limit (CPython accepts thousands of levels), bounded
    integers, no `NaN`/`Infinity`. Raises `JsonRejected` only, without a context."""
    rejected = False
    value: Any = None
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        if _depth_exceeds(text, MAX_JSON_DEPTH):
            rejected = True
        else:
            value = json.loads(
                text,
                parse_constant=_refuse_constant,
                parse_int=_bounded_int,
                parse_float=_finite_float,
            )
    except (ValueError, RecursionError, TypeError, UnicodeDecodeError):
        rejected = True
    if rejected:
        raise JsonRejected()
    return value


def parse_output(
    text: str | None, *, request_sent: bool = True, usage: ProviderUsage | None = None
) -> dict[str, Any]:
    """The model's JSON text as an object, or `invalid_output` (the worker's repair retry).
    Schema conformance is not checked here: the worker re-validates against
    `AnalysisOutput`."""
    parsed: Any = None
    ok = False
    if text is not None and text.strip():
        try:
            parsed = loads_strict(text)
            ok = isinstance(parsed, dict)
        except JsonRejected:
            ok = False
    if not ok:
        raise fail(ProviderErrorKind.INVALID_OUTPUT, request_sent=request_sent, usage=usage)
    result: dict[str, Any] = parsed
    return result


def clip(value: object, limit: int) -> str | None:
    """A short, printable string field from a provider (request ids, categories)."""
    if not isinstance(value, str) or not value:
        return None
    cleaned = "".join(ch for ch in value if ch.isprintable())[:limit]
    return cleaned or None


__all__ = [
    "JsonRejected",
    "ProviderUnavailable",
    "clip",
    "fail",
    "key_text",
    "kind_for_status",
    "loads_strict",
    "parse_duration",
    "parse_output",
    "parse_retry_after",
]
