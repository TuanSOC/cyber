"""Log redaction for identity secrets (M11 phase 1, FROZEN, implemented).

- `AccessLogFilter` (on the `uvicorn.access` logger): the query string of the OIDC callback
  (`/api/v1/auth/sso/callback?code=…&state=…`) is replaced by `?[redacted]`, so the
  authorization code and the state never reach the access log.
- `SecretRedactionFilter` (on every handler of the root and uvicorn loggers): any
  `Authorization` header value and any platform API key (`clk_…`) in a formatted message are
  replaced, whatever logger produced it.
`install()` is idempotent and called by `app.main.create_app()`; uvicorn has configured its
loggers by then, and filters survive later records.
"""

import logging
import re
from collections.abc import Sequence

SSO_CALLBACK_PATH = "/api/v1/auth/sso/callback"
REDACTED_QUERY = "?[redacted]"
_API_KEY = re.compile(r"clk_[A-Za-z0-9_-]+")
# `Authorization: Bearer x`, `'authorization': 'Bearer x'`, `(b'authorization', b'Bearer x')`.
_AUTHORIZATION = re.compile(r"((?i:authorization)['\"]?\s*[:=,]\s*(?:b['\"]|['\"])?)[^'\"\r\n,})]+")
_LOGGERS = ("", "uvicorn", "uvicorn.access", "uvicorn.error")


def redact_path(path: str) -> str:
    """The access-log path with the SSO callback's query removed."""
    base, sep, _query = path.partition("?")
    if sep and base == SSO_CALLBACK_PATH:
        return base + REDACTED_QUERY
    return path


def redact_text(text: str) -> str:
    text = _AUTHORIZATION.sub(lambda m: f"{m.group(1)}[redacted]", text)
    return _API_KEY.sub("clk_[redacted]", text)


class AccessLogFilter(logging.Filter):
    """uvicorn's access record args: (client, method, full_path, http_version, status)."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
            record.args = (*args[:2], redact_path(args[2]), *args[3:])
        return True


class SecretRedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        cleaned = redact_text(message)
        if cleaned != message:
            record.msg = cleaned
            record.args = None
        return True


def _has(filters: Sequence[object], kind: type) -> bool:
    return any(isinstance(f, kind) for f in filters)


def install() -> None:
    access = logging.getLogger("uvicorn.access")
    if not _has(access.filters, AccessLogFilter):
        access.addFilter(AccessLogFilter())
    for name in _LOGGERS:
        logger = logging.getLogger(name)
        if not _has(logger.filters, SecretRedactionFilter):
            logger.addFilter(SecretRedactionFilter())
        for handler in logger.handlers:
            if not _has(handler.filters, SecretRedactionFilter):
                handler.addFilter(SecretRedactionFilter())
