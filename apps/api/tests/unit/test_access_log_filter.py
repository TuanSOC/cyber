"""M11: the SSO callback's query string and any Authorization / `clk_` value never reach a
log (phase 1, `core.logging`)."""

import logging

import pytest

from app.core import logging as log_redaction
from app.core.logging import AccessLogFilter, SecretRedactionFilter, redact_path, redact_text


def _access_record(path: str) -> logging.LogRecord:
    return logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("10.0.0.1:4000", "GET", path, "1.1", 303),
        None,
    )


def test_the_sso_callback_query_is_redacted() -> None:
    record = _access_record("/api/v1/auth/sso/callback?code=abc123&state=s3cr3t&iss=x")
    assert AccessLogFilter().filter(record)
    message = record.getMessage()
    assert "abc123" not in message and "s3cr3t" not in message
    assert "/api/v1/auth/sso/callback?[redacted]" in message


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/auth/me",
        "/api/v1/orgs/x/investigations?limit=5",
        "/api/v1/auth/sso/callbackx?code=1",
        "/api/v1/auth/sso/start",
    ],
)
def test_other_paths_are_untouched(path: str) -> None:
    assert redact_path(path) == path


def test_the_bare_callback_keeps_its_path() -> None:
    assert redact_path("/api/v1/auth/sso/callback") == "/api/v1/auth/sso/callback"


@pytest.mark.parametrize(
    "text",
    [
        "Authorization: Bearer clk_abcdefabcdef_" + "A" * 43,
        "headers={'authorization': 'Bearer some-token'}",
        "[(b'authorization', b'Bearer zz')]",
        "AUTHORIZATION=Basic dXNlcjpwYXNz",
        "key clk_abcdefabcdef_" + "B" * 43 + " used",
    ],
)
def test_authorization_values_and_keys_are_redacted(text: str) -> None:
    cleaned = redact_text(text)
    for secret in ("clk_abcdefabcdef_A", "some-token", "zz'", "dXNlcjpwYXNz", "B" * 43):
        assert secret not in cleaned
    assert "[redacted]" in cleaned


def test_the_redaction_filter_rewrites_formatted_records() -> None:
    record = logging.LogRecord(
        "app", logging.WARNING, __file__, 1, "got %s", ("Bearer clk_abcdefabcdef_x",), None
    )
    SecretRedactionFilter().filter(record)
    assert "clk_abcdefabcdef" not in record.getMessage()


def test_install_is_idempotent() -> None:
    log_redaction.install()
    log_redaction.install()
    access = logging.getLogger("uvicorn.access")
    assert sum(isinstance(f, AccessLogFilter) for f in access.filters) == 1
    assert sum(isinstance(f, SecretRedactionFilter) for f in access.filters) == 1
