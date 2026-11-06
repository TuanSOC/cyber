"""Email transport backends: SMTP, capture, and disabled (M11 phase 2).

- `smtp`: sends via standard SMTP, supporting plaintext (local/test only), STARTTLS,
  or implicit TLS (SMTPS). Timeouts and errors are mapped to either `SmtpTransientError`
  (retried with backoff) or `SmtpPermanentError` (5xx codes, marked failed immediately).
- `capture`: writes `{subject, body, to}` into `email_outbox.captured` (test profile only).
- `disabled`: fails rows with `mail_disabled`.

Defense in depth:
`ENV=test` refuses any SMTP host other than `TEST_SMTP_HOST` (`mailpit-test`).
"""

from __future__ import annotations

import abc
from email.message import EmailMessage
import logging
from pathlib import Path
import smtplib
import socket
from typing import Any

from app.core.config import TEST_SMTP_HOST, Settings

log = logging.getLogger(__name__)


class MailTransportError(Exception):
    """Base exception for mail transport errors."""


class SmtpTransientError(MailTransportError):
    """Transient SMTP error (network failure, 4xx response, timeout) eligible for retry."""


class SmtpPermanentError(MailTransportError):
    """Permanent SMTP error (5xx response) not eligible for retry."""


class MailDisabledError(MailTransportError):
    """Mail delivery attempted while transport is disabled."""


class BaseMailTransport(abc.ABC):
    @abc.abstractmethod
    def send(self, msg: EmailMessage, to_email: str) -> dict[str, Any] | None:
        """Send or capture message. Returns capture payload if applicable."""


class SmtpTransport(BaseMailTransport):
    def __init__(self, settings: Settings) -> None:
        self._env = settings.env
        self._host = settings.smtp_host or "127.0.0.1"
        self._port = settings.smtp_port
        self._tls = settings.smtp_tls
        self._timeout = min(settings.smtp_timeout_s, 15)
        self._username = settings.smtp_username
        self._password_file = settings.smtp_password_file

        # Startup test-profile guard
        if self._env == "test" and self._host != TEST_SMTP_HOST:
            raise ValueError(f"ENV=test delivers SMTP to {TEST_SMTP_HOST} only (got {self._host})")

    def _read_password(self) -> str | None:
        if not self._password_file:
            return None
        path = Path(self._password_file)
        if not path.is_file():
            raise SmtpPermanentError(f"SMTP password file not found: {self._password_file}")
        return path.read_text("utf-8").strip()

    def send(self, msg: EmailMessage, to_email: str) -> None:
        if self._env == "test" and self._host != TEST_SMTP_HOST:
            raise SmtpPermanentError(f"ENV=test refuses SMTP to {self._host}")

        password = self._read_password()

        try:
            if self._tls == "implicit":
                server: smtplib.SMTP = smtplib.SMTP_SSL(
                    self._host, self._port, timeout=self._timeout
                )
            else:
                server = smtplib.SMTP(self._host, self._port, timeout=self._timeout)

            with server:
                if self._tls == "starttls":
                    server.starttls()
                if self._username and password:
                    server.login(self._username, password)
                server.send_message(msg)

        except smtplib.SMTPResponseException as exc:
            # 5xx is permanent; everything else (e.g. 4xx) is transient
            if 500 <= exc.smtp_code <= 599:
                log.warning("SMTP permanent failure %d: %s", exc.smtp_code, exc.smtp_error)
                raise SmtpPermanentError(f"{exc.smtp_code}: {exc.smtp_error}") from exc
            log.warning("SMTP transient failure %d: %s", exc.smtp_code, exc.smtp_error)
            raise SmtpTransientError(f"{exc.smtp_code}: {exc.smtp_error}") from exc

        except (
            socket.timeout,
            TimeoutError,
            ConnectionError,
            OSError,
            smtplib.SMTPException,
        ) as exc:
            log.warning("SMTP connection error to %s:%d: %s", self._host, self._port, exc)
            raise SmtpTransientError(f"connection error: {exc}") from exc


class CaptureTransport(BaseMailTransport):
    def __init__(self, settings: Settings) -> None:
        if settings.env == "prod":
            raise ValueError("MAIL_TRANSPORT=capture is not allowed in prod")

    def send(self, msg: EmailMessage, to_email: str) -> dict[str, Any]:
        return {
            "to": to_email,
            "subject": str(msg.get("Subject", "")),
            "body": msg.get_content(),
        }


class DisabledTransport(BaseMailTransport):
    def __init__(self, settings: Settings | None = None) -> None:
        pass

    def send(self, msg: EmailMessage, to_email: str) -> None:
        raise MailDisabledError("mail delivery is disabled")


def get_mail_transport(settings: Settings) -> BaseMailTransport:
    mode = settings.mail_transport
    if mode == "smtp":
        return SmtpTransport(settings)
    if mode == "capture":
        return CaptureTransport(settings)
    if mode == "disabled":
        return DisabledTransport(settings)
    raise ValueError(f"unknown mail transport: {mode}")
