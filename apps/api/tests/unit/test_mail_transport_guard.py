"""Unit tests for mail transport guards and error handling (M11 phase 2)."""

from email.message import EmailMessage
import smtplib
from unittest.mock import MagicMock, patch

import pytest

from pydantic import ValidationError

from app.core.config import Settings
from app.modules.mail.transport import (
    CaptureTransport,
    DisabledTransport,
    MailDisabledError,
    SmtpPermanentError,
    SmtpTransientError,
    SmtpTransport,
    get_mail_transport,
)


def _make_settings(**kwargs) -> Settings:
    defaults = {
        "database_url": "postgresql+asyncpg://cyberlab_app:secret@localhost:5432/cyberlab_test",
        "broker_url": "redis://localhost:6379/0",
        "jwt_secret": "test-secret-at-least-32-bytes-long-now",
        "minio_endpoint": "localhost:9000",
        "minio_access_key": "minioadmin",
        "minio_secret_key": "minioadmin",
        "redis_url": "redis://localhost:6379/1",
        "cookie_secure": True,
    }
    defaults.update(kwargs)
    return Settings(**defaults)


def _make_msg(subject: str = "Test Subject", body: str = "Hello Body") -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg.set_content(body)
    return msg


def test_test_profile_refuses_non_mailpit_smtp_host() -> None:
    with pytest.raises((ValueError, ValidationError), match="ENV=test delivers SMTP to mailpit-test only"):
        _make_settings(
            env="test",
            mail_transport="smtp",
            smtp_host="smtp.gmail.com",
        )

    mock_settings = MagicMock()
    mock_settings.env = "test"
    mock_settings.smtp_host = "smtp.gmail.com"
    mock_settings.smtp_port = 25
    mock_settings.smtp_tls = "none"
    mock_settings.smtp_timeout_s = 10
    mock_settings.smtp_username = None
    mock_settings.smtp_password_file = None
    with pytest.raises(ValueError, match="ENV=test delivers SMTP to mailpit-test only"):
        SmtpTransport(mock_settings)


def test_prod_refuses_capture_transport() -> None:
    mock_settings = MagicMock()
    mock_settings.env = "prod"
    with pytest.raises(ValueError, match="MAIL_TRANSPORT=capture is not allowed in prod"):
        CaptureTransport(mock_settings)


def test_capture_transport_captures_message_dict() -> None:
    settings = _make_settings(env="dev", mail_transport="capture")
    transport = get_mail_transport(settings)
    assert isinstance(transport, CaptureTransport)

    msg = _make_msg(subject="Important Notice", body="Please verify your email.")
    result = transport.send(msg, "user@example.com")

    assert result is not None
    assert result["to"] == "user@example.com"
    assert result["subject"] == "Important Notice"
    assert "Please verify your email." in result["body"]


def test_disabled_transport_raises_mail_disabled() -> None:
    settings = _make_settings(env="dev", mail_transport="disabled")
    transport = get_mail_transport(settings)
    assert isinstance(transport, DisabledTransport)

    msg = _make_msg()
    with pytest.raises(MailDisabledError, match="mail delivery is disabled"):
        transport.send(msg, "user@example.com")


@patch("smtplib.SMTP")
def test_smtp_transport_maps_5xx_to_permanent_error(mock_smtp_cls: MagicMock) -> None:
    mock_instance = mock_smtp_cls.return_value
    mock_instance.send_message.side_effect = smtplib.SMTPResponseException(550, b"User not found")

    settings = _make_settings(env="dev", mail_transport="smtp", smtp_host="localhost")
    transport = SmtpTransport(settings)

    msg = _make_msg()
    with pytest.raises(SmtpPermanentError, match="550"):
        transport.send(msg, "user@example.com")


@patch("smtplib.SMTP")
def test_smtp_transport_maps_4xx_to_transient_error(mock_smtp_cls: MagicMock) -> None:
    mock_instance = mock_smtp_cls.return_value
    mock_instance.send_message.side_effect = smtplib.SMTPResponseException(421, b"Try again later")

    settings = _make_settings(env="dev", mail_transport="smtp", smtp_host="localhost")
    transport = SmtpTransport(settings)

    msg = _make_msg()
    with pytest.raises(SmtpTransientError, match="421"):
        transport.send(msg, "user@example.com")
