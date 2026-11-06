"""Integration tests for the mail outbox worker, claims, retries, sweeps, and role isolation (M11 phase 2)."""

from datetime import datetime, timezone
from email.message import EmailMessage
from unittest.mock import MagicMock
import uuid

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import get_settings
from app.core.db import get_engine
from app.core.sealbox_open import parse_private_key
from app.modules.mail import outbox, worker
from app.modules.mail.models import EmailOutbox, OutboxError, OutboxStatus
from app.modules.mail.templates import MailTemplate
from app.modules.mail.transport import (
    BaseMailTransport,
    CaptureTransport,
    MailDisabledError,
    SmtpPermanentError,
    SmtpTransientError,
)

# Test dev private key corresponding to DEV_MAIL_SEAL_PUBLIC_KEYS
DEV_MAIL_PRIVATE_KEY_B64 = "451l7V250hOQ1k/Jk51N3GZ77X4h8zYw4e9w5i7x5g8="


class FailingTransport(BaseMailTransport):
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def send(self, msg: EmailMessage, to_email: str) -> None:
        raise self.exc


@pytest.fixture(autouse=True)
def _setup_worker_seams() -> None:
    engine = get_engine()
    sm = async_sessionmaker(engine, expire_on_commit=False, autobegin=False)
    pkey = parse_private_key(DEV_MAIL_PRIVATE_KEY_B64)
    worker.set_worker_seams(
        sessionmaker=sm,
        transport=CaptureTransport(get_settings()),
        private_keys={"dev-mail-2026-11": pkey},
    )
    yield
    worker.set_worker_seams()


@pytest.mark.asyncio
async def test_outbox_worker_processes_and_clears_secrets() -> None:
    engine = get_engine()
    sm = async_sessionmaker(engine, expire_on_commit=False, autobegin=False)

    # 1. Enqueue an invite with secret token
    async with sm() as session, session.begin():
        outbox_id = await outbox.enqueue(
            session,
            template=MailTemplate.INVITE,
            to="invited@example.com",
            params={
                "org_name": "Acme Defense",
                "inviter_name": "Alice Lead",
                "role": "analyst",
                "expires_at": datetime(2026, 12, 1, 12, 0, tzinfo=timezone.utc),
            },
            secret="super-secret-invite-token",
        )

    # Verify secret is initially sealed in DB
    async with sm() as session, session.begin():
        row = (
            await session.execute(select(EmailOutbox).where(EmailOutbox.id == outbox_id))
        ).scalar_one()
        assert row.status == OutboxStatus.PENDING.value
        assert row.secret_epk is not None
        assert row.secret_ct is not None

    # 2. Worker processes the row
    processed = await worker.process_outbox(outbox_id)
    assert processed is True

    # 3. Verify status sent and secrets NULLed
    async with sm() as session, session.begin():
        row = (
            await session.execute(select(EmailOutbox).where(EmailOutbox.id == outbox_id))
        ).scalar_one()
        assert row.status == OutboxStatus.SENT.value
        assert row.sent_at is not None
        assert row.last_error is None
        assert row.secret_epk is None
        assert row.secret_nonce is None
        assert row.secret_ct is None
        assert row.secret_kid is None

        # Verify captured payload
        assert row.captured is not None
        assert row.captured["to"] == "invited@example.com"
        assert "#t=super-secret-invite-token" in row.captured["body"]

    # 4. Duplicate call returns False (not claimable)
    second = await worker.process_outbox(outbox_id)
    assert second is False


@pytest.mark.asyncio
async def test_outbox_worker_unseal_failure_fails_row() -> None:
    engine = get_engine()
    sm = async_sessionmaker(engine, expire_on_commit=False, autobegin=False)

    async with sm() as session, session.begin():
        outbox_id = await outbox.enqueue(
            session,
            template=MailTemplate.EMAIL_VERIFY,
            to="user@example.com",
            params={"display_name": "Bob"},
            secret="verify-token-123",
        )
        # Corrupt ciphertext
        await session.execute(
            update(EmailOutbox).where(EmailOutbox.id == outbox_id).values(secret_ct=b"corrupted_ct")
        )

    processed = await worker.process_outbox(outbox_id)
    assert processed is True

    async with sm() as session, session.begin():
        row = (
            await session.execute(select(EmailOutbox).where(EmailOutbox.id == outbox_id))
        ).scalar_one()
        assert row.status == OutboxStatus.FAILED.value
        assert row.last_error == OutboxError.UNSEAL_FAILED.value
        assert row.secret_epk is None
        assert row.secret_ct is None


@pytest.mark.asyncio
async def test_outbox_worker_transient_failure_exponential_backoff() -> None:
    engine = get_engine()
    sm = async_sessionmaker(engine, expire_on_commit=False, autobegin=False)

    worker.set_worker_seams(
        sessionmaker=sm,
        transport=FailingTransport(SmtpTransientError("Connection timed out")),
        private_keys={"dev-mail-2026-11": parse_private_key(DEV_MAIL_PRIVATE_KEY_B64)},
    )

    async with sm() as session, session.begin():
        outbox_id = await outbox.enqueue(
            session,
            template=MailTemplate.PASSWORD_CHANGED,
            to="user@example.com",
            params={"display_name": "Bob"},
        )

    processed = await worker.process_outbox(outbox_id)
    assert processed is True

    async with sm() as session, session.begin():
        row = (
            await session.execute(select(EmailOutbox).where(EmailOutbox.id == outbox_id))
        ).scalar_one()
        assert row.status == OutboxStatus.PENDING.value
        assert row.attempts == 1
        assert row.last_error == OutboxError.SMTP_TRANSIENT.value
        assert row.next_attempt_at > row.claimed_at


@pytest.mark.asyncio
async def test_outbox_worker_permanent_failure_marks_failed() -> None:
    engine = get_engine()
    sm = async_sessionmaker(engine, expire_on_commit=False, autobegin=False)

    worker.set_worker_seams(
        sessionmaker=sm,
        transport=FailingTransport(SmtpPermanentError("550 Mailbox not found")),
        private_keys={"dev-mail-2026-11": parse_private_key(DEV_MAIL_PRIVATE_KEY_B64)},
    )

    async with sm() as session, session.begin():
        outbox_id = await outbox.enqueue(
            session,
            template=MailTemplate.PASSWORD_CHANGED,
            to="user@example.com",
            params={"display_name": "Bob"},
        )

    processed = await worker.process_outbox(outbox_id)
    assert processed is True

    async with sm() as session, session.begin():
        row = (
            await session.execute(select(EmailOutbox).where(EmailOutbox.id == outbox_id))
        ).scalar_one()
        assert row.status == OutboxStatus.FAILED.value
        assert row.last_error == OutboxError.SMTP_PERMANENT.value
        assert row.secret_epk is None


@pytest.mark.asyncio
async def test_outbox_worker_sweep_recovers_crashed_sending() -> None:
    engine = get_engine()
    sm = async_sessionmaker(engine, expire_on_commit=False, autobegin=False)

    async with sm() as session, session.begin():
        outbox_id = await outbox.enqueue(
            session,
            template=MailTemplate.PASSWORD_CHANGED,
            to="user@example.com",
            params={"display_name": "Bob"},
        )
        # Simulate worker crash: row in 'sending' claimed 10 minutes ago
        await session.execute(
            update(EmailOutbox)
            .where(EmailOutbox.id == outbox_id)
            .values(
                status=OutboxStatus.SENDING.value,
                claimed_at=text("now() - interval '10 minutes'"),
            )
        )

    recovered, _ = await worker.sweep()
    assert recovered >= 1

    async with sm() as session, session.begin():
        row = (
            await session.execute(select(EmailOutbox).where(EmailOutbox.id == outbox_id))
        ).scalar_one()
        assert row.status == OutboxStatus.PENDING.value
        assert row.claimed_at is None


@pytest.mark.asyncio
async def test_cyberlab_mail_role_cannot_read_users() -> None:
    engine = get_engine()
    async with engine.connect() as conn:
        await conn.execute(text("SET ROLE cyberlab_mail"))
        with pytest.raises(DBAPIError, match="permission denied"):
            await conn.execute(text("SELECT id FROM users LIMIT 1"))
        # Reset role
        await conn.execute(text("RESET ROLE"))
