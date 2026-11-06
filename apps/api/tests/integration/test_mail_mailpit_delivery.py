"""End-to-end integration test verifying delivery to Mailpit REST API (M11 phase 2)."""

from datetime import datetime, timezone
import os

import httpx
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.config import Settings
from app.core.db import get_engine
from app.core.sealbox_open import parse_private_key
from app.modules.mail import outbox, worker
from app.modules.mail.templates import MailTemplate
from app.modules.mail.transport import SmtpTransport

MAILPIT_URL = os.environ.get("MAILPIT_TEST_URL", "http://mailpit-test:8025")
DEV_MAIL_PRIVATE_KEY_B64 = "451l7V250hOQ1k/Jk51N3GZ77X4h8zYw4e9w5i7x5g8="


async def _mailpit_available() -> bool:
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            resp = await client.get(f"{MAILPIT_URL}/api/v1/messages")
            return resp.status_code == 200
    except Exception:
        return False


@pytest.mark.asyncio
async def test_mailpit_end_to_end_delivery() -> None:
    if not await _mailpit_available():
        pytest.skip(f"Mailpit not reachable at {MAILPIT_URL}")

    # 1. Clear existing messages in Mailpit
    async with httpx.AsyncClient(timeout=3.0) as client:
        await client.delete(f"{MAILPIT_URL}/api/v1/messages")

    engine = get_engine()
    sm = async_sessionmaker(engine, expire_on_commit=False, autobegin=False)

    # Configure worker with SmtpTransport pointing to mailpit-test:1025
    smtp_settings = Settings(
        env="test",
        mail_transport="smtp",
        smtp_host="mailpit-test",
        smtp_port=1025,
        smtp_tls="none",
        mail_from="noreply@cyberlab.local",
    )
    transport = SmtpTransport(smtp_settings)
    pkey = parse_private_key(DEV_MAIL_PRIVATE_KEY_B64)
    worker.set_worker_seams(
        sessionmaker=sm,
        transport=transport,
        private_keys={"dev-mail-2026-11": pkey},
    )

    try:
        # 2. Enqueue invite
        async with sm() as session, session.begin():
            outbox_id = await outbox.enqueue(
                session,
                template=MailTemplate.INVITE,
                to="newuser@example.com",
                params={
                    "org_name": "SecOps Team",
                    "inviter_name": "Charlie Admin",
                    "role": "analyst",
                    "expires_at": datetime(2026, 12, 31, 23, 59, tzinfo=timezone.utc),
                },
                secret="mailpit-test-token-777",
            )

        # 3. Process outbox
        processed = await worker.process_outbox(outbox_id)
        assert processed is True

        # 4. Check message in Mailpit via REST API
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{MAILPIT_URL}/api/v1/messages")
            assert resp.status_code == 200
            data = resp.json()
            messages = data.get("messages", [])
            assert len(messages) >= 1

            msg_meta = messages[0]
            assert msg_meta["Subject"] == "You are invited to an organization on CyberLab"
            assert msg_meta["To"][0]["Address"] == "newuser@example.com"

            # Check full content
            msg_id = msg_meta["ID"]
            detail_resp = await client.get(f"{MAILPIT_URL}/api/v1/message/{msg_id}")
            assert detail_resp.status_code == 200
            detail = detail_resp.json()
            body_text = detail.get("Text", "")
            assert "#t=mailpit-test-token-777" in body_text
            assert '"SecOps Team"' in body_text
    finally:
        worker.set_worker_seams()
