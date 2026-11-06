"""Mail outbox processing worker and sweep logic (M11 phase 2).

Connects to the database under the least-privileged `cyberlab_mail` role (RT9).
- Atomically claims rows due for sending (`status='pending' AND next_attempt_at <= now()`).
- Unseals link tokens with the mail worker's private key (`cyberlab.mail.v1`).
- Renders deterministic plain text and sends via configured transport.
- On success: marks `status='sent'`, `sent_at=now()`, and NULLs all sealed secret columns.
- On permanent error (5xx): marks `status='failed'`, records `last_error`, and NULLs secrets.
- On transient error: schedules retry with exponential backoff `now() + 2^attempts minutes`
  (up to `mail_max_attempts`, then fails and NULLs secrets).
- Periodic sweep: recovers stalled `sending` rows (> 5 min) and re-publishes due `pending` rows.
"""

from __future__ import annotations

from collections.abc import Mapping
import logging
from pathlib import Path
from typing import Any
import uuid

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.core.db import get_sessionmaker
from app.core.sealbox import SealedKey
from app.modules.mail.models import EmailOutbox, OutboxError, OutboxStatus
from app.modules.mail.outbox import publish_after_commit
from app.modules.mail.render import RenderRefusedError, render_mail
from app.modules.mail.templates import LINK_PATHS, MailTemplate
from app.modules.mail.transport import (
    BaseMailTransport,
    CaptureTransport,
    MailDisabledError,
    SmtpPermanentError,
    SmtpTransientError,
    get_mail_transport,
)
from app.modules.mail.unseal import UnsealError, load_private_keys, open_link_token

log = logging.getLogger(__name__)

# Seams for test injection
_override_sessionmaker: async_sessionmaker[AsyncSession] | None = None
_override_transport: BaseMailTransport | None = None
_override_private_keys: Mapping[str, X25519PrivateKey] | None = None


def set_worker_seams(
    *,
    sessionmaker: async_sessionmaker[AsyncSession] | None = None,
    transport: BaseMailTransport | None = None,
    private_keys: Mapping[str, X25519PrivateKey] | None = None,
) -> None:
    global _override_sessionmaker, _override_transport, _override_private_keys
    _override_sessionmaker = sessionmaker
    _override_transport = transport
    _override_private_keys = private_keys


def _get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return _override_sessionmaker or get_sessionmaker()


def _get_transport(settings: Settings) -> BaseMailTransport:
    return _override_transport or get_mail_transport(settings)


def _get_private_keys(settings: Settings) -> Mapping[str, X25519PrivateKey]:
    if _override_private_keys is not None:
        return _override_private_keys
    path = settings.mail_seal_private_keys_file
    if not path or not Path(path).exists():
        return {}
    return load_private_keys(path)


def _log_domain(email_str: str) -> str:
    parts = email_str.rsplit("@", 1)
    return parts[-1] if len(parts) == 2 else "unknown"


NULL_SECRETS: dict[str, Any] = {
    "secret_kid": None,
    "secret_key_version": None,
    "secret_epk": None,
    "secret_nonce": None,
    "secret_ct": None,
}


async def claim_outbox_row(
    session: AsyncSession,
    outbox_id: uuid.UUID,
) -> EmailOutbox | None:
    """Atomically transition a pending row due for sending to sending status."""
    stmt = (
        update(EmailOutbox)
        .where(
            EmailOutbox.id == outbox_id,
            EmailOutbox.status == OutboxStatus.PENDING.value,
            EmailOutbox.next_attempt_at <= func.now(),
        )
        .values(
            status=OutboxStatus.SENDING.value,
            attempts=EmailOutbox.attempts + 1,
            claimed_at=func.now(),
        )
        .returning(EmailOutbox)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def process_outbox(outbox_id: uuid.UUID) -> bool:
    """Process a single email outbox row. Returns True if processed, False if ignored."""
    sm = _get_sessionmaker()
    settings = get_settings()

    async with sm() as session, session.begin():
        row = await claim_outbox_row(session, outbox_id)
        if row is None:
            log.debug("outbox %s not claimable (already claimed or not due)", outbox_id)
            return False

        template_val = row.template
        to_email = row.to_email
        domain = _log_domain(to_email)
        attempts = row.attempts
        max_attempts = settings.mail_max_attempts

        # 1. Unseal link token if required by template
        token: str | None = None
        if row.template in LINK_PATHS:
            if not row.secret_epk:
                log.error("outbox %s template %s missing sealed token", outbox_id, template_val)
                await session.execute(
                    update(EmailOutbox)
                    .where(EmailOutbox.id == outbox_id)
                    .values(
                        status=OutboxStatus.FAILED.value,
                        last_error=OutboxError.UNSEAL_FAILED.value,
                        **NULL_SECRETS,
                    )
                )
                return True

            sealed = SealedKey(
                kid=row.secret_kid or "",
                key_version=row.secret_key_version or 1,
                epk=row.secret_epk,
                nonce=row.secret_nonce or b"",
                ct=row.secret_ct or b"",
            )
            try:
                pkeys = _get_private_keys(settings)
                token = open_link_token(sealed, row.id, pkeys).get_secret_value()
            except UnsealError as exc:
                log.warning("unseal failed for outbox %s: %s", outbox_id, exc)
                await session.execute(
                    update(EmailOutbox)
                    .where(EmailOutbox.id == outbox_id)
                    .values(
                        status=OutboxStatus.FAILED.value,
                        last_error=OutboxError.UNSEAL_FAILED.value,
                        **NULL_SECRETS,
                    )
                )
                return True

        # 2. Render message
        from_email = settings.mail_from or "noreply@cyberlab.invalid"
        base_url = settings.public_base_url or "http://localhost:8080"
        try:
            msg = render_mail(
                template_val,
                row.params or {},
                token=token,
                to_email=to_email,
                from_email=from_email,
                public_base_url=base_url,
            )
        except (RenderRefusedError, ValueError) as exc:
            log.warning("rendering refused for outbox %s: %s", outbox_id, exc)
            await session.execute(
                update(EmailOutbox)
                .where(EmailOutbox.id == outbox_id)
                .values(
                    status=OutboxStatus.FAILED.value,
                    last_error=OutboxError.RENDER_REFUSED.value,
                    **NULL_SECRETS,
                )
            )
            return True

        # 3. Deliver message via transport
        transport = _get_transport(settings)
        try:
            capture_res = transport.send(msg, to_email)
            log.info("mail sent template=%s domain=%s", template_val, domain)

            updates: dict[str, Any] = {
                "status": OutboxStatus.SENT.value,
                "sent_at": func.now(),
                "last_error": None,
                **NULL_SECRETS,
            }
            if isinstance(transport, CaptureTransport) and capture_res:
                updates["captured"] = capture_res

            await session.execute(
                update(EmailOutbox).where(EmailOutbox.id == outbox_id).values(**updates)
            )
            return True

        except MailDisabledError:
            log.warning("mail delivery disabled for outbox %s", outbox_id)
            await session.execute(
                update(EmailOutbox)
                .where(EmailOutbox.id == outbox_id)
                .values(
                    status=OutboxStatus.FAILED.value,
                    last_error=OutboxError.MAIL_DISABLED.value,
                    **NULL_SECRETS,
                )
            )
            return True

        except SmtpPermanentError as exc:
            log.warning("SMTP permanent failure for outbox %s: %s", outbox_id, exc)
            await session.execute(
                update(EmailOutbox)
                .where(EmailOutbox.id == outbox_id)
                .values(
                    status=OutboxStatus.FAILED.value,
                    last_error=OutboxError.SMTP_PERMANENT.value,
                    **NULL_SECRETS,
                )
            )
            return True

        except (SmtpTransientError, Exception) as exc:
            log.warning("SMTP transient failure for outbox %s (attempt %d): %s", outbox_id, attempts, exc)
            if attempts >= max_attempts:
                log.warning("outbox %s reached max attempts (%d); failing", outbox_id, max_attempts)
                await session.execute(
                    update(EmailOutbox)
                    .where(EmailOutbox.id == outbox_id)
                    .values(
                        status=OutboxStatus.FAILED.value,
                        last_error=OutboxError.MAX_ATTEMPTS.value,
                        **NULL_SECRETS,
                    )
                )
            else:
                delay_minutes = 2 ** attempts
                await session.execute(
                    update(EmailOutbox)
                    .where(EmailOutbox.id == outbox_id)
                    .values(
                        status=OutboxStatus.PENDING.value,
                        last_error=OutboxError.SMTP_TRANSIENT.value,
                        next_attempt_at=func.now() + (delay_minutes * text("interval '1 minute'")),
                    )
                )
            return True


async def sweep() -> tuple[int, int]:
    """Recover crashed sending rows and republish due pending rows.

    Returns (recovered_count, republished_count).
    """
    sm = _get_sessionmaker()

    # 1. Recover zombie rows stuck in sending > 5 min
    async with sm() as session, session.begin():
        stmt_recover = (
            update(EmailOutbox)
            .where(
                EmailOutbox.status == OutboxStatus.SENDING.value,
                EmailOutbox.claimed_at < (func.now() - text("interval '5 minutes'")),
            )
            .values(status=OutboxStatus.PENDING.value, claimed_at=None)
        )
        res_recover = await session.execute(stmt_recover)
        recovered_count = res_recover.rowcount or 0

    # 2. Query due pending rows to re-publish (up to 100 per tick)
    async with sm() as session, session.begin():
        stmt_due = (
            select(EmailOutbox.id)
            .where(
                EmailOutbox.status == OutboxStatus.PENDING.value,
                EmailOutbox.next_attempt_at <= func.now(),
            )
            .order_by(EmailOutbox.next_attempt_at.asc())
            .limit(100)
        )
        res_due = await session.execute(stmt_due)
        due_ids = [row[0] for row in res_due.all()]

    republished = 0
    for outbox_id in due_ids:
        if await publish_after_commit(outbox_id):
            republished += 1

    if recovered_count or republished:
        log.info("mail sweep: recovered %d stalled row(s), republished %d due row(s)", recovered_count, republished)

    return recovered_count, republished
