"""The mail outbox insert and its publish (M11 phase 1, FROZEN, implemented).

`enqueue(session, ...)` validates `params` with the template's model, seals the link token for
the mail worker and inserts the row in the CALLER's transaction (so a mail exists exactly when
its business change commits). After the commit the caller calls
`await publish_after_commit(outbox_id)`: `mail.send {outbox_id}` on the `mail` queue. A broker
failure is logged and left to the `mail.sweep` beat task (60 s), which re-publishes due
`pending` rows; nothing is lost.
"""

import json
import logging
import uuid
from collections.abc import Mapping
from typing import Any

import anyio
from pydantic import SecretStr, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.threads import broker_limiter
from app.modules.mail.models import EmailOutbox
from app.modules.mail.seal import seal_link_token
from app.modules.mail.templates import LINK_PATHS, MAX_PARAMS_BYTES, TEMPLATE_PARAMS, MailTemplate

log = logging.getLogger(__name__)

# Task names and queue (the mail worker's own: broker ACL user `mail`, `~mail* ~test.mail*`).
MAIL_SEND = "mail.send"
MAIL_SWEEP = "mail.sweep"
MAIL_QUEUE = "mail"
SEND_TIMEOUT_S = 15


class OutboxRefused(ValueError):
    """The template / params / secret combination is invalid (a programming error)."""


def mail_queue() -> str:
    return f"{get_settings().queue_prefix}{MAIL_QUEUE}"


def validate_params(template: MailTemplate, params: Mapping[str, Any]) -> dict[str, Any]:
    model = TEMPLATE_PARAMS[template]
    try:
        clean = model.model_validate(dict(params)).model_dump(mode="json")
    except ValidationError as exc:
        raise OutboxRefused(f"invalid params for {template.value}") from exc
    if len(json.dumps(clean, separators=(",", ":")).encode()) > MAX_PARAMS_BYTES:
        raise OutboxRefused("params too large")
    return clean


async def enqueue(
    session: AsyncSession,
    *,
    template: MailTemplate,
    to: str,
    params: Mapping[str, Any],
    secret: SecretStr | str | None = None,
    user_id: uuid.UUID | None = None,
    org_id: uuid.UUID | None = None,
) -> uuid.UUID:
    """Insert one pending mail; returns the outbox id. A link template needs its `secret`
    (the token), every other template refuses one."""
    template = MailTemplate(template)
    clean = validate_params(template, params)
    if (template in LINK_PATHS) != (secret is not None):
        raise OutboxRefused(f"{template.value} secret mismatch")
    outbox_id = uuid.uuid4()
    row = EmailOutbox(
        id=outbox_id,
        template=template.value,
        to_email=to,
        params=clean,
        user_id=user_id,
        context_org_id=org_id,
    )
    if secret is not None:
        sealed = seal_link_token(secret, outbox_id)
        row.secret_kid = sealed.kid
        row.secret_key_version = sealed.key_version
        row.secret_epk = sealed.epk
        row.secret_nonce = sealed.nonce
        row.secret_ct = sealed.ct
    session.add(row)
    return outbox_id


def _send_sync(outbox_id: uuid.UUID) -> None:
    from app.workers.celery_app import celery_app  # broker client only, no worker

    celery_app.send_task(
        MAIL_SEND,
        kwargs={"message": {"outbox_id": str(outbox_id)}},
        queue=mail_queue(),
        retry=True,
        retry_policy={"max_retries": 1, "interval_start": 0, "interval_step": 0.5},
    )


async def publish_after_commit(outbox_id: uuid.UUID) -> bool:
    """`mail.send` for a committed row; False (logged) when the broker refused it."""
    try:
        with anyio.fail_after(SEND_TIMEOUT_S):
            await anyio.to_thread.run_sync(
                _send_sync, outbox_id, limiter=broker_limiter(), abandon_on_cancel=True
            )
    except Exception as exc:  # noqa: BLE001 - the sweep re-publishes pending rows
        log.warning("mail.send publish failed for %s (%s)", outbox_id, type(exc).__name__)
        return False
    return True
