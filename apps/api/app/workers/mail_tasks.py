"""Celery tasks for the mail worker bridging into `app.modules.mail.worker`."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
import logging
from typing import Any
import uuid

import app.models  # noqa: F401
from app.modules.mail import worker
from app.modules.mail.outbox import MAIL_SEND, MAIL_SWEEP
from app.workers.mail_app import celery_app

log = logging.getLogger(__name__)

_loop: asyncio.AbstractEventLoop | None = None


def run[T](coro: Coroutine[Any, Any, T]) -> T:
    global _loop
    if _loop is None:
        _loop = asyncio.new_event_loop()
    return _loop.run_until_complete(coro)


def _uuid(message: dict[str, Any] | None, name: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(str((message or {})[name]))
    except (KeyError, ValueError):
        log.warning("mail task missing valid %s", name)
        return None


@celery_app.task(name=MAIL_SEND)  # type: ignore[untyped-decorator]
def mail_send(message: dict[str, Any]) -> None:
    outbox_id = _uuid(message, "outbox_id")
    if outbox_id is None:
        return
    run(worker.process_outbox(outbox_id))


@celery_app.task(name=MAIL_SWEEP)  # type: ignore[untyped-decorator]
def mail_sweep(message: dict[str, Any] | None = None) -> None:
    recovered, republished = run(worker.sweep())
    if recovered or republished:
        log.info("mail.sweep complete: %d recovered, %d republished", recovered, republished)
