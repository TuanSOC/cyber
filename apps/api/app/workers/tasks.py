"""Celery task entry points (sync) bridging into the async ingest code."""

import asyncio
import logging
from collections.abc import Coroutine
from typing import Any

from celery.signals import worker_init
from cyberlab_jobs import INGEST_EVENT, REAP

import app.models  # noqa: F401  (register every mapper before the first query)
from app.core.config import get_settings
from app.workers import ingest, reaper
from app.workers.celery_app import celery_app

log = logging.getLogger(__name__)


@worker_init.connect  # type: ignore[untyped-decorator]
def _prepare_scratch(**_: Any) -> None:
    # Celery logs and swallows exceptions raised by signal handlers: exit instead, so a
    # worker without a usable scratch dir never starts consuming.
    try:
        ingest.prepare_scratch(get_settings())
    except Exception as exc:
        log.critical("ingest worker cannot start: %s", exc)
        raise SystemExit(1) from exc


# One loop for the life of the (solo-pool) worker: the async engine's pool is bound to it.
_loop: asyncio.AbstractEventLoop | None = None


def run[T](coro: Coroutine[Any, Any, T]) -> T:
    global _loop
    if _loop is None:
        _loop = asyncio.new_event_loop()
    return _loop.run_until_complete(coro)


# Transient failures (DB/MinIO restarts) are retried with backoff; the handler is idempotent
# and records permanent failures on the job itself (`ingest_error`).
@celery_app.task(  # type: ignore[untyped-decorator]
    name=INGEST_EVENT,
    autoretry_for=ingest.TRANSIENT_ERRORS,
    retry_backoff=2,
    retry_backoff_max=120,
    max_retries=8,
)
def ingest_event(message: dict[str, Any]) -> None:
    run(ingest.handle_event(message))


@celery_app.task(name=REAP)  # type: ignore[untyped-decorator]
def reap() -> None:
    run(reaper.reap())
