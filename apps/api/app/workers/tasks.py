"""Celery task entry points (sync) bridging into the async ingest code."""

import asyncio
from collections.abc import Coroutine
from typing import Any

from cyberlab_jobs import INGEST_EVENT, REAP

import app.models  # noqa: F401  (register every mapper before the first query)
from app.workers import ingest, reaper
from app.workers.celery_app import celery_app

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
