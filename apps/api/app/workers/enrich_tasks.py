"""Celery task entry points of the enrich worker (sync) bridging into `enrich.py`.

Return values are always None (Celery would log them).
"""

import asyncio
import logging
from collections.abc import Coroutine
from typing import Any

from celery.signals import worker_init
from cyberlab_jobs import TI_ENRICH, TI_RESUME, TI_VERIFY

import app.models  # noqa: F401  (register every mapper before the first query)
from app.core.config import get_settings
from app.workers import enrich
from app.workers.enrich_app import celery_app

log = logging.getLogger(__name__)

# httpx logs request lines at INFO; headers and bodies are never logged anywhere (RT11).
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


@worker_init.connect  # type: ignore[untyped-decorator]
def _check_keys(**_: Any) -> None:
    # Celery logs and swallows exceptions raised by signal handlers: exit instead, so a
    # worker that could never open a key does not consume runs.
    try:
        enrich.check_startup(get_settings())
    except Exception as exc:
        log.critical("enrich worker cannot start: %s", exc)
        raise SystemExit(1) from exc


# One loop for the life of the (solo-pool) worker: the async engine's pool is bound to it.
_loop: asyncio.AbstractEventLoop | None = None


def run[T](coro: Coroutine[Any, Any, T]) -> T:
    global _loop
    if _loop is None:
        _loop = asyncio.new_event_loop()
    return _loop.run_until_complete(coro)


@celery_app.task(name=TI_ENRICH)  # type: ignore[untyped-decorator]
def ti_enrich(message: dict[str, Any]) -> None:
    run(enrich.handle_enrich(message))


@celery_app.task(name=TI_RESUME)  # type: ignore[untyped-decorator]
def ti_resume(message: dict[str, Any] | None = None) -> None:
    run(enrich.handle_resume(message))


@celery_app.task(name=TI_VERIFY)  # type: ignore[untyped-decorator]
def ti_verify(message: dict[str, Any]) -> None:
    run(enrich.handle_verify(message))
