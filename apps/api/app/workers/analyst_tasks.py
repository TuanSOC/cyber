"""Celery task entry points of the analyst worker (sync) bridging into `analyst.py`.

`ai.run` makes progress on one run (at most one provider call per message, RT2), `ai.resume`
re-sends due runs, `ai.verify` checks one stored key. The solo pool runs one message at a
time on one persistent event loop; `worker_init` refuses to start without a usable AI key
pair. Return values are always None.
"""

import asyncio
import logging
from collections.abc import Coroutine
from typing import Any

from celery.signals import worker_init
from cyberlab_jobs import AI_RESUME, AI_RUN, AI_VERIFY

import app.models  # noqa: F401  (register every mapper before the first query)
from app.core.config import get_settings
from app.workers import analyst
from app.workers.analyst_app import celery_app

log = logging.getLogger(__name__)


@worker_init.connect  # type: ignore[untyped-decorator]
def _check_keys(**_: Any) -> None:
    # Celery logs and swallows exceptions raised by signal handlers: exit instead, so a
    # worker that could never open a key does not consume runs.
    try:
        analyst.check_startup(get_settings())
    except Exception as exc:
        log.critical("analyst worker cannot start: %s", exc)
        raise SystemExit(1) from exc


# One loop for the life of the (solo-pool) worker: the async engine's pool is bound to it.
_loop: asyncio.AbstractEventLoop | None = None


def run[T](coro: Coroutine[Any, Any, T]) -> T:
    global _loop
    if _loop is None:
        _loop = asyncio.new_event_loop()
    return _loop.run_until_complete(coro)


@celery_app.task(name=AI_RUN)  # type: ignore[untyped-decorator]
def ai_run(message: dict[str, Any]) -> None:
    run(analyst.handle_run(message))


@celery_app.task(name=AI_RESUME)  # type: ignore[untyped-decorator]
def ai_resume(message: dict[str, Any] | None = None) -> None:
    run(analyst.handle_resume(message))


@celery_app.task(name=AI_VERIFY)  # type: ignore[untyped-decorator]
def ai_verify(message: dict[str, Any]) -> None:
    run(analyst.handle_verify(message))
