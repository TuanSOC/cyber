"""Celery task entry points of the retention worker (sync) bridging into `retention.py`.

Tasks take one keyword argument, `message` (a dict, the repo convention):
- `retention.sweep`: `{}` (beat, daily at 02:30 UTC);
- `retention.run_org`: `{"org_id", "run_id"}` (a manual run requested through the API);
- `retention.sync_holds`: `{"org_id"}` (published by the hold routes after the commit, RT5).
A message carries ids only: the mode and the values always come from the DB (RT1). Return
values are always None (Celery would log them).
"""

import asyncio
import logging
import uuid
from collections.abc import Coroutine
from typing import Any

from cyberlab_jobs import RETENTION_RUN_ORG, RETENTION_SWEEP, RETENTION_SYNC_HOLDS

import app.models  # noqa: F401  (register every mapper before the first query)
from app.workers import retention
from app.workers.retention_app import celery_app

log = logging.getLogger(__name__)

# One loop for the life of the (solo-pool) worker: the async engine's pool is bound to it.
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
        log.warning("retention task without a valid %s: dropped", name)
        return None


@celery_app.task(name=RETENTION_SWEEP)  # type: ignore[untyped-decorator]
def retention_sweep(message: dict[str, Any] | None = None) -> None:
    started = run(retention.sweep())
    log.info("retention sweep: %d run(s) started", started)


@celery_app.task(name=RETENTION_RUN_ORG)  # type: ignore[untyped-decorator]
def retention_run_org(message: dict[str, Any]) -> None:
    org_id, run_id = _uuid(message, "org_id"), _uuid(message, "run_id")
    if org_id is None or run_id is None:
        return
    run(retention.run_org(org_id, run_id))


@celery_app.task(name=RETENTION_SYNC_HOLDS)  # type: ignore[untyped-decorator]
def retention_sync_holds(message: dict[str, Any]) -> None:
    org_id = _uuid(message, "org_id")
    if org_id is None:
        return
    run(retention.sync_holds(org_id))
