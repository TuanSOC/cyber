"""Celery task entry points (sync) bridging into the async ingest code."""

import asyncio
import logging
from collections.abc import Coroutine
from typing import Any

from celery.signals import worker_init
from cyberlab_jobs import (
    CORRELATION_INDEX_PENDING,
    DISK_EXPIRE_EXPORTS,
    DISK_INGEST,
    INGEST_EVENT,
    REAP,
    REPORT_RENDERED,
)

import app.models  # noqa: F401  (register every mapper before the first query)
from app.core.config import get_settings
from app.modules.correlation import indexer as correlation_indexer
from app.modules.disk_forensics import export_service as disk_exports
from app.modules.reports import render_ingest
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
    run(reaper.reap_ti_runs())
    run(reaper.reap_ai_runs())
    run(reaper.reap_report_renders())


# M6: the report renderer's answer (per-render token; phase 4 implements the ingest).
@celery_app.task(name=REPORT_RENDERED)  # type: ignore[untyped-decorator]
def report_rendered(message: dict[str, Any]) -> None:
    run(render_ingest.handle_rendered_message(message))


# M7: the correlation indexer (beat, every 60 s). Bounded per tick (RT19): at most
# CORRELATION_INDEX_BATCH_JOBS jobs and CORRELATION_INDEX_BUDGET_S seconds, because this
# solo-pool worker also ingests results and runs the reaper. Phase 4 implements the indexer.
@celery_app.task(name=CORRELATION_INDEX_PENDING)  # type: ignore[untyped-decorator]
def correlation_index_pending(message: dict[str, Any] | None = None) -> None:
    indexed = run(correlation_indexer.index_pending(get_settings().correlation_index_batch_jobs))
    if indexed:
        log.info("correlation: %d job(s) indexed", indexed)


# M9 (RT9): the disk ingest worker's task (queue `ingest_disk`, its own solo process): the
# report `handle_event` handed off. Same retry policy as `ingest.event`.
@celery_app.task(  # type: ignore[untyped-decorator]
    name=DISK_INGEST,
    autoretry_for=ingest.TRANSIENT_ERRORS,
    retry_backoff=2,
    retry_backoff_max=120,
    max_retries=8,
)
def disk_ingest(message: dict[str, Any]) -> None:
    run(ingest.handle_disk_ingest(message))


# M9 (beat, hourly): unpromoted file exports older than DISK_EXPORT_TTL_S become `expired`
# (phase 10); the retention worker deletes the object versions (phase 9, RT19).
@celery_app.task(name=DISK_EXPIRE_EXPORTS)  # type: ignore[untyped-decorator]
def disk_expire_exports(message: dict[str, Any] | None = None) -> None:
    try:
        expired = run(disk_exports.expire_exports(500))
    except NotImplementedError:
        return  # M9 phase 1: the body lands with phase 10
    if expired:
        log.info("disk exports: %d expired", expired)
