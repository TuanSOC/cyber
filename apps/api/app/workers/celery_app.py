"""Celery app of the trusted side.

Imported by the API only to enqueue (`send_task`); run as the ingest worker with
`celery -A app.workers.celery_app worker` (consumes the ingest queue, embeds the reaper beat).
"""

from celery import Celery
from celery.schedules import crontab
from cyberlab_jobs import (
    AI_RESUME,
    CORRELATION_INDEX_PENDING,
    DISK_EXPIRE_EXPORTS,
    REAP,
    RETENTION_SWEEP,
    TI_RESUME,
    Queues,
)

from app.core.config import get_settings
from app.modules.mail.outbox import MAIL_QUEUE, MAIL_SWEEP

_settings = get_settings()
queues = Queues(_settings.queue_prefix)

celery_app = Celery("cyberlab", broker=_settings.broker_url, include=["app.workers.tasks"])
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_ignore_result=True,
    # The worker consumes the default queue (created on demand).
    task_default_queue=queues.ingest,
    # Ingest handlers are idempotent (guarded transitions), so redelivery is safe.
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    worker_enable_remote_control=False,
    worker_hijack_root_logger=False,
    broker_connection_retry_on_startup=True,
    broker_transport_options={
        "visibility_timeout": 3600,
        # Trusted-side bookkeeping keys, outside every pattern the analyzer's ACL user may touch.
        "unacked_key": f"{_settings.queue_prefix}trusted.unacked",
        "unacked_index_key": f"{_settings.queue_prefix}trusted.unacked_index",
        "unacked_mutex_key": f"{_settings.queue_prefix}trusted.unacked_mutex",
        # Publishing happens after a commit inside a request: never hang on a stalled broker.
        "socket_timeout": 5,
        "socket_connect_timeout": 3,
    },
    broker_connection_timeout=3,
    broker_connection_max_retries=1,
    beat_schedule={
        "reap-stale-analysis-jobs": {
            "task": REAP,
            "schedule": 60.0,
            "options": {"queue": queues.ingest, "expires": 55},
        },
        # Threat intel (M4, RT8): re-send due waiting runs and lost messages to the enrich
        # worker (no Celery ETA/countdown anywhere). Expires before the next tick.
        "resume-ti-runs": {
            "task": TI_RESUME,
            "schedule": 30.0,
            "kwargs": {"message": {}},
            "options": {"queue": queues.enrich, "expires": 25},
        },
        # AI analyst (M5): the same resume loop for the analyst worker's runs.
        "resume-ai-runs": {
            "task": AI_RESUME,
            "schedule": 30.0,
            "kwargs": {"message": {}},
            "options": {"queue": queues.analyst, "expires": 25},
        },
        # M7: the correlation indexer on this (ingest) worker, bounded per tick (RT19).
        "index-correlation-keys": {
            "task": CORRELATION_INDEX_PENDING,
            "schedule": 60.0,
            "kwargs": {"message": {}},
            "options": {"queue": queues.ingest, "expires": 55},
        },
        # M9: unpromoted disk file exports expire (phase 10; the retention worker deletes the
        # objects, RT19). Hourly, on this (ingest) worker.
        "expire-disk-exports": {
            "task": DISK_EXPIRE_EXPORTS,
            "schedule": 3600.0,
            "kwargs": {"message": {}},
            "options": {"queue": queues.ingest, "expires": 3500},
        },
        # M7: the daily retention sweep on the retention worker (dry-run unless the DB says
        # enforce is effective, RT1). Expires before the next day's tick.
        "retention-sweep": {
            "task": RETENTION_SWEEP,
            "schedule": crontab(hour="2", minute="30"),
            "kwargs": {"message": {}},
            "options": {"queue": queues.retention, "expires": 23 * 3600},
        },
        # M11: the mail worker's sweep (phase 2 implements it): re-publishes due `pending`
        # outbox rows and fails rows after MAIL_MAX_ATTEMPTS. Expires before the next tick.
        "mail-sweep": {
            "task": MAIL_SWEEP,
            "schedule": 60.0,
            "kwargs": {"message": {}},
            "options": {"queue": f"{_settings.queue_prefix}{MAIL_QUEUE}", "expires": 55},
        },
    },
)
