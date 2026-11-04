"""Celery app of the trusted side.

Imported by the API only to enqueue (`send_task`); run as the ingest worker with
`celery -A app.workers.celery_app worker` (consumes the ingest queue, embeds the reaper beat).
"""

from celery import Celery
from cyberlab_jobs import REAP, TI_RESUME, Queues

from app.core.config import get_settings

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
    },
)
