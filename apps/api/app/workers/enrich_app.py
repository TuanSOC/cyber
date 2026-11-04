"""Celery app of the trusted, internet-facing enrich worker (M4).

Run as `celery -A app.workers.enrich_app worker -Q enrich --pool solo --without-gossip
--without-mingle --without-heartbeat`. Its broker user (`enrich`) may only touch `enrich*`
keys, so everything Celery keeps on the broker is named under `{prefix}enrich`: the queue,
the unacked bookkeeping and (phase 2) the limiter keys `{prefix}enrich.ti:*`. Remote control
and task events are off (they use pidbox / celeryev keys outside that pattern, RT7).

The API never imports this module: it publishes `ti.*` tasks through `celery_app`.
"""

from celery import Celery
from cyberlab_jobs import Queues

from app.core.config import get_settings

_settings = get_settings()
queues = Queues(_settings.queue_prefix)

celery_app = Celery(
    "cyberlab-enrich", broker=_settings.broker_url, include=["app.workers.enrich_tasks"]
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_ignore_result=True,
    task_default_queue=queues.enrich,
    # Slices are idempotent (DB lease, ON CONFLICT DO NOTHING), so redelivery is safe.
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    worker_enable_remote_control=False,
    worker_send_task_events=False,
    task_send_sent_event=False,
    worker_hijack_root_logger=False,
    broker_connection_retry_on_startup=True,
    broker_transport_options={
        "visibility_timeout": 3600,
        "unacked_key": f"{queues.enrich}.unacked",
        "unacked_index_key": f"{queues.enrich}.unacked_index",
        "unacked_mutex_key": f"{queues.enrich}.unacked_mutex",
        "socket_timeout": 5,
        "socket_connect_timeout": 3,
    },
    broker_connection_timeout=3,
    broker_connection_max_retries=1,
)
