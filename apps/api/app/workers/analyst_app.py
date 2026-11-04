"""Celery app of the trusted, internet-facing AI analyst worker (M5).

Run as `celery -A app.workers.analyst_app worker -Q analyst --pool solo --without-gossip
--without-mingle --without-heartbeat`. Its broker user (`analyst`) may only touch `analyst*`
keys, so everything Celery keeps on the broker is named under `{prefix}analyst`: the queue,
the unacked bookkeeping and (phase 2) the limiter and budget keys `{prefix}analyst.ai:*`.
Remote control and task events are off (pidbox / celeryev keys are outside that pattern).

The API never imports this module: it publishes `ai.*` tasks through `celery_app`.
"""

from celery import Celery
from cyberlab_jobs import Queues

from app.core.config import get_settings

_settings = get_settings()
queues = Queues(_settings.queue_prefix)

celery_app = Celery(
    "cyberlab-analyst", broker=_settings.broker_url, include=["app.workers.analyst_tasks"]
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_ignore_result=True,
    task_default_queue=queues.analyst,
    # One message = at most one provider call; the DB lease and the call counter make a
    # redelivery safe (phase 2).
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    worker_enable_remote_control=False,
    worker_send_task_events=False,
    task_send_sent_event=False,
    worker_hijack_root_logger=False,
    broker_connection_retry_on_startup=True,
    broker_transport_options={
        # At least twice the hard call timeout: a long call is never redelivered mid-way.
        "visibility_timeout": max(3600, 2 * _settings.ai_call_timeout_s + 300),
        "unacked_key": f"{queues.analyst}.unacked",
        "unacked_index_key": f"{queues.analyst}.unacked_index",
        "unacked_mutex_key": f"{queues.analyst}.unacked_mutex",
        "socket_timeout": 5,
        "socket_connect_timeout": 3,
    },
    broker_connection_timeout=3,
    broker_connection_max_retries=1,
)
