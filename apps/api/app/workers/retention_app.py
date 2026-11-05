"""Celery app of the least-privilege retention worker (M7).

Run as `celery -A app.workers.retention_app worker -Q retention --pool solo --without-gossip
--without-mingle --without-heartbeat`. Its broker user (`retention`) may only touch
`retention*` keys, so everything Celery keeps on the broker is named under
`{prefix}retention`: the queue and the unacked bookkeeping. Remote control and task events
are off (they use pidbox / celeryev keys outside that pattern).

Its DB role is `cyberlab_retention` (NOBYPASSRLS, per-org tenant sessions) and its MinIO user
`cyberlab-purge`; Settings refuses the JWT secret, the app Redis, the api MinIO user and every
seal, signing or platform key for `PROCESS_ROLE=retention`. The API and the ingest beat
publish `retention.*` tasks through `celery_app`; they never import this module.
"""

from celery import Celery
from cyberlab_jobs import Queues

from app.core.config import get_settings

_settings = get_settings()
queues = Queues(_settings.queue_prefix)

celery_app = Celery(
    "cyberlab-retention", broker=_settings.broker_url, include=["app.workers.retention_tasks"]
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_ignore_result=True,
    task_default_queue=queues.retention,
    # A run is resumable (advisory lock per org, idempotent tombstones), so redelivery is safe.
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    worker_enable_remote_control=False,
    worker_send_task_events=False,
    task_send_sent_event=False,
    worker_hijack_root_logger=False,
    broker_connection_retry_on_startup=True,
    broker_transport_options={
        "visibility_timeout": 3600,
        "unacked_key": f"{queues.retention}.unacked",
        "unacked_index_key": f"{queues.retention}.unacked_index",
        "unacked_mutex_key": f"{queues.retention}.unacked_mutex",
        "socket_timeout": 5,
        "socket_connect_timeout": 3,
    },
    broker_connection_timeout=3,
    broker_connection_max_retries=1,
)
