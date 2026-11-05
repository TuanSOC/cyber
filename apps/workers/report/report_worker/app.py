"""Celery app of the untrusted report renderer (M6).

Run with the analyzers' command line: prefork `--concurrency 1 --max-tasks-per-child 1`
(the solo pool enforces neither the child recycling nor the hard time limit, RT4), so every
render gets a fresh child and one tenant's render never shares a process with the next.
Acks early (a render that crashes the child is never redelivered; the reaper fails it).
Remote control and events are off.
"""

import logging

from celery import Celery
from celery.signals import worker_process_init
from cyberlab_jobs import Queues
from cyberlab_worker import sandbox
from kombu import Exchange, Queue  # type: ignore[attr-defined]

from report_worker import config

# httpx logs full request URLs at INFO: presigned URLs are bearer credentials.
logging.getLogger("httpx").setLevel(logging.WARNING)

CONFIG = config.load()
queues = Queues(CONFIG.queue_prefix)

celery_app = Celery("cyberlab-report", broker=CONFIG.broker_url, include=["report_worker.tasks"])
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_ignore_result=True,
    task_default_queue=queues.report,
    task_acks_late=False,
    task_soft_time_limit=config.TASK_SOFT_TIME_LIMIT_S,
    task_time_limit=config.TASK_TIME_LIMIT_S,
    worker_prefetch_multiplier=1,
    worker_concurrency=1,
    worker_max_tasks_per_child=1,
    worker_enable_remote_control=False,
    worker_send_task_events=False,
    task_send_sent_event=False,
    worker_hijack_root_logger=False,
    broker_connection_retry_on_startup=True,
    # Own unacked bookkeeping keys: the broker ACL confines this user to `report*` keys.
    broker_transport_options={
        "unacked_key": f"{queues.report}.unacked",
        "unacked_index_key": f"{queues.report}.unacked_index",
        "unacked_mutex_key": f"{queues.report}.unacked_mutex",
        "socket_timeout": 10,
        "socket_connect_timeout": 5,
    },
)

# Publish-only handle on the ingest queue (never declared from here: the ACL makes kombu's
# bindings read-only for this user; the ingest worker declares them).
INGEST_QUEUE = Queue(  # type: ignore[no-untyped-call]
    queues.ingest,
    Exchange(queues.ingest, type="direct"),  # type: ignore[no-untyped-call]
    routing_key=queues.ingest,
    no_declare=True,
)


@worker_process_init.connect  # type: ignore[untyped-decorator]
def _fresh_sandbox(**_: object) -> None:
    """A new child (after a crash or the hard time limit) starts from a clean work dir."""
    sandbox.reset(CONFIG.work_dir)
