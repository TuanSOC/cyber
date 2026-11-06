"""Celery app of the untrusted reverse-engineering analyzer (M10 phase 1, FROZEN).

Acks early: a sample that crashes or OOM-kills the worker is never redelivered (the job fails
via the reaper instead of looping). One task per child process, one child at a time
(`--concurrency 1 --max-tasks-per-child 1`, the image CMD). The queue comes from the env
(`QUEUE_PREFIX` + `reverse`); the broker ACL user `reverse` may touch only `reverse*` keys and
add (never read) ingest reports.
"""

import logging
import sys
from typing import Any

from celery import Celery
from celery.signals import worker_process_init
from cyberlab_jobs import INGEST_EVENT, RE_ANALYZE, IngestMessageV1, Queues
from cyberlab_worker import sandbox
from kombu import Exchange, Queue  # type: ignore[attr-defined]

from re_worker import config, pipeline

# httpx logs full request URLs at INFO: presigned URLs are bearer credentials.
logging.getLogger("httpx").setLevel(logging.WARNING)

# A refused configuration (e.g. `RE_ENGINE=replay` outside the test profile) stops the worker
# before it consumes anything: EX_CONFIG (78).
try:
    CONFIG = config.load()
except config.ConfigError as exc:
    print(f"re-worker: refused configuration: {exc}", file=sys.stderr)
    sys.exit(78)
queues = Queues(CONFIG.queue_prefix)

celery_app = Celery("cyberlab-reverse", broker=CONFIG.broker_url)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_ignore_result=True,
    task_default_queue=queues.reverse,
    task_acks_late=False,
    worker_prefetch_multiplier=1,
    worker_enable_remote_control=False,
    worker_hijack_root_logger=False,
    broker_connection_retry_on_startup=True,
    # Soft limit: `pipeline.run_job` reports `failed / timed_out` and cleans up; the hard
    # limit kills the child (a new one resets /work). Per-task limits from the API win.
    task_soft_time_limit=config.TASK_SOFT_TIME_LIMIT_S,
    task_time_limit=config.TASK_TIME_LIMIT_S,
    # Own unacked bookkeeping keys: the broker ACL confines this user to `reverse*` keys.
    broker_transport_options={
        "unacked_key": f"{queues.reverse}.unacked",
        "unacked_index_key": f"{queues.reverse}.unacked_index",
        "unacked_mutex_key": f"{queues.reverse}.unacked_mutex",
        "socket_timeout": 10,
        "socket_connect_timeout": 5,
    },
)

# Publish-only handle on the ingest queue: never declared from here (the ACL makes kombu's
# bindings read-only for this user; the ingest worker declares them).
INGEST_QUEUE = Queue(  # type: ignore[no-untyped-call]
    queues.ingest,
    Exchange(queues.ingest, type="direct"),  # type: ignore[no-untyped-call]
    routing_key=queues.ingest,
    no_declare=True,
)


@worker_process_init.connect  # type: ignore[untyped-decorator]
def _fresh_sandbox(**_: object) -> None:
    """A new child (after a crash or hard time limit) starts from a clean work volume."""
    sandbox.reset(CONFIG.work_dir)


def send_ingest(message: IngestMessageV1) -> None:
    celery_app.send_task(
        INGEST_EVENT, kwargs={"message": message.model_dump(mode="json")}, queue=INGEST_QUEUE
    )


@celery_app.task(name=RE_ANALYZE)  # type: ignore[untyped-decorator]
def analyze(message: dict[str, Any]) -> None:
    pipeline.run_job(message, CONFIG, send_ingest)
