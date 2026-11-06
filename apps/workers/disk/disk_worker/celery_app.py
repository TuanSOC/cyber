"""Celery app of the untrusted disk analyzer (M9 phase 1, FROZEN).

Acks early: an image that crashes or OOM-kills the worker is never redelivered (the job fails
via the reaper instead of looping). One task per child process, one child at a time
(`--concurrency 1 --max-tasks-per-child 1`, the image CMD). The queue comes from the env
(`QUEUE_PREFIX` + `disk`); the broker ACL user `disk` may touch only `disk*` keys and add (never
read) ingest reports. Two tasks: `disk.analyze` (`disk.v1`) and `disk.export` (`disk-export.v1`).
"""

import logging
import sys
from typing import Any

from celery import Celery
from celery.signals import worker_process_init
from cyberlab_jobs import DISK_ANALYZE, DISK_EXPORT, INGEST_EVENT, IngestMessageV1, Queues
from cyberlab_worker import sandbox
from kombu import Exchange, Queue  # type: ignore[attr-defined]

from disk_worker import config, pipeline

# httpx logs full request URLs at INFO: presigned URLs are bearer credentials.
logging.getLogger("httpx").setLevel(logging.WARNING)

# A refused configuration (e.g. `DISK_TIMELINE_ENGINE=replay` outside the test profile) stops
# the worker before it consumes anything: EX_CONFIG (78).
try:
    CONFIG = config.load()
except config.ConfigError as exc:
    print(f"disk-worker: refused configuration: {exc}", file=sys.stderr)
    sys.exit(78)
queues = Queues(CONFIG.queue_prefix)

celery_app = Celery("cyberlab-disk", broker=CONFIG.broker_url)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_ignore_result=True,
    task_default_queue=queues.disk,
    task_acks_late=False,
    worker_prefetch_multiplier=1,
    worker_enable_remote_control=False,
    worker_hijack_root_logger=False,
    broker_connection_retry_on_startup=True,
    # Own unacked bookkeeping keys: the broker ACL confines this user to `disk*` keys.
    broker_transport_options={
        "unacked_key": f"{queues.disk}.unacked",
        "unacked_index_key": f"{queues.disk}.unacked_index",
        "unacked_mutex_key": f"{queues.disk}.unacked_mutex",
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
    """A new child (after a crash or hard time limit) starts from a clean work volume (no image
    cache survives: RT1)."""
    sandbox.reset(CONFIG.work_dir)


def send_ingest(message: IngestMessageV1) -> None:
    celery_app.send_task(
        INGEST_EVENT, kwargs={"message": message.model_dump(mode="json")}, queue=INGEST_QUEUE
    )


@celery_app.task(name=DISK_ANALYZE)  # type: ignore[untyped-decorator]
def analyze(message: dict[str, Any]) -> None:
    pipeline.run_job(message, CONFIG, send_ingest)


@celery_app.task(name=DISK_EXPORT)  # type: ignore[untyped-decorator]
def export(message: dict[str, Any]) -> None:
    pipeline.run_export_job(message, CONFIG, send_ingest)
