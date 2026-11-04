"""Celery app of the untrusted analyzer.

Acks early: a capture that crashes or OOM-kills the worker is never redelivered (the job
fails via the reaper instead of looping). One task per child process, one child at a time.
"""

import logging
from typing import Any

from celery import Celery
from celery.signals import worker_process_init
from cyberlab_jobs import INGEST_EVENT, PCAP_ANALYZE, IngestMessageV1, Queues
from cyberlab_worker import sandbox
from kombu import Exchange, Queue  # type: ignore[attr-defined]

from pcap_worker import config, pipeline

# httpx logs full request URLs at INFO: presigned URLs are bearer credentials.
logging.getLogger("httpx").setLevel(logging.WARNING)

CONFIG = config.load()
queues = Queues(CONFIG.queue_prefix)

celery_app = Celery("cyberlab-pcap", broker=CONFIG.broker_url)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_ignore_result=True,
    # The worker consumes the default queue (created on demand).
    task_default_queue=queues.pcap,
    task_acks_late=False,
    worker_prefetch_multiplier=1,
    worker_enable_remote_control=False,
    worker_hijack_root_logger=False,
    broker_connection_retry_on_startup=True,
    # Own unacked bookkeeping keys: the broker ACL confines this user to `pcap*` keys.
    broker_transport_options={
        "unacked_key": f"{queues.pcap}.unacked",
        "unacked_index_key": f"{queues.pcap}.unacked_index",
        "unacked_mutex_key": f"{queues.pcap}.unacked_mutex",
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


@celery_app.task(name=PCAP_ANALYZE)  # type: ignore[untyped-decorator]
def analyze(message: dict[str, Any]) -> None:
    pipeline.run_job(message, CONFIG, send_ingest)
