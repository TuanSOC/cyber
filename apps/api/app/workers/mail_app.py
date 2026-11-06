"""Celery app of the least-privilege mail delivery worker (M11 phase 2).

Run as `celery -A app.workers.mail_app worker -Q mail --pool solo --without-gossip
--without-mingle --without-heartbeat`. Its broker user (`mail`) may only touch
`mail*` / `test.mail*` keys, so everything Celery keeps on the broker is named
under `{prefix}mail`: the queue and the unacked bookkeeping. Remote control and
task events are off.

Its DB role is `cyberlab_mail` (SELECT/UPDATE on `email_outbox` only; RT9).
Settings refuses JWT secrets, MinIO credentials, and any sealing keys other than
`MAIL_SEAL_PRIVATE_KEYS_FILE`.
"""

from celery import Celery

from app.core.config import get_settings
from app.modules.mail.outbox import mail_queue

_settings = get_settings()
_queue = mail_queue()

celery_app = Celery(
    "cyberlab-mail",
    broker=_settings.broker_url,
    include=["app.workers.mail_tasks"],
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_ignore_result=True,
    task_default_queue=_queue,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    worker_enable_remote_control=False,
    worker_send_task_events=False,
    task_send_sent_event=False,
    worker_hijack_root_logger=False,
    broker_connection_retry_on_startup=True,
    broker_transport_options={
        "visibility_timeout": 3600,
        "unacked_key": f"{_queue}.unacked",
        "unacked_index_key": f"{_queue}.unacked_index",
        "unacked_mutex_key": f"{_queue}.unacked_mutex",
        "socket_timeout": 5,
        "socket_connect_timeout": 3,
    },
    broker_connection_timeout=3,
    broker_connection_max_retries=1,
)
