"""`report.render` (phase 1 skeleton): every valid message is answered with
`ReportRenderedV1{status: failed, error_code: not_implemented}` on the ingest queue.

Phase 4 replaces `render` with the real flow (prepare /work, download and verify the
snapshot, sandboxed render subprocess, output checks, presigned POST upload). An invalid
message carries no usable token and is dropped (ids only in the logs, never URLs).
"""

import logging
from collections.abc import Callable, Mapping
from typing import Any

from cyberlab_jobs import REPORT_RENDER, REPORT_RENDERED
from cyberlab_jobs.report import ReportRenderedV1, ReportRenderMessageV1
from pydantic import ValidationError

from report_worker import config
from report_worker.app import INGEST_QUEUE, celery_app

log = logging.getLogger(__name__)

Send = Callable[[ReportRenderedV1], None]


def render(msg: ReportRenderMessageV1) -> ReportRenderedV1:
    """Phase 4."""
    return ReportRenderedV1(
        render_id=msg.render_id,
        token=msg.token,
        status="failed",
        renderer_version=config.RENDERER_VERSION,
        error_code="not_implemented",
    )


def handle_render(message: Mapping[str, Any], send: Send) -> ReportRenderedV1 | None:
    try:
        msg = ReportRenderMessageV1.model_validate(message)
    except ValidationError:
        log.warning("report.render: invalid message dropped")
        return None
    result = render(msg)
    send(result)
    log.info("report render %s: %s %s", msg.render_id, result.status, result.error_code)
    return result


def send_rendered(result: ReportRenderedV1) -> None:
    celery_app.send_task(
        REPORT_RENDERED, kwargs={"message": result.model_dump(mode="json")}, queue=INGEST_QUEUE
    )


@celery_app.task(name=REPORT_RENDER)  # type: ignore[untyped-decorator]
def report_render(message: dict[str, Any]) -> None:
    handle_render(message, send_rendered)
