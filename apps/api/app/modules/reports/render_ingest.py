"""`report.rendered` in the trusted ingest worker (frozen entry point of M6 phase 1;
implemented by phase 4).

Phase 4: find the org through `report_render_index` (system session), check the token hash
and the `queued` / `running` state, re-hash the uploaded object version from MinIO (never
trusting the message's `sha256` / `bytes`), check the magic, set the per-object GOVERNANCE
retention, mark the render `succeeded` / `failed`, audit. Ingest never parses the artifact
(RT27). Allowlisted in `tests/unit/test_tenant_session_guard.py` (org from the index).

Until then the message is validated and dropped (the render stays `queued`; the reaper
fails it at its deadline).
"""

import logging
from collections.abc import Mapping
from typing import Any

from cyberlab_jobs.report import ReportRenderedV1
from pydantic import ValidationError

log = logging.getLogger(__name__)


async def handle_rendered(msg: ReportRenderedV1) -> None:
    """Phase 4."""
    log.warning("report render %s: ingest not implemented yet (%s)", msg.render_id, msg.status)


async def handle_rendered_message(message: Mapping[str, Any]) -> None:
    """The Celery entry point: validate, then `handle_rendered` (ids only in the logs)."""
    try:
        msg = ReportRenderedV1.model_validate(message)
    except ValidationError:
        log.warning("report.rendered: invalid message dropped")
        return
    await handle_rendered(msg)
