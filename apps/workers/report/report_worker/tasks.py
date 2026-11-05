"""`report.render`: one signed snapshot -> one rendition, answered on the ingest queue.

1. Validate the message (`ReportRenderMessageV1`) and its deadline (`timeout` once past).
2. `sandbox.prepare` the job dir under /work (it `reset`s first: every uid-10004 process is
   killed and earlier files removed, RT4).
3. Download the snapshot through `transfer.download` (exact size, sha256, the 8 MiB cap):
   anything else is `snapshot_mismatch`. The manifest must name the same sha256, size and
   org.
4. Validate it as `ReportSnapshot`.
5. Write `manifest.json` (the signed bytes), `manifest.sig.json` and `job.json` next to it
   in the root-owned, read-only input dir.
6. Run the sandboxed render subprocess (`report_worker.sandbox`).
7. Check the output (`checks.copy_checked`: magic, UTF-8, size; the page count).
8. Upload it through the presigned POST (fixed key, content type and size range).
9. Answer `ReportRenderedV1`, then clean up.

Every failure is a typed `error_code`; no exception text or URL ever leaves the worker
(logs carry the render id and the code only). An invalid message carries no usable token
and is dropped.
"""

import base64
import json
import logging
import os
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from celery.exceptions import SoftTimeLimitExceeded
from cyberlab_jobs import REPORT_RENDER, REPORT_RENDERED
from cyberlab_jobs.report import (
    MAX_SNAPSHOT_BYTES,
    RENDER_CONTENT_TYPES,
    RENDER_ERROR_CODES,
    Manifest,
    ReportRenderedV1,
    ReportRenderMessageV1,
    ReportSignatureFile,
    canonical_json,
    parse_snapshot,
    rfc3339,
)
from cyberlab_worker import sandbox, transfer
from cyberlab_worker.errors import JobFailed
from pydantic import ValidationError

from report_worker import checks, config
from report_worker import sandbox as render_sandbox
from report_worker.app import CONFIG, INGEST_QUEUE, celery_app

log = logging.getLogger(__name__)

Send = Callable[[ReportRenderedV1], None]
# Transfer codes of the worker kit -> render codes.
_TRANSFER_CODES = {
    "integrity_mismatch": "snapshot_mismatch",
    "evidence_unavailable": "snapshot_mismatch",
    "url_expired": "snapshot_mismatch",
    "snapshot_too_large": "snapshot_mismatch",
    "result_upload_failed": "renderer_error",
}


def _failed(msg: ReportRenderMessageV1, code: str) -> ReportRenderedV1:
    if code not in RENDER_ERROR_CODES:
        code = "renderer_error"
    return ReportRenderedV1(
        render_id=msg.render_id,
        token=msg.token,
        status="failed",
        renderer_version=config.RENDERER_VERSION,
        error_code=code,
    )


def _write_input(path: Path, data: bytes) -> None:
    with open(path, "xb") as f:
        f.write(data)
    os.chmod(path, 0o444)


def _manifest(msg: ReportRenderMessageV1) -> bytes:
    """The signed manifest bytes; they must describe exactly the snapshot to render."""
    raw = base64.b64decode(msg.manifest_b64, validate=True)
    manifest = Manifest.model_validate_json(raw)
    if (
        manifest.snapshot_sha256 != msg.snapshot_sha256
        or manifest.snapshot_bytes != msg.snapshot_bytes
        or manifest.org_id != msg.org_id
        or manifest.kid != msg.kid
    ):
        raise JobFailed("snapshot_mismatch", "manifest does not describe the snapshot")
    return raw


def _prepare_inputs(msg: ReportRenderMessageV1, dirs: sandbox.JobDirs) -> None:
    manifest_raw = _manifest(msg)
    snapshot_path = dirs.input / "snapshot.json"
    transfer.download(
        msg.snapshot_url,
        snapshot_path,
        expected_sha256=msg.snapshot_sha256,
        size_bytes=msg.snapshot_bytes,
        max_bytes=MAX_SNAPSHOT_BYTES,
        too_large_code="snapshot_too_large",
    )
    try:
        snapshot = parse_snapshot(snapshot_path.read_bytes())
    except ValidationError as exc:
        raise JobFailed("snapshot_mismatch", "not a cyberlab.report.v1 snapshot") from exc
    manifest = Manifest.model_validate_json(manifest_raw)
    if (snapshot.report.report_id, snapshot.report.version) != (
        manifest.report_id,
        manifest.version,
    ):
        raise JobFailed("snapshot_mismatch", "snapshot and manifest disagree")
    signature = ReportSignatureFile(kid=msg.kid, manifest=manifest, signature=msg.signature)
    _write_input(dirs.input / "manifest.json", manifest_raw)
    _write_input(dirs.input / "manifest.sig.json", canonical_json(signature))
    job = {
        "format": msg.format,
        "sha256": msg.snapshot_sha256,
        "finalized_at": rfc3339(msg.finalized_at),
    }
    _write_input(dirs.input / "job.json", json.dumps(job).encode())


def render(msg: ReportRenderMessageV1, *, work_dir: Path | None = None) -> ReportRenderedV1:
    if msg.deadline <= datetime.now(UTC):
        return _failed(msg, "timeout")
    dirs: sandbox.JobDirs | None = None
    try:
        dirs = sandbox.prepare(work_dir or CONFIG.work_dir, str(msg.render_id))
        _prepare_inputs(msg, dirs)
        run = render_sandbox.render(msg.format, dirs)
        artifact = checks.copy_checked(dirs, msg.format, dirs.root / "artifact")
        version_id = transfer.upload(
            msg.upload,
            artifact.path,
            filename=checks.OUTPUT_NAMES[msg.format],
            content_type=RENDER_CONTENT_TYPES[msg.format],
        )
        return ReportRenderedV1(
            render_id=msg.render_id,
            token=msg.token,
            status="succeeded",
            sha256=artifact.sha256,
            bytes=artifact.size,
            pages=run.pages,
            object_version_id=version_id,
            renderer_version=config.RENDERER_VERSION,
        )
    except JobFailed as exc:
        return _failed(msg, _TRANSFER_CODES.get(exc.code, exc.code))
    except SoftTimeLimitExceeded:
        return _failed(msg, "timeout")
    except Exception as exc:  # noqa: BLE001 - typed code only, never the text
        log.warning("report render %s: %s", msg.render_id, type(exc).__name__)
        return _failed(msg, "renderer_error")
    finally:
        sandbox.cleanup(dirs)


def handle_render(
    message: Mapping[str, Any], send: Send, *, work_dir: Path | None = None
) -> ReportRenderedV1 | None:
    try:
        msg = ReportRenderMessageV1.model_validate(message)
    except ValidationError:
        log.warning("report.render: invalid message dropped")
        return None
    result = render(msg, work_dir=work_dir)
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
