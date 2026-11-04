"""One job: fetch -> verify -> analyze (tools as the tool uid) -> upload -> report."""

import logging
from collections.abc import Callable
from pathlib import Path

from celery.exceptions import SoftTimeLimitExceeded
from cyberlab_jobs import IngestEvent, IngestMessageV1, Outcome, PcapJobV1
from cyberlab_jobs.capture import capture_format, compression
from cyberlab_jobs.results import ResultHeader
from pydantic import ValidationError

from pcap_worker import sandbox
from pcap_worker.config import WORKER_VERSION, Config, tool_versions
from pcap_worker.errors import JobFailed
from pcap_worker.result_writer import ResultWriter
from pcap_worker.transfer import download, upload

log = logging.getLogger(__name__)

SendIngest = Callable[[IngestMessageV1], None]


def _message(job: PcapJobV1, event: IngestEvent, **fields: object) -> IngestMessageV1:
    return IngestMessageV1.model_validate(
        {
            "job_id": job.job_id,
            "organization_id": job.organization_id,
            "ingest_token": job.ingest_token,
            "event": event,
            "worker_version": WORKER_VERSION,
            **fields,
        }
    )


def _check_format(capture: Path) -> str:
    with open(capture, "rb") as f:
        head = f.read(16)
    fmt = capture_format(head)
    if fmt is None:
        packed = compression(head)
        raise JobFailed("unsupported_capture_format", f"compressed ({packed})" if packed else "")
    return fmt


def analyze(job: PcapJobV1, dirs: sandbox.JobDirs) -> Path:
    """Phase-1 analyzer: proves the sandbox path end to end (tool reads the capture)."""
    download(job, dirs.capture)
    fmt = _check_format(dirs.capture)
    try:
        sandbox.run_tool(
            ["sha256sum", str(dirs.capture)],
            dirs,
            timeout_s=job.limits.tool_timeout_s,
            stdout_name="sha256.txt",
        )
    except sandbox.ToolTimeout as exc:
        raise JobFailed("tool_timeout", "sha256sum") from exc
    except sandbox.ToolFailed as exc:
        raise JobFailed("tool_failed", exc.stderr_tail[-200:]) from exc
    with sandbox.open_output(dirs, "sha256.txt") as f:
        seen = f.read(128).split(b" ", 1)[0].decode("ascii", "replace")
    if seen != job.expected_sha256:
        raise JobFailed("integrity_mismatch", "tool saw different bytes")

    result = dirs.root / "result.ndjson.gz"
    with ResultWriter(result) as writer:
        writer.write(
            ResultHeader(job_id=job.job_id, capture_format=fmt, tool_versions=tool_versions())
        )
    if result.stat().st_size > job.limits.max_result_bytes:
        raise JobFailed("result_too_large")
    return result


def run_job(raw: object, config: Config, send: SendIngest) -> None:
    try:
        job = PcapJobV1.model_validate(raw)
    except ValidationError:
        log.error("dropping invalid job message")  # nothing to report it against
        return

    send(_message(job, IngestEvent.STARTED))
    dirs: sandbox.JobDirs | None = None
    try:
        dirs = sandbox.prepare(config.work_dir, str(job.job_id))
        result = analyze(job, dirs)
        version_id = upload(job.result_post, result)
        send(
            _message(
                job, IngestEvent.FINISHED, outcome=Outcome.SUCCEEDED, result_version_id=version_id
            )
        )
    except JobFailed as exc:
        log.warning("job %s failed: %s", job.job_id, exc)
        send(_message(job, IngestEvent.FINISHED, outcome=Outcome.FAILED, error_code=exc.code))
    except SoftTimeLimitExceeded:
        send(_message(job, IngestEvent.FINISHED, outcome=Outcome.FAILED, error_code="timed_out"))
    except Exception:
        log.exception("job %s crashed", job.job_id)
        send(
            _message(job, IngestEvent.FINISHED, outcome=Outcome.FAILED, error_code="analyzer_error")
        )
    finally:
        sandbox.cleanup(dirs)
