"""One job: validate -> started -> analyze / export -> upload -> finished (M9 phases 1-2; the
calls `run_job(message, config, send)` and `run_export_job(message, config, send)` from
`celery_app.py` are frozen; `analyzer.analyze` (phase 2) and `export.handle_export` (phase 10)
are the bodies they reach).

- A full result is uploaded and reported `succeeded` with its version id.
- A diagnostic stream (`no_supported_filesystem`, `unsupported_disk_format`: header and at most
  the partitions) is uploaded and reported `failed` with that code WITH its version id.
- Any other failure is `failed` with its code and no upload. `sandbox.prepare` runs once per
  job (it resets the whole work dir: no image cache, RT1); every stage then gets a fresh out
  dir (`stage.fresh`, never `prepare` again); `sandbox.cleanup` kills every tool process and
  removes the job dir. A `SandboxCompromised` from a stage has already stopped the container
  (fail closed) and is reported `analyzer_error`.
"""

import logging
from collections.abc import Callable

from celery.exceptions import SoftTimeLimitExceeded
from cyberlab_jobs import IngestEvent, IngestMessageV1, Outcome
from cyberlab_jobs.disk import DiskExportJobV1, DiskJobV1
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed
from cyberlab_worker.transfer import upload
from pydantic import ValidationError

from disk_worker.analyzer import DiagnosticResult, analyze
from disk_worker.config import WORKER_VERSION, Config
from disk_worker.export import handle_export

log = logging.getLogger(__name__)

SendIngest = Callable[[IngestMessageV1], None]


def message(
    job: DiskJobV1 | DiskExportJobV1, event: IngestEvent, **fields: object
) -> IngestMessageV1:
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


def _failed(job: DiskJobV1 | DiskExportJobV1, code: str) -> IngestMessageV1:
    return message(job, IngestEvent.FINISHED, outcome=Outcome.FAILED, error_code=code)


def run_job(raw: object, config: Config, send: SendIngest) -> None:
    try:
        job = DiskJobV1.model_validate(raw)
    except ValidationError:
        log.error("dropping invalid disk job message")  # nothing to report it against
        return

    send(message(job, IngestEvent.STARTED))
    dirs: sandbox.JobDirs | None = None
    try:
        dirs = sandbox.prepare(config.work_dir, str(job.job_id))
        try:
            result = analyze(job, dirs, config)
        except DiagnosticResult as diagnostic:
            version_id = upload(job.result_post, diagnostic.path)
            send(
                message(
                    job,
                    IngestEvent.FINISHED,
                    outcome=Outcome.FAILED,
                    error_code=diagnostic.code,
                    result_version_id=version_id,
                )
            )
            return
        version_id = upload(job.result_post, result)
        send(
            message(
                job, IngestEvent.FINISHED, outcome=Outcome.SUCCEEDED, result_version_id=version_id
            )
        )
    except JobFailed as exc:
        log.warning("disk job %s failed: %s", job.job_id, exc)
        send(_failed(job, exc.code))
    except SoftTimeLimitExceeded:
        send(_failed(job, "timed_out"))
    except Exception:
        log.exception("disk job %s crashed", job.job_id)
        send(_failed(job, "analyzer_error"))
    finally:
        sandbox.cleanup(dirs)


def run_export_job(raw: object, config: Config, send: SendIngest) -> None:
    """`disk.export` (profile `extract`, phase 10): the same envelope around `handle_export`."""
    try:
        job = DiskExportJobV1.model_validate(raw)
    except ValidationError:
        log.error("dropping invalid disk export message")
        return

    send(message(job, IngestEvent.STARTED))
    try:
        handle_export(job)
    except JobFailed as exc:
        log.warning("disk export job %s failed: %s", job.job_id, exc)
        send(_failed(job, exc.code))
    except SoftTimeLimitExceeded:
        send(_failed(job, "timed_out"))
    except Exception:
        log.exception("disk export job %s crashed", job.job_id)
        send(_failed(job, "analyzer_error"))
