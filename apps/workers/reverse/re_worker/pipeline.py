"""One job: validate -> started -> analyze -> upload -> finished (M10 phase 1; the call
`run_job(message, config, send)` from `celery_app.py` is frozen, phase 2 owns the body).

- A full result is uploaded and reported `succeeded` with its version id.
- An unsupported architecture or managed (.NET) PE: the analyzer wrote the diagnostic stream
  (header, program, trailer); it is uploaded and reported `failed` with that code WITH its
  version id (the ingest stores `re_programs` only).
- Any other failure is `failed` with its code and no upload. `sandbox.prepare` runs once per
  job (it resets the whole work dir); `sandbox.cleanup` kills every tool process and removes
  the job dir whatever happened.
"""

import logging
from collections.abc import Callable

from celery.exceptions import SoftTimeLimitExceeded
from cyberlab_jobs import IngestEvent, IngestMessageV1, Outcome
from cyberlab_jobs.reverse import ReJobV1
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed
from cyberlab_worker.transfer import upload
from pydantic import ValidationError

from re_worker.analyzer import DiagnosticResult, analyze
from re_worker.config import WORKER_VERSION, Config

log = logging.getLogger(__name__)

SendIngest = Callable[[IngestMessageV1], None]


def message(job: ReJobV1, event: IngestEvent, **fields: object) -> IngestMessageV1:
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


def run_job(raw: object, config: Config, send: SendIngest) -> None:
    try:
        job = ReJobV1.model_validate(raw)
    except ValidationError:
        log.error("dropping invalid job message")  # nothing to report it against
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
        log.warning("job %s failed: %s", job.job_id, exc)
        send(message(job, IngestEvent.FINISHED, outcome=Outcome.FAILED, error_code=exc.code))
    except SoftTimeLimitExceeded:
        send(message(job, IngestEvent.FINISHED, outcome=Outcome.FAILED, error_code="timed_out"))
    except Exception:
        log.exception("job %s crashed", job.job_id)
        send(
            message(job, IngestEvent.FINISHED, outcome=Outcome.FAILED, error_code="analyzer_error")
        )
    finally:
        sandbox.cleanup(dirs)
