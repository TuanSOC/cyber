"""One job: fetch -> verify -> analyze (tools as the tool uid) -> upload -> report."""

import logging
from collections.abc import Callable

from celery.exceptions import SoftTimeLimitExceeded
from cyberlab_jobs import IngestEvent, IngestMessageV1, Outcome, PcapJobV1
from pydantic import ValidationError

from pcap_worker import sandbox
from pcap_worker.analyzer import analyze
from pcap_worker.config import WORKER_VERSION, Config
from pcap_worker.errors import JobFailed
from pcap_worker.transfer import upload

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
