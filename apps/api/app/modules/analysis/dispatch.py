"""Build the versioned job message and hand it to the broker (after the job row commits).

The analyzer receives no credentials: a presigned GET for the exact evidence version and a
presigned POST policy (fixed key, size-capped) for its result. Both are signed for the
internal MinIO endpoint and expire with the job's queue TTL.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import anyio
from cyberlab_jobs import PCAP_ANALYZE, JobLimits, PcapJobV1, PresignedPost, Queues
from minio.datatypes import PostPolicy

from app.core.clients import get_minio
from app.core.config import Settings, get_settings
from app.core.threads import broker_limiter


@dataclass(frozen=True)
class DispatchInput:
    job_id: uuid.UUID
    organization_id: uuid.UUID
    evidence_id: uuid.UUID
    storage_bucket: str
    storage_key: str
    storage_version_id: str
    sha256: str
    size_bytes: int
    ingest_token: str


def result_key(organization_id: uuid.UUID, job_id: uuid.UUID) -> str:
    """The only key an analyzer may write for a job; ingest re-derives it, never trusts one."""
    return f"results/{organization_id}/{job_id}.ndjson.gz"


def limits(settings: Settings) -> JobLimits:
    return JobLimits(
        max_bytes=settings.pcap_max_bytes,
        timeout_s=settings.analysis_timeout_s,
        tool_timeout_s=settings.analysis_tool_timeout_s,
        max_flows=settings.analysis_max_flows,
        max_records_per_kind=settings.analysis_max_records_per_kind,
        max_findings=settings.analysis_max_findings,
        max_result_bytes=settings.analysis_max_result_bytes,
    )


def build_message(item: DispatchInput) -> PcapJobV1:
    """Blocking (MinIO region lookup on first use): call from a worker thread."""
    settings = get_settings()
    minio = get_minio()
    ttl = timedelta(seconds=settings.analysis_queue_ttl_s)
    evidence_url = minio.presigned_get_object(
        item.storage_bucket, item.storage_key, expires=ttl, version_id=item.storage_version_id
    )
    key = result_key(item.organization_id, item.job_id)
    policy = PostPolicy(
        settings.results_bucket,
        datetime.now(UTC) + ttl + timedelta(seconds=settings.analysis_timeout_s),
    )
    policy.add_equals_condition("key", key)
    policy.add_content_length_range_condition(0, settings.analysis_max_result_bytes)
    fields = {**minio.presigned_post_policy(policy), "key": key}
    scheme = "https" if settings.minio_secure else "http"
    return PcapJobV1(
        job_id=item.job_id,
        organization_id=item.organization_id,
        evidence_id=item.evidence_id,
        expected_sha256=item.sha256,
        size_bytes=item.size_bytes,
        evidence_url=evidence_url,
        result_post=PresignedPost(
            url=f"{scheme}://{settings.minio_endpoint}/{settings.results_bucket}", fields=fields
        ),
        ingest_token=item.ingest_token,
        limits=limits(settings),
    )


def _send_sync(item: DispatchInput) -> None:
    from app.workers.celery_app import celery_app  # broker client only, no worker

    settings = get_settings()
    message = build_message(item)
    timeout = settings.analysis_timeout_s
    celery_app.send_task(
        PCAP_ANALYZE,
        kwargs={"message": message.model_dump(mode="json")},
        queue=Queues(settings.queue_prefix).pcap,
        # Never run a job whose URLs have expired; soft limit leaves room for cleanup.
        expires=settings.analysis_queue_ttl_s,
        soft_time_limit=timeout + 60,
        time_limit=timeout + 90,
        retry=True,
        retry_policy={"max_retries": 1, "interval_start": 0, "interval_step": 0.5},
    )


SEND_TIMEOUT_S = 15


async def send(item: DispatchInput) -> None:
    """Publish within a bounded time; on timeout the caller marks the job enqueue_failed.

    An abandoned publish that still completes later only delivers a job whose status is
    already final, which the analyzer's reports then cannot change.
    """
    with anyio.fail_after(SEND_TIMEOUT_S):
        await anyio.to_thread.run_sync(
            _send_sync, item, limiter=broker_limiter(), abandon_on_cancel=True
        )
