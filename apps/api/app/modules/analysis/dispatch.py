"""Build the versioned job message and hand it to the broker (after the job row commits).

The analyzer receives no credentials: a presigned GET for the exact evidence version and a
presigned POST policy (fixed key, size-capped) for its result. Both are signed for the
internal MinIO endpoint and expire with the job's queue TTL.

Each analyzer has its own message schema, Celery task and queue (and its own broker ACL
user): `pcap.v1` on `pcap`, `static.v1` on `static`, `memory.v1` on `memory` (M8; the message
is built by `memory_analysis.dispatch.build_memory_message`), `disk.v1` on `disk` (M9; one GET
per segment, `disk_forensics.dispatch.build_disk_message`).
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import anyio
from cyberlab_jobs import (
    DISK_ANALYZE,
    MEMORY_ANALYZE,
    PCAP_ANALYZE,
    STATIC_ANALYZE,
    DiskJobV1,
    JobLimits,
    MemoryJobV1,
    PcapJobV1,
    PresignedPost,
    Queues,
)
from cyberlab_jobs.memory import OsHint
from cyberlab_jobs.static import Profile, StaticJobV1, StaticLimits
from minio.datatypes import PostPolicy

from app.core.clients import get_minio
from app.core.config import Settings, get_settings
from app.core.threads import broker_limiter
from app.modules.analysis import analyzers
from app.modules.analysis.models import Analyzer, JobProfile

JobMessage = PcapJobV1 | StaticJobV1 | MemoryJobV1 | DiskJobV1


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
    analyzer: Analyzer = Analyzer.PCAP
    profile: JobProfile | None = None  # static and memory
    os_hint: OsHint | None = None  # memory and disk (M8 / M9)
    # Disk only (M9 phase 7): the ordered segment set (`disk_forensics.segments.Segment`),
    # ordinal 0 being the evidence above.
    segments: tuple[Any, ...] = ()


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


def static_limits(settings: Settings) -> StaticLimits:
    return StaticLimits(
        max_bytes=settings.static_max_bytes,
        timeout_s=settings.analysis_static_timeout_s,
        tool_timeout_s=settings.analysis_static_tool_timeout_s,
        max_sections=settings.static_max_sections,
        max_imports=settings.static_max_imports,
        max_exports=settings.static_max_exports,
        max_resources=settings.static_max_resources,
        max_strings=settings.static_max_strings,
        max_signature_matches=settings.static_max_signature_matches,
        max_capabilities=settings.static_max_capabilities,
        max_findings=settings.static_max_findings,
        max_iocs=settings.static_max_iocs,
        max_result_bytes=settings.static_max_result_bytes,
    )


def presigned_common(
    item: DispatchInput, settings: Settings, *, get_expires: timedelta
) -> dict[str, Any]:
    """The message fields every analyzer shares: the presigned GET of the exact evidence
    version (valid `get_expires`) and the presigned POST of its fixed result key, capped at
    the analyzer's result size and valid for the queue TTL plus the job timeout.

    Blocking (MinIO region lookup on first use): call from a worker thread."""
    minio = get_minio()
    ttl = timedelta(seconds=settings.analysis_queue_ttl_s)
    timeout = analyzers.timeout_s(settings, item.analyzer)
    evidence_url = minio.presigned_get_object(
        item.storage_bucket,
        item.storage_key,
        expires=get_expires,
        version_id=item.storage_version_id,
    )
    key = result_key(item.organization_id, item.job_id)
    policy = PostPolicy(
        settings.results_bucket, datetime.now(UTC) + ttl + timedelta(seconds=timeout)
    )
    policy.add_equals_condition("key", key)
    policy.add_content_length_range_condition(
        0, analyzers.max_result_bytes(settings, item.analyzer)
    )
    fields = {**minio.presigned_post_policy(policy), "key": key}
    scheme = "https" if settings.minio_secure else "http"
    return {
        "job_id": item.job_id,
        "organization_id": item.organization_id,
        "evidence_id": item.evidence_id,
        "expected_sha256": item.sha256,
        "size_bytes": item.size_bytes,
        "evidence_url": evidence_url,
        "result_post": PresignedPost(
            url=f"{scheme}://{settings.need('minio_endpoint')}/{settings.results_bucket}",
            fields=fields,
        ),
        "ingest_token": item.ingest_token,
    }


def build_message(item: DispatchInput) -> JobMessage:
    """Blocking (MinIO region lookup on first use): call from a worker thread."""
    settings = get_settings()
    if item.analyzer == Analyzer.MEMORY:
        from app.modules.memory_analysis.dispatch import build_memory_message

        return build_memory_message(item, settings)
    if item.analyzer == Analyzer.DISK:
        # M9 phase 7: one presigned GET per segment, `DiskLimits`, the deadline (RT5).
        from app.modules.disk_forensics.dispatch import build_disk_message

        return build_disk_message(item, list(item.segments), settings)
    ttl = timedelta(seconds=settings.analysis_queue_ttl_s)
    common = presigned_common(item, settings, get_expires=ttl)
    if item.analyzer == Analyzer.STATIC:
        return StaticJobV1.model_validate(
            {
                **common,
                "profile": Profile(item.profile or JobProfile.FULL),
                "limits": static_limits(settings),
            }
        )
    return PcapJobV1.model_validate({**common, "limits": limits(settings)})


def task_and_queue(analyzer: Analyzer, settings: Settings) -> tuple[str, str]:
    queues = Queues(settings.queue_prefix)
    routes = {
        Analyzer.PCAP: (PCAP_ANALYZE, queues.pcap),
        Analyzer.STATIC: (STATIC_ANALYZE, queues.static),
        Analyzer.MEMORY: (MEMORY_ANALYZE, queues.memory),
        Analyzer.DISK: (DISK_ANALYZE, queues.disk),
    }
    return routes[analyzer]


def _send_sync(item: DispatchInput) -> None:
    from app.workers.celery_app import celery_app  # broker client only, no worker

    settings = get_settings()
    message = build_message(item)
    task, queue = task_and_queue(item.analyzer, settings)
    timeout = analyzers.timeout_s(settings, item.analyzer)
    celery_app.send_task(
        task,
        kwargs={"message": message.model_dump(mode="json")},
        queue=queue,
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
