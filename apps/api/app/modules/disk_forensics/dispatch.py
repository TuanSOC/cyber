"""The `disk.v1` / `disk-export.v1` job messages (M9 phase 1 entry points; phase 7 owns
`build_disk_message`, phase 10 `build_export_message`; neither changes the signature).

`build_disk_message(job, segments, settings) -> DiskJobV1`: one presigned GET per segment (the
exact evidence version, expiring with the queue TTL plus the job timeout), the profile, the
OS hint, `DiskLimits` from settings and the job deadline (RT5). No image cache key (RT1).
Blocking (MinIO): called from the dispatch worker thread.

`deadline_at` is the message time plus `ANALYSIS_DISK_TIMEOUT_S`: never later than the
reaper's deadline of the run (its `started` report sets start + timeout + the M2 grace), so
the worker's stage budget can never outlive it. A job that waits in the queue gets less budget
(the default caps allow one active disk job, so it rarely waits).
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from cyberlab_jobs.disk import (
    DEADLINE_RESERVE_S,
    PROFILE_BUDGETS,
    DiskExportJobV1,
    DiskJobV1,
    DiskLimits,
    DiskProfile,
    StageLimits,
    default_stage_limits,
    split_event_quotas,
)
from cyberlab_jobs.memory import OsHint

from app.core.clients import get_minio
from app.core.config import Settings
from app.modules.analysis.models import JobProfile


def disk_limits(settings: Settings, profile: str = DiskProfile.TRIAGE.value) -> DiskLimits:
    """The limits every disk job of `profile` is sent (the ingest checks the same caps).

    Stage timeouts and the deadline reserve stay below the job timeout (the contract's
    validators), so a low test timeout still builds a valid message."""
    timeout = settings.analysis_disk_timeout_s
    budgets = dict(PROFILE_BUDGETS[DiskProfile(profile)])
    budgets["hash_budget_bytes"] = min(budgets["hash_budget_bytes"], settings.disk_max_image_bytes)
    stages: dict[str, StageLimits] = {
        name: stage.model_copy(update={"timeout_s": min(stage.timeout_s, timeout - 1)})
        for name, stage in default_stage_limits(
            budgets["artifact_max_bytes"], budgets["artifact_max_file_bytes"]
        ).items()
    }
    stored = settings.disk_max_events
    return DiskLimits.model_validate(
        {
            "max_image_bytes": settings.disk_max_image_bytes,
            "max_media_bytes": settings.disk_max_media_bytes,
            "timeout_s": timeout,
            "deadline_reserve_s": min(DEADLINE_RESERVE_S, timeout // 2),
            "stages": stages,
            **budgets,
            "max_partitions": settings.disk_max_partitions,
            "max_filesystems": settings.disk_max_filesystems,
            "max_files": settings.disk_max_files,
            "max_streams_per_file": settings.disk_max_streams_per_file,
            "max_events_stored": stored,
            "max_events_read": max(settings.disk_max_events_read, stored),
            "max_findings": settings.disk_max_findings,
            "max_iocs": settings.disk_max_iocs,
            "max_timeline": settings.disk_max_timeline,
            "max_result_bytes": settings.disk_max_result_bytes,
            "event_quotas": split_event_quotas(stored),
        }
    )


def _segment_url(segment: Any, expires: timedelta) -> str:
    return str(
        get_minio().presigned_get_object(
            segment.storage_bucket,
            segment.storage_key,
            expires=expires,
            version_id=segment.storage_version_id,
        )
    )


def build_disk_message(job: Any, segments: list[Any], settings: Settings) -> DiskJobV1:
    """`job`: the dispatch input of the disk job; `segments`: its ordered segments
    (`disk_forensics.segments.Segment`, ordinal 0 = the job's evidence)."""
    from app.modules.analysis.dispatch import presigned_common

    if not segments:
        raise ValueError(f"disk job {job.job_id} has no segments")
    timeout = settings.analysis_disk_timeout_s
    expires = timedelta(seconds=settings.analysis_queue_ttl_s + timeout)
    # The shared result POST (fixed key, DISK_MAX_RESULT_BYTES, queue TTL + job timeout) and
    # the token; its single-evidence GET is not part of `disk.v1` (one GET per segment below).
    common = presigned_common(job, settings, get_expires=expires)
    profile = JobProfile(job.profile or JobProfile.TRIAGE)
    return DiskJobV1.model_validate(
        {
            "job_id": job.job_id,
            "organization_id": job.organization_id,
            "segments": [
                {
                    "ordinal": s.ordinal,
                    "evidence_id": s.evidence_id,
                    "expected_sha256": s.sha256,
                    "size_bytes": s.size_bytes,
                    "url": _segment_url(s, expires),
                }
                for s in segments
            ],
            "profile": profile.value,
            "os_hint": job.os_hint or OsHint.AUTO,
            "result_post": common["result_post"],
            "ingest_token": job.ingest_token,
            "limits": disk_limits(settings, profile.value),
            "deadline_at": datetime.now(UTC) + timedelta(seconds=timeout),
        }
    )


def build_export_message(
    job: Any, source_job: Any, segments: list[Any], exports: list[Any], settings: Settings
) -> DiskExportJobV1:
    """One presigned POST per exported file plus one for the result stream (phase 10)."""
    raise NotImplementedError("disk file export dispatch lands with M9 phase 10")
