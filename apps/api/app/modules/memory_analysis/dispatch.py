"""The `memory.v1` job message (M8 phase 1 entry point; phase 6 owns the body, never the
signature).

`build_memory_message(item, settings) -> MemoryJobV1`: the shared presigned fields (the GET
pins the exact evidence version and expires with the queue TTL plus the job timeout, since a
large download may start late), the profile, the OS hint and `MemoryLimits` from settings.
Blocking (MinIO): called from the dispatch worker thread.
"""

from datetime import timedelta

from cyberlab_jobs.memory import MemoryJobV1, MemoryLimits, MemoryProfile, OsHint

from app.core.config import Settings
from app.modules.analysis.dispatch import DispatchInput, presigned_common
from app.modules.analysis.models import JobProfile


def memory_limits(settings: Settings) -> MemoryLimits:
    return MemoryLimits(
        max_bytes=settings.memory_max_bytes,
        timeout_s=settings.analysis_memory_timeout_s,
        identify_timeout_s=settings.analysis_memory_identify_timeout_s,
        tool_timeout_s=settings.analysis_memory_plugin_timeout_s,
        max_processes=settings.memory_max_processes,
        max_connections=settings.memory_max_connections,
        max_injections=settings.memory_max_injections,
        max_artifacts=settings.memory_max_artifacts,
        max_findings=settings.memory_max_findings,
        max_iocs=settings.memory_max_iocs,
        max_timeline=settings.memory_max_timeline,
        max_result_bytes=settings.memory_max_result_bytes,
    )


def build_memory_message(item: DispatchInput, settings: Settings) -> MemoryJobV1:
    expires = timedelta(
        seconds=settings.analysis_queue_ttl_s + settings.analysis_memory_timeout_s
    )
    common = presigned_common(item, settings, get_expires=expires)
    return MemoryJobV1.model_validate(
        {
            **common,
            "profile": MemoryProfile(item.profile or JobProfile.TRIAGE),
            "os_hint": item.os_hint or OsHint.AUTO,
            "limits": memory_limits(settings),
        }
    )
