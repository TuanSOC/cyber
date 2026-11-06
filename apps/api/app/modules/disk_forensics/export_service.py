"""File exports (M9 phase 1 entry points; phase 10 owns the bodies).

`expire_exports(limit) -> int`: the beat task `disk.expire_exports` marks `ready` exports older
than `DISK_EXPORT_TTL_S` `expired` (the retention worker's purge user then deletes the exact
object version and stamps `object_deleted_at`, phase 9, RT19). Returns the rows marked.
"""

from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.analysis.models import AnalysisJob


async def expire_exports(limit: int) -> int:
    raise NotImplementedError("disk export expiry lands with M9 phase 10")


async def fail_pending_exports(session: AsyncSession, job: AnalysisJob) -> int:
    """The reaper's disk arm: an `extract` job that timed out marks its `pending` exports
    `failed` (phase 10). A no-op until then (returns the rows marked)."""
    return 0
