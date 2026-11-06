"""The job's deadline budget (M9 phase 2, RT5; the `Budget(deadline_at, limits).timeout(stage)`
interface is frozen).

Every stage gets min(its cap, the time left before `deadline_at` minus the reserve, 900 s by
default, kept for assembly and upload). A stage that cannot get at least its minimum useful
run time (`MIN_STAGE_S`) gets `timeout() <= 0`: the runner reports it `skipped` (`deadline`)
and never starts it, so the stage sum can never pass the job deadline and the reaper never
kills a running job.

`verify` scales with the media: its cap is media size / `verify_bytes_per_s` + the stage's
base timeout (plan "Per stage"); `set_media_size` is called once the media size is known.
"""

import time
from dataclasses import dataclass
from datetime import UTC, datetime

from cyberlab_jobs.disk import DiskLimits, StageLimitKey

# Below this a stage is not started at all (it could not finish anything useful).
MIN_STAGE_S: dict[str, float] = {
    "verify": 30.0,
    "layout": 30.0,
    "walk": 120.0,
    "collect": 60.0,
    "scan": 120.0,
    "log2timeline": 600.0,
    "event_export": 120.0,
    "extract": 30.0,
}


@dataclass
class Budget:
    deadline_at: datetime
    limits: DiskLimits
    media_size: int = 0

    def set_media_size(self, size: int) -> None:
        self.media_size = max(0, int(size))

    def remaining(self, now: datetime | None = None) -> float:
        now = now or datetime.now(UTC)
        return (self.deadline_at - now).total_seconds() - self.limits.deadline_reserve_s

    def cap(self, stage: StageLimitKey) -> float:
        base = float(self.limits.stages[stage].timeout_s)
        if stage == "verify":
            return base + self.media_size / self.limits.verify_bytes_per_s
        return base

    def timeout(self, stage: StageLimitKey) -> float:
        """Seconds the stage may run (<= 0: skip it, reason `deadline`)."""
        seconds = min(self.cap(stage), self.remaining())
        return seconds if seconds >= MIN_STAGE_S.get(stage, 30.0) else 0.0

    @staticmethod
    def monotonic() -> float:
        return time.monotonic()


__all__ = ["MIN_STAGE_S", "Budget"]
