"""The job's deadline budget (M9 phase 1 interface; phase 2 owns the behaviour, RT5).

Every stage gets min(its cap, the time left before `job.deadline_at` minus the reserve); a stage
the budget cannot fit is `skipped` (`deadline`).
"""

import time
from dataclasses import dataclass
from datetime import UTC, datetime

from cyberlab_jobs.disk import DiskLimits, StageLimitKey


@dataclass
class Budget:
    deadline_at: datetime
    limits: DiskLimits

    def remaining(self, now: datetime | None = None) -> float:
        now = now or datetime.now(UTC)
        return (self.deadline_at - now).total_seconds() - self.limits.deadline_reserve_s

    def timeout(self, stage: StageLimitKey) -> float:
        """Seconds the stage may run (<= 0: skip it). Phase 2 adds the verify scaling."""
        return min(float(self.limits.stages[stage].timeout_s), self.remaining())

    @staticmethod
    def monotonic() -> float:
        return time.monotonic()
