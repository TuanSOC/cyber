"""The shared retention selector (M7; frozen signature, phase 3 implements it).

Both the API's read-only preview and the retention worker call `candidates`, so a dry run
lists exactly what an enforce run on the same data deletes. The caller passes the effective
policy it read from the DB (values and mode, never a task message, RT1) and an open tenant
session of that org.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

CATEGORIES = ("ti_results", "ai_runs", "closed_case")


@dataclass(frozen=True)
class EffectivePolicy:
    """The values and mode in force at `now` (pending changes whose delay passed applied)."""

    ti_results_days: int | None
    ai_runs_days: int | None
    closed_case_days: int | None
    enforce: bool

    @property
    def empty(self) -> bool:
        return (self.ti_results_days, self.ai_runs_days, self.closed_case_days) == (
            None,
            None,
            None,
        )


@dataclass(frozen=True)
class Candidate:
    category: str
    ref_table: str
    ref_id: str
    job_id: uuid.UUID | None
    investigation_id: uuid.UUID | None
    rows: int
    bytes: int
    # Set for object candidates (evidence bytes, results objects, report renditions).
    object_bucket: str | None = None
    object_key: str | None = None
    object_version_id: str | None = None


@dataclass
class CategoryCount:
    candidates: int = 0
    rows: int = 0
    bytes: int = 0
    kept_cited: int = 0
    skipped_hold: int = 0
    skipped_locked: int = 0


@dataclass
class CandidateSet:
    candidates: list[Candidate] = field(default_factory=list)
    counts: dict[str, CategoryCount] = field(
        default_factory=lambda: {c: CategoryCount() for c in CATEGORIES}
    )
    # More candidates exist than `limit` (the next run continues).
    truncated: bool = False


async def candidates(
    session: AsyncSession,
    org_id: uuid.UUID,
    policy: EffectivePolicy,
    *,
    now: datetime,
    limit: int,
) -> CandidateSet:
    """Expired, unheld, uncited candidates of every enabled category (phase 3)."""
    raise NotImplementedError("retention.select.candidates is implemented in M7 phase 3")
