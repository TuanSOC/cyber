"""The shared stage runner (M9 phase 1 stub; phase 2 owns the body, never the signature).

`run_stage(argv, dirs, stage, limits, budget) -> StageResult`: one sandboxed process (tool uid
10007, seccomp AF_UNIX-only + no io_uring, RLIMIT_AS / FSIZE / CPU / NPROC from
`limits.stages[stage]`, a timeout from `budget.timeout(stage)`, RT5) with the statvfs write
watchdog (RT4); afterwards root kills every tool-uid process and seals the stage's out dir
read-only (RT3). Used by phases 3, 5 and 10.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from cyberlab_jobs.disk import DiskLimits, StageLimitKey, StageStatus
from cyberlab_worker import sandbox

from disk_worker.budget import Budget


@dataclass(frozen=True)
class StageResult:
    stage: StageLimitKey
    status: StageStatus
    out_dir: Path
    duration_ms: int = 0
    truncated: bool = False
    reason: str | None = None  # e.g. `deadline` (skipped), `write_budget` (truncated)
    error_code: str | None = None
    audit_counts: dict[str, int] = field(default_factory=dict)


def run_stage(
    argv: Sequence[str],
    dirs: sandbox.JobDirs,
    stage: StageLimitKey,
    limits: DiskLimits,
    budget: Budget,
) -> StageResult:
    raise NotImplementedError("the stage runner lands with M9 phase 2")
