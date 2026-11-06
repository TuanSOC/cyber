"""The artifact timeline (M9 phase 3; the `run_timeline` signature is frozen by phase 1).

`run_timeline(dirs, partitions, profile, limits, budget) -> TimelineOutput`: per OS partition
(<= `limits.max_plaso_partitions`, the largest first), Plaso `log2timeline --single_process` on
the sealed, read-only mirrored artifact tree, then the event export (psort `json_line`, or
`cyberlab_plaso_export`), both through `stage.run_stage` (`runner`); or the test-profile-only
replay engine (`replay`). Modules:
- `catalog`: the artifact catalog, the parser lists and the frozen `match` entry point;
- `plan`: the collect plan built from a partition's walk listing;
- `flags`: the fixed Plaso argv (never from the image or the job);
- `runner` / `replay`: the two engines; both end in a root-written sources manifest that
  `disk_worker.normalize.events` reads twice (RT10).

The package import stays light (no sandbox import) so the catalog and the plan load anywhere.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from cyberlab_jobs.disk import AnalysisProfile, ArtifactStat, DiskLimits, DiskPartitionRecord

if TYPE_CHECKING:
    from cyberlab_worker import sandbox

    from disk_worker.budget import Budget
    from disk_worker.stage import StageResult


@dataclass
class TimelineOutput:
    # The root-written sources manifest (`normalize.events.write_sources`): every exported
    # `events.jsonl` (on disk, <= 4 GiB each; read twice, RT10) with its partition and collect
    # manifest. None: no event to read.
    events_path: Path | None
    stages: "list[StageResult]" = field(default_factory=list)
    artifacts: list[ArtifactStat] = field(default_factory=list)
    engine: str = "none"  # plaso | replay | none
    # The partition of each entry of `stages` (same order; the header reports it).
    stage_partitions: list[int | None] = field(default_factory=list)


def run_timeline(
    dirs: "sandbox.JobDirs",
    partitions: Sequence[DiskPartitionRecord],
    profile: AnalysisProfile,
    limits: DiskLimits,
    budget: "Budget",
) -> TimelineOutput:
    from disk_worker.timeline import runner  # noqa: PLC0415 - keeps the package import light

    return runner.run(dirs, partitions, profile, limits, budget)


__all__ = ["TimelineOutput", "run_timeline"]
