"""The artifact timeline (M9 phase 1 stub; phase 3 owns the body, never the signature).

`run_timeline(dirs, partitions, profile, limits, budget) -> TimelineOutput`: per OS partition
(<= `limits.max_plaso_partitions`), Plaso `log2timeline --single_process` on the read-only
mirrored artifact tree, then the event export (psort `json_line`, or `cyberlab_plaso_export`),
both through `stage.run_stage`; or the test-profile-only replay engine.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from cyberlab_jobs.disk import AnalysisProfile, ArtifactStat, DiskLimits, DiskPartitionRecord
from cyberlab_worker import sandbox

from disk_worker.budget import Budget
from disk_worker.stage import StageResult


@dataclass
class TimelineOutput:
    events_path: Path | None  # the exported JSONL (on disk, <= 4 GiB; read twice, RT10)
    stages: list[StageResult] = field(default_factory=list)
    artifacts: list[ArtifactStat] = field(default_factory=list)
    engine: str = "none"  # plaso | replay | none


def run_timeline(
    dirs: sandbox.JobDirs,
    partitions: Sequence[DiskPartitionRecord],
    profile: AnalysisProfile,
    limits: DiskLimits,
    budget: Budget,
) -> TimelineOutput:
    raise NotImplementedError("the artifact timeline lands with M9 phase 3")
