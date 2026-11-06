"""The Plaso engine (M9 phase 3): one `log2timeline` and one event export per OS partition.

Scope: partitions with a detected OS and an opened file system, the largest first, at most
`limits.max_plaso_partitions` (2 `triage`, 4 `full`): the same partitions phase 2's analyzer
collected. A partition without a sealed collect output (nothing matched, or collect skipped) is
reported `skipped` (`not_collected`).

Per partition, both through `stage.run_stage` (tool uid, seccomp AF_UNIX only + no io_uring,
RLIMIT_AS / FSIZE / NPROC from the stage table, the deadline budget, the write watchdog, kill +
seal afterwards; RT3 / RT4 / RT5):
1. `log2timeline` (`flags.log2timeline_argv`): input = the collect stage's sealed out dir (cwd,
   read-only), source = its `artifacts/p<i>` mirrored tree, out = a fresh dir holding the
   storage file. Plaso never sees the image. `--timezone UTC` is added only when no time-zone
   source was collected (Linux `etc/timezone` / `etc/localtime`, Windows `SYSTEM`); the stage
   report then says `timezone_assumed_utc`;
2. the export (`flags.export_argv`, psort `json_line` by default): input = the sealed
   `log2timeline` out dir, out = a fresh dir holding `events.jsonl`. It also runs after a
   `log2timeline` timeout or failure when a storage file exists (a partial storage still
   holds events).

A non-zero exit, a timeout or an FSIZE kill marks the stage `failed` / `timeout` /
`truncated` (`run_stage`); whatever complete lines the export wrote are still read. A stage
the deadline cannot fit is `skipped` (`deadline`) and never started.

The exported files are listed in the root-written sources manifest `<job>/timeline-sources.json`
that `normalize.events` reads twice.
"""

import dataclasses
import os
import stat
from collections.abc import Callable, Sequence
from pathlib import Path

from cyberlab_jobs.disk import (
    AnalysisProfile,
    DiskLimits,
    DiskOs,
    DiskPartitionRecord,
    StageLimitKey,
    StageStatus,
)
from cyberlab_worker import sandbox

from disk_worker import config, stage
from disk_worker.budget import Budget
from disk_worker.normalize.events import Source, load_targets, write_sources
from disk_worker.timeline import TimelineOutput, flags, replay
from disk_worker.timeline.plan import timeline_partitions

SOURCES = "timeline-sources.json"
ArgvOf = Callable[[Path], list[str]]  # a stage's argv, given its fresh out dir
TZ_SOURCES = {"linux": frozenset({"etc/timezone", "etc/localtime"})}


def _real_dir(path: Path) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except OSError:
        return False


def _real_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def has_time_zone(os_name: DiskOs, targets_paths: Sequence[str]) -> bool:
    """Whether a time-zone source for Plaso's preprocessing was collected."""
    if os_name == "windows":
        return any(p.casefold().endswith("system32/config/system") for p in targets_paths)
    return any(p in TZ_SOURCES["linux"] for p in targets_paths)


def _skipped(key: StageLimitKey, out: Path, reason: str) -> stage.StageResult:
    return stage.StageResult(stage=key, status=StageStatus.SKIPPED, out_dir=out, reason=reason)


class _Run:
    def __init__(
        self,
        dirs: sandbox.JobDirs,
        profile: AnalysisProfile,
        limits: DiskLimits,
        budget: Budget,
    ) -> None:
        self.dirs = dirs
        self.profile = profile
        self.limits = limits
        self.budget = budget
        self.out = TimelineOutput(events_path=None, engine="plaso")
        self.sources: list[Source] = []

    def report(self, result: stage.StageResult, partition_index: int) -> None:
        self.out.stages.append(result)
        self.out.stage_partitions.append(partition_index)

    def run_stage(
        self, key: StageLimitKey, name: str, input_dir: Path, argv_of: ArgvOf
    ) -> stage.StageResult:
        if self.budget.timeout(key) <= 0:
            return _skipped(key, self.dirs.root / f"{name}-out", "deadline")
        fresh = stage.fresh(self.dirs, name)
        run_dirs = sandbox.JobDirs(root=self.dirs.root, input=input_dir, out=fresh.out)
        return stage.run_stage(argv_of(fresh.out), run_dirs, key, self.limits, self.budget)

    def partition(self, p: DiskPartitionRecord) -> None:
        os_name: DiskOs = "windows" if p.os == "windows" else "linux"
        collect = stage.collect_out(self.dirs, p.index).out
        mirror = collect / "artifacts" / f"p{p.index}"
        collected = collect / "collected.jsonl"
        if not (_real_dir(mirror) and _real_file(collected)):
            self.report(_skipped("log2timeline", collect, "not_collected"), p.index)
            return
        plan = self.dirs.input / f"{stage.collect_name(p.index)}.json"
        probe = Source(
            partition_index=p.index,
            events=collected,  # unused here: only the targets are read
            os=os_name,
            profile=self.profile,
            mirror_roots=(),
            collected=collected,
            plan=plan if _real_file(plan) else None,
        )
        targets = load_targets(probe)
        if not targets:
            self.report(_skipped("log2timeline", collect, "not_collected"), p.index)
            return
        assume_utc = not has_time_zone(os_name, [t.path for t in targets.values()])

        l2t = self.run_stage(
            "log2timeline",
            f"plaso-p{p.index}",
            collect,
            lambda out: flags.log2timeline_argv(
                os_name, self.profile, self.limits, out, mirror, assume_utc=assume_utc
            ),
        )
        if assume_utc and l2t.status == StageStatus.OK and l2t.reason is None:
            l2t = dataclasses.replace(l2t, reason="timezone_assumed_utc")
        self.report(l2t, p.index)
        storage = l2t.out_dir / flags.STORAGE
        if l2t.status == StageStatus.SKIPPED or not _real_file(storage):
            return

        export = self.run_stage(
            "event_export",
            f"export-p{p.index}",
            l2t.out_dir,
            lambda out: flags.export_argv(storage, out),
        )
        self.report(export, p.index)
        events = export.out_dir / flags.EVENTS
        if export.status == StageStatus.SKIPPED or not _real_file(events):
            return
        roots = tuple(dict.fromkeys((str(mirror), os.path.realpath(mirror))))
        self.sources.append(dataclasses.replace(probe, events=events, mirror_roots=roots))


def run(
    dirs: sandbox.JobDirs,
    partitions: Sequence[DiskPartitionRecord],
    profile: AnalysisProfile,
    limits: DiskLimits,
    budget: Budget,
) -> TimelineOutput:
    engine = config.timeline_engine()
    if engine == "none":
        return TimelineOutput(events_path=None, engine="none")
    if engine == "replay":
        return replay.run_replay(dirs, partitions, profile, limits)
    chosen = timeline_partitions(partitions, limits)
    if not chosen:
        out = TimelineOutput(events_path=None, engine="none")
        out.stages.append(_skipped("log2timeline", dirs.root, "no_os_partition"))
        out.stage_partitions.append(None)
        return out
    run_ = _Run(dirs, profile, limits, budget)
    for p in chosen:
        run_.partition(p)
    if run_.sources:
        run_.out.events_path = write_sources(dirs.root / SOURCES, "plaso", run_.sources)
    return run_.out


__all__ = ["SOURCES", "has_time_zone", "run"]
