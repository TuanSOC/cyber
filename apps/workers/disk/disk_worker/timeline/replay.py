"""The replay timeline engine (M9 phase 3; `DISK_TIMELINE_ENGINE=replay`, test profile only).

EVTX, Prefetch and LNK have no Linux writer, so the generated images never hold them (plan
"Real-engine coverage"). The replay engine feeds hand-written, psort-shaped fixture rows
(`packages/py-jobs/tests/fixtures/psort/` from phase 1 and `psort_extra/` from phase 3, every
file labelled synthetic in its first row) **in place of** the Plaso runs, through the same
normalizer, detections and storage selection:
- refused unless `TEST_PROFILE=1` (here and in `config`): it is never real analysis;
- the header says `timeline_engine: replay` (`TimelineOutput.engine`);
- each fixture file is replayed on every timeline partition of its OS (decided from the first
  event's path through the catalog); the rows name the mirrored tree `/mirror/p1`;
- a path the partition's collect manifest maps keeps its natural key; any other path is
  classified by the catalog itself (`Source.replay`), with no file link; a path outside the
  profile's catalog is dropped and counted like a real unknown path.

Only the top-level `*.jsonl` files of each directory are replayed (`psort_extra/hostile/` holds
the normalizer's hostile rows for the unit tests).
"""

import os
from collections.abc import Mapping, Sequence
from pathlib import Path

import cyberlab_jobs
from cyberlab_jobs.disk import (
    AnalysisProfile,
    DiskLimits,
    DiskOs,
    DiskPartitionRecord,
    StageStatus,
)
from cyberlab_worker import sandbox

from disk_worker import stage
from disk_worker.normalize.events import Source, write_sources
from disk_worker.normalize.reader import ReadStats, read_jsonl
from disk_worker.timeline import TimelineOutput, catalog
from disk_worker.timeline.plan import timeline_partitions

REPLAY_MIRROR_ROOT = "/mirror/p1"
SOURCES = "timeline-sources.json"
MAX_FIXTURE_FILES = 64
PEEK_ROWS = 16
OSES: tuple[DiskOs, ...] = ("windows", "linux")


class ReplayRefused(RuntimeError):
    """The replay engine outside the test profile."""


def check_allowed(env: Mapping[str, str] | None = None) -> None:
    env = os.environ if env is None else env
    if env.get("TEST_PROFILE") != "1":
        raise ReplayRefused("the replay timeline engine runs in the test profile only")


def fixture_dirs() -> tuple[Path, ...]:
    base = Path(cyberlab_jobs.__file__).resolve().parents[2] / "tests" / "fixtures"
    return (base / "psort", base / "psort_extra")


def fixture_files(dirs: Sequence[Path]) -> list[Path]:
    files: list[Path] = []
    for d in dirs:
        if d.is_dir():
            files += sorted(p for p in d.iterdir() if p.suffix == ".jsonl" and p.is_file())
    return files[:MAX_FIXTURE_FILES]


def fixture_os(path: Path) -> DiskOs | None:
    """The OS whose catalog (`full`) matches the first event path of a fixture file."""
    stats = ReadStats()
    with open(path, "rb") as f:
        for raw in read_jsonl(f, stats, max_rows=PEEK_ROWS, max_bytes=1024 * 1024):
            filename = raw.get("filename")
            if not isinstance(filename, str):
                continue
            rel = filename.removeprefix(REPLAY_MIRROR_ROOT).lstrip("/")
            for os_name in OSES:
                if catalog.classify(rel, os_name, "full") is not None:
                    return os_name
            return None
    return None


def run_replay(
    dirs: sandbox.JobDirs,
    partitions: Sequence[DiskPartitionRecord],
    profile: AnalysisProfile,
    limits: DiskLimits,
    fixtures: Sequence[Path] | None = None,
) -> TimelineOutput:
    check_allowed()
    files = fixture_files(fixtures if fixtures is not None else fixture_dirs())
    by_os: dict[DiskOs, list[Path]] = {"windows": [], "linux": []}
    for f in files:
        os_name = fixture_os(f)
        if os_name is not None:
            by_os[os_name].append(f)
    out = TimelineOutput(events_path=None, engine="replay")
    sources: list[Source] = []
    for p in timeline_partitions(partitions, limits):
        os_name: DiskOs = "windows" if p.os == "windows" else "linux"
        collect = stage.collect_out(dirs, p.index).out
        collected = collect / "collected.jsonl"
        plan = dirs.input / f"{stage.collect_name(p.index)}.json"
        for f in by_os[os_name]:
            sources.append(
                Source(
                    partition_index=p.index,
                    events=f,
                    os=os_name,
                    profile=profile,
                    mirror_roots=(REPLAY_MIRROR_ROOT,),
                    collected=collected if collected.is_file() else None,
                    plan=plan if plan.is_file() else None,
                    replay=True,
                )
            )
        out.stages.append(
            stage.StageResult(
                stage="log2timeline",
                status=StageStatus.OK if by_os[os_name] else StageStatus.SKIPPED,
                out_dir=collect,
                reason="replay" if by_os[os_name] else "no_fixtures",
                rows=len(by_os[os_name]),
                has_status=True,
            )
        )
        out.stage_partitions.append(p.index)
    if sources:
        out.events_path = write_sources(dirs.root / SOURCES, "replay", sources)
    return out


__all__ = [
    "REPLAY_MIRROR_ROOT",
    "ReplayRefused",
    "check_allowed",
    "fixture_dirs",
    "fixture_files",
    "fixture_os",
    "run_replay",
]
