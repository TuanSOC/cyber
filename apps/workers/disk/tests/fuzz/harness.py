"""The run harness of the fuzz-lite and the pipeline proofs (M9 phase 13).

`run_case(segments, ...)` sends one disk job through the real worker path, `pipeline.run_job`
(`sandbox.prepare`, `analyzer.analyze`, every stage through `stage.run_stage`: tool uid,
seccomp, rlimits, the write watchdog, kill + seal; Plaso in /opt/plaso), with two seams only:
- `analyzer.download` copies the local segment instead of fetching a presigned URL (sha256 and
  size still checked, the copy root-owned 0444, as the kit's download leaves it);
- `pipeline.upload` decodes the stream it would upload instead of POSTing it.

Every stage result is recorded (a wrapper around `stage.run_stage`, which the analyzer, the
timeline runner and the export all call through the module), and after every stage the harness
checks that no tool-uid process survived. A sampler thread records the lowest free space of the
work volume while the job runs. Nothing here touches the broker, MinIO or the network.

Runs inside the disk worker image as root (`disk-worker-test`); the callers skip elsewhere.
Inputs and job dirs live under `FUZZ_ROOT` (default `/work/fuzz`): `sandbox.prepare` resets the
whole work dir it is given, so jobs get their own sub-directory (`<root>/jobs`) and the inputs
another (`<root>/inputs`), never the other way round.
"""

import gzip
import hashlib
import json
import os
import resource
import shutil
import threading
import uuid
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cyberlab_jobs import IngestMessageV1
from cyberlab_jobs.disk import (
    DISK_ERROR_CODES,
    PROFILE_BUDGETS,
    DiskLimits,
    DiskProfile,
    DiskResultHeader,
    StageStatus,
    default_stage_limits,
    split_event_quotas,
)
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

from disk_worker import analyzer, pipeline, stage
from disk_worker.config import Config, load
from disk_worker.probe.guard import FAMILIES

MIB = 1024**2
GIB = 1024**3
FUZZ_ROOT = Path(os.environ.get("DISK_FUZZ_ROOT", "/work/fuzz"))
REPORT = Path(os.environ.get("DISK_FUZZ_REPORT", "/work/fuzz-outcomes.json"))
# The fuzz jobs' artifact budget: the free-space check wants 3 x it on the 1 GiB test tmpfs.
ARTIFACT_MAX_BYTES = 32 * MIB
ARTIFACT_MAX_FILE_BYTES = 16 * MIB
# Stage caps short enough that a hang shows up as a `timeout` within minutes, long enough for
# every MIN_STAGE_S (log2timeline needs 600 s of budget to start at all).
STAGE_TIMEOUTS = {
    "verify": 120,
    "layout": 120,
    "walk": 600,
    "collect": 300,
    "scan": 600,
    "log2timeline": 900,
    "event_export": 300,
    "extract": 120,
}
JOB_TIMEOUT_S = 3600
DEADLINE = timedelta(minutes=40)
# Known terminal codes: the contract's disk codes. `analyzer_error` (a crash) and `timed_out`
# (the soft time limit, i.e. the reaper's view) are never a clean end.
CLEAN_CODES = frozenset(DISK_ERROR_CODES) - {"not_implemented"}
SAMPLE_S = 0.25


def limits(
    profile: str = "triage",
    *,
    timeout_s: int = JOB_TIMEOUT_S,
    deadline_reserve_s: int | None = None,
    stage_timeouts: dict[str, int] | None = None,
    **overrides: Any,
) -> DiskLimits:
    budgets = dict(PROFILE_BUDGETS[DiskProfile(profile)])
    budgets["artifact_max_bytes"] = min(budgets["artifact_max_bytes"], ARTIFACT_MAX_BYTES)
    budgets["artifact_max_file_bytes"] = min(
        budgets["artifact_max_file_bytes"], ARTIFACT_MAX_FILE_BYTES
    )
    stages = default_stage_limits(budgets["artifact_max_bytes"], budgets["artifact_max_file_bytes"])
    caps = {**STAGE_TIMEOUTS, **(stage_timeouts or {})}
    stage_data = {
        k: {**v.model_dump(), "timeout_s": min(v.timeout_s, caps[k], timeout_s - 1)}
        for k, v in stages.items()
    }
    data: dict[str, Any] = {
        "max_image_bytes": 16 * GIB,
        "max_media_bytes": 2 * 1024**4,
        "timeout_s": timeout_s,
        "stages": stage_data,
        **budgets,
        "max_partitions": 128,
        "max_filesystems": 32,
        "max_files": 500_000,
        "max_streams_per_file": 16,
        "max_events_stored": 250_000,
        "max_events_read": 20_000_000,
        "max_findings": 5_000,
        "max_iocs": 20_000,
        "max_timeline": 5_000,
        "max_result_bytes": 256 * MIB,
        "event_quotas": {k.value: v for k, v in split_event_quotas(250_000).items()},
    }
    if deadline_reserve_s is not None:
        data["deadline_reserve_s"] = deadline_reserve_s
    data.update(overrides)
    return DiskLimits.model_validate(data)


def config(**env: str) -> Config:
    """The worker's own settings plus a jobs dir of the harness (TEST_PROFILE as the service)."""
    jobs = FUZZ_ROOT / "jobs"
    jobs.mkdir(parents=True, exist_ok=True)
    os.chmod(jobs, 0o711)  # noqa: S103 - traverse-only, as the kit's work dir
    base = dict(os.environ)
    base.setdefault("BROKER_URL", "redis://disk:x@redis-broker:6379/0")
    return load({**base, "WORK_DIR": str(jobs), **env})


def inputs_dir(name: str) -> Path:
    d = FUZZ_ROOT / "inputs" / name
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    return d


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(4 * MIB):
            digest.update(chunk)
    return digest.hexdigest()


def job_message(
    segments: Sequence[Path],
    lim: DiskLimits,
    *,
    profile: str = "triage",
    deadline: timedelta = DEADLINE,
) -> dict[str, Any]:
    return {
        "job_id": str(uuid.uuid4()),
        "organization_id": str(uuid.uuid4()),
        "segments": [
            {
                "ordinal": i,
                "evidence_id": str(uuid.uuid4()),
                "expected_sha256": _sha256(p),
                "size_bytes": p.stat().st_size,
                "url": f"http://minio:9000/evidence/fuzz/{i}",
            }
            for i, p in enumerate(segments)
        ],
        "profile": profile,
        "os_hint": "auto",
        "result_post": {"url": "http://minio:9000/results", "fields": {"key": "fuzz"}},
        "ingest_token": "t" * 43,
        "limits": lim.model_dump(mode="json"),
        "deadline_at": (datetime.now(UTC) + deadline).isoformat(),
    }


@dataclass
class Run:
    """What one job left behind."""

    name: str
    outcome: str = "no_finish"  # `result`, `diagnostic:<code>`, `failed:<code>`
    code: str | None = None
    messages: list[IngestMessageV1] = field(default_factory=list)
    header: DiskResultHeader | None = None
    lines: int = 0
    stages: list[stage.StageResult] = field(default_factory=list)
    survivors: list[tuple[str, list[int]]] = field(default_factory=list)
    min_free: int | None = None
    max_child_rss: int = 0
    problems: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.problems


def _fake_download(sources: Sequence[Path]) -> Callable[..., None]:
    by_name = {f"segment-{i:03d}": p for i, p in enumerate(sources)}

    def download(
        url: str,
        dest: Path,
        *,
        expected_sha256: str,
        size_bytes: int,
        max_bytes: int,
        too_large_code: str = "evidence_too_large",
    ) -> None:
        src = by_name[dest.name]
        if size_bytes > max_bytes:
            raise JobFailed(too_large_code)
        shutil.copyfile(src, dest)
        if dest.stat().st_size != size_bytes or _sha256(dest) != expected_sha256:
            dest.unlink()
            raise JobFailed("integrity_mismatch")
        os.chown(dest, 0, 0)
        os.chmod(dest, 0o444)

    return download


def _decode(path: Path, run: Run) -> None:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        first = f.readline()
        run.lines = 1 + sum(1 for _ in f)
    run.header = DiskResultHeader.model_validate_json(first)


@contextmanager
def patched(obj: Any, name: str, value: Any) -> Iterator[None]:
    old = getattr(obj, name)
    setattr(obj, name, value)
    try:
        yield
    finally:
        setattr(obj, name, old)


class _FreeSampler(threading.Thread):
    def __init__(self, path: Path) -> None:
        super().__init__(daemon=True)
        self.path = path
        self.low: int | None = None
        self.done = threading.Event()

    def run(self) -> None:
        while not self.done.is_set():
            try:
                free = shutil.disk_usage(self.path).free
            except OSError:
                free = None
            if free is not None and (self.low is None or free < self.low):
                self.low = free
            self.done.wait(SAMPLE_S)


def check_stage(run: Run, result: stage.StageResult) -> None:
    """The per-stage invariants: offline (zero audit counts), a known status, no survivor."""
    if result.status not in set(StageStatus):
        run.problems.append(f"{result.stage}: unknown status {result.status}")
    if result.has_status:
        unknown = set(result.audit_counts) - set(FAMILIES)
        if unknown:
            run.problems.append(f"{result.stage}: unknown audit families {sorted(unknown)}")
        hits = {k: v for k, v in result.audit_counts.items() if v}
        if hits:
            run.problems.append(f"{result.stage}: audit hook refusals {hits}")
    survivors = sandbox.tool_pids()
    if survivors:
        run.survivors.append((result.stage, survivors))
        run.problems.append(f"{result.stage}: tool processes survived {survivors}")


def run_case(
    name: str,
    segments: Sequence[Path],
    *,
    profile: str = "triage",
    lim: DiskLimits | None = None,
    cfg: Config | None = None,
    deadline: timedelta = DEADLINE,
    before_stage: Callable[[Run, str, sandbox.JobDirs, Any], None] | None = None,
) -> Run:
    """One job through `pipeline.run_job`; the invariants are checked into `Run.problems`.

    `before_stage(run, stage, dirs, budget)` runs before every sandboxed stage (the proofs' hook
    stages); it must call the real `stage.run_stage` it saved, never the patched one."""
    lim = lim or limits(profile)
    cfg = cfg or config()
    run = Run(name)
    real_run_stage = stage.run_stage

    def recording(
        argv: Sequence[str],
        dirs: sandbox.JobDirs,
        key: Any,
        stage_limits: DiskLimits,
        budget: Any,
    ) -> stage.StageResult:
        if before_stage is not None:
            before_stage(run, str(key), dirs, budget)
        result = real_run_stage(argv, dirs, key, stage_limits, budget)
        run.stages.append(result)
        check_stage(run, result)
        return result

    def upload(post: Any, path: Path) -> str:
        _decode(path, run)
        return "fuzz-version"

    raw = job_message(segments, lim, profile=profile, deadline=deadline)
    sampler = _FreeSampler(cfg.work_dir)
    sampler.start()
    try:
        with (
            patched(analyzer, "download", _fake_download(segments)),
            patched(pipeline, "upload", upload),
            patched(stage, "run_stage", recording),
        ):
            pipeline.run_job(raw, cfg, run.messages.append)
    finally:
        sampler.done.set()
        sampler.join(5)
    run.min_free = sampler.low
    run.max_child_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024
    _classify(run, lim, stage.min_free_bytes(lim))
    return run


def _classify(run: Run, lim: DiskLimits, floor: int) -> None:
    events = [m.event.value for m in run.messages]
    if events[:1] != ["started"] or events.count("finished") != 1 or events[-1] != "finished":
        run.problems.append(f"ingest events {events}")
        return
    final = run.messages[-1]
    outcome = final.outcome.value if final.outcome is not None else None
    if outcome == "succeeded":
        run.outcome = "result"
        if run.header is None:
            run.problems.append("succeeded without a decoded stream")
    elif outcome == "failed":
        run.code = final.error_code
        kind = "diagnostic" if final.result_version_id else "failed"
        run.outcome = f"{kind}:{final.error_code}"
        if final.error_code not in CLEAN_CODES:
            run.problems.append(f"unclean end {run.outcome}")
    else:
        run.problems.append(f"outcome {outcome}")
    if run.header is not None:
        for report in run.header.stages:
            hits = {k: v for k, v in report.audit_counts.items() if v}
            if hits:
                run.problems.append(f"header {report.stage}: audit refusals {hits}")
    largest_as = max(s.rlimit_as for s in lim.stages.values())
    if run.max_child_rss > largest_as:
        run.problems.append(f"child RSS {run.max_child_rss} above RLIMIT_AS {largest_as}")
    if run.min_free is not None and run.min_free < floor:
        run.problems.append(f"free space {run.min_free} fell below the floor {floor}")
    if sandbox.tool_pids():
        run.problems.append("tool processes alive after the job")


# --- the outcome report -----------------------------------------------------------------------

_OUTCOMES: dict[str, list[dict[str, Any]]] = {}


def record(group: str, run: Run, **extra: Any) -> None:
    _OUTCOMES.setdefault(group, []).append(
        {
            "name": run.name,
            "outcome": run.outcome,
            "clean": run.clean,
            "problems": run.problems[:20],
            "stages": [
                f"{s.stage}:{s.status.value}" + (f"({s.reason})" if s.reason else "")
                for s in run.stages
            ],
            "min_free_bytes": run.min_free,
            "max_child_rss_bytes": run.max_child_rss,
            **extra,
        }
    )


def record_raw(group: str, entry: dict[str, Any]) -> None:
    _OUTCOMES.setdefault(group, []).append(entry)


def summary() -> dict[str, Any]:
    groups: dict[str, Any] = {}
    for group, entries in _OUTCOMES.items():
        groups[group] = {
            "total": len(entries),
            "clean": sum(1 for e in entries if e.get("clean")),
            "by_outcome": dict(Counter(str(e.get("outcome")) for e in entries).most_common()),
            "cases": entries,
        }
    return {
        "note": "fuzz-lite over generated / mutated synthetic inputs (not real disks)",
        "finished_at": datetime.now(UTC).isoformat(),
        "groups": groups,
    }


def write_report(path: Path = REPORT) -> dict[str, Any] | None:
    if not _OUTCOMES:
        return None
    doc = summary()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    return doc


__all__ = [
    "CLEAN_CODES",
    "FUZZ_ROOT",
    "REPORT",
    "Run",
    "check_stage",
    "config",
    "inputs_dir",
    "job_message",
    "limits",
    "patched",
    "record",
    "record_raw",
    "run_case",
    "summary",
    "write_report",
]
