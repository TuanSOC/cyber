"""The Plaso engine's control flow (M9 phase 3) with the stage processes replaced: which
partitions run, the exact argv and input dirs handed to `stage.run_stage`, the time-zone
decision, skips (not collected, deadline, no OS partition), and the sources manifest the
normalizer reads. The real Plaso runs in `tests/engine/test_plaso_engine.py`.

Runs where the worker kit imports (Linux: the disk-worker-test service), as any uid: nothing
here starts a process."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("resource")  # the kit's sandbox module (Linux only)

from cyberlab_jobs.disk import DiskArtifact, DiskPartitionRecord, StageStatus  # noqa: E402
from cyberlab_worker import sandbox  # noqa: E402

from disk_worker import stage, timeline  # noqa: E402
from disk_worker.budget import Budget  # noqa: E402
from disk_worker.normalize.events import EventSource  # noqa: E402
from disk_worker.timeline import flags  # noqa: E402
from tests.unit.phase2_helpers import limits  # noqa: E402
from tests.unit.timeline_helpers import collect_outputs, write_jsonl  # noqa: E402

T = 1_790_000_000_000_000


def _dirs(tmp_path: Path) -> sandbox.JobDirs:
    (tmp_path / "input").mkdir()
    (tmp_path / "out").mkdir()
    return sandbox.JobDirs(root=tmp_path, input=tmp_path / "input", out=tmp_path / "out")


def _partition(index: int, os: str, length: int = 1_000_000) -> DiskPartitionRecord:
    return DiskPartitionRecord(
        index=index,
        start_sector=2048 + index * 10_000_000,
        length_sectors=length,
        fs_type="ext4",
        fs_status="ok",
        os=os,  # type: ignore[arg-type]
    )


def _collected(
    dirs: sandbox.JobDirs, index: int, entries: list[tuple[str, DiskArtifact]]
) -> Path:
    """Phase 2's sealed collect output and root's collect arguments for a partition."""
    out = stage.collect_out(dirs, index).out
    mirror = out / "artifacts" / f"p{index}"
    mirror.mkdir(parents=True)
    scratch = dirs.root / "scratch"
    scratch.mkdir(exist_ok=True)
    collected, plan = collect_outputs(
        scratch, index, [(p, p, a, 100 + n) for n, (p, a) in enumerate(entries)]
    )
    collected.rename(out / "collected.jsonl")
    plan.rename(dirs.input / f"{stage.collect_name(index)}.json")
    return mirror


class FakeStages:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, rows: list[dict[str, Any]]) -> None:
        self.calls: list[tuple[str, list[str], Path, Path]] = []
        self.rows = rows
        monkeypatch.setattr(stage, "fresh", self.fresh)
        monkeypatch.setattr(stage, "run_stage", self.run_stage)

    @staticmethod
    def fresh(dirs: sandbox.JobDirs, name: str) -> sandbox.JobDirs:
        out = dirs.root / f"{name}-out"
        out.mkdir()
        return sandbox.JobDirs(root=dirs.root, input=dirs.input, out=out)

    def run_stage(
        self, argv: list[str], dirs: sandbox.JobDirs, key: str, lim: Any, budget: Any
    ) -> stage.StageResult:
        self.calls.append((key, list(argv), dirs.input, dirs.out))
        if key == "log2timeline":
            (dirs.out / flags.STORAGE).write_bytes(b"storage")
        else:
            write_jsonl(dirs.out / flags.EVENTS, self.rows)
        return stage.StageResult(
            stage=key,  # type: ignore[arg-type]
            status=StageStatus.OK,
            out_dir=dirs.out,
            has_status=True,
        )


def _budget(hours: float = 4) -> Budget:
    return Budget(datetime.now(UTC) + timedelta(hours=hours), limits())


def test_one_run_per_collected_os_partition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DISK_TIMELINE_ENGINE", raising=False)
    dirs = _dirs(tmp_path)
    mirror = _collected(
        dirs,
        1,
        [("var/log/syslog", DiskArtifact.SYSLOG), ("etc/passwd", DiskArtifact.PREPROCESS)],
    )
    row = {
        "__container_type__": "event",
        "data_type": "syslog:line",
        "filename": f"{mirror}/var/log/syslog",
        "message": "[sshd, pid: 7] hello",
        "parser": "text/syslog",
        "timestamp": T,
        "timestamp_desc": "Content Modification Time",
        "reporter": "sshd",
        "pid": 7,
        "body": "hello",
    }
    fake = FakeStages(monkeypatch, [row])
    parts = [_partition(1, "linux", 5_000_000), _partition(2, "linux"), _partition(3, "none")]
    out = timeline.run_timeline(dirs, parts, "triage", limits(), _budget())

    assert out.engine == "plaso"
    assert [(s.stage, s.status, s.reason) for s in out.stages] == [
        ("log2timeline", StageStatus.OK, "timezone_assumed_utc"),  # no etc/timezone collected
        ("event_export", StageStatus.OK, None),
        ("log2timeline", StageStatus.SKIPPED, "not_collected"),
    ]
    assert out.stage_partitions == [1, 1, 2]
    (l2t_key, l2t_argv, l2t_input, l2t_out), (exp_key, exp_argv, exp_input, exp_out) = fake.calls
    collect = stage.collect_out(dirs, 1).out
    assert (l2t_key, l2t_input) == ("log2timeline", collect)  # cwd: the sealed collect output
    assert l2t_argv == flags.log2timeline_argv(
        "linux", "triage", limits(), l2t_out, mirror, assume_utc=True
    )
    assert (exp_key, exp_input) == ("event_export", l2t_out)
    assert exp_argv == flags.export_argv(l2t_out / flags.STORAGE, exp_out)

    assert out.events_path == dirs.root / "timeline-sources.json"
    manifest = json.loads(out.events_path.read_text())
    assert manifest["engine"] == "plaso" and len(manifest["sources"]) == 1
    events = list(EventSource(out.events_path, limits()).events())
    assert [(e.path, e.artifact, e.file and e.file.meta_addr) for e in events] == [
        ("var/log/syslog", DiskArtifact.SYSLOG, 100)
    ]


def test_a_collected_time_zone_means_no_utc_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DISK_TIMELINE_ENGINE", raising=False)
    dirs = _dirs(tmp_path)
    _collected(
        dirs,
        1,
        [("var/log/syslog", DiskArtifact.SYSLOG), ("etc/timezone", DiskArtifact.PREPROCESS)],
    )
    fake = FakeStages(monkeypatch, [])
    out = timeline.run_timeline(dirs, [_partition(1, "linux")], "full", limits(), _budget())
    assert "--timezone" not in fake.calls[0][1]
    assert out.stages[0].reason is None


def test_a_stage_the_deadline_cannot_fit_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DISK_TIMELINE_ENGINE", raising=False)
    dirs = _dirs(tmp_path)
    _collected(dirs, 1, [("var/log/syslog", DiskArtifact.SYSLOG)])
    fake = FakeStages(monkeypatch, [])
    out = timeline.run_timeline(dirs, [_partition(1, "linux")], "triage", limits(), _budget(0.1))
    assert [(s.status, s.reason) for s in out.stages] == [(StageStatus.SKIPPED, "deadline")]
    assert fake.calls == [] and out.events_path is None


def test_no_os_partition_and_the_none_engine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DISK_TIMELINE_ENGINE", raising=False)
    dirs = _dirs(tmp_path)
    out = timeline.run_timeline(dirs, [_partition(1, "none")], "triage", limits(), _budget())
    assert out.engine == "none" and out.events_path is None
    assert [(s.status, s.reason) for s in out.stages] == [(StageStatus.SKIPPED, "no_os_partition")]
    monkeypatch.setenv("DISK_TIMELINE_ENGINE", "none")
    out = timeline.run_timeline(dirs, [_partition(1, "linux")], "triage", limits(), _budget())
    assert out.engine == "none" and out.stages == []
