"""The replay timeline engine (M9 phase 3): refused outside the test profile, labelled inside it,
and the phase-1 / phase-3 psort fixtures replayed through the same normalizer.

Runs where the worker kit imports (Linux: the disk-worker-test service), as any uid: nothing
here starts a process."""

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("resource")  # the kit's sandbox module (Linux only)

from cyberlab_jobs.disk import DiskArtifact, DiskPartitionRecord  # noqa: E402
from cyberlab_worker import sandbox  # noqa: E402

from disk_worker import timeline  # noqa: E402
from disk_worker.config import ConfigError  # noqa: E402
from disk_worker.normalize.events import EventSource  # noqa: E402
from disk_worker.timeline import replay  # noqa: E402
from tests.unit.phase2_helpers import limits  # noqa: E402
from tests.unit.timeline_helpers import (  # noqa: E402
    LINUX_FIXTURES,
    PSORT_EXTRA,
    PSORT_FIXTURES,
    WINDOWS_FIXTURES,
)


NO: Any = None  # no deadline budget: the replay engine starts no stage


def _dirs(tmp_path: Path) -> sandbox.JobDirs:
    (tmp_path / "input").mkdir(exist_ok=True)
    (tmp_path / "out").mkdir(exist_ok=True)
    return sandbox.JobDirs(root=tmp_path, input=tmp_path / "input", out=tmp_path / "out")


def _partition(index: int, os: str, length: int = 1_000_000) -> DiskPartitionRecord:
    return DiskPartitionRecord(
        index=index,
        start_sector=2048 + index * 10_000_000,
        length_sectors=length,
        fs_type="ntfs" if os == "windows" else "ext4",
        fs_status="ok",
        os=os,  # type: ignore[arg-type]
    )


def test_the_fixture_files_are_sorted_by_os() -> None:
    for name in WINDOWS_FIXTURES:
        assert replay.fixture_os(PSORT_FIXTURES / name) == "windows", name
    for name in LINUX_FIXTURES:
        assert replay.fixture_os(PSORT_FIXTURES / name) == "linux", name
    assert replay.fixture_os(PSORT_EXTRA / "windows_extra.jsonl") == "windows"
    assert replay.fixture_os(PSORT_EXTRA / "linux_extra.jsonl") == "linux"
    files = replay.fixture_files(replay.fixture_dirs())
    assert not any("hostile" in str(f) for f in files)  # only top-level files are replayed


def test_replay_is_refused_outside_the_test_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TEST_PROFILE", raising=False)
    with pytest.raises(replay.ReplayRefused):
        replay.run_replay(_dirs(tmp_path), [_partition(1, "windows")], "triage", limits())
    monkeypatch.setenv("DISK_TIMELINE_ENGINE", "replay")
    with pytest.raises(ConfigError):
        timeline.run_timeline(_dirs(tmp_path), [_partition(1, "windows")], "triage", limits(), NO)


def test_replay_runs_each_fixture_on_its_os_partitions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TEST_PROFILE", "1")
    monkeypatch.setenv("DISK_TIMELINE_ENGINE", "replay")
    parts = [_partition(1, "windows", 5_000_000), _partition(2, "linux"), _partition(3, "none")]
    out = timeline.run_timeline(_dirs(tmp_path), parts, "triage", limits(), NO)
    assert out.engine == "replay"
    assert out.stage_partitions == [1, 2]
    assert [s.reason for s in out.stages] == ["replay", "replay"]
    assert out.events_path is not None
    src = EventSource(out.events_path, limits())
    events = list(src.events())
    windows = [e for e in events if e.partition_index == 1]
    linux = [e for e in events if e.partition_index == 2]
    assert {e.artifact for e in windows} == {
        DiskArtifact.EVTX,
        DiskArtifact.REGISTRY_SYSTEM,
        DiskArtifact.REGISTRY_USER,
        DiskArtifact.AMCACHE,
        DiskArtifact.PREFETCH,
        DiskArtifact.LNK,
    }
    assert {e.artifact for e in linux} >= {
        DiskArtifact.SYSLOG,
        DiskArtifact.AUTH_LOG,
        DiskArtifact.UTMP,
        DiskArtifact.SHELL_HISTORY,
        DiskArtifact.PACKAGES,
    }
    # `full`-only rows ($MFT, browser, recycle bin) are unknown paths in `triage`.
    assert src.counts.dropped == {"unknown_path": 3}
    assert all(e.file is None for e in events)  # nothing was collected: no file links
