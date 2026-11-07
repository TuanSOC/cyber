"""The disk watchdog and the cgroup poller (RT5, RT14) with a fake cgroup dir and a fake
walker: an oversized project is killed as `re_work_too_large`, an OOM kill during the stage
is `re_out_of_memory`, the peak memory is root's own measurement."""

import os
from pathlib import Path

import pytest

from re_worker.engines.watch import (
    OVER,
    Watch,
    memory_current,
    oom_kills,
    tree_bytes,
)


def _cgroup(tmp_path: Path, current: int, oom: int) -> Path:
    cg = tmp_path / "cgroup"
    cg.mkdir(exist_ok=True)
    (cg / "memory.current").write_text(f"{current}\n")
    (cg / "memory.events").write_text(f"low 0\nhigh 0\nmax 3\noom 1\noom_kill {oom}\n")
    return cg


def test_cgroup_files(tmp_path: Path) -> None:
    cg = _cgroup(tmp_path, 123, 4)
    assert memory_current(cg) == 123 and oom_kills(cg) == 4
    assert memory_current(tmp_path) is None and oom_kills(tmp_path) is None
    (cg / "memory.current").write_text("garbage")
    assert memory_current(cg) is None


def test_oversized_work_is_killed_once(tmp_path: Path) -> None:
    cg = _cgroup(tmp_path, 10, 0)
    sizes = iter([100, 5000, 9000])
    kills: list[int] = []
    watch = Watch(
        tmp_path, 1000, cgroup=cg, measure=lambda _p: next(sizes), kill=lambda: kills.append(1)
    )
    watch._oom_start = 0
    assert watch.tick() is False
    assert watch.tick() is True
    assert kills == [1]
    result = watch.stop()
    assert result.work_too_large and result.error_code == "re_work_too_large"
    assert result.peak_work_bytes == 5000


def test_oom_kill_and_peak_memory(tmp_path: Path) -> None:
    cg = _cgroup(tmp_path, 100, 2)
    with Watch(tmp_path, 1 << 40, cgroup=cg, interval_s=3600, measure=lambda _p: 0) as watch:
        _cgroup(tmp_path, 900, 2)
        watch.tick()
        _cgroup(tmp_path, 300, 3)  # the kernel killed a process of this container
    result = watch.result
    assert result.oom_killed and result.error_code == "re_out_of_memory"
    assert result.peak_memory_bytes == 900
    assert not result.work_too_large


def test_no_cgroup_means_no_memory_facts(tmp_path: Path) -> None:
    with Watch(tmp_path, 1 << 40, cgroup=tmp_path / "none", interval_s=3600) as watch:
        pass
    assert watch.result.peak_memory_bytes is None and not watch.result.oom_killed


def test_tree_bytes_counts_without_following_links(tmp_path: Path) -> None:
    root = tmp_path / "job"
    (root / "project").mkdir(parents=True)
    (root / "project" / "db").write_bytes(b"x" * 8192)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "big").write_bytes(b"y" * 100_000)
    try:
        os.symlink(outside, root / "link", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("no symlinks on this host")
    assert 8192 <= tree_bytes(root) < 100_000
    assert tree_bytes(root, max_entries=2) == OVER
