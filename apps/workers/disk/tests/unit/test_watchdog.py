"""The per-stage write watchdog (M9 phase 2, RT4). Pure: a fake `statvfs`, runs anywhere.
The real kill of a writing stage is in `test_stage_isolation.py` (container)."""

from dataclasses import dataclass
from pathlib import Path

from disk_worker.watchdog import Watchdog

GIB = 1024**3


@dataclass
class Vfs:
    f_blocks: int = 100 * GIB // 4096
    f_bfree: int = 50 * GIB // 4096
    f_bavail: int = 50 * GIB // 4096
    f_frsize: int = 4096
    f_files: int = 10_000_000
    f_favail: int = 5_000_000


class Disk:
    def __init__(self) -> None:
        self.vfs = Vfs()

    def write(self, size: int) -> None:
        self.vfs.f_bfree -= size // 4096
        self.vfs.f_bavail -= size // 4096

    def __call__(self, _path: Path) -> Vfs:
        return self.vfs


def _dog(disk: Disk, kills: list[int], budget: int = GIB, floor: int = 4 * GIB) -> Watchdog:
    return Watchdog(Path("/work"), budget, floor, lambda: kills.append(1), statvfs=disk)


def test_writes_within_the_budget_are_fine() -> None:
    disk, kills = Disk(), []
    dog = _dog(disk, kills)
    disk.write(GIB // 2)
    assert not dog.poll() and kills == []


def test_writing_past_the_budget_kills_the_stage() -> None:
    disk, kills = Disk(), []
    dog = _dog(disk, kills)
    disk.write(GIB + 8192)
    assert dog.poll() and dog.fired == "write_budget" and kills == [1]
    assert dog.poll() and kills == [1]  # fires once


def test_the_free_space_floor_kills_the_stage() -> None:
    disk, kills = Disk(), []
    dog = _dog(disk, kills, budget=100 * GIB, floor=49 * GIB)
    disk.write(2 * GIB)
    assert dog.poll() and dog.fired == "min_free"


def test_the_inode_floor_kills_the_stage_unless_the_fs_reports_none() -> None:
    disk, kills = Disk(), []
    dog = _dog(disk, kills)
    disk.vfs.f_favail = 99_999
    assert dog.poll() and dog.fired == "min_inodes"
    disk2, kills2 = Disk(), []
    disk2.vfs.f_files = 0
    disk2.vfs.f_favail = 0
    assert not _dog(disk2, kills2).poll()


def test_a_kill_error_is_kept_for_the_runner() -> None:
    disk = Disk()

    def kill() -> None:
        raise RuntimeError("survivor")

    dog = Watchdog(Path("/work"), GIB, 0, kill, statvfs=disk)
    disk.write(2 * GIB)
    assert dog.poll() and isinstance(dog.kill_error, RuntimeError)


def test_the_thread_polls_until_stopped() -> None:
    disk, kills = Disk(), []
    dog = Watchdog(Path("/work"), GIB, 0, lambda: kills.append(1), statvfs=disk, interval=0.01)
    dog.start()
    disk.write(2 * GIB)
    for _ in range(500):
        if kills:
            break
        import time

        time.sleep(0.01)
    dog.stop()
    assert kills == [1] and dog.fired == "write_budget"
