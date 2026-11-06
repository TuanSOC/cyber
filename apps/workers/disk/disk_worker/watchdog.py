"""The per-stage write watchdog (M9 phase 2, RT4; root side, pure Python + `statvfs`).

`disk_work` is a named volume on the host disk that also holds MinIO and Postgres, and
RLIMIT_FSIZE bounds single files only. While a stage runs, a root thread polls
`statvfs(<job dir>)` every 2 s and calls `kill` (every tool-uid process) when:
- the bytes used on the volume grew by more than the stage's write budget since the stage
  started (`write_budget` → the stage is `truncated`);
- free bytes fell below the floor (`DISK_WORK_MIN_FREE_BYTES`, 4 GiB) or free inodes below
  100 000 (`min_free` / `min_inodes` → `truncated`, and `insufficient_disk` for the job when
  no walk has succeeded yet).
A file system that reports no inode counts (`f_files == 0`) skips the inode check.
"""

import os
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

POLL_S = 2.0
MIN_FREE_INODES = 100_000
StatVfs = Callable[[Path], Any]


def _used(s: Any) -> int:
    return int((s.f_blocks - s.f_bfree) * s.f_frsize)


class Watchdog:
    def __init__(
        self,
        path: Path,
        write_budget: int,
        min_free_bytes: int,
        kill: Callable[[], None],
        *,
        statvfs: StatVfs | None = None,
        interval: float = POLL_S,
        min_free_inodes: int = MIN_FREE_INODES,
    ) -> None:
        self.path = path
        self.write_budget = write_budget
        self.min_free_bytes = min_free_bytes
        self.min_free_inodes = min_free_inodes
        self.kill = kill
        self.statvfs: StatVfs = statvfs or os.statvfs
        self.interval = interval
        self.fired: str | None = None
        self.kill_error: BaseException | None = None
        self.peak_written = 0
        self._baseline = _used(self.statvfs(path))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def check(self) -> str | None:
        """One poll: the reason to stop the stage, or None."""
        s = self.statvfs(self.path)
        written = _used(s) - self._baseline
        self.peak_written = max(self.peak_written, written)
        if written > self.write_budget:
            return "write_budget"
        if s.f_bavail * s.f_frsize < self.min_free_bytes:
            return "min_free"
        if s.f_files and s.f_favail < self.min_free_inodes:
            return "min_inodes"
        return None

    def poll(self) -> bool:
        """Check once and kill on a breach; True when the watchdog fired."""
        if self.fired is not None:
            return True
        try:
            reason = self.check()
        except OSError:
            return False
        if reason is None:
            return False
        self.fired = reason
        try:
            self.kill()
        except BaseException as exc:  # noqa: BLE001 - re-raised by the stage runner
            self.kill_error = exc
        return True

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            if self.poll():
                return

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="disk-watchdog", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join()


__all__ = ["MIN_FREE_INODES", "POLL_S", "Watchdog"]
