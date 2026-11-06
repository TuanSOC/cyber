"""Root's watchdog over one running stage (M10 phase 2; RT5 disk, RT14 memory).

While a stage process runs, a root thread every `interval_s`:
- measures the job directory (a bounded `os.scandir` walk: no symlink is followed, at most
  `MAX_ENTRIES` entries, disk blocks counted, so sparse files count what they occupy); above
  `max_work_bytes` (or above `MAX_ENTRIES` entries: a directory flood) it kills the tool uid
  and the stage ends `re_work_too_large` (class `input`). RLIMIT_FSIZE bounds one file only;
  a hostile binary could make Ghidra write a project of many large files on the Docker VM
  disk Postgres and MinIO share;
- polls the container cgroup (v2, the container's own namespace at `/sys/fs/cgroup`):
  `memory.current` (the stage's peak is the largest value seen; a short spike between two
  polls is missed: stated) and the `oom_kill` counter of `memory.events`. An increase of
  that counter during the stage means the kernel OOM killer ended a process of this
  container: the stage ends `re_out_of_memory`. `RUSAGE_CHILDREN` is never used (it gives
  the largest single process, cumulated over the worker child's life, RT14).

The peak goes into the header's stage entry (root's measurement, never the tool's claim).
Everything is injectable (walker, cgroup dir, kill, clock) for the unit tests.
"""

import contextlib
import os
import stat
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

CGROUP_DIR = Path("/sys/fs/cgroup")
INTERVAL_S = 2.0
MAX_ENTRIES = 200_000
OVER = 2**63 - 1


def tree_bytes(root: Path, max_entries: int = MAX_ENTRIES) -> int:
    """Disk blocks used under `root` (no symlink followed); `OVER` beyond `max_entries`."""
    total, seen = 0, 0
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            info = os.lstat(current)
        except OSError:
            continue
        seen += 1
        if seen > max_entries:
            return OVER
        blocks = getattr(info, "st_blocks", None)  # absent off Linux (host unit tests)
        total += blocks * 512 if blocks is not None else info.st_size
        if stat.S_ISDIR(info.st_mode):
            with contextlib.suppress(OSError), os.scandir(current) as entries:
                stack.extend(Path(entry.path) for entry in entries)
    return total


def _read_int(path: Path) -> int | None:
    try:
        with open(path, "rb") as f:
            return int(f.read(64).split()[0])
    except (OSError, ValueError, IndexError):
        return None


def oom_kills(cgroup: Path) -> int | None:
    """The `oom_kill` counter of `memory.events` (None without cgroup v2 memory files)."""
    try:
        with open(cgroup / "memory.events", "rb") as f:
            data = f.read(4096)
    except OSError:
        return None
    for line in data.decode("ascii", "replace").splitlines():
        key, _, value = line.partition(" ")
        if key == "oom_kill":
            try:
                return int(value)
            except ValueError:
                return None
    return None


def memory_current(cgroup: Path) -> int | None:
    return _read_int(cgroup / "memory.current")


def _kill_tool() -> None:  # pragma: no cover - the kit's sandbox (Linux, in the image)
    from cyberlab_worker import sandbox

    sandbox.kill_tool_processes()


@dataclass
class WatchResult:
    work_too_large: bool = False
    oom_killed: bool = False
    peak_memory_bytes: int | None = None
    peak_work_bytes: int = 0

    @property
    def error_code(self) -> str | None:
        if self.work_too_large:
            return "re_work_too_large"
        if self.oom_killed:
            return "re_out_of_memory"
        return None


class Watch:
    """`with Watch(job_dir, max_work_bytes) as watch: run the stage`; then `watch.result`."""

    def __init__(
        self,
        job_dir: Path,
        max_work_bytes: int,
        *,
        cgroup: Path = CGROUP_DIR,
        interval_s: float = INTERVAL_S,
        measure: Callable[[Path], int] = tree_bytes,
        kill: Callable[[], None] = _kill_tool,
    ) -> None:
        self.job_dir = job_dir
        self.max_work_bytes = max_work_bytes
        self.cgroup = cgroup
        self.interval_s = interval_s
        self.measure = measure
        self.kill = kill
        self.result = WatchResult()
        self._oom_start: int | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _memory(self) -> None:
        current = memory_current(self.cgroup)
        if current is not None:
            peak = self.result.peak_memory_bytes or 0
            self.result.peak_memory_bytes = max(peak, current)

    def _oom(self) -> None:
        count = oom_kills(self.cgroup)
        if count is not None and self._oom_start is not None and count > self._oom_start:
            self.result.oom_killed = True

    def tick(self) -> bool:
        """One measurement; True when the stage was killed (stop watching)."""
        self._memory()
        self._oom()
        used = self.measure(self.job_dir)
        self.result.peak_work_bytes = max(self.result.peak_work_bytes, used)
        if used > self.max_work_bytes and not self.result.work_too_large:
            self.result.work_too_large = True
            self.kill()
            return True
        return False

    def _loop(self) -> None:
        while not self._stop.wait(self.interval_s):
            if self.tick():
                return

    def start(self) -> None:
        self._oom_start = oom_kills(self.cgroup)
        self._memory()
        self._thread = threading.Thread(target=self._loop, name="re-watch", daemon=True)
        self._thread.start()

    def stop(self) -> WatchResult:
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        # A last look: an OOM kill at the very end, the final project size and memory.
        self._memory()
        self._oom()
        if not self.result.work_too_large:
            used = self.measure(self.job_dir)
            self.result.peak_work_bytes = max(self.result.peak_work_bytes, used)
            if used > self.max_work_bytes:
                self.result.work_too_large = True
        return self.result

    def __enter__(self) -> "Watch":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


__all__ = [
    "CGROUP_DIR",
    "INTERVAL_S",
    "MAX_ENTRIES",
    "Watch",
    "WatchResult",
    "memory_current",
    "oom_kills",
    "tree_bytes",
]
