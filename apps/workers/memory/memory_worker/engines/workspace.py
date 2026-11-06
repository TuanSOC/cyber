"""Per-probe output directories, the job's time budget and safe writes into out dirs.

`sandbox.prepare` runs once per job (it resets the whole `/work`, RT26); every probe run then
gets a fresh directory `<job>/<name>-out` (the static `Workspace.engine()` pattern): created
by root in the root-owned 0711 job dir after every tool process was killed, owned by the tool
uid, mode 0700, with a fresh `cache/volatility3/identifier.cache` seeded from the read-only
store (RT5; one cache per process, thrown away with the dir: bugs #2050 / #2042).

After its run a directory is *sealed* (owned by root again): a later, possibly compromised
probe (same tool uid) can no longer reach an earlier plugin's output, so one plugin cannot
alter another's rows. Root reads them through the kit (`sandbox.open_output`).
"""

import contextlib
import os
import shutil
import stat
import time
from pathlib import Path

from cyberlab_jobs.memory import MemoryLimits
from cyberlab_worker import sandbox

IMAGE_NAME = "image"
ROWS = "rows.jsonl"
STATUS = "status.json"
CACHE_FILE = Path(".cache") / "volatility3" / "identifier.cache"
MAX_CACHE_BYTES = 256 * 1024**2
# Slack for housekeeping after the last plugin (normalize, detect, write, upload, report).
RESERVE_S = 60
MIN_TOOL_S = 10


class Workspace:
    def __init__(self, dirs: sandbox.JobDirs, symbols_dir: Path) -> None:
        self.dirs = dirs
        self.symbols_dir = symbols_dir
        # The ISF the symbol lookup resolved (as a file URI); the replay engine reports it.
        self.isf_uri: str | None = None

    @property
    def image(self) -> Path:
        return self.dirs.input / IMAGE_NAME

    def fresh(self, name: str) -> sandbox.JobDirs:
        """A new, empty, tool-owned out dir (nothing of earlier probes alive or reachable)."""
        sandbox.kill_tool_processes()
        out = self.dirs.root / f"{name}-out"
        os.mkdir(out, 0o700)  # FileExistsError: a name is used once per job
        os.chown(out, sandbox.TOOL_UID, sandbox.TOOL_GID)
        cache = out / "cache" / "volatility3"
        for d in (out / "cache", cache):
            os.mkdir(d, 0o700)
            os.chown(d, sandbox.TOOL_UID, sandbox.TOOL_GID)
        self._seed_cache(cache / "identifier.cache")
        return sandbox.JobDirs(root=self.dirs.root, input=self.dirs.input, out=out)

    def _seed_cache(self, target: Path) -> None:
        """Copy the store's prebuilt identifier cache (if any) for one probe run."""
        source = self.symbols_dir / CACHE_FILE
        try:
            fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return  # no prebuilt cache: Volatility indexes the store itself
        with os.fdopen(fd, "rb") as src:
            info = os.fstat(src.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CACHE_BYTES:
                return
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            with os.fdopen(os.open(target, flags, 0o600), "wb") as dst:
                shutil.copyfileobj(src, dst)
        os.chown(target, sandbox.TOOL_UID, sandbox.TOOL_GID)

    @staticmethod
    def seal(dirs: sandbox.JobDirs) -> None:
        """After a run: no tool process left, the dir root-owned (unreachable by the tool)."""
        sandbox.kill_tool_processes()
        with contextlib.suppress(OSError):
            os.chown(dirs.out, 0, 0)
            os.chmod(dirs.out, 0o700)

    @staticmethod
    def write(dirs: sandbox.JobDirs, name: str, data: bytes) -> None:
        """Root writes a file into an out dir (the replay engine): O_EXCL | O_NOFOLLOW."""
        dir_fd = os.open(dirs.out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            fd = os.open(name, flags, 0o600, dir_fd=dir_fd)
        finally:
            os.close(dir_fd)
        with os.fdopen(fd, "wb") as f:
            f.write(data)


class Budget:
    """The job's wall-clock budget: each probe gets min(its timeout, what is left)."""

    def __init__(self, limits: MemoryLimits) -> None:
        self._deadline = time.monotonic() + limits.timeout_s - RESERVE_S
        self._tool = limits.tool_timeout_s
        self._identify = limits.identify_timeout_s

    def remaining(self) -> float:
        return self._deadline - time.monotonic()

    def plugin(self) -> float | None:
        """Seconds for the next plugin, or None when it cannot start within the budget."""
        left = self.remaining()
        return None if left < MIN_TOOL_S else min(float(self._tool), left)

    def identify(self) -> float | None:
        left = self.remaining()
        return None if left < MIN_TOOL_S else min(float(self._identify), left)


__all__ = ["IMAGE_NAME", "ROWS", "STATUS", "Budget", "Workspace"]
