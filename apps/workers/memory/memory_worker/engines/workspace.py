"""Per-probe output directories, the job's time budget and safe writes into out dirs.

`sandbox.prepare` runs once per job (it resets the whole `/work`, RT26); every probe run then
gets a fresh directory `<job>/<name>-out` (the static `Workspace.engine()` pattern): created
by root in the root-owned 0711 job dir after every tool process was killed, owned by the tool
uid, mode 0700, with a fresh `cache/volatility3/identifier.cache` seeded from the read-only
store (RT5; one cache per process, thrown away with the dir: bugs #2050 / #2042). The copy is
hashed and must equal the manifest's `identifier_cache_sha256` (review fix: a cache the
manifest does not vouch for is never seeded; a mismatch fails the job `symbols_corrupt`).

Probe output is bounded per job (review fix): after every probe the analyzer checks
`output_bytes()` against `probe_output_budget()` and the free space of the work volume
(`insufficient_disk` when over).

After its run a directory is *sealed* (owned by root again): a later, possibly compromised
probe (same tool uid) can no longer reach an earlier plugin's output, so one plugin cannot
alter another's rows. Root reads them through the kit (`sandbox.open_output`).
"""

import contextlib
import hashlib
import os
import stat
import time
from pathlib import Path

from cyberlab_jobs.memory import MemoryLimits
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

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
        # The manifest's identifier-cache sha256 (the analyzer sets it before the first
        # probe); None: no cache is seeded and Volatility indexes the store itself.
        self.cache_sha256: str | None = None

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
        """Copy the store's prebuilt identifier cache for one probe run, only when the
        manifest records its sha256 and the copied bytes hash to it."""
        expected = self.cache_sha256
        if expected is None:
            return  # the manifest vouches for no cache: Volatility indexes the store itself
        source = self.symbols_dir / CACHE_FILE
        try:
            fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return  # no prebuilt cache: Volatility indexes the store itself
        digest = hashlib.sha256()
        with os.fdopen(fd, "rb") as src:
            info = os.fstat(src.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CACHE_BYTES:
                raise JobFailed("symbols_corrupt", "the identifier cache is not a bounded file")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            with os.fdopen(os.open(target, flags, 0o600), "wb") as dst:
                copied = 0
                while chunk := src.read(1024 * 1024):
                    copied += len(chunk)
                    if copied > MAX_CACHE_BYTES:
                        break
                    digest.update(chunk)
                    dst.write(chunk)
        if copied > MAX_CACHE_BYTES or digest.hexdigest() != expected:
            target.unlink(missing_ok=True)
            raise JobFailed("symbols_corrupt", "the identifier cache does not match the manifest")
        os.chown(target, sandbox.TOOL_UID, sandbox.TOOL_GID)

    def output_bytes(self, max_entries: int = 100_000) -> int:
        """Disk blocks used under every probe out dir of this job (no symlink followed;
        sparse files count what they occupy). More than `max_entries` entries counts as
        over any budget (a probe that floods the directory with files)."""
        total, seen = 0, 0
        stack = [p for p in self.dirs.root.iterdir() if p.name.endswith("-out")]
        while stack:
            current = stack.pop()
            try:
                info = os.lstat(current)
            except OSError:
                continue
            seen += 1
            if seen > max_entries:
                return 2**63 - 1
            total += info.st_blocks * 512
            if stat.S_ISDIR(info.st_mode):
                with contextlib.suppress(OSError), os.scandir(current) as entries:
                    stack.extend(Path(entry.path) for entry in entries)
        return total

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
