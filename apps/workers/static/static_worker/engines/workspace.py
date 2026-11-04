"""Per-engine output directories and bounded reads of tool output.

The kit's JobDirs gives one tool-owned `out/` per job. Here every engine gets its own fresh
directory instead (RT5): `<job>/<engine>-out`, created by root (in the root-owned 0711 job
dir, so no tool can pre-create or swap it) after every tool process was killed, owned by the
tool uid, mode 0700. The engine's JobDirs view points `out` at it, so the kit's run_tool,
open_output (dir_fd + O_NOFOLLOW, regular files only) and JsonLines are reused unchanged.
"""

import os
import time
from pathlib import Path

from cyberlab_jobs.static import StaticLimits
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

SAMPLE_NAME = "sample"
# Slack for housekeeping after the last engine (detections, write, upload, report).
RESERVE_S = 20
MIN_TOOL_S = 3


class Workspace:
    def __init__(self, dirs: sandbox.JobDirs) -> None:
        self.dirs = dirs

    @property
    def sample(self) -> Path:
        return self.dirs.input / SAMPLE_NAME

    def engine(self, name: str) -> sandbox.JobDirs:
        """A fresh, empty, tool-owned out dir for one engine run (nothing of earlier engines
        is alive or reachable from it)."""
        sandbox.kill_tool_processes()
        out = self.dirs.root / f"{name}-out"
        os.mkdir(out, 0o700)  # FileExistsError: an engine name is used once per job
        os.chown(out, sandbox.TOOL_UID, sandbox.TOOL_GID)
        return sandbox.JobDirs(root=self.dirs.root, input=self.dirs.input, out=out)


def read_bounded(dirs: sandbox.JobDirs, name: str, limit: int) -> tuple[bytes, bool]:
    """(content, capped): at most `limit` bytes of a tool output file; missing = empty."""
    try:
        with sandbox.open_output(dirs, name) as f:
            data = f.read(limit + 1)
    except (OSError, ValueError):
        return b"", False
    return data[:limit], len(data) > limit


class Budget:
    def __init__(self, limits: StaticLimits) -> None:
        self._deadline = time.monotonic() + limits.timeout_s - RESERVE_S
        self._tool = limits.tool_timeout_s

    def tool(self, cap: float | None = None) -> float | None:
        """Seconds for the next engine, or None when too little time is left to run one."""
        remaining = self._deadline - time.monotonic()
        if remaining < MIN_TOOL_S:
            return None
        return min(self._tool, remaining, cap if cap is not None else remaining)

    def required(self, engine: str) -> float:
        seconds = self.tool()
        if seconds is None:
            raise JobFailed("timed_out", f"no time left for {engine}")
        return seconds
