"""The real engine: one sandboxed probe process per step (identify, then one per plugin).

Every probe runs through the worker kit's `run_tool` as the tool uid (10006, RT18) in
`python -I -s -B -m memory_worker.probe ...` with:
- seccomp: every socket family but AF_UNIX denied, io_uring denied (RT7);
- `RLIMIT_AS` = `MEMORY_PLUGIN_RLIMIT_AS`, `RLIMIT_FSIZE` = 512 MiB, CPU = the timeout;
- a wall-clock timeout (kill of the whole session on expiry, kill-by-uid before the next);
- cwd = the root-owned, read-only input dir; a fresh out dir (`Workspace.fresh`);
- env: `PATH`, `TMPDIR` = the out dir, `XDG_CACHE_HOME` = `<out>/cache` (seeded identifier
  cache), `HOME` = `XDG_CONFIG_HOME` = /nonexistent, `LANG`.
stdout is `rows.jsonl` (created by root, O_EXCL); the probe writes `status.json`.
"""

import sys
import time
from typing import Literal

from cyberlab_jobs.memory import MemoryPlugin, OsHint
from cyberlab_worker import sandbox

from memory_worker.config import Config, tool_versions
from memory_worker.engines.base import ProbeRun, ProcessEnd
from memory_worker.engines.workspace import ROWS, Workspace

MODULE = "memory_worker.probe"
FSIZE_BYTES = 512 * 1024**2
NOFILE = 512


class VolatilityEngine:
    name: Literal["volatility3", "replay"] = "volatility3"

    def __init__(self, config: Config, python: str = sys.executable) -> None:
        self.config = config
        self.python = python

    def tool_versions(self) -> dict[str, str]:
        return tool_versions()

    def _run(self, ws: Workspace, name: str, args: list[str], seconds: float) -> ProbeRun:
        dirs = ws.fresh(name)
        argv = [
            self.python, "-I", "-s", "-B", "-m", MODULE, *args,
            "--image", str(ws.image), "--symbols", str(ws.symbols_dir), "--out", str(dirs.out),
        ]  # fmt: skip
        env = {
            "TMPDIR": str(dirs.out),
            "XDG_CACHE_HOME": str(dirs.out / "cache"),
            "HOME": "/nonexistent",
            "XDG_CONFIG_HOME": "/nonexistent",
        }
        limits = sandbox.Rlimits(
            as_bytes=self.config.plugin_rlimit_as, fsize_bytes=FSIZE_BYTES, nofile=NOFILE
        )
        started = time.monotonic()
        end: ProcessEnd = "exited"
        try:
            sandbox.run_tool(
                argv,
                dirs,
                timeout_s=seconds,
                stdout_name=ROWS,
                extra_env=env,
                cwd=ws.dirs.input,
                rlimits=limits,
                deny_io_uring=True,
                unix_sockets_only=True,
            )
        except sandbox.ToolTimeout:
            end = "timeout"
        except sandbox.ToolFailed:
            end = "failed"
        duration = int((time.monotonic() - started) * 1000)
        Workspace.seal(dirs)
        return ProbeRun(dirs=dirs, end=end, duration_ms=duration)

    def identify(self, ws: Workspace, hint: OsHint, seconds: float) -> ProbeRun:
        return self._run(ws, "identify", ["identify", "--os-hint", hint.value], seconds)

    def run(self, ws: Workspace, plugin: MemoryPlugin, seconds: float, max_rows: int) -> ProbeRun:
        args = ["run", plugin.value, "--max-rows", str(max_rows)]
        return self._run(ws, plugin.value, args, seconds)


__all__ = ["VolatilityEngine"]
