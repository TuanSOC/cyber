"""Running one stage process and reading what it left (root side; M10 phases 2 and 3).

`SandboxRunner.run(ws, spec, max_work_bytes)` is the real engine: a fresh out dir
(`workspace.fresh`, after kill-by-uid), one `sandbox.run_tool` call with the spec's argv,
environment and rlimits (uid 10010, `unix_sockets_only`, `deny_io_uring`, cwd = the
root-owned input dir), the watchdog (`watch.py`) for its whole life, then the dir is sealed.
The replay engine (`replay.py`) implements the same `StageRunner` protocol by writing
hand-written files into the same fresh dir, so everything after it is the same root code.

`read_status` / `read_rows` open the outputs through the kit (`sandbox.open_output`).
"""

import functools
import os
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from typing import Any, Protocol

from cyberlab_worker import sandbox

from re_worker.engines import Workspace, workspace
from re_worker.engines.outcome import ProcessEnd, ProcessResult
from re_worker.engines.spec import STATUS, StageSpec
from re_worker.engines.watch import Watch, WatchResult
from re_worker.normalize.reader import RowStats, StageStatus, read_rows, read_status

HS_ERR = "hs_err.log"


@dataclass(frozen=True)
class StageRun:
    dirs: sandbox.JobDirs
    process: ProcessResult


class StageRunner(Protocol):
    name: str

    def tool_versions(self) -> dict[str, str]: ...

    def run(
        self,
        ws: Workspace,
        spec: StageSpec,
        max_work_bytes: int,
        *,
        dirs: sandbox.JobDirs | None = None,
        seal: bool = True,
    ) -> StageRun: ...


def process_result(
    end: ProcessEnd, returncode: int | None, started: float, watch: WatchResult, hs_err: bool
) -> ProcessResult:
    return ProcessResult(
        end=end,
        returncode=returncode,
        duration_ms=int((time.monotonic() - started) * 1000),
        work_too_large=watch.work_too_large,
        oom_killed=watch.oom_killed,
        peak_memory_bytes=watch.peak_memory_bytes,
        hs_err=hs_err,
    )


class SandboxRunner:
    name = "ghidra"

    def tool_versions(self) -> dict[str, str]:
        from re_worker.config import tool_versions

        return tool_versions()

    def run(
        self,
        ws: Workspace,
        spec: StageSpec,
        max_work_bytes: int,
        *,
        dirs: sandbox.JobDirs | None = None,
        seal: bool = True,
    ) -> StageRun:
        dirs = dirs or workspace.fresh(ws, spec.name, spec.subdirs)
        end: ProcessEnd = "exited"
        returncode: int | None = 0
        started = time.monotonic()
        with Watch(ws.root, max_work_bytes) as watch:
            try:
                sandbox.run_tool(
                    list(spec.argv),
                    dirs,
                    timeout_s=spec.timeout_s,
                    stdout_name=spec.stdout_name,
                    extra_env=spec.env,
                    cwd=ws.input,
                    rlimits=sandbox.Rlimits(**asdict(spec.limits)),
                    deny_io_uring=True,
                    unix_sockets_only=True,
                )
            except sandbox.ToolTimeout:
                end, returncode = "timeout", None
            except sandbox.ToolFailed as exc:
                end, returncode = "failed", exc.returncode
        hs_err = sandbox.output_exists(dirs, HS_ERR)
        if seal:
            workspace.seal(dirs)
        return StageRun(dirs, process_result(end, returncode, started, watch.result, hs_err))


def status_of(run: StageRun) -> StageStatus | None:
    try:
        with sandbox.open_output(run.dirs, STATUS) as f:
            return read_status(f)
    except (OSError, ValueError):
        return None


def rows_of(
    run: StageRun, name: str, max_rows: int, stats: RowStats
) -> Iterator[dict[str, Any]]:
    """The stage's rows, read lazily through the kit (a missing or non-regular file yields
    nothing)."""
    opener = functools.partial(sandbox.open_output, run.dirs, name)
    try:
        with opener() as f:
            yield from read_rows(f, max_rows, stats)
    except (OSError, ValueError):
        return


def output_size(run: StageRun, name: str) -> int | None:
    try:
        with sandbox.open_output(run.dirs, name) as f:
            return os.fstat(f.fileno()).st_size
    except (OSError, ValueError):
        return None


__all__ = [
    "HS_ERR",
    "SandboxRunner",
    "StageRun",
    "StageRunner",
    "output_size",
    "process_result",
    "rows_of",
    "status_of",
]
