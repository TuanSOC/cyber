"""The shared stage runner (M9 phase 2; `run_stage(argv, dirs, stage, limits, budget)` is frozen
and used by phases 3, 5 and 10).

One stage = one sandboxed process through the kit's `run_tool`:
- tool uid 10007, seccomp `unix_sockets_only=True` + `deny_io_uring=True`;
- RLIMIT_AS / FSIZE / NPROC from `limits.stages[stage]`, CPU = the timeout;
- the timeout from `budget.timeout(stage)` (RT5): <= 0 → `skipped` (`deadline`), never run;
- cwd = the root-owned, read-only `input/` dir; env `TMPDIR` / `XDG_CACHE_HOME` = the out dir,
  `HOME` = `XDG_CONFIG_HOME` = /nonexistent;
- the write watchdog (`watchdog.Watchdog`, RT4) for the whole run.

The caller gives the stage a **fresh out dir** (`fresh(dirs, name)`: created by root in the
0711 job dir after every tool process was killed, tool-owned 0700; never `sandbox.prepare`,
which resets `/work`, the M8 RT26 lesson). After the process (RT3):
1. `sandbox.kill_tool_processes()`: a `setsid` survivor cannot reach the next stage (fail
   closed: `SandboxCompromised` stops the container);
2. `seal(out)`: the out dir becomes root-owned and read-only (directories 0555, files 0444)
   through `O_NOFOLLOW` descriptors (`fchown` / `fchmod`); a symlink, FIFO, socket or device
   the tool planted is removed, never followed; later stages (Plaso reading the mirrored tree)
   can read it, none can change it.
3. `status.json` is read bounded and validated; its audit counts go into the result.
"""

import contextlib
import dataclasses
import os
import shutil
import signal
import stat
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cyberlab_jobs.disk import DiskLimits, StageLimitKey, StageStatus
from cyberlab_worker import sandbox
from pydantic import ValidationError

from disk_worker.budget import Budget
from disk_worker.normalize.models import StageStatusDoc
from disk_worker.normalize.reader import read_status
from disk_worker.watchdog import Watchdog

STATUS = "status.json"
NOFILE = 1024
MAX_SEAL_ENTRIES = 2_000_000
MAX_SEAL_DEPTH = 128
CODES = frozenset(
    {
        "unsupported_disk_format",
        "disk_parse_failed",
        "walk_memory",
        "engine_unavailable",
        "disk_export_not_allowed",
        "timeline_failed",
    }
)


@dataclass(frozen=True)
class StageResult:
    stage: StageLimitKey
    status: StageStatus
    out_dir: Path
    duration_ms: int = 0
    truncated: bool = False
    reason: str | None = None  # e.g. `deadline` (skipped), `write_budget` (truncated)
    error_code: str | None = None
    audit_counts: dict[str, int] = field(default_factory=dict)
    # Phase 2 additions (defaults keep the frozen constructor valid):
    rows: int = 0
    counts: dict[str, int] = field(default_factory=dict)
    facts: dict[str, Any] = field(default_factory=dict)
    has_status: bool = False

    @property
    def usable(self) -> bool:
        """The stage ran offline-verified (status read) and produced output root may read."""
        return self.has_status and self.status in (StageStatus.OK, StageStatus.TRUNCATED)


def min_free_bytes(limits: DiskLimits) -> int:
    """The worker's floor (`DISK_WORK_MIN_FREE_BYTES`, the test service sets a small one on its
    tmpfs) wins over the job's; the job's applies when the env does not set one."""
    value = os.environ.get("DISK_WORK_MIN_FREE_BYTES")
    return int(value) if value is not None and value.isdigit() else limits.min_free_bytes


def fresh(dirs: sandbox.JobDirs, name: str) -> sandbox.JobDirs:
    """A new, empty, tool-owned out dir `<job>/<name>-out` (FileExistsError: one per name)."""
    sandbox.kill_tool_processes()
    out = dirs.root / f"{name}-out"
    os.mkdir(out, 0o700)
    os.chown(out, sandbox.TOOL_UID, sandbox.TOOL_GID)
    return sandbox.JobDirs(root=dirs.root, input=dirs.input, out=out)


def _dir_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _seal_file(dir_fd: int, name: str) -> None:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    try:
        if stat.S_ISREG(os.fstat(fd).st_mode):
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o444)
            return
    finally:
        os.close(fd)
    os.unlink(name, dir_fd=dir_fd)


def seal(out: Path) -> int:
    """Make `out` root-owned read-only, post-order, without following anything; returns the
    entries removed (planted non-regular files, or anything past the depth / entry caps)."""
    removed = 0
    seen = 0
    root_fd = os.open(out, _dir_flags())
    stack: list[tuple[int, list[str]]] = [(root_fd, sorted(os.listdir(root_fd)))]
    try:
        while stack:
            dir_fd, pending = stack[-1]
            if not pending:
                os.fchown(dir_fd, 0, 0)
                os.fchmod(dir_fd, 0o555)
                stack.pop()
                os.close(dir_fd)
                continue
            name = pending.pop()
            seen += 1
            info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                if len(stack) >= MAX_SEAL_DEPTH or seen > MAX_SEAL_ENTRIES:
                    shutil.rmtree(name, dir_fd=dir_fd)
                    removed += 1
                    continue
                sub = os.open(name, _dir_flags(), dir_fd=dir_fd)
                stack.append((sub, sorted(os.listdir(sub))))
            elif stat.S_ISREG(info.st_mode) and seen <= MAX_SEAL_ENTRIES:
                _seal_file(dir_fd, name)
            else:
                os.unlink(name, dir_fd=dir_fd)
                removed += 1
    finally:
        for fd, _ in stack:
            with contextlib.suppress(OSError):
                os.close(fd)
    return removed


def collect_name(partition_index: int) -> str:
    """The `collect` stage's out dir name of a partition (phase 3 reads the mirrored tree at
    `<job>/<name>-out/artifacts/p<i>` and its manifest `collected.jsonl` beside it)."""
    return f"collect-p{partition_index}"


def collect_out(dirs: sandbox.JobDirs, partition_index: int) -> sandbox.JobDirs:
    """The sealed out dir of a partition's `collect` stage (it may not exist: not collected)."""
    out = dirs.root / f"{collect_name(partition_index)}-out"
    return sandbox.JobDirs(root=dirs.root, input=dirs.input, out=out)


def read_stage_status(dirs: sandbox.JobDirs) -> StageStatusDoc | None:
    try:
        with sandbox.open_output(dirs, STATUS) as f:
            raw = read_status(f)
    except (OSError, ValueError):
        return None
    if raw is None:
        return None
    try:
        return StageStatusDoc.model_validate(raw)
    except ValidationError:
        return None


def _result(
    stage: StageLimitKey,
    dirs: sandbox.JobDirs,
    end: str,
    returncode: int,
    fired: str | None,
    doc: StageStatusDoc | None,
    duration_ms: int,
) -> StageResult:
    common: dict[str, Any] = {
        "stage": stage,
        "out_dir": dirs.out,
        "duration_ms": duration_ms,
        "has_status": doc is not None,
    }
    if doc is not None:
        common.update(
            audit_counts=dict(doc.audit),
            rows=doc.rows,
            counts=dict(doc.counts),
            facts=dict(doc.facts),
        )
    if fired is not None:
        code = "insufficient_disk" if fired in ("min_free", "min_inodes") else None
        return StageResult(
            status=StageStatus.TRUNCATED, truncated=True, reason=fired, error_code=code, **common
        )
    if end == "timeout":
        return StageResult(
            status=StageStatus.TIMEOUT, reason="timeout", error_code="stage_timeout", **common
        )
    if end == "failed" and returncode == -signal.SIGXFSZ:
        return StageResult(
            status=StageStatus.TRUNCATED, truncated=True, reason="rlimit_fsize", **common
        )
    if doc is None:
        return StageResult(
            status=StageStatus.FAILED, reason="no_status", error_code="disk_parse_failed", **common
        )
    code = doc.error_code if doc.error_code in CODES else None
    if doc.status == "unsupported":
        return StageResult(
            status=StageStatus.UNSUPPORTED,
            reason=doc.reason,
            error_code=code or "unsupported_disk_format",
            **common,
        )
    if doc.status != "ok" or end != "exited":
        return StageResult(
            status=StageStatus.FAILED,
            reason=doc.reason or doc.error,
            error_code=code or "disk_parse_failed",
            **common,
        )
    if doc.truncated:
        return StageResult(
            status=StageStatus.TRUNCATED, truncated=True, reason=doc.reason, **common
        )
    return StageResult(status=StageStatus.OK, **common)


def _reason(value: str | None) -> str | None:
    """Reasons are short snake_case words (they reach the header's `Text64`)."""
    if value is None:
        return None
    cleaned = "".join(ch for ch in value.lower() if ch.isalnum() or ch == "_")[:64]
    return cleaned or None


def run_stage(
    argv: Sequence[str],
    dirs: sandbox.JobDirs,
    stage: StageLimitKey,
    limits: DiskLimits,
    budget: Budget,
) -> StageResult:
    timeout = budget.timeout(stage)
    if timeout <= 0:
        return StageResult(
            stage=stage, status=StageStatus.SKIPPED, out_dir=dirs.out, reason="deadline"
        )
    lim = limits.stages[stage]
    rlimits = sandbox.Rlimits(
        as_bytes=lim.rlimit_as,
        fsize_bytes=lim.rlimit_fsize,
        nproc=lim.rlimit_nproc,
        nofile=NOFILE,
    )
    env = {
        "TMPDIR": str(dirs.out),
        "XDG_CACHE_HOME": str(dirs.out),
        "HOME": "/nonexistent",
        "XDG_CONFIG_HOME": "/nonexistent",
    }
    watchdog = Watchdog(
        dirs.root, lim.write_budget, min_free_bytes(limits), sandbox.kill_tool_processes
    )
    started = time.monotonic()
    end, returncode = "exited", 0
    watchdog.start()
    try:
        sandbox.run_tool(
            list(argv),
            dirs,
            timeout_s=timeout,
            extra_env=env,
            cwd=dirs.input,
            rlimits=rlimits,
            deny_io_uring=True,
            unix_sockets_only=True,
        )
    except sandbox.ToolTimeout:
        end = "timeout"
    except sandbox.ToolFailed as exc:
        end, returncode = "failed", exc.returncode
    finally:
        watchdog.stop()
    watchdog.poll()  # a breach in the last interval still counts
    duration_ms = int((time.monotonic() - started) * 1000)
    sandbox.kill_tool_processes()  # RT3; raises SandboxCompromised (fail closed)
    if watchdog.kill_error is not None:
        raise watchdog.kill_error
    seal(dirs.out)
    doc = read_stage_status(dirs)
    result = _result(stage, dirs, end, returncode, watchdog.fired, doc, duration_ms)
    if result.reason != _reason(result.reason):
        result = dataclasses.replace(result, reason=_reason(result.reason))
    return result


__all__ = [
    "STATUS",
    "StageResult",
    "collect_name",
    "collect_out",
    "fresh",
    "min_free_bytes",
    "read_stage_status",
    "run_stage",
    "seal",
]
