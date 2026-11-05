"""The sandboxed render subprocess (worker kit `run_tool` with the M6 extensions, RT3, RT4).

    python -I -B -m report_worker.render <format> <job>/input <job>/out/<artifact>

- uid 10004, the renderer's own tool uid (`CYBERLAB_TOOL_UID` in the image; not the
  static worker's 10003, whose RLIMIT_NPROC count it would share, review L6). The Celery
  process runs as root with the analyzers' capabilities and drops it;
- `-I`: isolated mode, no `PYTHON*` variables and neither the cwd nor the user site on
  `sys.path`; `-B`: no `.pyc` writes. Not `-S`: the venv's site-packages (and the `.pth`
  that adds `report_worker`) must stay importable;
- environment: `PATH`, `LANG=C.UTF-8`, `HOME` / `TMPDIR` / `XDG_CONFIG_HOME` = the job's
  out/ dir (worker-kit defaults), `FONTCONFIG_FILE` and `MALLOC_ARENA_MAX=2` (glibc arenas
  stay under `RLIMIT_AS`). Never the broker URL;
- cwd: the job's root-owned, read-only input dir;
- `Rlimits(as=768 MiB, cpu=75 s, fsize=artifact cap, nofile=64, nproc=16)`, wall timeout
  80 s (the process group is killed). Both sit below Celery's 90 s soft limit
  (`config.TASK_SOFT_TIME_LIMIT_S`) with 10 s left for the download, the output check and
  the upload, so a slow render is answered `timeout` by the sandbox itself, never cut by
  the soft limit mid-render;
- seccomp: an allowlist (review L5): `socket()` / `socketpair()` of every family but
  `AF_UNIX` and the io_uring syscalls fail with `EACCES`. `AF_UNIX` stays allowed:
  fontconfig and Pango open no socket of any family during a render
  (`tests/test_sandbox.py` records it).

Results map to typed error codes only (`timeout`, `oom`, `too_large`, `fetch_blocked`,
`too_many_pages`, `invalid_output`, `renderer_error`); stderr is never reported.
"""

import json
import resource
import signal
import sys
from dataclasses import dataclass

from cyberlab_jobs.report import MAX_ARTIFACT_BYTES
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

from report_worker import checks
from report_worker.render import EXIT_CODES, META_NAME

MiB = 1024 * 1024
RENDER_RLIMITS = sandbox.Rlimits(
    as_bytes=768 * MiB,
    cpu_s=75,
    fsize_bytes=MAX_ARTIFACT_BYTES,
    nofile=64,
    nproc=16,
)
WALL_TIMEOUT_S = 80.0
# What the task needs besides the render subprocess (download, checks, upload): the wall
# timeout plus this margin stays within the Celery soft limit (`tests/test_sandbox.py`).
TASK_MARGIN_S = 10.0
RENDER_ENV = {
    "FONTCONFIG_FILE": "/app/assets/fonts.conf",
    "MALLOC_ARENA_MAX": "2",
}
# Killed by a signal (negative return codes): the kernel's OOM killer (the tool has
# oom_score_adj 1000), the CPU limit (SIGXCPU, or SIGKILL with the budget spent) or the
# file size limit.
SIGNAL_CODES: dict[int, str] = {
    int(signal.SIGKILL): "oom",
    int(signal.SIGXCPU): "timeout",
    int(signal.SIGXFSZ): "too_large",
}


@dataclass(frozen=True)
class RenderRun:
    pages: int | None


def render_argv(fmt: str, dirs: sandbox.JobDirs) -> list[str]:
    return [
        sys.executable,
        "-I",
        "-B",
        "-m",
        "report_worker.render",
        fmt,
        str(dirs.input),
        str(dirs.out / checks.OUTPUT_NAMES[fmt]),
    ]


def run(
    argv: list[str],
    dirs: sandbox.JobDirs,
    *,
    timeout_s: float = WALL_TIMEOUT_S,
    rlimits: sandbox.Rlimits = RENDER_RLIMITS,
) -> None:
    """Run one sandboxed command; raises `JobFailed` with a typed render error code."""
    cpu_before = _children_cpu_s()
    try:
        sandbox.run_tool(
            argv,
            dirs,
            timeout_s=timeout_s,
            extra_env=RENDER_ENV,
            cwd=dirs.input,
            rlimits=rlimits,
            unix_sockets_only=True,
            deny_io_uring=True,
        )
    except sandbox.ToolTimeout as exc:
        raise JobFailed("timeout") from exc
    except sandbox.ToolFailed as exc:
        rc = exc.returncode
        if rc < 0:
            code = SIGNAL_CODES.get(-rc, "renderer_error")
            # RLIMIT_CPU has soft == hard: the kernel sends SIGKILL with SIGXCPU, so a
            # SIGKILL after (nearly) the whole CPU budget is the CPU limit, not memory.
            cpu_limit = rlimits.cpu_s or int(timeout_s)
            if code == "oom" and _children_cpu_s() - cpu_before >= cpu_limit - 0.5:
                code = "timeout"
        else:
            code = EXIT_CODES.get(rc, "renderer_error")
        raise JobFailed(code) from exc


def _children_cpu_s() -> float:
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def render(fmt: str, dirs: sandbox.JobDirs) -> RenderRun:
    """Render `fmt` from the job's input dir into its out dir."""
    run(render_argv(fmt, dirs), dirs)
    try:
        with sandbox.open_output(dirs, META_NAME) as f:
            meta = json.loads(f.read(checks.MAX_META_BYTES + 1)[: checks.MAX_META_BYTES])
    except (OSError, ValueError) as exc:
        raise JobFailed("invalid_output", "no render metadata") from exc
    pages = meta.get("pages") if isinstance(meta, dict) else None
    return RenderRun(pages=checks.check_pages(fmt, pages))
