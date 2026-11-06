"""The job's directories and root's safe writes into them (M10 phase 2; the static
`Workspace.engine()` pattern, M8 RT26).

`sandbox.prepare` ran once for the job (the pipeline); `create(dirs)` adds:

    /work/<job>/            root 0711   (kit)
    /work/<job>/input/      root 0755   the sample, root-owned 0444 (the download)
    /work/<job>/stage/      root 0755   root's hand-off files, 0444 (RT23: the decompile
                                        list is never written into a tool-writable dir)
    /work/<job>/project/    tool 0700   the Ghidra project: created by `analyze`, re-opened
                                        by `decompile` (program opened without saving; the
                                        dir stays tool-writable for Ghidra's lock file;
                                        same uid, no trust boundary between the stages)
    /work/<job>/<stage>-out tool 0700   one fresh out dir per stage (`fresh`), created after
                                        every tool process was killed; sealed (root 0700)
                                        after its run, so a later stage cannot alter an
                                        earlier stage's output

Root reads stage output only through the kit (`sandbox.open_output`: dir fd, O_NOFOLLOW,
regular files only). `Workspace.out` is the kit's own `out/` (unused by the stages).

Free space (RT5): before the download, `/work` must have the sample size +
`max_work_bytes` + 1 GiB free (`insufficient_disk`); during every stage the watchdog
(`engines/watch.py`) bounds the job dir.
"""

import contextlib
import os
import shutil
from pathlib import Path

from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

from re_worker.engines import Workspace

GIB = 1024**3
DISK_HEADROOM = GIB
TEST_DISK_HEADROOM = 16 * 1024**2  # the test service's work volume


def disk_headroom() -> int:
    return TEST_DISK_HEADROOM if os.environ.get("TEST_PROFILE") == "1" else DISK_HEADROOM


def check_free_space(work_dir: Path, size: int, max_work_bytes: int) -> None:
    if shutil.disk_usage(work_dir).free < size + max_work_bytes + disk_headroom():
        raise JobFailed("insufficient_disk")


def create(dirs: sandbox.JobDirs) -> Workspace:
    stage = dirs.root / "stage"
    os.mkdir(stage, 0o755)
    os.chmod(stage, 0o755)  # umask-independent
    project = dirs.root / "project"
    os.mkdir(project, 0o700)
    os.chown(project, sandbox.TOOL_UID, sandbox.TOOL_GID)
    return Workspace(root=dirs.root, input=dirs.input, stage=stage, out=dirs.out, project=project)


def job_dirs(ws: Workspace, out: Path) -> sandbox.JobDirs:
    return sandbox.JobDirs(root=ws.root, input=ws.input, out=out)


def fresh(ws: Workspace, name: str, subdirs: tuple[str, ...] = ()) -> sandbox.JobDirs:
    """A new, empty, tool-owned out dir (nothing of an earlier stage alive)."""
    sandbox.kill_tool_processes()
    out = ws.root / f"{name}-out"
    os.mkdir(out, 0o700)  # FileExistsError: a stage name is used once per job
    os.chown(out, sandbox.TOOL_UID, sandbox.TOOL_GID)
    for sub in subdirs:
        path = out / sub
        os.mkdir(path, 0o700)
        os.chown(path, sandbox.TOOL_UID, sandbox.TOOL_GID)
    return job_dirs(ws, out)


def seal(dirs: sandbox.JobDirs) -> None:
    """After a run: no tool process left, the out dir root-owned (unreachable by the tool)."""
    sandbox.kill_tool_processes()
    with contextlib.suppress(OSError):
        os.chown(dirs.out, 0, 0)
        os.chmod(dirs.out, 0o700)


def _write_at(directory: Path, name: str, data: bytes, mode: int) -> Path:
    if "/" in name or name in {"", ".", ".."}:
        raise ValueError("a single path component")
    dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        fd = os.open(name, flags, 0o600, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        os.fchmod(f.fileno(), mode)
    return directory / name


def write_stage(ws: Workspace, name: str, data: bytes) -> Path:
    """Root's hand-off file (root-owned 0444 in the root-owned stage dir, RT23)."""
    return _write_at(ws.stage, name, data, 0o444)


def write_out(dirs: sandbox.JobDirs, name: str, data: bytes) -> None:
    """Root writes a file into an out dir in place of a probe (the replay engine)."""
    _write_at(dirs.out, name, data, 0o600)


__all__ = [
    "check_free_space",
    "create",
    "disk_headroom",
    "fresh",
    "job_dirs",
    "seal",
    "write_out",
    "write_stage",
]
