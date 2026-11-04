"""Run analysis tools as an unprivileged uid and clean up everything they leave behind.

Layout per job (on the `pcap_work` volume):

    /work                 root 0711   (no listing: tools cannot discover other jobs)
    /work/<job>/          root 0711
    /work/<job>/input/    root 0755   capture (root-owned, 0444): readable, not writable
    /work/<job>/out/      tool 0700   the only place tools can write

The root process reads tool output only through `open_output()`: single path component,
opened relative to the out/ directory with O_NOFOLLOW, regular files only. A compromised
tool therefore cannot make root read (or overwrite) anything outside out/ via symlinks.
"""

import contextlib
import logging
import os
import resource
import secrets
import shutil
import signal
import stat
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from pcap_worker import seccomp

log = logging.getLogger(__name__)

TOOL_UID = 10003
TOOL_GID = 10003
TOOL_PATH = "/usr/local/zeek/bin:/usr/bin:/bin"
MAX_OUTPUT_FILE = 2 * 1024**3


class ToolTimeout(Exception):
    pass


class SandboxCompromised(Exception):
    """A tool process could not be killed: this container must not run another job."""


class ToolFailed(Exception):
    def __init__(self, argv0: str, returncode: int, stderr_tail: str) -> None:
        super().__init__(f"{argv0} exited with {returncode}")
        self.returncode = returncode
        self.stderr_tail = stderr_tail


@dataclass(frozen=True)
class JobDirs:
    root: Path
    input: Path
    out: Path

    @property
    def capture(self) -> Path:
        return self.input / "capture"


def reset(work_dir: Path) -> None:
    """Start from nothing: no tool process alive, no file of any earlier job left.

    Runs before every job (and when a worker child starts), so leftovers of a job whose
    cleanup never ran (hard time limit, OOM kill of the worker child) cannot reach the next.
    """
    kill_tool_processes()
    os.chmod(work_dir, 0o711)  # noqa: S103 - traverse-only: tools cannot list other jobs
    for entry in work_dir.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry, ignore_errors=True)
        else:
            entry.unlink(missing_ok=True)


def prepare(work_dir: Path, job_id: str) -> JobDirs:
    reset(work_dir)
    root = work_dir / job_id
    root.mkdir(mode=0o711)
    input_dir = root / "input"
    input_dir.mkdir(mode=0o755)
    out = root / "out"
    out.mkdir(mode=0o700)
    os.chown(out, TOOL_UID, TOOL_GID)
    return JobDirs(root=root, input=input_dir, out=out)


def _child_setup(cpu_s: int) -> None:  # runs in the child, after it dropped to the tool uid
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT_FILE, MAX_OUTPUT_FILE))
    resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
    seccomp.deny_network()


def run_tool(
    argv: list[str],
    dirs: JobDirs,
    *,
    timeout_s: float,
    stdout_name: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> None:
    """Run one tool as the tool uid in out/. Raises ToolTimeout / ToolFailed."""
    env = {
        "PATH": TOOL_PATH,
        "HOME": str(dirs.out),
        "XDG_CONFIG_HOME": str(dirs.out),
        "TMPDIR": str(dirs.out),
        "LANG": "C.UTF-8",
        **(extra_env or {}),
    }
    # Unpredictable names per run; O_EXCL still refuses anything a tool planted.
    run = f".{Path(argv[0]).name}.{secrets.token_hex(8)}"
    stderr_name = f"{run}.stderr"
    cpu = max(1, int(timeout_s))
    with (
        _create_output(dirs, stdout_name or f"{run}.stdout") as stdout,
        _create_output(dirs, stderr_name) as stderr,
    ):
        proc = subprocess.Popen(
            argv,
            cwd=dirs.out,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            user=TOOL_UID,
            group=TOOL_GID,
            extra_groups=[],
            umask=0o077,
            start_new_session=True,
            close_fds=True,
            preexec_fn=lambda: _child_setup(cpu),  # rlimits + seccomp, no locks taken
        )
        try:
            returncode = proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired as exc:
            _kill_group(proc.pid)
            proc.wait()
            raise ToolTimeout(argv[0]) from exc
        finally:
            _kill_group(proc.pid)  # anything the tool forked into its session
    if returncode != 0:
        raise ToolFailed(argv[0], returncode, _tail(dirs, stderr_name))


@contextlib.contextmanager
def _create_output(dirs: JobDirs, name: str) -> Iterator[BinaryIO]:
    """Create a new file in out/ for a tool's stdout/stderr.

    O_EXCL | O_NOFOLLOW relative to out/: a name planted by an earlier (compromised) tool,
    symlink or not, fails the job instead of redirecting a root-opened write.
    """
    dir_fd = os.open(dirs.out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        fd = os.open(name, flags, 0o600, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    os.fchown(fd, TOOL_UID, TOOL_GID)
    with os.fdopen(fd, "wb") as f:
        yield f


def _kill_group(pgid: int) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, signal.SIGKILL)


def _tail(dirs: JobDirs, name: str, size: int = 2048) -> str:
    try:
        with open_output(dirs, name) as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - size))
            return f.read().decode("utf-8", "replace")
    except (OSError, ValueError):
        return ""


@contextlib.contextmanager
def open_output(dirs: JobDirs, name: str) -> Iterator[BinaryIO]:
    """Open a tool output file safely (see module docstring)."""
    if "/" in name or name in {"", ".", ".."}:
        raise ValueError("output names are single path components")
    dir_fd = os.open(dirs.out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError(f"{name} is not a regular file")
    os.set_blocking(fd, True)
    with os.fdopen(fd, "rb") as f:
        yield f


def output_exists(dirs: JobDirs, name: str) -> bool:
    try:
        with open_output(dirs, name):
            return True
    except (OSError, ValueError):
        return False


def tool_pids() -> list[int]:
    """Live (non-zombie) processes running with the tool uid as real, effective or saved uid.

    Read from /proc/<pid>/status rather than the owner of /proc/<pid>: a process that made
    itself non-dumpable gets a root-owned /proc entry but keeps its uids.
    """
    pids = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = dict(
                line.split(":", 1) for line in (entry / "status").read_text().splitlines()
            )
            uids = {int(u) for u in fields["Uid"].split()[:3]}
            state = fields["State"].split()[0]
        except (OSError, KeyError, ValueError):
            continue
        if TOOL_UID in uids and state not in {"Z", "X"}:
            pids.append(int(entry.name))
    return pids


def _kill_as_tool_uid() -> None:
    """Fork a helper that becomes the tool uid and SIGKILLs every process it may signal.

    kill(-1) as uid 10003 reaches every process of that uid whatever its session, process
    group or dumpable flag (never the helper itself or PID 1). Its return value says nothing
    useful (0 whenever any other process exists), so callers verify with tool_pids().
    """
    pid = os.fork()
    if pid == 0:  # pragma: no cover - runs in the forked helper
        try:
            os.setgroups([])
            os.setresgid(TOOL_GID, TOOL_GID, TOOL_GID)
            os.setresuid(TOOL_UID, TOOL_UID, TOOL_UID)
            for _ in range(3):  # catch processes forked while the previous round ran
                with contextlib.suppress(ProcessLookupError):
                    os.kill(-1, signal.SIGKILL)
                time.sleep(0.01)
        finally:
            os._exit(0)
    os.waitpid(pid, 0)


def kill_tool_processes() -> None:
    """Kill every tool-uid process; if any survives, stop the whole container (fail closed)."""
    for _ in range(20):
        if not tool_pids():
            return
        _kill_as_tool_uid()
        time.sleep(0.05)
    log.critical("tool processes survived SIGKILL: %s; stopping the container", tool_pids())
    with contextlib.suppress(OSError):
        os.kill(1, signal.SIGTERM)  # tini -> container exits; compose restarts it clean
    raise SandboxCompromised("tool processes survived cleanup")


def cleanup(dirs: JobDirs | None) -> None:
    kill_tool_processes()
    if dirs is not None:
        shutil.rmtree(dirs.root, ignore_errors=True)
