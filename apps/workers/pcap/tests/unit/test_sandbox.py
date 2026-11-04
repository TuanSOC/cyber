"""Privilege separation: tools run as uid 10003 and cannot reach root's secrets or files."""

import os
import stat
import time
from pathlib import Path

import pytest

from pcap_worker import sandbox


def _read(dirs: sandbox.JobDirs, name: str) -> str:
    with sandbox.open_output(dirs, name) as f:
        return f.read().decode().strip()


def test_tool_runs_unprivileged(dirs: sandbox.JobDirs) -> None:
    sandbox.run_tool(["id", "-u"], dirs, timeout_s=5, stdout_name="uid.txt")
    assert _read(dirs, "uid.txt") == str(sandbox.TOOL_UID)
    sandbox.run_tool(
        ["sh", "-c", "grep -E '^Cap(Eff|Prm)' /proc/self/status"],
        dirs,
        timeout_s=5,
        stdout_name="caps.txt",
    )
    assert all(line.endswith("0000000000000000") for line in _read(dirs, "caps.txt").splitlines())


def test_tool_cannot_read_the_worker_environment(dirs: sandbox.JobDirs) -> None:
    """The broker credentials live in the root process; the tool uid cannot read them."""
    with pytest.raises(sandbox.ToolFailed):
        sandbox.run_tool(["cat", "/proc/1/environ"], dirs, timeout_s=5)
    with pytest.raises(sandbox.ToolFailed):
        sandbox.run_tool(["cat", f"/proc/{os.getpid()}/environ"], dirs, timeout_s=5)


def test_tool_gets_a_minimal_environment(dirs: sandbox.JobDirs) -> None:
    sandbox.run_tool(["env"], dirs, timeout_s=5, stdout_name="env.txt")
    names = {line.split("=", 1)[0] for line in _read(dirs, "env.txt").splitlines()}
    assert names <= {"PATH", "HOME", "XDG_CONFIG_HOME", "TMPDIR", "LANG", "PWD", "SHLVL", "_"}


def test_tool_can_read_but_not_modify_the_capture(dirs: sandbox.JobDirs) -> None:
    sandbox.run_tool(["cat", str(dirs.capture)], dirs, timeout_s=5, stdout_name="copy")
    assert _read(dirs, "copy") == "capture bytes"
    for script in (f"echo x >> {dirs.capture}", f"rm -f {dirs.capture}", f"ls {dirs.root.parent}"):
        with pytest.raises(sandbox.ToolFailed):
            sandbox.run_tool(["sh", "-c", script], dirs, timeout_s=5)
    assert dirs.capture.read_bytes() == b"capture bytes"


def test_job_directory_permissions(dirs: sandbox.JobDirs) -> None:
    assert stat.S_IMODE(dirs.root.parent.stat().st_mode) == 0o711
    assert stat.S_IMODE(dirs.root.stat().st_mode) == 0o711
    assert dirs.input.stat().st_uid == 0 and stat.S_IMODE(dirs.input.stat().st_mode) == 0o755
    assert dirs.out.stat().st_uid == sandbox.TOOL_UID
    assert stat.S_IMODE(dirs.out.stat().st_mode) == 0o700


def test_timeout_kills_the_whole_process_group(dirs: sandbox.JobDirs) -> None:
    with pytest.raises(sandbox.ToolTimeout):
        sandbox.run_tool(["sh", "-c", "sleep 30 & sleep 30"], dirs, timeout_s=1)
    assert sandbox.tool_pids() == []


def test_cleanup_kills_processes_that_escaped_the_session(dirs: sandbox.JobDirs) -> None:
    sandbox.run_tool(
        ["sh", "-c", "(setsid sleep 60 </dev/null >/dev/null 2>&1 &); sleep 0.2"],
        dirs,
        timeout_s=5,
    )
    assert sandbox.tool_pids() != []  # a would-be persistent process survived the run
    sandbox.cleanup(None)
    assert sandbox.tool_pids() == []


def test_output_symlinks_and_special_files_are_refused(dirs: sandbox.JobDirs) -> None:
    sandbox.run_tool(
        ["sh", "-c", "ln -s /etc/shadow evil && mkfifo pipe && mkdir sub"], dirs, timeout_s=5
    )
    with pytest.raises(OSError):
        with sandbox.open_output(dirs, "evil"):
            pass
    for name in ("pipe", "sub"):
        with pytest.raises(ValueError):
            with sandbox.open_output(dirs, name):
                pass
    for name in ("../input/capture", "/etc/passwd", ".."):
        with pytest.raises(ValueError):
            with sandbox.open_output(dirs, name):
                pass


def test_planted_output_names_cannot_redirect_root_writes(dirs: sandbox.JobDirs) -> None:
    before = Path("/etc/passwd").read_bytes()
    sandbox.run_tool(["sh", "-c", "ln -s /etc/passwd result.txt"], dirs, timeout_s=5)
    with pytest.raises(FileExistsError):
        sandbox.run_tool(["cat", str(dirs.capture)], dirs, timeout_s=5, stdout_name="result.txt")
    assert Path("/etc/passwd").read_bytes() == before


def test_cleanup_removes_the_job_directory(dirs: sandbox.JobDirs) -> None:
    sandbox.run_tool(["sh", "-c", "echo data > leftover"], dirs, timeout_s=5)
    sandbox.cleanup(dirs)
    assert not dirs.root.exists()


# A would-be persistent attacker: own session + non-dumpable (root-owned /proc entry).
SURVIVOR = (
    "import ctypes, os, time\n"
    "if os.fork() == 0:\n"
    "    os.setsid()\n"
    "    ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE = 0\n"
    "    time.sleep(120)\n"
)


def test_non_dumpable_escapees_are_found_and_killed(dirs: sandbox.JobDirs) -> None:
    sandbox.run_tool(["python3", "-c", SURVIVOR], dirs, timeout_s=5)
    time.sleep(0.3)  # let the forked child detach and drop its dumpable flag
    assert sandbox.tool_pids() != []  # found through /proc/<pid>/status uids
    sandbox.cleanup(None)
    assert sandbox.tool_pids() == []


def test_next_job_starts_without_leftovers(dirs: sandbox.JobDirs) -> None:
    """Even when a job's cleanup never ran (hard time limit, OOM), prepare() resets."""
    sandbox.run_tool(["python3", "-c", SURVIVOR], dirs, timeout_s=5)
    assert sandbox.tool_pids() != []
    nxt = sandbox.prepare(dirs.root.parent, "next-job")
    try:
        assert sandbox.tool_pids() == []
        assert not dirs.root.exists()
    finally:
        sandbox.cleanup(nxt)


def test_tools_cannot_open_network_sockets(dirs: sandbox.JobDirs) -> None:
    probe = (
        "import socket\n"
        "for family in (socket.AF_INET, socket.AF_INET6):\n"
        "    try:\n"
        "        socket.socket(family, socket.SOCK_STREAM)\n"
        "    except PermissionError:\n"
        "        continue\n"
        "    raise SystemExit('socket allowed')\n"
        "socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close()\n"
    )
    sandbox.run_tool(["python3", "-c", probe], dirs, timeout_s=5)


def test_tool_scratch_space_is_its_own_job_directory(dirs: sandbox.JobDirs) -> None:
    sandbox.run_tool(
        ["python3", "-c", "import tempfile; print(tempfile.gettempdir())"],
        dirs,
        timeout_s=5,
        stdout_name="tmp.txt",
    )
    assert _read(dirs, "tmp.txt") == str(dirs.out)
    for shared in ("/tmp", "/dev/shm"):
        with pytest.raises(sandbox.ToolFailed):
            sandbox.run_tool(["sh", "-c", f"echo x > {shared}/leak"], dirs, timeout_s=5)
