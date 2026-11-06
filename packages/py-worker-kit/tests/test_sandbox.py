"""Privilege separation: tools run as uid 10003 and cannot reach root's secrets or files."""

import os
import stat
import time
from pathlib import Path

import pytest

from cyberlab_worker import sandbox


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


def test_tools_are_the_oom_killers_first_choice(dirs: sandbox.JobDirs) -> None:
    sandbox.run_tool(["cat", "/proc/self/oom_score_adj"], dirs, timeout_s=5, stdout_name="oom.txt")
    assert _read(dirs, "oom.txt") == "1000"


def test_memory_limit_is_enforced(dirs: sandbox.JobDirs) -> None:
    hog = "x = bytearray(512 * 1024 * 1024)"
    with pytest.raises(sandbox.ToolFailed):
        sandbox.run_tool(["python3", "-c", hog], dirs, timeout_s=10, memory_bytes=256 * 1024 * 1024)
    sandbox.run_tool(["python3", "-c", "x = bytearray(16)"], dirs, timeout_s=10,
                     memory_bytes=256 * 1024 * 1024)  # fmt: skip


# --- M6 (RT3): per-run rlimits and the extended network deny -------------------------------

# io_uring_setup is syscall 425 on x86_64 and aarch64 (the unified syscall table).
_IO_URING_PROBE = (
    "import ctypes, errno, socket\n"
    "libc = ctypes.CDLL(None, use_errno=True)\n"
    "params = ctypes.create_string_buffer(120)\n"
    "fd = libc.syscall(425, 1, params)\n"
    "err = ctypes.get_errno()\n"
    "print('io_uring', 'ok' if fd >= 0 else errno.errorcode.get(err, str(err)))\n"
    "for name in ('AF_INET', 'AF_INET6', 'AF_NETLINK', 'AF_PACKET'):\n"
    "    try:\n"
    "        socket.socket(getattr(socket, name), socket.SOCK_DGRAM).close()\n"
    "        print(name, 'ok')\n"
    "    except OSError as exc:\n"
    "        print(name, errno.errorcode.get(exc.errno, str(exc.errno)))\n"
    "socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close()\n"
    "print('AF_UNIX', 'ok')\n"
)


def _probe(dirs: sandbox.JobDirs, name: str, **kw: object) -> dict[str, str]:
    sandbox.run_tool(["python3", "-c", _IO_URING_PROBE], dirs, timeout_s=10, stdout_name=name,
                     **kw)  # type: ignore[arg-type]  # fmt: skip
    return dict(line.split(" ", 1) for line in _read(dirs, name).splitlines())


def test_extended_deny_refuses_netlink_packet_and_io_uring_with_eacces(
    dirs: sandbox.JobDirs,
) -> None:
    import socket

    seen = _probe(dirs, "deny.txt", deny_extra_domains=(socket.AF_NETLINK,), deny_io_uring=True)
    assert seen["AF_INET"] == "EACCES" and seen["AF_INET6"] == "EACCES"
    assert seen["AF_NETLINK"] == "EACCES" and seen["AF_PACKET"] == "EACCES"
    assert seen["io_uring"] == "EACCES"
    assert seen["AF_UNIX"] == "ok"


_UNIX_ONLY_PROBE = (
    "import errno, socket\n"
    "def attempt(name, family, kind):\n"
    "    try:\n"
    "        socket.socket(family, kind).close()\n"
    "        print(name, 'ok')\n"
    "    except OSError as exc:\n"
    "        print(name, errno.errorcode.get(exc.errno, str(exc.errno)))\n"
    "for name in ('AF_INET', 'AF_INET6', 'AF_NETLINK', 'AF_PACKET'):\n"
    "    attempt(name, getattr(socket, name), socket.SOCK_DGRAM)\n"
    "attempt('AF_ALG', 38, socket.SOCK_SEQPACKET)\n"
    "attempt('AF_VSOCK', 40, socket.SOCK_STREAM)\n"
    "attempt('AF_UNIX', socket.AF_UNIX, socket.SOCK_STREAM)\n"
    "for name, family in (('pair_unix', socket.AF_UNIX), ('pair_tipc', 30)):\n"
    "    try:\n"
    "        a, b = socket.socketpair(family, socket.SOCK_DGRAM)\n"
    "        a.close(); b.close()\n"
    "        print(name, 'ok')\n"
    "    except OSError as exc:\n"
    "        print(name, errno.errorcode.get(exc.errno, str(exc.errno)))\n"
)


def test_unix_only_filter_denies_every_other_socket_family(dirs: sandbox.JobDirs) -> None:
    """The renderer's allowlist (review L5): only AF_UNIX `socket()` / `socketpair()`."""
    sandbox.run_tool(["python3", "-c", _UNIX_ONLY_PROBE], dirs, timeout_s=10,
                     stdout_name="unix.txt", unix_sockets_only=True)  # fmt: skip
    seen = dict(line.split(" ", 1) for line in _read(dirs, "unix.txt").splitlines())
    for name in ("AF_INET", "AF_INET6", "AF_NETLINK", "AF_PACKET", "AF_ALG", "AF_VSOCK"):
        assert seen[name] == "EACCES", name
    assert seen["pair_tipc"] == "EACCES"
    assert seen["AF_UNIX"] == "ok" and seen["pair_unix"] == "ok"


def test_tool_uid_comes_from_the_image_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CYBERLAB_TOOL_UID", "10004")
    assert sandbox._tool_id("CYBERLAB_TOOL_UID") == 10004  # noqa: SLF001
    monkeypatch.delenv("CYBERLAB_TOOL_UID")
    assert sandbox._tool_id("CYBERLAB_TOOL_UID") == 10003  # noqa: SLF001
    for bad in ("0", "999", "65534"):
        monkeypatch.setenv("CYBERLAB_TOOL_UID", bad)
        with pytest.raises(ValueError, match="unprivileged"):
            sandbox._tool_id("CYBERLAB_TOOL_UID")  # noqa: SLF001


def test_default_filter_is_unchanged_for_the_analyzers(dirs: sandbox.JobDirs) -> None:
    """Without the M6 options a tool keeps netlink (and io_uring is whatever the container
    runtime decides): the analyzers' filter is exactly the M2/M3 one."""
    seen = _probe(dirs, "default.txt")
    assert seen["AF_INET"] == "EACCES" and seen["AF_INET6"] == "EACCES"
    assert seen["AF_NETLINK"] == "ok"
    assert seen["io_uring"] != "EACCES"


def test_rlimits_are_applied(dirs: sandbox.JobDirs) -> None:
    probe = (
        "import resource\n"
        "names = ('RLIMIT_AS', 'RLIMIT_CPU', 'RLIMIT_FSIZE', 'RLIMIT_NOFILE', 'RLIMIT_NPROC')\n"
        "for name in names:\n"
        "    print(name, resource.getrlimit(getattr(resource, name))[1])\n"
    )
    limits = sandbox.Rlimits(
        as_bytes=768 * 1024**2, cpu_s=90, fsize_bytes=32 * 1024**2, nofile=64, nproc=16
    )
    sandbox.run_tool(["python3", "-c", probe], dirs, timeout_s=10, stdout_name="rl.txt",
                     rlimits=limits)  # fmt: skip
    seen = dict(line.split(" ", 1) for line in _read(dirs, "rl.txt").splitlines())
    assert seen == {
        "RLIMIT_AS": str(768 * 1024**2),
        "RLIMIT_CPU": "90",
        "RLIMIT_FSIZE": str(32 * 1024**2),
        "RLIMIT_NOFILE": "64",
        "RLIMIT_NPROC": "16",
    }


def test_default_rlimits_are_unchanged(dirs: sandbox.JobDirs) -> None:
    probe = (
        "import resource\n"
        "print(resource.getrlimit(resource.RLIMIT_NOFILE)[1],"
        " resource.getrlimit(resource.RLIMIT_FSIZE)[1])\n"
    )
    sandbox.run_tool(["python3", "-c", probe], dirs, timeout_s=10, stdout_name="d.txt")
    assert _read(dirs, "d.txt") == f"1024 {sandbox.MAX_OUTPUT_FILE}"


def test_file_size_limit_stops_oversized_output(dirs: sandbox.JobDirs) -> None:
    writer = "open('big', 'wb').write(b'x' * (2 * 1024 * 1024))"
    with pytest.raises(sandbox.ToolFailed):
        sandbox.run_tool(["python3", "-c", writer], dirs, timeout_s=10,
                         rlimits=sandbox.Rlimits(fsize_bytes=1024 * 1024))  # fmt: skip


def test_nproc_limit_stops_fork_bombs(dirs: sandbox.JobDirs) -> None:
    bomb = (
        "import os, sys\n"
        "pids = []\n"
        "try:\n"
        "    for _ in range(64):\n"
        "        pid = os.fork()\n"
        "        if pid == 0:\n"
        "            import time; time.sleep(5); os._exit(0)\n"
        "        pids.append(pid)\n"
        "except OSError:\n"
        "    sys.exit(3)\n"
    )
    with pytest.raises(sandbox.ToolFailed) as failed:
        sandbox.run_tool(["python3", "-c", bomb], dirs, timeout_s=10,
                         rlimits=sandbox.Rlimits(nproc=8))  # fmt: skip
    assert failed.value.returncode == 3
    sandbox.cleanup(None)


def test_memory_limit_is_given_once(dirs: sandbox.JobDirs) -> None:
    with pytest.raises(ValueError, match="once"):
        sandbox.run_tool(["true"], dirs, timeout_s=5, memory_bytes=1024**3,
                         rlimits=sandbox.Rlimits(as_bytes=1024**3))  # fmt: skip


def test_a_failed_kill_helper_fork_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Security review: when root cannot fork its kill helper (pids limit exhausted by a fork
    bomb), the tool processes count as alive: the container is stopped, never left running."""
    import signal

    signals: list[tuple[int, int]] = []

    def no_fork() -> int:
        raise BlockingIOError(11, "Resource temporarily unavailable")

    def record_kill(pid: int, sig: int) -> None:
        signals.append((pid, sig))

    monkeypatch.setattr(sandbox, "tool_pids", lambda: [4242])
    monkeypatch.setattr(os, "fork", no_fork)
    monkeypatch.setattr(os, "kill", record_kill)
    with pytest.raises(sandbox.SandboxCompromised):
        sandbox.kill_tool_processes()
    assert signals == [(1, signal.SIGTERM)]


def test_no_survivor_means_no_fork(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_fork() -> int:
        raise AssertionError("nothing to kill: no helper is forked")

    monkeypatch.setattr(sandbox, "tool_pids", lambda: [])
    monkeypatch.setattr(os, "fork", no_fork)
    sandbox.kill_tool_processes()
