"""Isolation of the probe / analyzer child, exactly as `VolatilityEngine` starts it (M8; the
pcap / static / report sandbox tests are the pattern). The engine's real `run_tool` call is
kept (tool uid 10006, seccomp `unix_sockets_only` + `deny_io_uring`, its rlimits, cwd = the
read-only input dir, the reduced env, a fresh out dir, `Workspace.seal` after the run); only
the module the interpreter runs is swapped for a hostile payload, so these tests show what a
compromised Volatility parser could do from inside the probe:

- every socket family but AF_UNIX (inet, inet6, netlink, packet, vsock, alg, tipc, bluetooth,
  xdp) and the three io_uring syscalls are refused with EACCES;
- nothing outside the probe's own out dir is writable: the image, the input dir, the job and
  work dirs, the symbol store, an earlier probe's (sealed) out dir, /tmp, /dev/shm, the code;
- after a timeout (or a normal exit) no process of the tool uid is left, also ones that
  escaped the session (setsid) or made themselves non-dumpable.

    scripts/lane-test.sh 4 --service memory-worker-test \\
        pytest -q tests/engine/test_probe_isolation.py
"""

import json
import os
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("resource")

from cyberlab_jobs.memory import MemoryPlugin, OsHint  # noqa: E402
from cyberlab_worker import sandbox  # noqa: E402

from memory_worker.config import load  # noqa: E402
from memory_worker.engines import volatility  # noqa: E402
from memory_worker.engines.volatility import VolatilityEngine  # noqa: E402
from memory_worker.engines.workspace import ROWS, Workspace  # noqa: E402


@pytest.fixture
def setup(dirs: sandbox.JobDirs) -> tuple[Workspace, VolatilityEngine]:
    store = dirs.root / "symbols"
    for sub in ("", "windows", "linux"):
        (store / sub).mkdir(mode=0o755, exist_ok=True)
    (store / "manifest.json").write_text('{"version": 1, "volatility_version": "2.28.2"}\n')
    os.chmod(store / "manifest.json", 0o644)
    config = load({"BROKER_URL": "redis://x", "MEMORY_SYMBOLS_DIR": str(store)})
    ws = Workspace(dirs, store)
    ws.image.write_bytes(b"not a memory image")
    os.chmod(ws.image, 0o444)
    return ws, VolatilityEngine(config)


@pytest.fixture
def payload(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Swap `-m memory_worker.probe <args>` for `-c <code>`; everything else the engine passes
    to `run_tool` (interpreter flags, limits, seccomp switches, cwd, env) is kept and
    recorded."""
    real = sandbox.run_tool
    seen: dict[str, Any] = {}

    def swapped(argv: list[str], dirs: sandbox.JobDirs, **kwargs: Any) -> None:
        cut = argv.index("-m")
        seen["argv"], seen["kwargs"] = argv, kwargs
        real([*argv[:cut], "-c", seen["code"]], dirs, **kwargs)

    monkeypatch.setattr(sandbox, "run_tool", swapped)
    return seen


def _rows(run_dirs: sandbox.JobDirs) -> dict[str, str]:
    with sandbox.open_output(run_dirs, ROWS) as f:
        return dict(line.split(" ", 1) for line in f.read().decode().splitlines())


SOCKETS = """
import ctypes, errno, socket
def attempt(name, family, kind):
    try:
        socket.socket(family, kind).close()
        print(name, "ok")
    except OSError as exc:
        print(name, errno.errorcode.get(exc.errno, str(exc.errno)))
for name, family, kind in [
    ("AF_INET", 2, socket.SOCK_STREAM), ("AF_INET_DGRAM", 2, socket.SOCK_DGRAM),
    ("AF_INET6", 10, socket.SOCK_STREAM), ("AF_NETLINK", 16, socket.SOCK_RAW),
    ("AF_NETLINK_DGRAM", 16, socket.SOCK_DGRAM), ("AF_PACKET", 17, socket.SOCK_RAW),
    ("AF_TIPC", 30, socket.SOCK_RDM), ("AF_BLUETOOTH", 31, socket.SOCK_STREAM),
    ("AF_ALG", 38, socket.SOCK_SEQPACKET), ("AF_VSOCK", 40, socket.SOCK_STREAM),
    ("AF_VSOCK_DGRAM", 40, socket.SOCK_DGRAM), ("AF_XDP", 44, socket.SOCK_RAW),
    ("AF_UNIX", 1, socket.SOCK_STREAM),
]:
    attempt(name, family, kind)
for name, family in (("pair_unix", 1), ("pair_tipc", 30), ("pair_vsock", 40)):
    try:
        a, b = socket.socketpair(family, socket.SOCK_STREAM)
        a.close(); b.close()
        print(name, "ok")
    except OSError as exc:
        print(name, errno.errorcode.get(exc.errno, str(exc.errno)))
libc = ctypes.CDLL(None, use_errno=True)
params = ctypes.create_string_buffer(120)
# io_uring_setup / io_uring_enter / io_uring_register (x86_64 and aarch64: 425..427)
for name, number, args in (("io_uring_setup", 425, (1, params)),
                           ("io_uring_enter", 426, (0, 0, 0, 0, None, 0)),
                           ("io_uring_register", 427, (0, 0, None, 0))):
    ctypes.set_errno(0)
    rc = libc.syscall(number, *args)
    err = ctypes.get_errno()
    print(name, "ok" if rc >= 0 else errno.errorcode.get(err, str(err)))
"""

DENIED = (
    "AF_INET", "AF_INET_DGRAM", "AF_INET6", "AF_NETLINK", "AF_NETLINK_DGRAM", "AF_PACKET",
    "AF_TIPC", "AF_BLUETOOTH", "AF_ALG", "AF_VSOCK", "AF_VSOCK_DGRAM", "AF_XDP",
    "pair_tipc", "pair_vsock", "io_uring_setup", "io_uring_enter", "io_uring_register",
)  # fmt: skip


@pytest.mark.parametrize("step", ["identify", "plugin"])
def test_only_unix_sockets_and_no_io_uring_from_the_probe(
    setup: tuple[Workspace, VolatilityEngine], payload: Any, step: str
) -> None:
    ws, engine = setup
    payload["code"] = SOCKETS
    if step == "identify":
        run = engine.identify(ws, OsHint.AUTO, 30)
    else:
        run = engine.run(ws, MemoryPlugin.LINUX_PSLIST, 30, 10)
    assert run.end == "exited", run
    kwargs = payload["kwargs"]
    assert kwargs["unix_sockets_only"] is True and kwargs["deny_io_uring"] is True
    assert payload["argv"][1:4] == ["-I", "-s", "-B"]
    seen = _rows(run.dirs)
    for name in DENIED:
        assert seen[name] == "EACCES", (name, seen[name])
    assert seen["AF_UNIX"] == "ok" and seen["pair_unix"] == "ok"


# Targets arrive as JSON in TARGETS (prepended by the test); "OUT_DIR" is the probe's own
# out dir (its TMPDIR), the one place it may create a file.
WRITES = """
import json, os
targets = json.loads(TARGETS)
def attempt(name, action):
    try:
        action()
        print(name, "ok")
    except OSError as exc:
        print(name, type(exc).__name__)
def create(path):
    if path == "OUT_DIR":
        path = os.path.join(os.environ["TMPDIR"], "planted")
    return lambda: open(path, "xb").close()
for name, path in targets["create"].items():
    attempt("create:" + name, create(path))
for name, path in targets["append"].items():
    attempt("append:" + name, lambda p=path: open(p, "ab").close())
for name, path in targets["remove"].items():
    attempt("remove:" + name, lambda p=path: os.unlink(p))
for name, path in targets["chmod"].items():
    attempt("chmod:" + name, lambda p=path: os.chmod(p, 0o777))
for name, path in targets["mkdir"].items():
    attempt("mkdir:" + name, lambda p=path: os.mkdir(p))
attempt("rename:image", lambda: os.rename(targets["image"], targets["image"] + ".moved"))
attempt("symlink:input", lambda: os.symlink("/etc/passwd", os.path.join(os.getcwd(), "ln")))
"""


def test_nothing_outside_the_out_dir_is_writable(
    setup: tuple[Workspace, VolatilityEngine], payload: Any
) -> None:
    ws, engine = setup
    # An earlier probe of the same job, sealed after its run.
    earlier = ws.fresh("earlier")
    (earlier.out / "rows.jsonl").write_text("{}\n")
    Workspace.seal(earlier)
    store, root, work = ws.symbols_dir, ws.dirs.root, ws.dirs.root.parent
    engine_file = Path(volatility.__file__).resolve()
    targets = {
        "image": str(ws.image),
        "create": {
            "input": str(ws.dirs.input / "planted"),
            "job_root": str(root / "planted"),
            "work_root": str(work / "planted"),
            "store": str(store / "linux" / "planted.json.xz"),
            "store_root": str(store / "planted"),
            "sealed_out": str(earlier.out / "planted"),
            "tmp": "/tmp/planted",
            "dev_shm": "/dev/shm/planted",
            "code": str(engine_file.parent / "planted.py"),
            "slash": "/planted",
            "etc": "/etc/planted",
            "own_out": "OUT_DIR",
        },
        "append": {
            "image": str(ws.image),
            "manifest": str(store / "manifest.json"),
            "sealed_rows": str(earlier.out / "rows.jsonl"),
            "engine_code": str(engine_file),
        },
        "remove": {"image": str(ws.image), "manifest": str(store / "manifest.json")},
        "chmod": {"image": str(ws.image), "input": str(ws.dirs.input), "job_root": str(root)},
        "mkdir": {
            "input": str(ws.dirs.input / "d"),
            "job_root": str(root / "d"),
            "store": str(store / "d"),
        },
    }
    payload["code"] = f"TARGETS = {json.dumps(json.dumps(targets))}\n" + WRITES
    run = engine.identify(ws, OsHint.AUTO, 30)
    assert run.end == "exited", run
    seen = _rows(run.dirs)
    assert len(seen) == 26  # every attempt reported
    for name, outcome in seen.items():
        if name == "create:own_out":
            assert outcome == "ok", name
        else:
            assert outcome != "ok", (name, outcome)
    assert ws.image.read_bytes() == b"not a memory image"
    assert not (store / "linux" / "planted.json.xz").exists()
    assert not (ws.dirs.input / "planted").exists()


SURVIVORS = """
import ctypes, os, time
# A grandchild in its own session (escapes the process-group kill) ...
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        time.sleep(600)
    os._exit(0)
# ... and one that also made itself non-dumpable (root-owned /proc entry).
if os.fork() == 0:
    os.setsid()
    ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE = 0
    time.sleep(600)
time.sleep(0.5)
print("spawned", "ok", flush=True)
EXIT
"""


@pytest.mark.parametrize(("ending", "tail"), [("timeout", "time.sleep(600)"),
                                              ("exited", "pass")])  # fmt: skip
def test_no_tool_process_survives_a_probe(
    setup: tuple[Workspace, VolatilityEngine], payload: Any, ending: str, tail: str
) -> None:
    ws, engine = setup
    payload["code"] = SURVIVORS.replace("EXIT", tail)
    run = engine.run(ws, MemoryPlugin.LINUX_PSLIST, 3, 10)
    assert run.end == ending, run
    assert _rows(run.dirs) == {"spawned": "ok"}
    # Workspace.seal killed every process of the tool uid, whatever its session or flags.
    assert sandbox.tool_pids() == []
    # The out dir is root's again: nothing that survived could still write to it.
    assert run.dirs.out.stat().st_uid == 0


def test_the_probe_runs_as_its_own_unprivileged_uid(
    setup: tuple[Workspace, VolatilityEngine], payload: Any
) -> None:
    ws, engine = setup
    payload["code"] = (
        "import os, resource\n"
        "print('uid', os.getuid(), flush=True)\n"
        "print('euid', os.geteuid())\n"
        "print('cwd', os.getcwd())\n"
        "print('as', resource.getrlimit(resource.RLIMIT_AS)[1])\n"
        "print('fsize', resource.getrlimit(resource.RLIMIT_FSIZE)[1])\n"
        "print('env', ','.join(sorted(os.environ)))\n"
    )
    run = engine.identify(ws, OsHint.AUTO, 30)
    seen = _rows(run.dirs)
    assert seen["uid"] == seen["euid"] == str(sandbox.TOOL_UID) == "10006"
    assert seen["cwd"] == str(ws.dirs.input)
    assert seen["as"] == str(engine.config.plugin_rlimit_as)
    assert seen["fsize"] == str(volatility.FSIZE_BYTES)
    assert set(seen["env"].split(",")) <= {"PATH", "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
                                          "TMPDIR", "LANG", "LC_CTYPE"}  # fmt: skip
