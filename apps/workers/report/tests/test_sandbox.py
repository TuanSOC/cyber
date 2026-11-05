"""The render subprocess sandbox (RT3, RT4): uid 10004 (its own, review L6), `python -I -B`
from the venv, an environment without the broker URL, AF_UNIX sockets only (every other
family `EACCES`, review L5) and no io_uring (`EACCES`), rlimits, the wall timeout, and
`reset` killing leftovers.

Each probe runs through `report_worker.sandbox.run`, the exact configuration of a render,
and reports through a JSON file in its out/ dir (its HOME / TMPDIR).
"""

import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

import pytest
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

from report_worker import sandbox as render_sandbox
from tests.conftest import WORK, in_container, load_snapshot, stage

pytestmark = in_container

PROBE_PREFIX = """
import json, os, sys
def report(value):
    with open(os.path.join(os.environ["TMPDIR"], "probe.json"), "w") as f:
        json.dump(value, f)
"""


def probe(dirs: sandbox.JobDirs, code: str, **kwargs: Any) -> Any:
    render_sandbox.run([sys.executable, "-I", "-B", "-c", PROBE_PREFIX + code], dirs, **kwargs)
    with sandbox.open_output(dirs, "probe.json") as f:
        return json.loads(f.read())


SOCKETS = """
import errno, socket
out = {}
FAMILIES = {"AF_INET": 2, "AF_INET6": 10, "AF_NETLINK": 16, "AF_PACKET": 17, "AF_UNIX": 1,
            "AF_TIPC": 30, "AF_BLUETOOTH": 31, "AF_ALG": 38, "AF_VSOCK": 40, "AF_XDP": 44}
for name, family in FAMILIES.items():
    try:
        kind = socket.SOCK_RAW if name == "AF_PACKET" else socket.SOCK_DGRAM
        kind = socket.SOCK_SEQPACKET if name == "AF_ALG" else kind
        socket.socket(family, kind).close()
        out[name] = "allowed"
    except OSError as exc:
        out[name] = errno.errorcode.get(exc.errno, str(exc.errno))
for name, family in (("pair_unix", socket.AF_UNIX), ("pair_tipc", 30)):
    try:
        a, b = socket.socketpair(family, socket.SOCK_DGRAM)
        a.close()
        b.close()
        out[name] = "allowed"
    except OSError as exc:
        out[name] = errno.errorcode.get(exc.errno, str(exc.errno))
report(out)
"""


def test_every_socket_family_but_unix_is_denied_with_eacces(dirs: sandbox.JobDirs) -> None:
    """An allowlist (review L5): a family missing from a denylist cannot be reached."""
    assert probe(dirs, SOCKETS) == {
        "AF_INET": "EACCES",
        "AF_INET6": "EACCES",
        "AF_NETLINK": "EACCES",
        "AF_PACKET": "EACCES",
        "AF_TIPC": "EACCES",
        "AF_BLUETOOTH": "EACCES",
        "AF_ALG": "EACCES",
        "AF_VSOCK": "EACCES",
        "AF_XDP": "EACCES",
        "AF_UNIX": "allowed",
        "pair_tipc": "EACCES",
        "pair_unix": "allowed",
    }


IO_URING = """
import ctypes, errno, platform
NR = {"x86_64": 425, "aarch64": 425}[platform.machine()]
libc = ctypes.CDLL(None, use_errno=True)
params = ctypes.create_string_buffer(120)
fd = libc.syscall(NR, 8, params)
report({"fd": fd, "errno": errno.errorcode.get(ctypes.get_errno(), "")})
"""


def test_io_uring_setup_is_denied_with_eacces(dirs: sandbox.JobDirs) -> None:
    assert probe(dirs, IO_URING) == {"fd": -1, "errno": "EACCES"}


def test_the_broker_and_minio_cannot_be_resolved_or_reached(dirs: sandbox.JobDirs) -> None:
    broker = socket.gethostbyname("redis-broker")  # the parent can (it needs the broker)
    minio = socket.gethostbyname("minio")
    result = probe(
        dirs,
        f"""
import socket
out = {{}}
for host in ("redis-broker", "minio"):
    try:
        socket.getaddrinfo(host, 80)
        out[host] = "resolved"
    except OSError as exc:
        out[host] = type(exc).__name__
for name, ip, port in (("broker-ip", {broker!r}, 6379), ("minio-ip", {minio!r}, 9000)):
    try:
        socket.create_connection((ip, port), timeout=2).close()
        out[name] = "connected"
    except OSError as exc:
        out[name] = exc.errno
report(out)
""",
    )
    assert result["redis-broker"] == "gaierror" and result["minio"] == "gaierror"
    assert result["broker-ip"] == 13 and result["minio-ip"] == 13  # EACCES


def test_python_runs_isolated_from_the_venv_and_imports_the_renderer(
    dirs: sandbox.JobDirs,
) -> None:
    result = probe(
        dirs,
        """
import weasyprint, report_worker.render_pdf, report_worker, cyberlab_jobs
report({
    "isolated": sys.flags.isolated, "dont_write_bytecode": sys.flags.dont_write_bytecode,
    "no_site": sys.flags.no_site, "prefix": sys.prefix, "path0": sys.path[0],
    "cwd": os.getcwd(), "weasyprint": weasyprint.__version__,
    "report_worker": report_worker.__file__, "uid": os.getuid(), "euid": os.geteuid(),
    "groups": os.getgroups(),
})
""",
    )
    assert result["isolated"] == 1 and result["dont_write_bytecode"] == 1
    assert result["no_site"] == 0
    assert result["prefix"] == "/opt/venv"
    assert result["path0"] != result["cwd"] and result["path0"] != ""
    assert result["cwd"] == str(dirs.input)
    assert result["weasyprint"].startswith("70.")
    assert result["report_worker"].startswith("/srv/workers/report/report_worker/")
    # The renderer's own uid, not the static worker's 10003 (review L6).
    assert (result["uid"], result["euid"], result["groups"]) == (10004, 10004, [])
    assert sandbox.TOOL_UID == sandbox.TOOL_GID == 10004


def test_the_environment_holds_no_broker_url(dirs: sandbox.JobDirs) -> None:
    assert "BROKER_URL" in os.environ  # the parent holds it
    env = probe(dirs, "report(dict(os.environ))")
    assert "BROKER_URL" not in env
    assert set(env) <= {
        "PATH",
        "LANG",
        "HOME",
        "TMPDIR",
        "XDG_CONFIG_HOME",
        "FONTCONFIG_FILE",
        "MALLOC_ARENA_MAX",
        "LC_CTYPE",  # set by Python's C locale coercion
    }
    assert env["MALLOC_ARENA_MAX"] == "2"
    assert env["FONTCONFIG_FILE"] == "/app/assets/fonts.conf"
    assert env["HOME"] == env["TMPDIR"] == str(dirs.out)


def test_the_rlimits_apply(dirs: sandbox.JobDirs) -> None:
    result = probe(
        dirs,
        """
import resource
report({name: resource.getrlimit(getattr(resource, name))[0] for name in
        ("RLIMIT_AS", "RLIMIT_CPU", "RLIMIT_FSIZE", "RLIMIT_NOFILE", "RLIMIT_NPROC",
         "RLIMIT_CORE")})
""",
    )
    assert result == {
        "RLIMIT_AS": 768 * 1024 * 1024,
        "RLIMIT_CPU": 90,
        "RLIMIT_FSIZE": 32 * 1024 * 1024,
        "RLIMIT_NOFILE": 64,
        "RLIMIT_NPROC": 16,
        "RLIMIT_CORE": 0,
    }


def test_a_2_gb_allocation_is_oom(dirs: sandbox.JobDirs) -> None:
    code = (
        "import sys\nfrom report_worker.render import run_guarded\n"
        "sys.exit(run_guarded(lambda: bytearray(2 * 1024**3)))"
    )
    with pytest.raises(JobFailed) as exc:
        render_sandbox.run([sys.executable, "-I", "-B", "-c", code], dirs)
    assert exc.value.code == "oom"


def test_an_infinite_loop_is_a_timeout(dirs: sandbox.JobDirs) -> None:
    with pytest.raises(JobFailed) as exc:
        render_sandbox.run(
            [sys.executable, "-I", "-B", "-c", "while True: pass"], dirs, timeout_s=2
        )
    assert exc.value.code == "timeout"
    assert sandbox.tool_pids() == []


def test_the_cpu_limit_is_a_timeout(dirs: sandbox.JobDirs) -> None:
    limits = sandbox.Rlimits(as_bytes=768 * 1024**2, cpu_s=1, nofile=64, nproc=16)
    with pytest.raises(JobFailed) as exc:
        render_sandbox.run(
            [sys.executable, "-I", "-B", "-c", "while True: pass"],
            dirs,
            timeout_s=30,
            rlimits=limits,
        )
    assert exc.value.code == "timeout"


def test_writing_past_the_artifact_cap_is_too_large(dirs: sandbox.JobDirs) -> None:
    code = (
        "import os, sys\nfrom report_worker.render import run_guarded\n"
        "def big():\n"
        "    with open(os.path.join(os.environ['TMPDIR'], 'big'), 'wb') as f:\n"
        "        f.write(b'x' * (33 * 1024 * 1024))\n"
        "sys.exit(run_guarded(big))"
    )
    with pytest.raises(JobFailed) as exc:
        render_sandbox.run([sys.executable, "-I", "-B", "-c", code], dirs)
    assert exc.value.code == "too_large"


def test_a_background_process_is_killed_by_reset_before_the_next_render(
    dirs: sandbox.JobDirs,
) -> None:
    probe(
        dirs,
        """
import subprocess
subprocess.Popen(["setsid", "sleep", "60"], stdin=subprocess.DEVNULL,
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
import time; time.sleep(0.2)
report({"spawned": True})
""",
    )
    assert sandbox.tool_pids() != []  # it survived the run's process-group kill
    nxt = sandbox.prepare(WORK, "next-render")
    try:
        assert sandbox.tool_pids() == []
    finally:
        sandbox.cleanup(nxt)


def test_the_tool_cannot_read_the_parent_environment(dirs: sandbox.JobDirs) -> None:
    result = probe(
        dirs,
        f"""
out = {{}}
for pid in ("1", "{os.getpid()}"):
    try:
        open(f"/proc/{{pid}}/environ", "rb").read()
        out[pid] = "read"
    except OSError as exc:
        out[pid] = exc.errno
report(out)
""",
    )
    assert all(v == 13 for v in result.values()), result


def test_a_real_render_needs_no_socket_at_all(dirs: sandbox.JobDirs) -> None:
    """fontconfig / Pango / WeasyPrint open no socket of any family during a render: the
    hostile snapshot renders to PDF with AF_UNIX denied as well (recorded in sandbox.py)."""
    stage(dirs, load_snapshot("hostile_snapshot.json"), "pdf")
    argv = render_sandbox.render_argv("pdf", dirs)
    sandbox.run_tool(
        argv,
        dirs,
        timeout_s=render_sandbox.WALL_TIMEOUT_S,
        extra_env=render_sandbox.RENDER_ENV,
        cwd=dirs.input,
        rlimits=render_sandbox.RENDER_RLIMITS,
        unix_sockets_only=True,
        deny_extra_domains=(socket.AF_UNIX,),
        deny_io_uring=True,
    )
    with sandbox.open_output(dirs, "report.pdf") as f:
        assert f.read(5) == b"%PDF-"


def test_the_font_cache_is_prebuilt_and_read_only() -> None:
    cache = Path("/var/cache/fontconfig")
    assert any(cache.iterdir())
    assert all(p.stat().st_uid == 0 and not p.stat().st_mode & 0o022 for p in cache.iterdir())
