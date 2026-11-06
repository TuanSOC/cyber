"""The probe's PEP 578 audit hook (RT7): network and process events are refused and counted;
file URLs (symbol tables, the image) stay allowed. Pure Python: the real hook is exercised in
a child interpreter (an audit hook can never be removed from the test process)."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from memory_worker.probe.guard import FAMILIES, Guard, Refused

APP = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("event", "args", "family"),
    [
        ("socket.__new__", (None, 2, 1, 0), "socket"),
        ("socket.connect", (None, ("203.0.113.1", 80)), "socket"),
        ("socket.getaddrinfo", ("example.com", 80, 0, 0, 0), "socket"),
        ("socket.gethostbyname", ("msdl.microsoft.com",), "socket"),
        (
            "urllib.Request",
            ("http://msdl.microsoft.com/download/symbols/x", None, {}, "GET"),
            "urllib",
        ),  # noqa: E501
        ("urllib.Request", ("https://example.com/banners.json", None, {}, "GET"), "urllib"),
        ("urllib.Request", ("smb://host/share", None, {}, "GET"), "urllib"),
        ("subprocess.Popen", ("/bin/sh", ["/bin/sh"], None, None), "subprocess"),
        ("os.exec", ("/bin/sh", ["sh"], None), "exec"),
        ("os.posix_spawn", ("/bin/sh", ["sh"], None), "spawn"),
        ("os.spawn", (0, "/bin/sh", ["sh"], None), "spawn"),
        ("os.system", (b"id",), "system"),
        ("os.fork", (), "fork"),
    ],
)
def test_refused_events_are_counted(event: str, args: tuple[object, ...], family: str) -> None:
    guard = Guard()
    with pytest.raises(Refused):
        guard.hook(event, args)
    assert guard.snapshot()[family] == 1
    assert sum(guard.snapshot().values()) == 1


@pytest.mark.parametrize(
    ("event", "args"),
    [
        ("urllib.Request", ("file:///symbols/windows/ntkrnlmp.pdb/X-1.json.xz", None, {}, "GET")),
        ("urllib.Request", ("FILE:///work/job/input/image", None, {}, "GET")),
        ("urllib.Request", ("jar:file:///symbols/linux.zip!/linux/x.json.xz", None, {}, "GET")),
        ("open", ("/work/job/input/image", "rb", 0)),
        ("sqlite3.connect", ("/work/job/x-out/cache/volatility3/identifier.cache",)),
        ("import", ("volatility3", None, [], [], [])),
    ],
)
def test_file_access_stays_allowed(event: str, args: tuple[object, ...]) -> None:
    guard = Guard()
    guard.hook(event, args)
    assert sum(guard.snapshot().values()) == 0


def test_install_is_once_and_file_output_is_counted() -> None:
    hooks: list[object] = []
    guard = Guard()
    guard.install(hooks.append)
    guard.install(hooks.append)
    assert len(hooks) == 1 and guard.installed
    with pytest.raises(Refused):
        guard.refuse_file_output()
    assert guard.snapshot()["file_output"] == 1
    assert set(guard.snapshot()) == set(FAMILIES)


CHILD = """
import json, socket, subprocess, urllib.request
from memory_worker.probe.guard import GUARD, Refused
GUARD.install()
outcomes = {}
for name, attempt in (
    ("socket", lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM)),
    ("unix", lambda: socket.socket(getattr(socket, "AF_UNIX", socket.AF_INET))),
    ("dns", lambda: socket.getaddrinfo("localhost", 80)),
    ("http", lambda: urllib.request.urlopen("http://127.0.0.1:9/x", timeout=1)),
    ("subprocess", lambda: subprocess.run(["true"])),
):
    try:
        attempt()
        outcomes[name] = "allowed"
    except Refused:
        outcomes[name] = "refused"
    except Exception as exc:
        outcomes[name] = type(exc).__name__
print(json.dumps({"outcomes": outcomes, "counts": GUARD.snapshot()}))
"""


def test_the_installed_hook_refuses_in_a_real_interpreter() -> None:
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(APP), *sys.path])}
    done = subprocess.run(
        [sys.executable, "-c", CHILD], capture_output=True, text=True, env=env, timeout=60
    )
    assert done.returncode == 0, done.stderr
    report = json.loads(done.stdout.strip().splitlines()[-1])
    assert set(report["outcomes"].values()) == {"refused"}, report
    counts = report["counts"]
    assert counts["socket"] >= 3 and counts["urllib"] == 1 and counts["subprocess"] == 1
