"""The probe's PEP 578 audit hook (M9 phase 2). Pure: a fresh `Guard` with a fake installer,
so the test process itself never gets a hook it cannot remove."""

import pytest

from disk_worker.probe.guard import FAMILIES, Guard, Refused


@pytest.mark.parametrize(
    ("event", "args", "family"),
    [
        ("socket.socket", (2, 1, 0), "socket"),
        ("socket.getaddrinfo", ("example.com", 80), "socket"),
        ("urllib.Request", ("file:///etc/passwd", None, {}, "GET"), "urllib"),
        ("subprocess.Popen", ("/bin/sh", ["sh"], None, None), "subprocess"),
        ("os.exec", ("/bin/sh", ["sh"], None), "exec"),
        ("os.posix_spawn", ("/bin/sh", ["sh"], None), "spawn"),
        ("os.system", (b"id",), "system"),
        ("os.fork", (), "fork"),
        ("ctypes.dlopen", ("/usr/lib/x86_64-linux-gnu/libc.so.6",), "dlopen"),
        ("ctypes.dlopen", (None,), "dlopen"),
    ],
)
def test_refused_events_are_counted_and_raised(event: str, args: tuple, family: str) -> None:
    guard = Guard(prefixes=("/opt/venv",))
    with pytest.raises(Refused):
        guard.hook(event, args)
    assert guard.snapshot()[family] == 1
    assert sum(guard.snapshot().values()) == 1


def test_allowed_events_pass() -> None:
    guard = Guard(prefixes=("/opt/venv",))
    for event, args in (
        ("open", ("/work/x/input/image.raw", "rb", 0)),
        ("import", ("pytsk3", None, [], [], [])),
        ("ctypes.dlopen", ("/opt/venv/lib/python3.12/site-packages/x.so",)),
    ):
        guard.hook(event, args)
    assert set(guard.snapshot()) == set(FAMILIES)
    assert sum(guard.snapshot().values()) == 0


def test_install_adds_the_hook_once() -> None:
    added = []
    guard = Guard(prefixes=("/opt/venv",))
    guard.install(added.append)
    guard.install(added.append)
    assert added == [guard.hook]
