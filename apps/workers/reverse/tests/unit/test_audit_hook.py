"""The probes' audit hook and the decompile stage's child records (RT1, RT4, RT15). The real
hook runs in a child interpreter (an audit hook can never be removed from the test process);
the child scan runs over a fake `/proc`."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from re_worker.probe.children import Children, child_pids
from re_worker.probe.guard import FAMILIES, Guard, Refused

APP = Path(__file__).resolve().parents[2]
DECOMPILER = Path("/opt/ghidra/Ghidra/Features/Decompiler/os/linux_x86_64/decompile")
HELPER = Path("/opt/java/openjdk/lib/jspawnhelper")


@pytest.mark.parametrize(
    ("event", "family"),
    [
        ("socket.__new__", "socket"),
        ("socket.connect", "socket"),
        ("socket.getaddrinfo", "socket"),
        ("urllib.Request", "urllib"),
        ("subprocess.Popen", "subprocess"),
        ("os.exec", "exec"),
        ("os.posix_spawn", "spawn"),
        ("os.spawn", "spawn"),
        ("os.system", "system"),
        ("os.fork", "fork"),
        ("os.forkpty", "fork"),
    ],
)
def test_refused_events_are_counted(event: str, family: str) -> None:
    guard = Guard()
    with pytest.raises(Refused):
        guard.hook(event, ())
    assert guard.snapshot()[family] == 1 and sum(guard.snapshot().values()) == 1


@pytest.mark.parametrize("event", ["open", "import", "resource.prlimit", "os.listdir"])
def test_file_and_limit_events_stay_allowed(event: str) -> None:
    guard = Guard()
    guard.hook(event, ())
    assert sum(guard.snapshot().values()) == 0


def test_install_once() -> None:
    hooks: list[object] = []
    guard = Guard()
    guard.install(hooks.append)
    guard.install(hooks.append)
    assert len(hooks) == 1 and set(guard.snapshot()) == set(FAMILIES)


CHILD = """
import json, socket, subprocess
from re_worker.probe.guard import GUARD, Refused
GUARD.install()
for attempt in (lambda: socket.socket(), lambda: subprocess.run(["true"])):
    try:
        attempt()
    except Refused:
        pass
print(json.dumps(GUARD.snapshot()))
"""


def test_the_real_hook_refuses_in_a_child_interpreter() -> None:
    out = subprocess.run(
        [sys.executable, "-c", CHILD], cwd=APP, capture_output=True, text=True, check=True
    )
    counts = json.loads(out.stdout)
    assert counts["socket"] == 1 and counts["subprocess"] == 1


def _proc(tmp_path: Path, children: dict[int, tuple[int, str]]) -> Path:
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "self").mkdir()
    for pid, (ppid, exe) in children.items():
        d = proc / str(pid)
        d.mkdir()
        (d / "stat").write_text(f"{pid} (a b) c) S {ppid} 1 1 0\n")
        (d / "exe_target").write_text(exe)  # Linux: the `exe` symlink's target
    return proc


def test_children_are_recorded_and_new_decompilers_limited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc = _proc(
        tmp_path,
        {
            11: (10, str(DECOMPILER)),
            12: (10, str(HELPER)),
            13: (99, "/bin/sh"),  # not our child
            14: (10, "/bin/sh"),
        },
    )
    assert child_pids(10, proc) == [11, 12, 14]
    monkeypatch.setattr(
        "re_worker.probe.children.executable",
        lambda pid, root: (root / str(pid) / "exe_target").read_text(),
    )
    lowered: list[tuple[int, int]] = []
    children = Children(
        decompiler=DECOMPILER,
        spawn_helper=HELPER,
        as_limit=1536 * 1024**2,
        proc=proc,
        parent=10,
        lower=lambda pid, limit: lowered.append((pid, limit)),
    )
    assert children.scan() == [11]
    assert children.scan() == [11]  # seen once, limited once
    assert lowered == [(11, 1536 * 1024**2)]
    assert children.counts == {"child:decompile": 1, "child:jspawnhelper": 1, "child:other": 1}
    assert children.unexpected == ["/bin/sh"]


def test_a_failed_prlimit_is_counted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    proc = _proc(tmp_path, {21: (20, str(DECOMPILER))})
    monkeypatch.setattr(
        "re_worker.probe.children.executable",
        lambda pid, root: (root / str(pid) / "exe_target").read_text(),
    )

    def refuse(pid: int, limit: int) -> None:
        raise PermissionError(pid, limit)

    children = Children(
        decompiler=DECOMPILER,
        spawn_helper=HELPER,
        as_limit=1,
        proc=proc,
        parent=20,
        lower=refuse,
    )
    children.scan()
    assert children.limit_failures == 1 and not children.limited
