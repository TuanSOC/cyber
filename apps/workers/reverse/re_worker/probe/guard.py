"""PEP 578 audit hook of the stage probes (the M8 pattern; RT1 / RT15).

Installed **after `pyghidra.start()` returns and before the sample is opened** (RT1: the
launcher itself may run `LaunchSupport` / `java -version` through `subprocess`; installed
earlier, the hook would refuse them and the JVM would never start). The radare2 reducer
installs it first thing (it starts no JVM).

Refused and counted per family (the counts go to `status.json`; root copies them into the
header's `audit`, zero expected):
- `socket`: every `socket.*` event (creation, connect, bind, DNS lookups, ...);
- `urllib`: every `urllib.Request` (no stage opens anything by URL);
- `subprocess`: `subprocess.Popen`;
- `exec`, `spawn`, `system`, `fork`: `os.exec*`, `os.posix_spawn*` / `os.spawn*`,
  `os.system`, `os.fork` / `os.forkpty`.

The JVM's own spawn of the decompiler (`jspawnhelper`, a JVM `posix_spawn`) is not a Python
event: the decompile stage records its children instead (`probe/children.py`). Seccomp (AF_UNIX
only, no io_uring), the uid and the rlimits stay the enforcing layer; this hook is detection
that makes an attempt visible. An audit hook cannot be removed: the probe ends after its stage.
"""

import sys
from collections.abc import Callable
from typing import Any

FAMILIES = ("socket", "urllib", "subprocess", "exec", "spawn", "system", "fork")
AuditHook = Callable[[str, tuple[Any, ...]], None]


class Refused(RuntimeError):
    """Raised into the caller of a refused operation."""


class Guard:
    def __init__(self) -> None:
        self.counts: dict[str, int] = dict.fromkeys(FAMILIES, 0)
        self.installed = False

    @staticmethod
    def family(event: str) -> str | None:
        """The refused family of an audit event, or None when it is allowed."""
        if event.startswith("socket."):
            return "socket"
        if event == "urllib.Request":
            return "urllib"
        if event == "subprocess.Popen":
            return "subprocess"
        if event == "os.exec":
            return "exec"
        if event in ("os.posix_spawn", "os.spawn"):
            return "spawn"
        if event == "os.system":
            return "system"
        if event in ("os.fork", "os.forkpty"):
            return "fork"
        return None

    def hook(self, event: str, args: tuple[Any, ...]) -> None:
        del args
        family = self.family(event)
        if family is not None:
            self.counts[family] += 1
            raise Refused(f"{event} refused in the RE probe")

    def install(self, add_hook: Callable[[AuditHook], None] = sys.addaudithook) -> None:
        if not self.installed:
            add_hook(self.hook)
            self.installed = True

    def snapshot(self) -> dict[str, int]:
        return dict(self.counts)


GUARD = Guard()

__all__ = ["FAMILIES", "GUARD", "Guard", "Refused"]
