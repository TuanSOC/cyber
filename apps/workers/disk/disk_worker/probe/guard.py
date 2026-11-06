"""PEP 578 audit hook of the disk probe: refuses and counts network and process events.

Installed after every import (pytsk3, pyewf, yara are C extensions loaded by `import`, which
the hook never sees as `ctypes.dlopen`), before any image byte is read. Seccomp (AF_UNIX only,
no io_uring) stays the enforcing layer underneath; the hook makes an attempt *visible*: each
refusal is counted per family, the counts go into `status.json`, root copies them into the
stage report (`audit_counts`) and the engine tests assert zero.

Refused families:
- `socket`: every `socket.*` event (creation, connect, bind, DNS lookups);
- `urllib`: every `urllib.Request` (the probe opens nothing by URL);
- `subprocess`: `subprocess.Popen`;
- `exec`, `spawn`, `system`, `fork`: `os.exec*`, `os.posix_spawn*` / `os.spawn*`, `os.system`,
  `os.fork` / `os.forkpty`;
- `dlopen`: `ctypes.dlopen` of anything outside the interpreter's prefix (the venv), including
  `CDLL(None)` (the process's own symbols).

An audit hook cannot be removed; the probe process ends after one stage anyway.
"""

import os
import sys
from collections.abc import Callable
from typing import Any

FAMILIES = ("socket", "urllib", "subprocess", "exec", "spawn", "system", "fork", "dlopen")
AuditHook = Callable[[str, tuple[Any, ...]], None]


class Refused(RuntimeError):
    """Raised into the caller of a refused operation."""


def _inside_prefix(path: object, prefixes: tuple[str, ...]) -> bool:
    if not isinstance(path, str) or not path:
        return False
    real = os.path.realpath(path)
    return any(real == p or real.startswith(os.path.join(p, "")) for p in prefixes)


class Guard:
    def __init__(self, prefixes: tuple[str, ...] | None = None) -> None:
        self.counts: dict[str, int] = dict.fromkeys(FAMILIES, 0)
        self.installed = False
        roots = prefixes or (sys.prefix, sys.base_prefix, sys.exec_prefix)
        self.prefixes = tuple(sorted({os.path.realpath(p) for p in roots}))

    def family(self, event: str, args: tuple[Any, ...]) -> str | None:
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
        if event == "ctypes.dlopen":
            name = args[0] if args else None
            return None if _inside_prefix(name, self.prefixes) else "dlopen"
        return None

    def hook(self, event: str, args: tuple[Any, ...]) -> None:
        family = self.family(event, args)
        if family is not None:
            self.counts[family] += 1
            raise Refused(f"{event} refused in the disk probe")

    def install(self, add_hook: Callable[[AuditHook], None] = sys.addaudithook) -> None:
        if not self.installed:
            add_hook(self.hook)
            self.installed = True

    def snapshot(self) -> dict[str, int]:
        return dict(self.counts)


GUARD = Guard()

__all__ = ["FAMILIES", "GUARD", "Guard", "Refused"]
