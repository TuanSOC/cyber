"""PEP 578 audit hook of the probe (RT7): refuses and counts network and process events.

Installed after the imports, before any Volatility automagic runs. Seccomp (AF_UNIX only, no
io_uring) stays the enforcing layer underneath; this hook makes an attempt *visible*: every
refusal is counted per family and the counts go into `status.json`, which root copies into
the result header (`audit_events`, phase 11 asserts zero).

Refused families:
- `socket`: every `socket.*` event (creation, connect, bind, DNS lookups, ...);
- `urllib`: `urllib.Request` for any scheme but `file:` / `jar:file:` (Volatility opens its
  symbol tables and the image through urllib with file URLs, which must keep working);
- `subprocess`: `subprocess.Popen`;
- `exec`, `spawn`, `system`: `os.exec*`, `os.posix_spawn*` / `os.spawn*`, `os.system`;
- `fork`: `os.fork` / `os.forkpty`.

An audit hook cannot be removed: the probe process ends after one plugin anyway.
"""

import sys
from collections.abc import Callable
from typing import Any

FAMILIES = ("socket", "urllib", "subprocess", "exec", "spawn", "system", "fork", "file_output")
ALLOWED_URL_SCHEMES = ("file:", "jar:file:")
AuditHook = Callable[[str, tuple[Any, ...]], None]


class Refused(RuntimeError):
    """Raised into the caller of a refused operation."""


class Guard:
    def __init__(self) -> None:
        self.counts: dict[str, int] = dict.fromkeys(FAMILIES, 0)
        self.installed = False

    def family(self, event: str, args: tuple[Any, ...]) -> str | None:
        """The refused family of an audit event, or None when it is allowed."""
        if event.startswith("socket."):
            return "socket"
        if event == "urllib.Request":
            url = args[0] if args and isinstance(args[0], str) else ""
            return None if url.lower().startswith(ALLOWED_URL_SCHEMES) else "urllib"
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
        family = self.family(event, args)
        if family is not None:
            self.counts[family] += 1
            raise Refused(f"{event} refused in the memory probe")

    def refuse_file_output(self) -> None:
        """Called by the probe's refusing file handler (RT20)."""
        self.counts["file_output"] += 1
        raise Refused("file output refused in the memory probe")

    def install(self, add_hook: Callable[[AuditHook], None] = sys.addaudithook) -> None:
        if not self.installed:
            add_hook(self.hook)
            self.installed = True

    def snapshot(self) -> dict[str, int]:
        return dict(self.counts)


GUARD = Guard()

__all__ = ["ALLOWED_URL_SCHEMES", "FAMILIES", "GUARD", "Guard", "Refused"]
