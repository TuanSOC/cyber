"""`heuristic:mem_linux_shell_history@1` (Linux, `linux.bash`): history lines with
download-and-execute or reverse-shell patterns.

The line is quoted masked (RT13). Every pattern is linear (single bounded wildcards), and a
history line is at most 1 024 characters (the contract's attribute bound).
"""

import re
from dataclasses import dataclass

from memory_worker.detections.base import Context, Finding, joined, refs
from memory_worker.detections.mask import excerpt
from memory_worker.view import MemoryView


@dataclass(frozen=True)
class ShellPattern:
    label: str
    all_of: tuple[re.Pattern[str], ...]


def _p(label: str, *patterns: str) -> ShellPattern:
    return ShellPattern(label, tuple(re.compile(p, re.I) for p in patterns))


_FETCH = r"\b(?:curl|wget)\b"
PATTERNS = (
    # curl ... | sh  /  wget -O- ... | sudo bash
    _p("download_piped_to_shell", _FETCH + r"[^|]{0,1000}\|\s*(?:sudo\s+)?(?:ba|da|z|k)?sh\b"),
    # wget ... && chmod +x  /  curl -o x ...; chmod 755 x
    _p(
        "download_then_chmod",
        _FETCH,
        r"(?:&&|;|\|\|)\s*chmod\s+(?:[ugoa]*\+[rwx]*x|[0-7]?[0-7][1357][0-7]{0,2})\b",
    ),
    _p("dev_tcp_redirect", r"/dev/(?:tcp|udp)/"),
    _p("netcat_exec", r"\b(?:nc|ncat|netcat)\b", r"(?<!\S)(?:-[a-z]*[ec]|--(?:sh-)?exec)\b"),
    _p("python_socket_one_liner", r"\bpython[23]?(?:\.\d+)?\b", r"(?<!\S)-c\b", r"\bsocket\b"),
    _p("socat_exec", r"\bsocat\b", r"\bexec:"),
)
CONFIDENCE = 0.7
QUOTE_LIMIT = 300


def matches(command: str) -> list[str]:
    return [p.label for p in PATTERNS if all(r.search(command) for r in p.all_of)]


def detect(view: MemoryView, ctx: Context) -> list[Finding]:
    del ctx
    if view.os != "linux":
        return []
    out: list[Finding] = []
    for index, artifact in enumerate(view.artifacts):
        if artifact.type != "bash":
            continue
        command = artifact.attributes.get("command")
        if not isinstance(command, str) or not command.strip():
            continue
        labels = matches(command)
        if not labels:
            continue
        pid = artifact.pid
        out.append(
            Finding(
                type="mem_shell_history_pattern",
                severity="medium",
                confidence=CONFIDENCE,
                values={
                    "pid": pid if pid is not None else "unknown",
                    "command": excerpt(command, QUOTE_LIMIT),
                    "patterns": joined(labels, 200),
                },
                key=f"{pid}|{index}",
                pid=pid,
                refs=refs([f"pid:{pid}"] if pid is not None else []),
                attributes={
                    **({"pid": pid} if pid is not None else {}),
                    "patterns": joined(labels, 255),
                },
            )
        )
    return out
