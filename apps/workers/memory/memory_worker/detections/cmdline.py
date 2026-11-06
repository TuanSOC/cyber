"""`heuristic:mem_suspicious_cmdline@1`: Windows command lines matching download / execution
patterns.

`medium` when a strong pattern or at least two patterns match, `low` for a single weak one.
The command line is quoted masked (RT13) and shortened. Every pattern is linear and the input
is at most 4 096 characters.
"""

import re
from dataclasses import dataclass

from memory_worker.detections.base import Context, Finding, joined, refs
from memory_worker.detections.mask import excerpt
from memory_worker.view import MemoryView


@dataclass(frozen=True)
class Pattern:
    label: str
    strong: bool
    all_of: tuple[re.Pattern[str], ...]


def _p(label: str, strong: bool, *patterns: str) -> Pattern:
    return Pattern(label, strong, tuple(re.compile(p, re.I) for p in patterns))


POWERSHELL = re.compile(r"(?i)\b(?:powershell|pwsh)(?:_ise)?(?:\.exe)?\b")
# -e / -ec / -en ... -EncodedCommand (PowerShell accepts any unambiguous prefix) + base64.
_ENC = (
    r"(?<!\S)[-/]e(?:c|n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?"
    r"\s+['\"]?[A-Za-z0-9+/]{16,}={0,2}"
)
_HIDDEN = (
    r"(?<!\S)[-/]w(?:i(?:n(?:d(?:o(?:w(?:s(?:t(?:y(?:l(?:e)?)?)?)?)?)?)?)?)?)?"
    r"\s+['\"]?hidden\b"
)
_IEX = r"\biex\b|invoke-expression"
_CRADLE = (
    r"downloadstring|downloaddata|downloadfile|net\.webclient|invoke-webrequest|\biwr\b|"
    r"invoke-restmethod|\birm\b|start-bitstransfer"
)
# PowerShell-only patterns (checked when the process is PowerShell).
POWERSHELL_PATTERNS = (
    _p("powershell_encoded_command", True, _ENC),
    _p("powershell_download_cradle", True, _IEX, _CRADLE),
    _p("powershell_hidden_window", False, _HIDDEN),
)
PATTERNS = (
    _p("certutil_urlcache", True, r"\bcertutil(?:\.exe)?\b", r"(?<!\S)[-/]urlcache\b"),
    _p("bitsadmin_transfer", True, r"\bbitsadmin(?:\.exe)?\b", r"(?<!\S)/transfer\b"),
    _p("mshta_remote", True, r"\bmshta(?:\.exe)?['\"]?\s+['\"]?(?:https?|ftp)://"),
    _p("rundll32_javascript", True, r"\brundll32(?:\.exe)?\b", r"javascript:"),
    _p("regsvr32_remote_scriptlet", True, r"\bregsvr32(?:\.exe)?\b", r"/i:\s*['\"]?https?://"),
    _p("wmic_process_create", False, r"\bwmic(?:\.exe)?\b", r"\bprocess\s+call\s+create\b"),
)
CONFIDENCE_STRONG = 0.6
CONFIDENCE_WEAK = 0.35
QUOTE_LIMIT = 300


def matches(cmdline: str, *, powershell: bool) -> list[Pattern]:
    candidates = (*POWERSHELL_PATTERNS, *PATTERNS) if powershell else PATTERNS
    return [p for p in candidates if all(r.search(cmdline) for r in p.all_of)]


def detect(view: MemoryView, ctx: Context) -> list[Finding]:
    if view.os != "windows":
        return []
    out: list[Finding] = []
    for procs in ctx.by_pid.values():
        for proc in procs:
            if not proc.cmdline:
                continue
            is_ps = bool(POWERSHELL.search(proc.name) or POWERSHELL.search(proc.cmdline))
            found = matches(proc.cmdline, powershell=is_ps)
            if not found:
                continue
            medium = any(p.strong for p in found) or len(found) >= 2
            labels = [p.label for p in found]
            out.append(
                Finding(
                    type="mem_suspicious_cmdline",
                    severity="medium" if medium else "low",
                    confidence=CONFIDENCE_STRONG if medium else CONFIDENCE_WEAK,
                    values={
                        "pid": proc.pid,
                        "name": excerpt(proc.name, 64),
                        "cmdline": excerpt(proc.cmdline, QUOTE_LIMIT),
                        "patterns": joined(labels, 200),
                    },
                    key=f"{proc.pid}|{proc.create_time}",
                    pid=proc.pid,
                    refs=refs([f"pid:{proc.pid}"]),
                    attributes={"pid": proc.pid, "patterns": joined(labels, 255)},
                )
            )
    return out
