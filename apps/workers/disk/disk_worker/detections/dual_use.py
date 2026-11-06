"""`heuristic:disk_dual_use_execution@1`: execution evidence of a fixed dual-use list.

Evidence: Prefetch, Amcache, UserAssist and BAM (program names), shell history and EVTX 4688
(command lines, when process auditing is on). The list is fixed (`PATTERNS`):

- low: running `psexec` / `psexesvc`, `procdump`, `rclone`, Windows netcat (`nc.exe`, `ncat.exe`);
- medium: `wevtutil cl`, `vssadmin delete shadows`, `certutil -urlcache`, `powershell -enc`
  with an encoded argument, `curl` / `wget` piped into a shell, `nc -e` / `--exec`.

Near misses stay silent: `curl -O` without a pipe, `wevtutil qe`, `vssadmin list shadows`,
`certutil -hashfile`, `powershell -File`, `-ExecutionPolicy`, `nc -zv`. Command lines are quoted
masked (`cyberlab_worker.mask`); their URLs, domains and IPs become IOCs from the masked text.
One finding per (evidence kind, masked text); repeats are cited (at most 20 events).
"""

import re
from dataclasses import dataclass, field

from cyberlab_jobs.disk import DiskEventRecord

from disk_worker.detections import events as ev
from disk_worker.detections import evtx_fields
from disk_worker.detections.base import (
    SEVERITY_RANK,
    Context,
    Finding,
    Rule,
    Severity,
    iso,
    joined,
    quoted,
)

_START = r"(?<![\w.-])"
_END = r"(?![\w-])"


# `-e`, `-ec`, `-en`, `-enc`, ... `-encodedcommand`: PowerShell takes any unambiguous prefix.
_ENCODED_FLAGS = "|".join(
    sorted({"ec", *("encodedcommand"[:n] for n in range(1, 15))}, key=len, reverse=True)
)


@dataclass(frozen=True)
class Pattern:
    id: str
    severity: Severity
    regex: re.Pattern[str]


def _p(id_: str, severity: Severity, regex: str) -> Pattern:
    return Pattern(id_, severity, re.compile(regex, re.IGNORECASE))


PATTERNS: tuple[Pattern, ...] = (
    _p("psexec", "low", _START + r"ps(?:exec|exesvc)(?:64)?(?:\.exe)?" + _END),
    _p("procdump", "low", _START + r"procdump(?:64)?(?:\.exe)?" + _END),
    _p("rclone", "low", _START + r"rclone(?:\.exe)?" + _END),
    _p("wevtutil cl", "medium", _START + r"wevtutil(?:\.exe)?\s+(?:cl|clear-log)" + _END),
    _p(
        "vssadmin delete shadows",
        "medium",
        _START + r"vssadmin(?:\.exe)?\s+delete\s+shadows" + _END,
    ),
    _p(
        "certutil -urlcache",
        "medium",
        _START + r"certutil(?:\.exe)?\s[^\r\n]{0,256}?[-/]urlcache" + _END,
    ),
    _p(
        "powershell -enc",
        "medium",
        _START
        + r"(?:powershell|pwsh)(?:\.exe)?\s(?:[^\r\n]{0,256}?\s)?[-/](?:"
        + _ENCODED_FLAGS
        + r")\s+[A-Za-z0-9+/=]{8,}",
    ),
    _p(
        "curl | sh",
        "medium",
        _START + r"(?:curl|wget)\s[^\r\n|]{0,1024}\|\s*(?:sudo\s+)?(?:ba|da|z|k)?sh" + _END,
    ),
    _p(
        "nc -e",
        "medium",
        _START + r"(?:nc|ncat|netcat)(?:\.exe)?(?:\s[^\r\n|;&]{0,256}?)?"
        r"\s(?:-[a-z]{0,6}e|--(?:sh-)?exec)(?![\w-])",
    ),
)
# Program names in execution artifacts (Prefetch, Amcache, UserAssist, BAM).
TOOL_EXES: dict[str, str] = {
    "psexec.exe": "psexec",
    "psexec64.exe": "psexec",
    "psexesvc.exe": "psexec",
    "procdump.exe": "procdump",
    "procdump64.exe": "procdump",
    "rclone.exe": "rclone",
    "nc.exe": "netcat",
    "nc64.exe": "netcat",
    "ncat.exe": "netcat",
}
EXE_TOKEN = re.compile(r"[^\\/\s\[\]\"':|<>]{1,128}\.exe(?![\w])", re.IGNORECASE)
# (data type or artifact, attribute holding the program path, label)
EXECUTION_SOURCES: tuple[tuple[str, str, str], ...] = (
    ("windows:prefetch:execution", "executable", "Prefetch"),
    ("windows:registry:amcache", "full_path", "Amcache"),
    ("windows:registry:userassist", "value_name", "UserAssist"),
    ("windows:registry:bam", "binary_path", "BAM"),
)
SHELL_PREFIX = "Command executed: "
CONFIDENCE = 0.6


def command_patterns(text: str) -> list[Pattern]:
    return [pattern for pattern in PATTERNS if pattern.regex.search(text) is not None]


def program_tools(text: str) -> list[str]:
    tools: list[str] = []
    for match in EXE_TOKEN.finditer(text[:4096]):
        tool = TOOL_EXES.get(match.group(0).casefold())
        if tool is not None and tool not in tools:
            tools.append(tool)
    return tools


@dataclass
class DualUse(Rule):
    pending: dict[str, Finding] = field(default_factory=dict)

    def observe(self, event: DiskEventRecord, ctx: Context) -> None:
        for data_type, attribute, label in EXECUTION_SOURCES:
            if (
                event.data_type == data_type
                or (label == "Amcache" and event.artifact == "amcache")
                or (label == "Prefetch" and event.artifact == "prefetch")
            ):
                program = ev.text(event, attribute) or event.message
                tools = program_tools(program)
                if tools:
                    self._add(event, ctx, label, program, [(t, "low") for t in tools])
                return
        if event.artifact == "shell_history":
            command = ev.text(event, "command") or event.message.removeprefix(SHELL_PREFIX)
            self._command(event, ctx, "Shell history", command)
            return
        record = ctx.evtx(event)
        if record is None or record.event_id != 4688 or record.provider != evtx_fields.SECURITY:
            return
        if record.fields is None:
            ctx.counts["evtx_layout_unknown"] += 1
            return
        command = record.get("CommandLine") or record.get("NewProcessName") or ""
        self._command(event, ctx, "EVTX 4688", command)

    def _command(self, event: DiskEventRecord, ctx: Context, label: str, command: str) -> None:
        if not command:
            return
        matched = [(p.id, p.severity) for p in command_patterns(command[:4096])]
        if matched:
            self._add(event, ctx, label, command, matched)

    def _add(
        self,
        event: DiskEventRecord,
        ctx: Context,
        label: str,
        text: str,
        matched: list[tuple[str, Severity]],
    ) -> None:
        shown = quoted(text)
        ids = [m[0] for m in matched]
        key = f"{label}|{shown}"
        finding = self.pending.get(key)
        if finding is None:
            if not ctx.budget.take():
                return
            severity: Severity = max((m[1] for m in matched), key=lambda s: SEVERITY_RANK[s])
            finding = Finding(
                type="disk_dual_use_execution",
                severity=severity,
                confidence=CONFIDENCE,
                values={
                    "artifact": label,
                    "when": iso(event.ts),
                    "text": shown,
                    "patterns": joined(ids, 128),
                },
                subject=f"{label}:{','.join(ids)}",
                key=key,
                ts=event.ts,
                texts=[quoted(text, 2048)],
                attributes={
                    "subject": quoted(f"{label}:{','.join(ids)}", 255),
                    "patterns": joined(ids, 128),
                    "artifact": label,
                },
            )
            self.pending[key] = finding
        finding.cite(ev.cited(event, "file_executed", f"{label}: {text}"))

    def finish(self, ctx: Context) -> list[Finding]:
        return list(self.pending.values())
