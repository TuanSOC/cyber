"""`heuristic:disk_log_cleared@1` (medium).

- EVTX: Security 1102 ("the audit log was cleared") and System 104 ("the <channel> log was
  cleared"), from the Eventlog provider (a record of another provider with the same id is not
  one). The clearing itself needs no event field: an unknown string layout only drops the
  account and channel from the description (counted as `evtx_layout_unknown`), never the finding.
- Linux: `auth.log` / `secure` / `wtmp` that is empty (or, for `wtmp`, not a whole number of
  384-byte records) while a rotated sibling (`.1`, `.2.gz`, `-20261001`) with content exists in
  the same directory.
"""

import re
from dataclasses import dataclass, field

from cyberlab_jobs.disk import DiskEventRecord, DiskFileRecord

from disk_worker.detections import events as ev
from disk_worker.detections import evtx_fields
from disk_worker.detections.base import (
    Context,
    FileFacts,
    Finding,
    Rule,
    file_time,
    iso,
    joined,
    quoted,
    shown,
)
from disk_worker.detections.file_rules import file_finding, size_text

WTMP_RECORD = 384
ROTATED = re.compile(r"^(?P<base>auth\.log|secure|wtmp)(?:\.\d{1,3}(?:\.gz)?|-\d{8}(?:\.gz)?)$")
BASES = frozenset({"auth.log", "secure", "wtmp"})
LOG_DIR = "var/log"
CONFIDENCE = 0.8
CHANNEL_BY_PATH = {"security.evtx": "Security", "system.evtx": "System"}


@dataclass
class LogCleared(Rule):
    findings: list[Finding] = field(default_factory=list)
    # (directory, base) -> the current file / rotated siblings with content (names).
    current: dict[tuple[str, str], tuple[DiskFileRecord, FileFacts]] = field(default_factory=dict)
    rotated: dict[tuple[str, str], list[str]] = field(default_factory=dict)

    def observe(self, event: DiskEventRecord, ctx: Context) -> None:
        record = ctx.evtx(event)
        if record is None or record.event_id not in (1102, 104):
            return
        leaf = event.path.replace("\\", "/").rsplit("/", 1)[-1].casefold()
        if record.provider == "":
            # No provider exported: accept only the channel each id belongs to.
            expected = "security.evtx" if record.event_id == 1102 else "system.evtx"
            if leaf != expected:
                return
        elif record.provider != evtx_fields.EVENTLOG:
            return
        if record.fields is None:
            ctx.counts["evtx_layout_unknown"] += 1
        if not ctx.budget.take():
            return
        if record.event_id == 1102:
            channel = "Security"
        else:
            channel = record.get("Channel") or CHANNEL_BY_PATH.get(leaf, "unknown channel")
        account = record.get("SubjectUserName") or "unknown"
        finding = Finding(
            type="disk_log_cleared",
            severity="medium",
            confidence=CONFIDENCE,
            values={
                "channel": quoted(channel, 64),
                "event_id": record.event_id,
                "provider": quoted(record.provider or "an unnamed provider", 64),
                "when": iso(event.ts),
                "account": quoted(account, 64),
            },
            subject=f"{channel}@{iso(event.ts)}",
            key=f"event:{event.ordinal}",
            ts=event.ts,
            attributes={
                "subject": quoted(f"{channel}@{iso(event.ts)}", 255),
                "event_id": record.event_id,
                "channel": quoted(channel, 64),
            },
        )
        finding.cite(ev.cited(event, "log_cleared", f"Event log cleared ({channel})"))
        self.findings.append(finding)

    def check_file(self, file: DiskFileRecord, facts: FileFacts, ctx: Context) -> list[Finding]:
        if facts.family != "linux" or file.type != "reg" or not file.has_flag("allocated"):
            return []
        directory, _, name = facts.norm.rpartition("/")
        if directory != LOG_DIR:
            return []
        if name in BASES:
            if ctx.budget.take():
                self.current[(directory, name)] = (file, facts)
            return []
        rotated = ROTATED.match(name)
        if rotated and (file.size or 0) > 0 and ctx.budget.take():
            self.rotated.setdefault((directory, rotated.group("base")), []).append(name)
        return []

    def finish(self, ctx: Context) -> list[Finding]:
        out = list(self.findings)
        for key, (file, facts) in sorted(self.current.items()):
            siblings = sorted(self.rotated.get(key, []))
            if not siblings or file.size is None:
                continue
            if file.size == 0:
                reason = "empty"
            elif key[1] == "wtmp" and file.size % WTMP_RECORD:
                reason = f"not a whole number of {WTMP_RECORD}-byte records"
            else:
                continue
            out.append(
                file_finding(
                    "disk_log_emptied",
                    "medium",
                    CONFIDENCE,
                    file,
                    facts,
                    ctx,
                    {
                        "name": shown(file.name, 64),
                        "path": shown(file.path),
                        "size": size_text(file),
                        "reason": reason,
                        "when": iso(file_time(file)),
                        "siblings": shown(joined(siblings[:8]), 255),
                    },
                )
            )
        return out
