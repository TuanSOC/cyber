"""`heuristic:disk_persistence@1`: autostart locations.

medium (the entry starts a program in a user-writable class, or a loader-wide hook):
- Run / RunOnce / RunServices / Policies\\Explorer\\Run values (registry events) naming a program
  in a user-writable class;
- service keys (`windows:registry:service`) whose ImagePath is in a user-writable class;
- executables placed directly in a Startup folder;
- cron runs (syslog `CRON ... CMD (...)`) of a program in a user-writable class;
- `/etc/ld.so.preload` present and not empty.

low (listing only: contents are never read; RT28):
- other Startup-folder entries (shortcuts) created or modified inside the analysed window;
- scheduled-task files under `Windows/System32/Tasks` created or modified inside the window
  (the task XML is never parsed, so where a task points cannot be evaluated);
- cron files, systemd units (admin and per-user directories) and `authorized_keys` created or
  modified inside the window; `/etc/rc.local` present.

Registry and cron entries pointing elsewhere are not findings (every clean system has dozens).
"""

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from cyberlab_jobs.disk import DiskEventRecord, DiskFileRecord

from disk_worker.detections import events as ev
from disk_worker.detections import paths
from disk_worker.detections.base import (
    Context,
    FileFacts,
    Finding,
    Rule,
    changed,
    file_time,
    iso,
    quoted,
    shown,
)
from disk_worker.detections.file_rules import EXEC_MAGIC, MAGIC_LABEL, file_finding, size_text

RUN_KEY = re.compile(
    r"\\CurrentVersion\\(?:Run(?:Once(?:Ex)?)?|RunServices(?:Once)?|Policies\\Explorer\\Run)"
    r"(?:\\|$)",
    re.IGNORECASE,
)
SERVICE_KEY = re.compile(r"\\Services\\[^\\]{1,256}$", re.IGNORECASE)
CRON_LINE = re.compile(r"^\((?P<user>[^)\s]{1,64})\) CMD \((?P<command>.{1,2048})\)\s*$")
CRON_REPORTERS = frozenset({"cron", "crond", "anacron"})

STARTUP_EXEC_EXTENSIONS = frozenset(
    "exe scr com pif bat cmd vbs vbe js jse wsf wsh hta ps1 msi cpl jar dll".split()
)
STARTUP_IGNORED = frozenset({"desktop.ini"})
CRON_FILES = (
    "etc/crontab",
    "etc/cron.d/*",
    "etc/cron.hourly/*",
    "etc/cron.daily/*",
    "etc/cron.weekly/*",
    "etc/cron.monthly/*",
    "var/spool/cron/crontabs/*",
    "var/spool/cron/*",
)
CRON_IGNORED = frozenset({".placeholder"})
SYSTEMD_UNITS = ("etc/systemd/system/**", "home/*/.config/systemd/user/**")
SYSTEMD_SUFFIXES = (".service", ".timer", ".socket", ".path")
AUTHORIZED_KEYS = (
    "home/*/.ssh/authorized_keys",
    "home/*/.ssh/authorized_keys2",
    "root/.ssh/authorized_keys",
    "root/.ssh/authorized_keys2",
)
CONFIDENCE_HIGH = 0.7
CONFIDENCE_LOW = 0.4


@dataclass
class _Target:
    finding: Finding
    norm: str  # normalised target path (resolved against the listing at finish)


@dataclass
class Persistence(Rule):
    pending: dict[str, _Target] = field(default_factory=dict)

    # --- registry and cron events ---------------------------------------------------------

    def observe(self, event: DiskEventRecord, ctx: Context) -> None:
        if event.data_type.startswith("windows:registry"):
            self._registry(event, ctx)
        elif event.data_type.startswith("syslog"):
            self._cron(event, ctx)

    def _registry(self, event: DiskEventRecord, ctx: Context) -> None:
        key = ev.registry_key(event)
        if key is None:
            return
        if event.data_type == "windows:registry:run" or RUN_KEY.search(key):
            values = ev.texts(event, "entries") or [ev.message_after_key(event)]
            for value in values:
                for target in paths.windows_targets(value, named=True):
                    self._add_registry(event, ctx, "disk_persistence_run_key", key, value, target)
        elif event.data_type == "windows:registry:service" or SERVICE_KEY.search(key):
            image = ev.text(event, "image_path")
            if image is None:
                return
            for target in paths.windows_targets(image):
                self._add_registry(event, ctx, "disk_persistence_service", key, image, target)

    def _add_registry(
        self, event: DiskEventRecord, ctx: Context, kind: str, key: str, value: str, target: str
    ) -> None:
        norm = paths.windows_path(target)
        writable = paths.user_writable_class(norm, "windows")
        if writable is None:
            return
        pending_key = f"{kind}|{key.casefold()}|{norm}"
        title = f"Autostart entry {key}: {value}"
        self._pending(
            ctx,
            pending_key,
            norm,
            event,
            title,
            lambda: Finding(
                type=kind,
                severity="medium",
                confidence=CONFIDENCE_HIGH,
                values={
                    "key": quoted(key, 300),
                    "value": quoted(value),
                    "target": quoted(target),
                    "path_class": writable,
                },
                subject=target,
                key=pending_key,
                ts=event.ts,
                paths=[norm],
                texts=[quoted(value, 2048)],
                attributes={
                    "subject": quoted(target, 255),
                    "registry_key": quoted(key, 255),
                    "path_class": writable,
                },
            ),
        )

    def _cron(self, event: DiskEventRecord, ctx: Context) -> None:
        command: str | None = None
        reporter = "cron"
        if event.data_type == "syslog:cron:task_run":
            command = ev.text(event, "command")
        else:
            line = ev.syslog(event)
            if line is None or line[0].casefold() not in CRON_REPORTERS:
                return
            reporter = line[0]
            found = CRON_LINE.match(line[1])
            command = found.group("command") if found else None
        if not command:
            return
        target = paths.linux_target(command)
        if target is None:
            return
        norm = paths.normalize(target, False)
        writable = paths.user_writable_class(norm, "linux")
        if writable is None:
            return
        pending_key = f"disk_persistence_cron_exec|{norm}"
        self._pending(
            ctx,
            pending_key,
            norm,
            event,
            f"Cron ran {command}",
            lambda: Finding(
                type="disk_persistence_cron_exec",
                severity="medium",
                confidence=CONFIDENCE_HIGH,
                values={
                    "reporter": quoted(reporter, 64),
                    "command": quoted(command),
                    "target": quoted(target),
                    "path_class": writable,
                },
                subject=target,
                key=pending_key,
                ts=event.ts,
                paths=[norm],
                texts=[quoted(command, 2048)],
                attributes={"subject": quoted(target, 255), "path_class": writable},
            ),
        )

    def _pending(
        self,
        ctx: Context,
        key: str,
        norm: str,
        event: DiskEventRecord,
        title: str,
        build: Callable[[], Finding],
    ) -> None:
        item = self.pending.get(key)
        if item is None:
            if not ctx.budget.take():
                return
            item = _Target(build(), norm)
            self.pending[key] = item
        item.finding.cite(ev.cited(event, "persistence", title))

    def finish(self, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        for item in self.pending.values():
            listed = ctx.indexed_files.get(item.norm)
            if listed is not None:
                item.finding.files.append(listed)
            out.append(item.finding)
        return out

    # --- file listing ---------------------------------------------------------------------

    def check_file(self, file: DiskFileRecord, facts: FileFacts, ctx: Context) -> list[Finding]:
        if not file.has_flag("allocated") or file.type == "dir" or file.stream is not None:
            return []
        if facts.family == "windows":
            return self._windows_file(file, facts, ctx)
        return self._linux_file(file, facts, ctx)

    def _windows_file(self, file: DiskFileRecord, facts: FileFacts, ctx: Context) -> list[Finding]:
        if paths.is_startup(facts.norm):
            name = file.name.casefold()
            if name in STARTUP_IGNORED:
                return []
            ext = name.rsplit(".", 1)[-1] if "." in name else ""
            executable = file.magic in EXEC_MAGIC or ext in STARTUP_EXEC_EXTENSIONS
            if not executable and changed(file, ctx) is None:
                return []
            kind = "executable" if executable else "shortcut or other file"
            return [
                file_finding(
                    "disk_persistence_startup",
                    "medium" if executable else "low",
                    CONFIDENCE_HIGH if executable else CONFIDENCE_LOW,
                    file,
                    facts,
                    ctx,
                    {
                        "path": shown(file.path),
                        "magic": MAGIC_LABEL.get(file.magic or "", file.magic or "unknown type"),
                        "size": size_text(file),
                        "when": iso(file_time(file)),
                        "entry_kind": kind,
                    },
                )
            ]
        if paths.is_task(facts.norm) and file.type == "reg":
            return self._changed("disk_persistence_task", file, facts, ctx)
        return []

    def _linux_file(self, file: DiskFileRecord, facts: FileFacts, ctx: Context) -> list[Finding]:
        norm = facts.norm
        if paths.matches(norm, CRON_FILES, False):
            if file.type != "reg" or file.name in CRON_IGNORED:
                return []
            return self._changed("disk_persistence_cron_file", file, facts, ctx)
        if paths.matches(norm, SYSTEMD_UNITS, False) and norm.endswith(SYSTEMD_SUFFIXES):
            return self._changed("disk_persistence_systemd_unit", file, facts, ctx)
        if paths.matches(norm, AUTHORIZED_KEYS, False):
            return self._changed("disk_persistence_authorized_keys", file, facts, ctx)
        if norm == "etc/rc.local" and file.type == "reg":
            return [self._present("disk_persistence_rc_local", "low", file, facts, ctx)]
        if norm == "etc/ld.so.preload" and file.type == "reg" and file.size != 0:
            return [self._present("disk_persistence_ld_preload", "medium", file, facts, ctx)]
        return []

    def _changed(
        self, kind: str, file: DiskFileRecord, facts: FileFacts, ctx: Context
    ) -> list[Finding]:
        change = changed(file, ctx)
        if change is None:
            return []
        what, when = change
        found = file_finding(
            kind,
            "low",
            CONFIDENCE_LOW,
            file,
            facts,
            ctx,
            {
                "path": shown(file.path),
                "change": what,
                "when": iso(when),
                "window_start": iso(ctx.window_start),
            },
        )
        found.ts = when
        return [found]

    def _present(
        self, kind: str, severity: str, file: DiskFileRecord, facts: FileFacts, ctx: Context
    ) -> Finding:
        return file_finding(
            kind,
            "medium" if severity == "medium" else "low",
            CONFIDENCE_HIGH if severity == "medium" else CONFIDENCE_LOW,
            file,
            facts,
            ctx,
            {"path": shown(file.path), "size": size_text(file), "when": iso(file_time(file))},
        )
