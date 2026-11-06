"""Shared pieces of the disk detections (M9 phase 6).

Findings describe *what was observed* in the image's normalised records (file listing, Plaso
events, YARA hits, hash-set matches), with the measured values behind them. They never call a
file, a host or an account malicious: every title and description comes from `TEMPLATES`,
which `test_finding_wording.py` checks for verdict wording. Values from the image (paths, names,
registry values, command lines, service paths, URLs) are inserted into placeholders after
`cyberlab_worker.mask.excerpt`, so a secret keeps 2 characters and its length (plan
"Sensitivity"); the raw text stays only in `disk_events` / `disk_files`.

Severity policy: every `heuristic:*` method stops at `medium` (and at its own ceiling, e.g.
`disk_exec_user_writable` at `low`); `known_file:hashset@1` stops at `medium` (operator lists are
unverified); only `signature:yara@1` may reach `high`, through the M3 allow-list.

Evidence refs (`FindingRecord.evidence_refs`, <= 50 x 64 characters), resolved by the trusted
ingest (phase 7):
- `file:<partition>:<meta_addr>:<meta_seq>[:<stream>]` (`meta_seq` empty when absent; a stream
  name that would not fit is replaced by `#` + the first 16 hex digits of its sha256);
- `event:<ordinal>` (the event's position in the worker's export; every cited ordinal is in
  `DetectionOutput.cited_events`, so pass 2 stores it, RT10);
- `finding:<uuid>` (correlation).
"""

import hashlib
import uuid
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from types import MappingProxyType
from typing import Literal

from cyberlab_jobs.disk import (
    CASE_INSENSITIVE_FS,
    DiskEventRecord,
    DiskFileRecord,
    DiskPartitionRecord,
    FsType,
)
from cyberlab_worker.mask import excerpt

from disk_worker.detections import evtx_fields, paths

Severity = Literal["info", "low", "medium", "high"]
SEVERITY_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3}
HEURISTIC_MAX: Severity = "medium"
FINDING_NAMESPACE = uuid.UUID("0d6c8b1e-3f2a-4c55-9b7e-6a4e2d9f1c37")
MAX_REFS = 50
MAX_CITED_EVENTS = 20  # event ordinals cited by one finding (the rest are counted)
MAX_ATTRIBUTES = 20
# Detector working state (aggregation keys, pending findings, the user-writable file index) is
# capped across all rules; beyond it the run is flagged `truncated` and the remaining keys are
# not tracked (never a failure, never unbounded memory).
MAX_DETECTOR_KEYS = 200_000
# The analysed window: file-listing persistence rules look at changes in the last WINDOW of
# activity on the image (the newest event, else the newest file time).
WINDOW = timedelta(days=7)
CORRELATION_WINDOW = timedelta(minutes=10)
# The shared surfaces (findings, IOCs, timeline) take timestamps in 1970..2100.
EARLIEST = datetime(1970, 1, 1, tzinfo=UTC)
LATEST = datetime(2100, 1, 1, tzinfo=UTC)

M_EXEC = "heuristic:disk_exec_user_writable@1"
M_DOUBLE = "heuristic:disk_double_extension@1"
M_MISMATCH = "heuristic:disk_extension_mismatch@1"
M_ADS = "heuristic:disk_ads_executable@1"
M_PERSISTENCE = "heuristic:disk_persistence@1"
M_LOG_CLEARED = "heuristic:disk_log_cleared@1"
M_SERVICE = "heuristic:disk_service_installed@1"
M_ACCOUNT = "heuristic:disk_account_change@1"
M_LOGON = "heuristic:disk_remote_logon@1"
M_DUAL_USE = "heuristic:disk_dual_use_execution@1"
M_CORRELATED = "heuristic:disk_correlated_indicators@1"
M_YARA = "signature:yara@1"
M_HASHSET = "known_file:hashset@1"

# Per-method severity ceiling (plan phase 6 table).
METHOD_MAX: MappingProxyType[str, Severity] = MappingProxyType(
    {
        M_EXEC: "low",
        M_DOUBLE: "medium",
        M_MISMATCH: "medium",
        M_ADS: "medium",
        M_PERSISTENCE: "medium",
        M_LOG_CLEARED: "medium",
        M_SERVICE: "medium",
        M_ACCOUNT: "low",
        M_LOGON: "medium",
        M_DUAL_USE: "medium",
        M_CORRELATED: "medium",
        M_YARA: "high",
        M_HASHSET: "medium",
    }
)

_PERSIST_NOTE = "Software installers and administrators create autostart entries too."
# type -> (method, title template, description template). Every finding text comes from here.
TEMPLATES: MappingProxyType[str, tuple[str, str, str]] = MappingProxyType(
    {
        "disk_exec_user_writable": (
            M_EXEC,
            "Executable in a user-writable location ({path_class})",
            "{path} ({magic} executable, {size} bytes) is in {path_class}, a location ordinary "
            "users can write to. Installers and updaters also unpack programs there; software "
            "installed for all users normally lives in protected program directories.",
        ),
        "disk_double_extension": (
            M_DOUBLE,
            "File name with a document extension before an executable one",
            "{name} in {directory} ends in .{inner} followed by .{outer}. With extensions "
            "hidden, such a name shows as a document while it opens as a program.",
        ),
        "disk_rtlo_name": (
            M_DOUBLE,
            "File name with a right-to-left override character",
            "{name} in {directory} contains U+202E (shown here as <U+202E>), which reverses the "
            "displayed order of the characters after it, so the visible extension differs "
            "from the real one (.{outer}).",
        ),
        "disk_extension_mismatch": (
            M_MISMATCH,
            "Executable content under a non-executable extension (.{ext})",
            "{path} ({size} bytes) starts with a {magic} executable header but is named "
            ".{ext}. Programs saved under data extensions are not started by a double click; "
            "they are usually started by another program.",
        ),
        "disk_ads_executable": (
            M_ADS,
            "NTFS alternate data stream with executable content",
            "{path} has a named stream {stream} ({size} bytes) that starts with a {magic} "
            "executable header. Named streams normally hold small metadata (Zone.Identifier "
            "and similar), not programs.",
        ),
        "disk_persistence_run_key": (
            M_PERSISTENCE,
            "Autostart registry value points into a user-writable location",
            "{key} holds (secrets masked): {value}. The program {target} is in {path_class}. "
            + _PERSIST_NOTE,
        ),
        "disk_persistence_service": (
            M_PERSISTENCE,
            "Service image path in a user-writable location",
            "Service key {key} has the image path (secrets masked) {value}, in {path_class}. "
            "Services normally run programs from protected program directories.",
        ),
        "disk_persistence_startup": (
            M_PERSISTENCE,
            "Startup folder entry ({entry_kind})",
            "{path} ({magic}, {size} bytes, modified {when}) is started at user logon from a "
            "Startup folder. " + _PERSIST_NOTE,
        ),
        "disk_persistence_task": (
            M_PERSISTENCE,
            "Scheduled task file created or modified in the analysed window",
            "{path} was {change} at {when}; the analysed window starts at {window_start}. The "
            "task definition itself is not parsed. " + _PERSIST_NOTE,
        ),
        "disk_persistence_cron_file": (
            M_PERSISTENCE,
            "Cron file created or modified in the analysed window",
            "{path} was {change} at {when}; the analysed window starts at {window_start}. The "
            "file content is not read. " + _PERSIST_NOTE,
        ),
        "disk_persistence_systemd_unit": (
            M_PERSISTENCE,
            "systemd unit created or modified in the analysed window",
            "{path} was {change} at {when}; the analysed window starts at {window_start}. The "
            "unit content is not read. Package upgrades also rewrite units.",
        ),
        "disk_persistence_rc_local": (
            M_PERSISTENCE,
            "/etc/rc.local is present",
            "{path} ({size} bytes, modified {when}) is run at boot by the rc-local service when "
            "it is executable. Current Debian and Ubuntu systems ship without it.",
        ),
        "disk_persistence_ld_preload": (
            M_PERSISTENCE,
            "/etc/ld.so.preload is present",
            "{path} ({size} bytes, modified {when}) lists libraries the dynamic loader adds to "
            "every program it starts. It is absent or empty on most systems.",
        ),
        "disk_persistence_authorized_keys": (
            M_PERSISTENCE,
            "SSH authorized_keys modified in the analysed window",
            "{path} was {change} at {when}; the analysed window starts at {window_start}. A key "
            "added there allows logons without a password.",
        ),
        "disk_persistence_cron_exec": (
            M_PERSISTENCE,
            "Cron job runs a program from a user-writable location",
            "{reporter} ran (secrets masked): {command}. The program {target} is in "
            "{path_class}, where ordinary users can replace it.",
        ),
        "disk_log_cleared": (
            M_LOG_CLEARED,
            "Event log cleared ({channel})",
            "Event {event_id} from {provider} at {when}: the {channel} log was cleared (account: "
            "{account}). Administrators clear logs too; the cleared records are not in this "
            "image.",
        ),
        "disk_log_emptied": (
            M_LOG_CLEARED,
            "{name} is empty or truncated while rotated copies exist",
            "{path} is {size} bytes ({reason}, modified {when}); rotated siblings: {siblings}. "
            "Log rotation leaves an empty file only until the next entry is written.",
        ),
        "disk_service_installed": (
            M_SERVICE,
            "Service installed: {service}",
            "Event 7045 at {when}: service {service} was installed with the image path "
            "(secrets masked) {image} ({location}). Software installers register services too.",
        ),
        "disk_account_created": (
            M_ACCOUNT,
            "Account created: {account}",
            "{source} at {when}: the account {account} was created{detail}. Administrators and "
            "installers create accounts too.",
        ),
        "disk_account_enabled": (
            M_ACCOUNT,
            "Account enabled: {account}",
            "{source} at {when}: the account {account} was enabled.",
        ),
        "disk_group_member_added": (
            M_ACCOUNT,
            "Account added to group {group}",
            "{source} at {when}: {account} was added to the group {group}.",
        ),
        "disk_remote_logon": (
            M_LOGON,
            "Remote logon ({logon_kind}) from {address}",
            "{count} successful logon(s) of {account} from {address} ({logon_kind}) between "
            "{first} and {last}, recorded by {source}.",
        ),
        "disk_logon_failure_burst": (
            M_LOGON,
            "{count} failed logons from {address} within 10 minutes",
            "{source}: {count} failed logons from {address} between {first} and {last} "
            "(accounts tried: {accounts}). Repeated failures in a short time come from "
            "password guessing or from a client with a stale password.",
        ),
        "disk_dual_use_execution": (
            M_DUAL_USE,
            "Execution evidence of dual-use tools or commands ({patterns})",
            "{artifact} at {when} (secrets masked): {text}. Matched: {patterns}. These tools and "
            "commands have administrative uses; they also appear when systems are accessed "
            "remotely by hand.",
        ),
        "disk_correlated_indicators": (
            M_CORRELATED,
            "Several independent observations on one {scope} ({count})",
            "{subject}: {count} separate observations ({indicators}). Each is listed as its own "
            "finding; together they deserve a closer look.",
        ),
        "disk_yara_match": (
            M_YARA,
            "YARA rule {rule} matched {name}",
            "{path} ({size} bytes) matched the rule {rule} ({namespace}). A rule match is a "
            "pattern observation; its severity comes from the rule allow-list.",
        ),
        "disk_hashset_match": (
            M_HASHSET,
            "File hash listed in the reference set {set_name} ({kind})",
            "{path} ({size} bytes): its hash is listed in the operator-supplied {kind} set "
            "{set_name}. Operator lists are not verified by CyberLab.",
        ),
    }
)


def cap(severity: Severity, ceiling: Severity) -> Severity:
    return severity if SEVERITY_RANK[severity] <= SEVERITY_RANK[ceiling] else ceiling


@dataclass(frozen=True)
class CitedEvent:
    """An event a finding cites, with what the shared timeline needs (built at observe time:
    events are never retained)."""

    ordinal: int
    ts: datetime
    kind: str  # DiskTimelineKind
    title: str  # masked
    src_ip: str | None = None


@dataclass
class Finding:
    """Detector output before it becomes a `finding` line."""

    type: str
    severity: Severity
    confidence: float
    values: dict[str, object]
    subject: str  # what the finding is about (path, address, service, ...); labels match it
    key: str  # discriminates findings of one type (stable id)
    ts: datetime | None
    files: list[DiskFileRecord] = field(default_factory=list)
    events: list[CitedEvent] = field(default_factory=list)
    extra_refs: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)  # normalised, for correlation
    texts: list[str] = field(default_factory=list)  # masked text quoted (URL / IP IOCs)
    src_ip: IPv4Address | IPv6Address | None = None
    attributes: dict[str, str | int | float | bool] = field(default_factory=dict)
    cited_more: int = 0  # cited events beyond MAX_CITED_EVENTS (counted, not referenced)

    @property
    def method(self) -> str:
        return TEMPLATES[self.type][0]

    @property
    def title(self) -> str:
        return TEMPLATES[self.type][1].format(**self.values)[:255]

    @property
    def description(self) -> str:
        return TEMPLATES[self.type][2].format(**self.values)[:2048]

    @property
    def capped_severity(self) -> Severity:
        severity = cap(self.severity, METHOD_MAX[self.method])
        return cap(severity, HEURISTIC_MAX) if self.method.startswith("heuristic:") else severity

    def finding_id(self, image_key: str) -> uuid.UUID:
        """Stable: the same observation on the same image always gets the same id."""
        return uuid.uuid5(FINDING_NAMESPACE, f"{image_key}|{self.method}|{self.type}|{self.key}")

    def cite(self, event: CitedEvent) -> None:
        if len(self.events) < MAX_CITED_EVENTS:
            self.events.append(event)
        else:
            self.cited_more += 1

    def refs(self) -> list[str]:
        out: list[str] = []
        for value in [
            *(file_ref(f) for f in self.files),
            *(f"event:{e.ordinal}" for e in self.events),
            *self.extra_refs,
        ]:
            if value not in out:
                out.append(value)
            if len(out) >= MAX_REFS:
                break
        return out


class Budget:
    """Counts detector-state keys across all rules of one run."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0
        self.exhausted = False

    def take(self, n: int = 1) -> bool:
        if self.used + n > self.limit:
            self.exhausted = True
            return False
        self.used += n
        return True


@dataclass
class Context:
    """What every rule receives: partitions, the budget, counters and the analysed window."""

    budget: Budget
    partitions: dict[int, DiskPartitionRecord]
    image_key: str
    counts: Counter[str] = field(default_factory=Counter)
    newest_event: datetime | None = None
    newest_file: datetime | None = None
    # Normalised path -> file, for files in user-writable classes and Startup folders only
    # (persistence / service targets resolve against it; bounded by the budget).
    indexed_files: dict[str, DiskFileRecord] = field(default_factory=dict)
    # YARA rule (as stored in `DiskFileRecord.yara_rules`) -> its severity, computed by phase 5
    # through the M3 sha256-keyed allow-list; a rule missing here is `low` (the M3 default).
    yara_severity: Mapping[str, Severity] = field(default_factory=dict)

    # The EVTX fields of the event being observed, read once for every rule.
    _evtx_event: DiskEventRecord | None = None
    _evtx_record: evtx_fields.EvtxRecord | None = None

    def evtx(self, event: DiskEventRecord) -> evtx_fields.EvtxRecord | None:
        if self._evtx_event is not event:
            self._evtx_event = event
            self._evtx_record = evtx_fields.read(event)
        return self._evtx_record

    def case_insensitive(self, partition_index: int) -> bool:
        part = self.partitions.get(partition_index)
        if part is None or part.fs_type is None:
            return False
        return FsType(part.fs_type) in CASE_INSENSITIVE_FS

    def norm(self, file: DiskFileRecord) -> str:
        return paths.normalize(file.path, self.case_insensitive(file.partition_index))

    def family(self, file: DiskFileRecord) -> paths.OsFamily:
        return paths.family_of(self.case_insensitive(file.partition_index))

    @property
    def reference(self) -> datetime | None:
        return self.newest_event or self.newest_file

    @property
    def window_start(self) -> datetime | None:
        ref = self.reference
        return None if ref is None else ref - WINDOW

    def in_window(self, ts: datetime | None) -> bool:
        start = self.window_start
        return ts is not None and start is not None and ts >= start

    def see_event(self, event: DiskEventRecord) -> None:
        if self.newest_event is None or event.ts > self.newest_event:
            self.newest_event = event.ts

    def see_file(self, file: DiskFileRecord) -> None:
        ts = file.mtime
        if ts is not None and (self.newest_file is None or ts > self.newest_file):
            self.newest_file = ts

    @property
    def fallback_ts(self) -> datetime:
        return shared_ts(self.reference) or EARLIEST


@dataclass(frozen=True)
class FileFacts:
    """Per-file values computed once per run and shared by the file rules."""

    norm: str  # normalised path (case-folded on NTFS / FAT / exFAT)
    family: paths.OsFamily
    writable: str | None  # the user-writable class, if any


class Rule:
    """One detection rule. File rules implement `check_file` (called once per listed file, after
    every event has been observed, so the analysed window is known); event rules implement
    `observe` (called once per event, in a single streaming pass, keeping only bounded
    aggregates) and `finish`."""

    def observe(self, event: DiskEventRecord, ctx: Context) -> None:
        return None

    def check_file(self, file: DiskFileRecord, facts: FileFacts, ctx: Context) -> list[Finding]:
        return []

    def finish(self, ctx: Context) -> list[Finding]:
        return []


# --- helpers ----------------------------------------------------------------------------------


def shared_ts(value: datetime | None) -> datetime | None:
    """`value` when the shared surfaces accept it (1970..2100), else None."""
    if value is None or not EARLIEST <= value < LATEST:
        return None
    return value


def iso(value: datetime | None) -> str:
    return "unknown time" if value is None else value.strftime("%Y-%m-%dT%H:%M:%SZ")


def file_time(file: DiskFileRecord) -> datetime | None:
    """The time a file finding is placed at: its last modification, else its creation."""
    return file.mtime or file.crtime


def changed(file: DiskFileRecord, ctx: Context) -> tuple[str, datetime] | None:
    """("created" | "modified", when) if the file changed inside the analysed window."""
    for what, ts in (("created", file.crtime), ("modified", file.mtime), ("changed", file.ctime)):
        if ts is not None and ctx.in_window(ts):
            return what, ts
    return None


def file_ref(file: DiskFileRecord) -> str:
    seq = "" if file.meta_seq is None else str(file.meta_seq)
    ref = f"file:{file.partition_index}:{file.meta_addr}:{seq}"
    if file.stream is None:
        return ref
    with_stream = f"{ref}:{file.stream}"
    if len(with_stream) <= 64:
        return with_stream
    return f"{ref}:#{hashlib.sha256(file.stream.encode('utf-8', 'surrogatepass')).hexdigest()[:16]}"


RTLO = chr(0x202E)
CR = chr(13)
LF = chr(10)


def quoted(text: str | None, limit: int = 300) -> str:
    """Free text from the image (registry values, service image paths, command lines, history
    lines, URLs) for a shared surface: masked (`cyberlab_worker.mask`), then shortened; bidi
    overrides made visible."""
    return excerpt((text or "").replace(RTLO, "<U+202E>"), limit)


def shown(text: str | None, limit: int = 300) -> str:
    """A path or name from the file listing for a shared surface: shortened, bidi overrides made
    visible, not masked (plan "Sensitivity" masks quoted free text; the masker's 40-character
    key rule would hide ordinary `/`-separated paths)."""
    value = (text or "").replace(RTLO, "<U+202E>").replace(CR, " ").replace(LF, " ")
    return value if len(value) <= limit else value[: limit - 3] + "..."


def directory_of(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else "/"


def joined(values: list[str], limit: int = 255) -> str:
    text = ", ".join(values)
    return text if len(text) <= limit else text[: limit - 3] + "..."


__all__ = [
    "CORRELATION_WINDOW",
    "EARLIEST",
    "HEURISTIC_MAX",
    "LATEST",
    "MAX_ATTRIBUTES",
    "MAX_CITED_EVENTS",
    "MAX_DETECTOR_KEYS",
    "MAX_REFS",
    "METHOD_MAX",
    "SEVERITY_RANK",
    "TEMPLATES",
    "WINDOW",
    "Budget",
    "CitedEvent",
    "Context",
    "FileFacts",
    "Finding",
    "Rule",
    "Severity",
    "cap",
    "changed",
    "directory_of",
    "file_ref",
    "file_time",
    "iso",
    "joined",
    "quoted",
    "shared_ts",
    "shown",
]
