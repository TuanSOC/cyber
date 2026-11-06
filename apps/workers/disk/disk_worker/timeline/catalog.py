"""The artifact catalog (M9 phase 3): which listed files the collect stage copies per (OS,
profile), and the Plaso parsers that read them.

- Categories are the frozen `DiskArtifact` enum; a category is in a profile only when
  `ARTIFACTS_BY_PROFILE` lists it (plan "Scope").
- Patterns are '/'-separated paths relative to the file-system root: `*` matches within one
  component, `**/` any directories (only under `var/log/journal`). Windows entries match
  case-insensitively (NTFS / FAT), Linux entries case-sensitively (ext).
- Entry order is the collect priority: small, high-value artifacts first, so the byte budget
  never starves EVTX or the hives for a large `$MFT` or browser history.
- Per-file caps: 512 MiB (`$MFT` 1 GiB, `full` only); a rotated `.gz` / `.xz` log is accepted in
  `full` only, up to 64 MiB compressed (RT11, see `plan`).
- The never-collected list (`cyberlab_jobs.disk.never_collect`, RT7) is applied by `plan.build`
  **after** pattern matching, over every name of each matched inode: no pattern here can ever
  select those files, whatever it says.

Scheduled-task XML (`Windows/System32/Tasks/**`) is never collected: Plaso does not parse it;
the detections use the listing only (RT28).

`match(files, os, profile) -> CollectPlan` is the frozen entry point phase 2's analyzer calls;
the selection itself lives in `plan`.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from types import MappingProxyType

from cyberlab_jobs.disk import (
    ARTIFACTS_BY_PROFILE,
    AnalysisProfile,
    DiskArtifact,
    DiskFileRecord,
    DiskOs,
    DiskProfile,
)

MIB = 1024**2
GIB = 1024**3
DEFAULT_MAX_BYTES = 512 * MIB
ROTATED_MAX_BYTES = 64 * MIB  # a rotated `.gz` / `.xz` log, compressed size (`full` only)
ROTATED_SUFFIXES = (".gz", ".xz")
# Names of compressed or archive content: dropped unless the entry expects a rotated log.
COMPRESSED_SUFFIXES = (
    ".gz",
    ".xz",
    ".bz2",
    ".zst",
    ".lz4",
    ".lzma",
    ".z",
    ".zip",
    ".7z",
    ".rar",
    ".tar",
    ".tgz",
    ".cab",
)

_A = DiskArtifact

# The Windows event-log channels collected (plan "Scope"), as their file names.
EVTX_CHANNELS: tuple[str, ...] = (
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell%4Operational",
    "Windows PowerShell",
    "Microsoft-Windows-TaskScheduler%4Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational",
    "Microsoft-Windows-Windows Defender%4Operational",
    "Microsoft-Windows-Sysmon%4Operational",
    "Microsoft-Windows-Bits-Client%4Operational",
)


@dataclass(frozen=True)
class Entry:
    os: DiskOs
    artifact: DiskArtifact
    patterns: tuple[str, ...]
    max_bytes: int = DEFAULT_MAX_BYTES
    # The category's file-count share: beyond it the newest files (by mtime) are kept.
    max_files: int = 256
    # `full` only: rotated `.gz` / `.xz` copies of these logs are expected compressed content.
    rotated: bool = False


def _user(*tails: str) -> tuple[str, ...]:
    return tuple(f"Users/*/{t}" for t in tails)


def _home(*tails: str) -> tuple[str, ...]:
    return (*(f"home/*/{t}" for t in tails), *(f"root/{t}" for t in tails))


WINDOWS: tuple[Entry, ...] = (
    Entry(
        "windows",
        _A.REGISTRY_SYSTEM,
        ("Windows/System32/config/SYSTEM", "Windows/System32/config/SOFTWARE"),
        max_files=4,
    ),
    Entry("windows", _A.AMCACHE, ("Windows/AppCompat/Programs/Amcache.hve",), max_files=2),
    Entry(
        "windows",
        _A.EVTX,
        tuple(f"Windows/System32/winevt/Logs/{c}.evtx" for c in EVTX_CHANNELS),
        max_files=len(EVTX_CHANNELS),
    ),
    Entry(
        "windows",
        _A.REGISTRY_USER,
        _user("NTUSER.DAT", "AppData/Local/Microsoft/Windows/UsrClass.dat"),
        max_files=512,
    ),
    Entry("windows", _A.PREFETCH, ("Windows/Prefetch/*.pf",), max_files=1024),
    Entry(
        "windows",
        _A.LNK,
        _user("AppData/Roaming/Microsoft/Windows/Recent/*.lnk"),
        max_files=4096,
    ),
    Entry("windows", _A.RECYCLE_BIN, ("$Recycle.Bin/*/$I*",), max_files=4096),
    Entry(
        "windows",
        _A.BROWSER,
        _user(
            "AppData/Local/Google/Chrome/User Data/*/History",
            "AppData/Local/Microsoft/Edge/User Data/*/History",
            "AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
        ),
        max_files=256,
    ),
    Entry("windows", _A.MFT, ("$MFT",), max_bytes=GIB, max_files=1),
)

LINUX: tuple[Entry, ...] = (
    Entry(
        "linux",
        _A.PREPROCESS,
        tuple(
            f"etc/{name}"
            for name in ("timezone", "localtime", "hostname", "passwd", "os-release", "lsb-release")
        ),
        max_bytes=MIB,
        max_files=16,
    ),
    Entry(
        "linux",
        _A.AUTH_LOG,
        ("var/log/auth.log", "var/log/auth.log.*", "var/log/secure", "var/log/secure*"),
        max_files=64,
        rotated=True,
    ),
    Entry(
        "linux",
        _A.UTMP,
        (
            "var/log/wtmp",
            "var/log/wtmp.*",
            "var/log/btmp",
            "var/log/btmp.*",
            "var/run/utmp",
            "run/utmp",
        ),
        max_files=32,
    ),
    Entry(
        "linux",
        _A.SHELL_HISTORY,
        _home(".bash_history", ".zsh_history"),
        max_bytes=64 * MIB,
        max_files=512,
    ),
    Entry(
        "linux",
        _A.CRON,
        ("var/log/cron", "var/log/cron.*", "var/log/cron-*"),
        max_files=32,
        rotated=True,
    ),
    Entry(
        "linux",
        _A.PACKAGES,
        (
            "var/log/dpkg.log",
            "var/log/dpkg.log.*",
            "var/log/apt/history.log",
            "var/log/apt/history.log.*",
        ),
        max_files=64,
        rotated=True,
    ),
    Entry(
        "linux",
        _A.SYSLOG,
        (
            "var/log/syslog",
            "var/log/syslog.*",
            "var/log/messages",
            "var/log/messages*",
            "var/log/kern.log",
            "var/log/kern.log.*",
        ),
        max_files=64,
        rotated=True,
    ),
    Entry(
        "linux",
        _A.SYSTEMD_JOURNAL,
        ("var/log/journal/**/*.journal", "var/log/journal/**/*.journal~"),
        max_files=512,
    ),
    Entry(
        "linux",
        _A.BROWSER,
        _home(
            ".config/google-chrome/*/History",
            ".config/chromium/*/History",
            ".mozilla/firefox/*/places.sqlite",
        ),
        max_files=256,
    ),
)

ENTRIES: MappingProxyType[DiskOs, tuple[Entry, ...]] = MappingProxyType(
    {"windows": WINDOWS, "linux": LINUX}
)

# Plaso parser names per (OS, profile) (`--parsers`; `!filestat` always: the copies' own times
# are meaningless). PENDING the 3a spike: `log2timeline.py --parsers list` of 20261027 confirms
# every name (the text-log parsers are `text/<plugin>` since Plaso's text-parser rework).
_WINDOWS_PARSERS = ("winevtx", "winreg", "prefetch", "lnk")
_LINUX_PARSERS = (
    "text/syslog",
    "text/bash_history",
    "text/zsh_extended_history",
    "text/dpkg",
    "text/apt_history",
    "utmp",
)
PARSERS: MappingProxyType[tuple[DiskOs, str], tuple[str, ...]] = MappingProxyType(
    {
        ("windows", "triage"): _WINDOWS_PARSERS,
        ("windows", "full"): (*_WINDOWS_PARSERS, "mft", "recycle_bin", "sqlite"),
        ("linux", "triage"): _LINUX_PARSERS,
        ("linux", "full"): (*_LINUX_PARSERS, "systemd_journal", "sqlite"),
    }
)
EXCLUDED_PARSERS = ("filestat",)


def parser_expression(os: DiskOs, profile: AnalysisProfile) -> str:
    """The fixed `--parsers` value of a run (never derived from the image or the job)."""
    return ",".join((*PARSERS[(os, profile)], *(f"!{p}" for p in EXCLUDED_PARSERS)))


def _glob(pattern: str, case_insensitive: bool) -> re.Pattern[str]:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:[^/]+/)*")
            i += 3
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    flags = re.DOTALL | (re.IGNORECASE if case_insensitive else 0)
    return re.compile("^" + "".join(out) + "$", flags)


@dataclass(frozen=True)
class _Compiled:
    entry: Entry
    regexes: tuple[re.Pattern[str], ...]


_COMPILED: dict[DiskOs, tuple[_Compiled, ...]] = {
    os: tuple(_Compiled(e, tuple(_glob(p, os == "windows") for p in e.patterns)) for e in entries)
    for os, entries in ENTRIES.items()
}


def _wanted(os: DiskOs, profile: AnalysisProfile) -> frozenset[DiskArtifact]:
    return frozenset(ARTIFACTS_BY_PROFILE[(os, DiskProfile(profile))])


def entries_for(os: DiskOs, profile: AnalysisProfile) -> tuple[Entry, ...]:
    """The catalog entries of a profile, in collect priority order."""
    wanted = _wanted(os, profile)
    return tuple(e for e in ENTRIES[os] if e.artifact in wanted)


def classify(path: str, os: DiskOs, profile: AnalysisProfile) -> Entry | None:
    """The first entry of the profile whose pattern matches `path` (relative, '/'-separated),
    or None. Never consults the never-collected list: `plan.build` does, over every name."""
    wanted = _wanted(os, profile)
    rel = path.replace("\\", "/").lstrip("/")
    for compiled in _COMPILED[os]:
        if compiled.entry.artifact in wanted and any(rx.match(rel) for rx in compiled.regexes):
            return compiled.entry
    return None


def compressed_name(name: str) -> bool:
    return name.lower().endswith(COMPRESSED_SUFFIXES)


def rotated_name(name: str) -> bool:
    return name.lower().endswith(ROTATED_SUFFIXES)


@dataclass
class CollectPlan:
    files: list[tuple[DiskArtifact, DiskFileRecord]] = field(default_factory=list)
    bytes: int = 0
    refused_never_collect: int = 0
    # Matched files left out, by reason: `compressed`, `too_large`, `size_unknown`,
    # `category_cap`, `budget`, `max_files`.
    dropped: dict[str, int] = field(default_factory=dict)


def match(files: Sequence[DiskFileRecord], os: DiskOs, profile: AnalysisProfile) -> CollectPlan:
    """The collect plan of one partition's listing (see `plan.build`)."""
    from disk_worker.timeline import plan  # noqa: PLC0415 - `plan` imports this module

    return plan.build(files, os, profile)


__all__ = [
    "COMPRESSED_SUFFIXES",
    "ENTRIES",
    "EVTX_CHANNELS",
    "PARSERS",
    "ROTATED_MAX_BYTES",
    "CollectPlan",
    "Entry",
    "classify",
    "compressed_name",
    "entries_for",
    "match",
    "parser_expression",
    "rotated_name",
]
