"""Path classes of the disk detections (M9 phase 6; also read by phase 5's YARA candidate order,
RT18).

Every path the rules look at is normalised first:
- separators become `/`, a drive letter (`C:`), the NT prefixes `\\??\\` / `\\\\?\\` and leading
  or doubled separators are dropped, so a listed file (`Users/alice/...`, relative to its file
  system root) and a registry value (`C:\\Users\\alice\\...`) compare equal;
- on NTFS / FAT / exFAT (and for every Windows text path) components are case-folded and Win32's
  ignored trailing dots and spaces are stripped; ext paths stay case-sensitive;
- `%SystemRoot%`-style variables are expanded **only** from `ENV_TABLE` (a fixed table, never
  from the image); per-user variables expand to `Users/%user%/...`, whose `%user%` component
  matches the `*` of a pattern like any user name. An unknown variable is left as it is, so it
  never matches a class.

Patterns are globs over normalised paths: `*` is one component (or part of one), `**` any number
of components. `user_writable_class` answers the class name (or None); a path under
`CLEAN_SYSTEM_EXCLUSIONS` is never in a class (the M8 RT21 lesson: Defender's platform directory,
OneDrive / Teams per-user installs, `Windows\\Installer`, package caches, developer tool caches).
"""

import re
from collections.abc import Iterable
from functools import lru_cache
from types import MappingProxyType
from typing import Literal

OsFamily = Literal["windows", "linux"]

# `%NAME%` -> replacement (normalised, relative to the system volume root). Fixed table.
ENV_TABLE: MappingProxyType[str, str] = MappingProxyType(
    {
        "systemroot": "Windows",
        "windir": "Windows",
        "systemdrive": "",
        "programdata": "ProgramData",
        "allusersprofile": "ProgramData",
        "programfiles": "Program Files",
        "programw6432": "Program Files",
        "programfiles(x86)": "Program Files (x86)",
        "commonprogramfiles": "Program Files/Common Files",
        "commonprogramfiles(x86)": "Program Files (x86)/Common Files",
        "public": "Users/Public",
        "userprofile": "Users/%user%",
        "homepath": "Users/%user%",
        "appdata": "Users/%user%/AppData/Roaming",
        "localappdata": "Users/%user%/AppData/Local",
        "temp": "Users/%user%/AppData/Local/Temp",
        "tmp": "Users/%user%/AppData/Local/Temp",
    }
)

# Class name -> patterns. Windows patterns are case-folded; Linux patterns are case-sensitive.
WINDOWS_CLASSES: MappingProxyType[str, tuple[str, ...]] = MappingProxyType(
    {
        "user temp directory": ("users/*/appdata/local/temp/**",),
        "Downloads folder": ("users/*/downloads/**",),
        "public user profile": ("users/public/**",),
        "ProgramData": ("programdata/**",),
        "Windows temp directory": ("windows/temp/**",),
        "Recycle Bin": ("$recycle.bin/**", "recycler/**"),
    }
)
LINUX_CLASSES: MappingProxyType[str, tuple[str, ...]] = MappingProxyType(
    {
        # Class labels shown in findings (never opened as files).
        "/tmp": ("tmp/**",),  # noqa: S108
        "/var/tmp": ("var/tmp/**",),  # noqa: S108
        "/dev/shm": ("dev/shm/**",),  # noqa: S108
        "hidden directory in a home directory": ("home/*/.*/**", "home/*/.*"),
    }
)

# Clean-system exclusions (a maintained constant; benign baselines test every entry).
WINDOWS_EXCLUSIONS: tuple[str, ...] = (
    "programdata/microsoft/windows defender/**",
    "programdata/microsoft/windows defender advanced threat protection/**",
    "programdata/microsoft/clicktorun/**",
    "programdata/microsoft/visualstudio/packages/**",
    "programdata/package cache/**",
    "programdata/oracle/java/javapath/**",
    "users/*/appdata/local/microsoft/onedrive/**",
    "users/*/appdata/local/microsoft/teams/**",
    "users/*/appdata/local/package cache/**",
    "windows/installer/**",
)
LINUX_EXCLUSIONS: tuple[str, ...] = (
    "home/*/.cache/**",
    "home/*/.cargo/**",
    "home/*/.rustup/**",
    "home/*/.npm/**",
    "home/*/.nvm/**",
    "home/*/.pyenv/**",
    "home/*/.sdkman/**",
    "home/*/.dotnet/**",
    "home/*/.gradle/**",
    "home/*/.m2/**",
    "home/*/.mozilla/**",
    "home/*/.vscode/**",
    "home/*/.vscode-server/**",
    "home/*/.local/lib/**",
    "home/*/.local/share/virtualenvs/**",
    "home/*/.local/share/flatpak/**",
    "home/*/.local/share/Steam/**",
    "home/*/.local/share/JetBrains/**",
)
CLEAN_SYSTEM_EXCLUSIONS: MappingProxyType[OsFamily, tuple[str, ...]] = MappingProxyType(
    {"windows": WINDOWS_EXCLUSIONS, "linux": LINUX_EXCLUSIONS}
)

# Startup folders (Windows; case-folded) and standard program locations (service images).
STARTUP_PATTERNS: tuple[str, ...] = (
    "users/*/appdata/roaming/microsoft/windows/start menu/programs/startup/**",
    "programdata/microsoft/windows/start menu/programs/startup/**",
)
STANDARD_PROGRAM_PATTERNS: tuple[str, ...] = (
    "windows/system32/**",
    "windows/syswow64/**",
    "windows/microsoft.net/**",
    "windows/winsxs/**",
    "windows/servicing/**",
    "program files/**",
    "program files (x86)/**",
    *WINDOWS_EXCLUSIONS[:2],  # the Defender platform and definition directories
)
TASK_PATTERNS: tuple[str, ...] = ("windows/system32/tasks/**",)

_DRIVE = re.compile(r"^(?:[\\/]{2}[?.][\\/]|\\\?\?\\)?(?:[A-Za-z]:)?")
_ENV = re.compile(r"%([A-Za-z0-9_()]{1,32})%")
_SYSTEMROOT = re.compile(r"^[\\/]?systemroot(?=[\\/])", re.IGNORECASE)
_RELATIVE_SYSTEM = re.compile(r"^(?:system32|syswow64)(?=[\\/])", re.IGNORECASE)


def expand(text: str) -> str:
    """`%VAR%` from `ENV_TABLE` (case-insensitive names), `\\SystemRoot\\` and a driver-style
    `System32\\...` relative path; anything else is left unchanged."""

    def sub(match: re.Match[str]) -> str:
        value = ENV_TABLE.get(match.group(1).lower())
        return match.group(0) if value is None else "/" + value

    text = _SYSTEMROOT.sub("/Windows", text, count=1)
    text = _RELATIVE_SYSTEM.sub(lambda m: "/Windows/" + m.group(0), text, count=1)
    return _ENV.sub(sub, text)


def normalize(path: str, case_insensitive: bool) -> str:
    """Normalised relative path (see the module docstring)."""
    path = _DRIVE.sub("", path.strip(), count=1)
    parts = [p for p in path.replace("\\", "/").split("/") if p and p != "."]
    if case_insensitive:
        parts = [(p.rstrip(". ") or p).casefold() for p in parts]
    return "/".join(parts)


def windows_path(text: str) -> str:
    """A Windows path from a registry value or an event string: expanded, normalised,
    case-folded."""
    return normalize(expand(text), True)


@lru_cache(maxsize=256)
def _compile(pattern: str, case_insensitive: bool) -> re.Pattern[str]:
    out: list[str] = []
    for i, part in enumerate(pattern.split("/")):
        sep = "" if i == 0 else "/"
        if part == "**":
            # Any number (>= 1) of components below: `a/**` needs something inside `a`.
            out.append(f"{sep}[^/]+(?:/[^/]+)*")
        else:
            piece = "".join("[^/]*" if c == "*" else re.escape(c) for c in part)
            out.append(sep + piece)
    flags = re.DOTALL | (re.IGNORECASE if case_insensitive else 0)
    return re.compile("^" + "".join(out) + "$", flags)


def matches(path: str, patterns: Iterable[str], case_insensitive: bool) -> bool:
    """`path` is already normalised."""
    return any(_compile(p, case_insensitive).match(path) for p in patterns)


def family_of(case_insensitive: bool) -> OsFamily:
    """NTFS / FAT / exFAT trees use the Windows classes, ext trees the Linux ones."""
    return "windows" if case_insensitive else "linux"


def excluded(path: str, family: OsFamily) -> bool:
    return matches(path, CLEAN_SYSTEM_EXCLUSIONS[family], family == "windows")


def user_writable_class(path: str, family: OsFamily) -> str | None:
    """The user-writable class of a normalised path, or None (also for excluded paths)."""
    classes = WINDOWS_CLASSES if family == "windows" else LINUX_CLASSES
    ci = family == "windows"
    for name, patterns in classes.items():
        if matches(path, patterns, ci):
            if family == "linux" and name.startswith("hidden") and _only_dot_components(path):
                return None
            return None if excluded(path, family) else name
    return None


def _only_dot_components(path: str) -> bool:
    # `home/alice/..` style components are not hidden directories (normalize keeps `..`).
    parts = path.split("/")[2:]
    return not any(p.startswith(".") and p not in {".", ".."} for p in parts)


def is_startup(path: str) -> bool:
    return matches(path, STARTUP_PATTERNS, True)


def is_task(path: str) -> bool:
    return matches(path, TASK_PATTERNS, True)


def is_standard_program(path: str) -> bool:
    return matches(path, STANDARD_PROGRAM_PATTERNS, True)


# --- command targets --------------------------------------------------------------------------

EXEC_EXTENSIONS = (
    "exe|dll|sys|scr|com|pif|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|ps1|msi|cpl|jar|py|ocx"
)
_QUOTED = re.compile(r'^\s*"([^"]{1,1024})"')
# An unquoted path up to the first executable extension (spaces allowed: `C:\Program Files\x.exe`).
_UNQUOTED = re.compile(
    r"(?:[A-Za-z]:|%[A-Za-z0-9_()]{1,32}%|\\SystemRoot|\\\?\?\\[A-Za-z]:|System32|SysWOW64)"
    r"[\\/][^\"\r\n]{0,512}?\.(?:" + EXEC_EXTENSIONS + r")(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_NAME_PREFIX = re.compile(r"^[^\\/:\"]{1,256}:\s+(?=\S)")  # Plaso's `name: value` run entries


def windows_target(command: str, *, named: bool = False) -> str | None:
    """The program a Windows command line / ImagePath / Run value starts, as written (not
    normalised), or None. `named`: the text is a Plaso `name: value` run entry."""
    text = command[:2048]
    if named:
        text = _NAME_PREFIX.sub("", text, count=1)
    quoted = _QUOTED.match(text)
    if quoted:
        return quoted.group(1)
    found = _UNQUOTED.search(text)
    if found:
        return found.group(0)
    first = text.strip().split(" ", 1)[0]
    return first or None


_QUOTED_ANY = re.compile(r'"([^"]{1,1024})"')
_EXEC_SUFFIX = re.compile(r"\.(?:" + EXEC_EXTENSIONS + r")$", re.IGNORECASE)
MAX_TARGETS = 8


def windows_targets(command: str, *, named: bool = False) -> list[str]:
    """Every program path a Windows command line names, as written: the program it starts, then
    unquoted paths up to an executable extension and quoted ones ending in one (an argument such
    as the DLL of `rundll32.exe <path>.dll,Run`); at most `MAX_TARGETS`."""
    text = command[:2048]
    found: list[str] = []
    first = windows_target(text, named=named)
    if first:
        found.append(first)
    for match in _UNQUOTED.finditer(text):
        found.append(match.group(0))
    for match in _QUOTED_ANY.finditer(text):
        if _EXEC_SUFFIX.search(match.group(1).strip()):
            found.append(match.group(1))
    return list(dict.fromkeys(found))[:MAX_TARGETS]


_SHELLS = frozenset(
    {"sh", "bash", "dash", "zsh", "ksh", "python", "python3", "perl", "nohup", "env", "exec"}
)


def linux_target(command: str) -> str | None:
    """The program a cron / shell command runs (the first token, or the first non-option token
    after a shell or interpreter); None when it is not an absolute path."""
    tokens = command[:2048].split()
    i = 0
    while i < len(tokens):
        token = tokens[i].strip("'\"")
        base = token.rsplit("/", 1)[-1]
        if base in _SHELLS:
            i += 1
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 1
            continue
        return token if token.startswith("/") else None
    return None


__all__ = [
    "CLEAN_SYSTEM_EXCLUSIONS",
    "ENV_TABLE",
    "EXEC_EXTENSIONS",
    "LINUX_CLASSES",
    "LINUX_EXCLUSIONS",
    "STANDARD_PROGRAM_PATTERNS",
    "STARTUP_PATTERNS",
    "TASK_PATTERNS",
    "WINDOWS_CLASSES",
    "WINDOWS_EXCLUSIONS",
    "OsFamily",
    "excluded",
    "expand",
    "family_of",
    "is_standard_program",
    "is_startup",
    "is_task",
    "linux_target",
    "matches",
    "normalize",
    "user_writable_class",
    "windows_path",
    "windows_target",
    "windows_targets",
]
