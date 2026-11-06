"""`heuristic:mem_masquerade@1`: look-alike names of Windows core processes, and core names
running from outside their directory.

- A name at edit distance `MIN_DISTANCE`..`MAX_DISTANCE` from a core name (`scvhost.exe`,
  `lsas.exe`, `svch0st.exe`), except the real core names and the constant list of legitimate
  Windows binaries that happen to be that close (`lsaiso.exe`, `sihost.exe`, ...).
- A core name whose image directory (drive or device prefix removed, compared exactly) is not
  its expected one (`\\Windows\\System32\\` or `\\Windows\\SysWOW64\\`; `explorer.exe` lives in
  `\\Windows\\`).
"""

import re

from memory_worker.detections.base import Context, Finding, alive, refs
from memory_worker.detections.mask import excerpt
from memory_worker.view import MemoryView

MIN_DISTANCE = 1
MAX_DISTANCE = 2
SYSTEM_DIRS = ("\\windows\\system32\\", "\\windows\\syswow64\\")
# Lower-case core name -> the directories its image may live in (lower case, exact).
CORE_DIRS: dict[str, tuple[str, ...]] = {
    "smss.exe": SYSTEM_DIRS,
    "csrss.exe": SYSTEM_DIRS,
    "wininit.exe": SYSTEM_DIRS,
    "winlogon.exe": SYSTEM_DIRS,
    "services.exe": SYSTEM_DIRS,
    "lsass.exe": SYSTEM_DIRS,
    "svchost.exe": SYSTEM_DIRS,
    "spoolsv.exe": SYSTEM_DIRS,
    "taskhostw.exe": SYSTEM_DIRS,
    "explorer.exe": ("\\windows\\", "\\windows\\syswow64\\"),
}
# Targets of the look-alike rule (short names such as dwm.exe are left out: too many
# unrelated names sit within two edits of them).
LOOKALIKE_TARGETS = tuple(CORE_DIRS)
# Legitimate Windows binaries within two edits of a core name.
LOOKALIKE_EXCLUSIONS = frozenset(
    {
        "lsaiso.exe",  # Credential Guard (near lsass.exe)
        "sihost.exe",  # shell infrastructure host (near svchost.exe)
        "iexplore.exe",  # Internet Explorer (near explorer.exe)
        "taskhost.exe",  # Windows 7 task host (near taskhostw.exe)
        "taskhostex.exe",  # Windows 8 task host (near taskhostw.exe)
        "lsm.exe",  # Windows 7 local session manager
    }
)
CONFIDENCE_NAME = 0.6
CONFIDENCE_PATH = 0.6

DRIVE = re.compile(r"^[a-z]:(?=\\)")
DEVICE = re.compile(r"^\\device\\harddiskvolume\d{1,3}(?=\\)")
LONG_PREFIXES = ("\\??\\", "\\\\?\\")
SYSTEMROOT = "\\systemroot\\"


def distance(a: str, b: str, bound: int = MAX_DISTANCE) -> int:
    """Levenshtein distance, or `bound + 1` once it exceeds `bound` (names are <= 64 chars)."""
    if abs(len(a) - len(b)) > bound:
        return bound + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        if min(current) > bound:
            return bound + 1
        previous = current
    return previous[-1]


def directory(path: str) -> str:
    """Lower-case directory of a Windows image path, drive / device prefix removed, with a
    trailing backslash (`C:\\Windows\\System32\\x.exe` -> `\\windows\\system32\\`)."""
    value = path.strip().strip('"').replace("/", "\\").lower()
    for prefix in LONG_PREFIXES:
        if value.startswith(prefix):
            value = value[len(prefix) :]
    if DRIVE.match(value):
        value = value[2:]
    elif (device := DEVICE.match(value)) is not None:
        value = value[device.end() :]
    if value.startswith(SYSTEMROOT):
        value = "\\windows\\" + value[len(SYSTEMROOT) :]
    return value.rsplit("\\", 1)[0] + "\\" if "\\" in value else ""


def _lookalike(name: str) -> tuple[str, int] | None:
    if name in CORE_DIRS or name in LOOKALIKE_EXCLUSIONS:
        return None
    best: tuple[str, int] | None = None
    for core in LOOKALIKE_TARGETS:
        d = distance(name, core)
        if MIN_DISTANCE <= d <= MAX_DISTANCE and (best is None or d < best[1]):
            best = (core, d)
    return best


def detect(view: MemoryView, ctx: Context) -> list[Finding]:
    if view.os != "windows":
        return []
    out: list[Finding] = []
    for procs in ctx.by_pid.values():
        for proc in procs:
            if not alive(proc):
                continue
            name = proc.name.lower()
            if (near := _lookalike(name)) is not None:
                core, d = near
                out.append(
                    Finding(
                        type="mem_name_similar_to_core",
                        severity="medium",
                        confidence=CONFIDENCE_NAME,
                        values={
                            "pid": proc.pid,
                            "name": excerpt(proc.name, 64),
                            "core": core,
                            "distance": d,
                        },
                        key=f"{proc.pid}|{name}",
                        pid=proc.pid,
                        refs=refs([f"pid:{proc.pid}"]),
                        attributes={"pid": proc.pid, "core_name": core, "edit_distance": d},
                    )
                )
            dirs = CORE_DIRS.get(name)
            if dirs is None or not proc.image_path or directory(proc.image_path) in dirs:
                continue
            out.append(
                Finding(
                    type="mem_core_name_unexpected_path",
                    severity="medium",
                    confidence=CONFIDENCE_PATH,
                    values={
                        "pid": proc.pid,
                        "name": excerpt(proc.name, 64),
                        "path": excerpt(proc.image_path, 300),
                        "expected": " or ".join(dirs),
                    },
                    key=f"{proc.pid}|path",
                    pid=proc.pid,
                    refs=refs([f"pid:{proc.pid}"]),
                    attributes={"pid": proc.pid, "image_path": excerpt(proc.image_path, 255)},
                )
            )
    return out
