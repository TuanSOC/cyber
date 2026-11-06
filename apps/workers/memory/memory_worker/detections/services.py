"""`heuristic:mem_service_path@1` (`svcscan`, at most `low`): service binaries under
user-writable directories, and kernel drivers loaded from outside the drivers directory.

A constant exclusion list covers the vendor platform paths every clean image has (Microsoft
Defender runs from `\\ProgramData\\Microsoft\\Windows Defender\\Platform\\`, RT21). Driver
object names (`\\Driver\\Tcpip`, `\\FileSystem\\Ntfs`) are not paths and are skipped.
"""

from collections.abc import Mapping

from memory_worker.detections.base import Context, Finding, refs
from memory_worker.detections.mask import excerpt
from memory_worker.view import MemoryView

# Attribute keys of `service` artifacts (phase-2 normalizer): name, state, start, binary and,
# when reported, type (SERVICE_KERNEL_DRIVER, SERVICE_FILE_SYSTEM_DRIVER, ...).
USER_WRITABLE = ("\\users\\", "\\temp\\", "\\programdata\\", "\\appdata\\")
EXCLUDED_PREFIXES = (
    "\\programdata\\microsoft\\windows defender\\platform\\",
    "\\programdata\\microsoft\\windows defender advanced threat protection\\platform\\",
)
DRIVER_DIRS = ("\\system32\\drivers\\", "\\system32\\driverstore\\filerepository\\")
DRIVER_OBJECT_PREFIXES = ("\\driver\\", "\\filesystem\\")
CONFIDENCE = 0.4


def _binary_path(binary: str) -> str:
    """Lower-case executable path of a service command (quotes and arguments removed)."""
    value = binary.strip().replace("/", "\\")
    if value.startswith('"'):
        value = value[1:].split('"', 1)[0]
    else:
        lowered = value.lower()
        for ext in (".exe", ".sys", ".dll"):
            cut = lowered.find(ext + " ")
            if cut != -1:
                value = value[: cut + len(ext)]
                break
    return value.lower()


def _without_drive(path: str) -> str:
    return path[2:] if len(path) > 2 and path[1] == ":" else path


def _is_driver(attrs: Mapping[str, object], path: str) -> bool:
    kind = attrs.get("type")
    if isinstance(kind, str) and "DRIVER" in kind.upper():
        return True
    return path.endswith(".sys")


def detect(view: MemoryView, ctx: Context) -> list[Finding]:
    del ctx
    if view.os != "windows":
        return []
    out: list[Finding] = []
    for artifact in view.artifacts:
        if artifact.type != "service":
            continue
        attrs = dict(artifact.attributes)
        binary = attrs.get("binary")
        if not isinstance(binary, str) or not binary.strip():
            continue
        path = _binary_path(binary)
        if path.startswith(DRIVER_OBJECT_PREFIXES):
            continue
        # A leading separator, so `System32\drivers\x.sys` (no root) still matches the dirs.
        tail = "\\" + _without_drive(path).lstrip("\\")
        if any(tail.startswith(prefix) for prefix in EXCLUDED_PREFIXES):
            continue
        name = attrs.get("name") if isinstance(attrs.get("name"), str) else "unknown"
        state = attrs.get("state") if isinstance(attrs.get("state"), str) else "state unknown"
        values: dict[str, object] = {
            "service": excerpt(str(name), 64),
            "state": excerpt(str(state), 64),
            "binary": excerpt(binary, 300),
        }
        if _is_driver(attrs, path):
            if any(d in tail for d in DRIVER_DIRS):
                continue
            kind = "mem_driver_unexpected_path"
        else:
            marker = next((m for m in USER_WRITABLE if m in tail), None)
            if marker is None:
                continue
            values["marker"] = marker
            kind = "mem_service_user_writable_path"
        out.append(
            Finding(
                type=kind,
                severity="low",
                confidence=CONFIDENCE,
                values=values,
                key=f"{name}|{path}",
                pid=artifact.pid,
                refs=refs([f"service:{name}", *([f"pid:{artifact.pid}"] if artifact.pid else [])]),
                attributes={"service": str(name)[:64], "binary": excerpt(binary, 255)},
            )
        )
    return out
