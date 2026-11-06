"""Names and paths from the image (pure Python; used by the probe, re-checked by root).

Display names (`display_name`, `join_path`):
- TSK hands names over as bytes; they are decoded as UTF-8 with replacement (`lossy` set when
  the bytes were not valid UTF-8);
- control characters (C0, DEL) are escaped as `\\xNN`, so every name and path is printable and
  single-line (the contract refuses control characters, never sees them);
- a name is cut to 1 024 UTF-8 bytes, a path to 4 096 on a UTF-8 boundary with `truncated`
  set (64 levels of 255-character names reach about 49 KB: such rows are valid, RT13).

Mirrored-tree names (`sanitize_relative`, RT31), used by `collect` for the files it writes
under `out/artifacts/p<i>/` (the tree Plaso reads):
- on a case-insensitive file system a component found in `CANONICAL` (casefolded) takes its
  canonical spelling, so Plaso's preprocessors find `Windows/System32/config/SYSTEM`,
  `Users/<name>/NTUSER.DAT`, ...;
- every other component is reduced to `[A-Za-z0-9 ._-]`: each run of other characters becomes
  `_`, and a component that changed gets `_` plus 6 hex digits of the sha256 of the original
  component (so `José` and `Jos?` stay distinct);
- at most 255 bytes per component (a longer one is cut and also gets the hash suffix);
- a component that is empty or made only of dots is refused (`UnsafeName`), whatever it came
  from; `.` / `..` can never reach the file system.
The original path always comes back through `collected.jsonl`.
"""

import hashlib
import re

MAX_NAME_BYTES = 1024
MAX_PATH_BYTES = 4096
MAX_COMPONENT_BYTES = 255
MAX_DEPTH = 64
_SAFE = re.compile(r"[A-Za-z0-9 ._-]+")
_UNSAFE_RUN = re.compile(r"[^A-Za-z0-9 ._-]+")
_SUFFIX_HEX = 6

# Casefolded component -> the spelling Plaso's preprocessors and parsers expect (applied on
# NTFS / FAT / exFAT only; ext names are case-sensitive and kept as they are). Every value is
# a fixed string from this table, never derived from the image.
CANONICAL: dict[str, str] = {
    c.casefold(): c
    for c in (
        "Windows",
        "System32",
        "SysWOW64",
        "config",
        "winevt",
        "Logs",
        "Prefetch",
        "AppCompat",
        "Programs",
        "Tasks",
        "Users",
        "AppData",
        "Local",
        "Roaming",
        "LocalLow",
        "Microsoft",
        "Recent",
        "Start Menu",
        "Startup",
        "Google",
        "Chrome",
        "User Data",
        "Default",
        "Mozilla",
        "Firefox",
        "Profiles",
        "Edge",
        "History",
        "NTUSER.DAT",
        "UsrClass.dat",
        "SYSTEM",
        "SOFTWARE",
        "DEFAULT",
        "Amcache.hve",
        "$Recycle.Bin",
        "$MFT",
        "$LogFile",
        "$UsnJrnl",
        "$Extend",
    )
}


class UnsafeName(ValueError):
    """A component that cannot be written safely (empty, only dots, nothing left)."""


def escape_controls(text: str) -> str:
    out = []
    for ch in text:
        code = ord(ch)
        out.append(f"\\x{code:02x}" if code < 0x20 or code == 0x7F else ch)
    return "".join(out)


def cut_utf8(text: str, limit: int) -> tuple[str, bool]:
    """`text` cut to at most `limit` UTF-8 bytes on a character boundary."""
    raw = text.encode("utf-8")
    if len(raw) <= limit:
        return text, False
    return raw[:limit].decode("utf-8", "ignore"), True


def display_name(raw: bytes) -> tuple[str, bool]:
    """(printable name, lossy): UTF-8 with replacement, controls escaped, <= 1 024 bytes."""
    try:
        text = raw.decode("utf-8")
        lossy = False
    except UnicodeDecodeError:
        text = raw.decode("utf-8", "replace")
        lossy = True
    name, _ = cut_utf8(escape_controls(text), MAX_NAME_BYTES)
    return name, lossy


def join_path(parent: str, name: str) -> str:
    """The full (uncut) path of `name` in `parent` (`/` is the file system root)."""
    return f"/{name}" if parent in ("", "/") else f"{parent}/{name}"


def bounded_path(path: str) -> tuple[str, bool]:
    """(path <= 4 096 UTF-8 bytes, truncated)."""
    return cut_utf8(path, MAX_PATH_BYTES)


def _suffix(original: str) -> str:
    digest = hashlib.sha256(original.encode("utf-8", "surrogatepass")).hexdigest()
    return "_" + digest[:_SUFFIX_HEX]


def sanitize_component(component: str, case_insensitive: bool) -> str:
    if case_insensitive:
        canonical = CANONICAL.get(component.casefold())
        if canonical is not None:
            return canonical
    reduced = _UNSAFE_RUN.sub("_", component)
    changed = reduced != component
    limit = MAX_COMPONENT_BYTES - len(_suffix(component))
    if changed or len(reduced.encode()) > MAX_COMPONENT_BYTES:
        reduced = reduced.encode()[:limit].decode("ascii", "ignore") + _suffix(component)
    if not reduced or set(reduced) <= {"."}:
        raise UnsafeName("an empty or all-dot component")
    return reduced


def sanitize_relative(path: str, case_insensitive: bool) -> list[str]:
    """The original path (`/a/b/c`) as safe components for the mirrored tree."""
    parts = [p for p in path.split("/") if p != ""]
    if not parts:
        raise UnsafeName("an empty path")
    if len(parts) > MAX_DEPTH:
        raise UnsafeName("deeper than the walk's depth cap")
    return [sanitize_component(p, case_insensitive) for p in parts]


def with_collision_suffix(component: str, n: int) -> str:
    """The `n`-th alternative of a component already taken (`name_c2`, keeps the extension
    so Plaso's parser selection by name still applies)."""
    stem, dot, ext = component.rpartition(".")
    if not dot or not stem:
        stem, ext, dot = component, "", ""
    tag = f"_c{n}"
    stem = stem.encode()[: MAX_COMPONENT_BYTES - len(tag) - len(dot + ext)].decode(
        "ascii", "ignore"
    )
    return f"{stem}{tag}{dot}{ext}"


def is_safe_relative(target: str) -> bool:
    """Root's re-check of a target the probe reports: relative, `/`-separated, every
    component safe (from the table or the reduced alphabet), no `.` / `..` / empty part."""
    if not target or target.startswith("/") or len(target.encode()) > MAX_PATH_BYTES:
        return False
    canonical = set(CANONICAL.values())
    for part in target.split("/"):
        if not part or set(part) <= {"."} or len(part.encode()) > MAX_COMPONENT_BYTES:
            return False
        if part not in canonical and not _SAFE.fullmatch(part):
            return False
    return True


__all__ = [
    "CANONICAL",
    "MAX_DEPTH",
    "MAX_NAME_BYTES",
    "MAX_PATH_BYTES",
    "UnsafeName",
    "bounded_path",
    "cut_utf8",
    "display_name",
    "escape_controls",
    "is_safe_relative",
    "join_path",
    "sanitize_component",
    "sanitize_relative",
    "with_collision_suffix",
]
