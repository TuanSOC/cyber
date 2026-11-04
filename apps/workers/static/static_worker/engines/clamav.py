"""ClamAV (`clamscan`) as the tool uid, with explicit scan limits (RT2).

Exit codes: 0 nothing found, 1 something found, 2 error (no DB, unreadable file, ...).
A limit hit (`Heuristics.Limits.Exceeded.*`, encrypted content) or an archive pre-check
showing more content than the limits allow becomes `av_not_fully_scanned`: never a silent
"clean". An error exit or a timeout still keeps the matches already printed.
"""

from collections.abc import Mapping
from pathlib import Path

from cyberlab_jobs.static import SignatureMatch
from cyberlab_worker import sandbox
from cyberlab_worker.parsing import clip

from static_worker.config import Engines
from static_worker.engines.workspace import Workspace, read_bounded

MEMORY = 2 * 1024**3  # full DB: ~1.2 GiB resident (README measurements)
MAX_FILESIZE = 64 * 1024**2
MAX_SCANSIZE = 256 * 1024**2
MAX_FILES = 10_000
MAX_RECURSION = 16
OUTPUT = "clamscan.txt"
MAX_OUTPUT = 1024**2
LIMIT_PREFIX = "Heuristics.Limits.Exceeded."
INCOMPLETE_PREFIXES = (LIMIT_PREFIX, "Heuristics.Encrypted.")
DEFAULT_DB = Path("/var/lib/clamav")
DB_SUFFIXES = {".cvd", ".cld", ".cud", ".hdb", ".hsb", ".ndb", ".ldb", ".cdb", ".mdb", ".msb"}
# --max-scantime counts from the scan start, after the DB load (15-20 s with the full DB):
# leave that much headroom below the tool timeout so the limit alert, not the kill, fires.
SCANTIME_HEADROOM_S = 30


def database_present(db: Path) -> bool:
    try:
        paths = [db] if db.is_file() else list(db.iterdir())
    except OSError:
        return False
    return any(p.suffix in DB_SUFFIXES for p in paths)


def argv(engines: Engines, sample: Path, out: Path, seconds: float, size: int) -> list[str]:
    scantime_ms = max(1000, int((seconds - SCANTIME_HEADROOM_S) * 1000))
    return [
        engines.clamscan,
        "--no-summary",
        "--infected",
        "--allmatch=yes",
        f"--tempdir={out}",
        f"--max-filesize={max(MAX_FILESIZE, size + 1)}",
        f"--max-scansize={max(MAX_SCANSIZE, size + 1)}",
        f"--max-files={MAX_FILES}",
        f"--max-recursion={MAX_RECURSION}",
        f"--max-scantime={scantime_ms}",
        "--alert-exceeds-max=yes",
        "--alert-encrypted=yes",
        *(["--database", str(engines.clamav_db)] if engines.clamav_db else []),
        "--",
        str(sample),
    ]


def scan(
    ws: Workspace,
    engines: Engines,
    seconds: float | None,
    *,
    size: int,
    errors: list[str],
    truncated: dict[str, bool],
) -> list[SignatureMatch]:
    db = engines.clamav_db or DEFAULT_DB
    if seconds is None or not database_present(db):
        errors.append("av_unavailable")
        return []
    dirs = ws.engine("clamav")
    returncode: int | None = 0
    try:
        sandbox.run_tool(
            argv(engines, ws.sample, dirs.out, seconds, size),
            dirs,
            timeout_s=seconds,
            stdout_name=OUTPUT,
            memory_bytes=MEMORY,
        )
    except sandbox.ToolTimeout:
        returncode = None
    except sandbox.ToolFailed as exc:
        returncode = exc.returncode
    return outcome(dirs, ws.sample, returncode, errors=errors, truncated=truncated)


def outcome(
    dirs: sandbox.JobDirs,
    sample: Path,
    returncode: int | None,
    *,
    errors: list[str],
    truncated: dict[str, bool],
) -> list[SignatureMatch]:
    """Matches + engine errors for one clamscan run (`returncode` None: timed out).

    0 / 1 is a complete scan. Anything else (2 = error, a signal, a timeout) is not: matches
    already printed are kept and the scan is reported as incomplete (`av_not_fully_scanned`
    with hits, `av_unavailable` / `av_timeout` without).
    """
    matches = parse(dirs, sample, errors=errors, truncated=truncated)
    if returncode in (0, 1):
        return matches
    if returncode is None:
        errors.append("av_timeout")
    elif not matches:
        errors.append("av_unavailable")
    if matches and "av_not_fully_scanned" not in errors:
        errors.append("av_not_fully_scanned")
        truncated["clamav_incomplete"] = True
    return matches


def parse(
    dirs: sandbox.JobDirs, sample: Path, *, errors: list[str], truncated: dict[str, bool]
) -> list[SignatureMatch]:
    """`<sample>: <name> FOUND` lines; anything else (other paths, noise) is ignored."""
    data, capped = read_bounded(dirs, OUTPUT, MAX_OUTPUT)
    prefix = f"{sample}: "
    names: list[str] = []
    incomplete = capped  # an unreadable tail could hide a limit alert
    if capped:
        truncated["clamav_output"] = True
    for raw in data.decode("utf-8", "replace").splitlines():
        if not (raw.startswith(prefix) and raw.endswith(" FOUND")):
            continue
        name = clip(raw[len(prefix) : -len(" FOUND")].strip(), 255)
        if not name or name in names:
            continue
        if name.startswith(INCOMPLETE_PREFIXES):
            incomplete = True
            truncated["clamav_limits"] = True
        if not name.startswith(LIMIT_PREFIX):
            names.append(name)
    if incomplete:
        errors.append("av_not_fully_scanned")
    return [SignatureMatch(engine="clamav", name=name) for name in names]


def exceeds_limits(archive: Mapping[str, int | bool | str]) -> bool:
    """The archive pre-check (tool-uid probe) saw more than clamscan will look at."""
    return bool(
        archive.get("unchecked")
        or archive.get("encrypted")
        or int(archive.get("largest_member", 0)) > MAX_FILESIZE
        or int(archive.get("declared_bytes", 0)) > MAX_SCANSIZE
        or int(archive.get("members", 0)) > MAX_FILES
        or int(archive.get("depth", 0)) > MAX_RECURSION
    )
