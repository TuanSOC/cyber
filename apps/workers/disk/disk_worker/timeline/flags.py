"""The fixed Plaso command lines (M9 phase 3; pure, `test_plaso_flags.py` asserts them exactly).

Every flag comes from code and the catalog, never from the image or the job: the only
variable parts are root-chosen paths (the stage's fresh out dir, the sealed mirrored tree),
the stage's RLIMIT_AS (for `--process_memory_limit`) and whether the run assumes UTC.

Both tools run as `/opt/plaso/bin/python -I -m cyberlab_plaso_launch <tool> ...` (the launcher
installs the audit hook and writes `status.json`; RT24). Flag spellings are Plaso's underscore
forms (RT11), PENDING the 3a spike's check against 20261027: a flag the spike finds missing is
dropped here with the reason recorded in the phase file.
"""

from pathlib import Path
from typing import Literal

from cyberlab_jobs.disk import AnalysisProfile, DiskLimits, DiskOs

from disk_worker.timeline.catalog import parser_expression

PLASO_PYTHON = "/opt/plaso/bin/python"
LAUNCHER = "cyberlab_plaso_launch"
EXPORTER = "cyberlab_plaso_export"
STORAGE = "timeline.plaso"
EVENTS = "events.jsonl"
TMP = "tmp"
MIB = 1024**2
MEMORY_MARGIN = 256 * MIB  # `--process_memory_limit` = the stage's RLIMIT_AS minus this
MIN_PROCESS_MEMORY = 256 * MIB
# The event export: psort (`json_line`, no analysis plugins) or, if the 3a spike sees psort
# start a process or a zmq TCP queue under the filter, `cyberlab_plaso_export` (RT11).
ExportTool = Literal["psort", "export"]
EXPORT_TOOL: ExportTool = "psort"


def _python(module: str) -> list[str]:
    return [PLASO_PYTHON, "-I", "-m", module]


def process_memory_limit(limits: DiskLimits) -> int:
    return max(MIN_PROCESS_MEMORY, limits.stages["log2timeline"].rlimit_as - MEMORY_MARGIN)


def log2timeline_argv(
    os: DiskOs,
    profile: AnalysisProfile,
    limits: DiskLimits,
    out: Path,
    source: Path,
    *,
    assume_utc: bool,
) -> list[str]:
    """`log2timeline` on one partition's sealed mirrored tree `source`, writing into `out`."""
    argv = [
        *_python(LAUNCHER),
        "log2timeline",
        "--single_process",
        "--status_view",
        "none",
        "--unattended",
        "--hashers",
        "none",
        "--no_dependencies_check",
        "--archives",
        "none",
        "--vss_stores",
        "none",
    ]
    if profile == "triage":
        # dfVFS decompresses gzip / bzip2 / xz streams whatever the name (RT11).
        argv.append("--skip_compressed_streams")
    argv += [
        "--process_memory_limit",
        str(process_memory_limit(limits)),
        "--parsers",
        parser_expression(os, profile),
        "--temporary_directory",
        str(out / TMP),
        "--logfile",
        str(out / "log2timeline.log.gz"),
        "--storage_file",
        str(out / STORAGE),
    ]
    if assume_utc:
        argv += ["--timezone", "UTC"]
    argv.append(str(source))
    return argv


def export_argv(storage: Path, out: Path, tool: ExportTool = EXPORT_TOOL) -> list[str]:
    """The event export of one storage file into `out/events.jsonl` (no `--analysis`, ever)."""
    if tool == "export":
        return [*_python(EXPORTER), str(storage), str(out / EVENTS)]
    return [
        *_python(LAUNCHER),
        "psort",
        "--status_view",
        "none",
        "--logfile",
        str(out / "psort.log.gz"),
        "-o",
        "json_line",
        "-w",
        str(out / EVENTS),
        str(storage),
    ]


__all__ = [
    "EVENTS",
    "EXPORT_TOOL",
    "LAUNCHER",
    "PLASO_PYTHON",
    "STORAGE",
    "export_argv",
    "log2timeline_argv",
    "process_memory_limit",
]
