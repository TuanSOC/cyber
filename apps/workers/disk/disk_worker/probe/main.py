"""Probe command line (tool uid only): one stage on one image per process.

    python -I -s -B -m disk_worker.probe <stage> <input/<name>.json>

`<stage>` is one of `verify`, `layout`, `walk`, `collect`, `scan`, `extract`. Every other
argument comes from the root-written JSON in the read-only `input/` dir (never from argv
strings built from image data): `image` (`format`, `paths`, `max_media`), `out` (the stage's
fresh out dir) and the stage's own keys.

Outputs, all in `out` (created `O_EXCL | O_NOFOLLOW`):
- the stage's JSONL (`partitions.jsonl`, `files.jsonl` + `hashes.jsonl`, `collected.jsonl`
  and `artifacts/`, `hits.jsonl`, `export/<n>`);
- `status.json`: `status` (`ok` / `failed` / `unsupported`), `error` (exception class name
  only, never a message that may quote image bytes), `error_code` (a contract code or null),
  `reason`, `rows`, `truncated`, `counts`, `facts` (stage-specific), `audit` (the hook's
  refusal counts).

Exit codes: 0 ok, 2 usage, 3 unsupported (the image or partition is refused), 4 failed.
"""

import os
import sys
from pathlib import Path
from typing import Any

from disk_worker.probe import rows
from disk_worker.probe.guard import GUARD

EXIT_OK, EXIT_USAGE, EXIT_UNSUPPORTED, EXIT_FAILED = 0, 2, 3, 4
STAGES = ("verify", "layout", "walk", "collect", "scan", "extract")
MiB = 1024**2
# Status / error codes the probe may name; root accepts nothing else.
PROBE_ERROR_CODES = frozenset(
    {
        "unsupported_disk_format",
        "disk_parse_failed",
        "walk_memory",
        "engine_unavailable",
        "disk_export_not_allowed",
    }
)


def _take_stdout() -> None:
    """Nothing a library prints can reach a file root reads: stdout goes to stderr."""
    os.dup2(2, 1)
    sys.stdout = sys.stderr


def _layout(img: Any, reader: Any, out: Path, args: dict[str, Any], status: dict[str, Any]) -> None:
    from disk_worker.probe import layout  # noqa: PLC0415

    with rows.RowWriter(
        out, "partitions.jsonl", max_rows=int(args["max_partitions"]), max_bytes=16 * MiB
    ) as writer:
        for row in layout.run(img, reader, args):
            writer.write(row)
        status["rows"], status["truncated"] = writer.rows, writer.truncated
    status["facts"] = {"media_size": reader.size, "sector_size": reader.sector_size}
    handle = getattr(reader, "handle", None)
    if handle is not None:
        from disk_worker.probe import verify  # noqa: PLC0415

        status["facts"].update(verify.stored_hashes(handle))


def _walk(img: Any, out: Path, args: dict[str, Any], status: dict[str, Any]) -> None:
    from disk_worker.probe.tsk import Fs  # noqa: PLC0415
    from disk_worker.probe.walk import WalkArgs, Walker  # noqa: PLC0415

    fs = Fs(img, int(args["offset"]), str(args["family"]))
    wargs = WalkArgs(
        max_rows=int(args["max_rows"]),
        max_bytes=int(args["max_bytes"]),
        max_dir_entries=int(args["max_dir_entries"]),
        max_streams=int(args["max_streams"]),
        hash_max_file_bytes=int(args["hash_max_file_bytes"]),
        hash_budget_bytes=int(args["hash_budget_bytes"]),
        deadline_s=float(args["deadline_s"]),
    )
    with (
        rows.RowWriter(
            out, "files.jsonl", max_rows=wargs.max_rows, max_bytes=wargs.max_bytes
        ) as files,
        rows.RowWriter(
            out, "hashes.jsonl", max_rows=wargs.max_rows, max_bytes=wargs.max_bytes // 4
        ) as hashes,
    ):
        walker = Walker(fs, wargs, files)
        stats = walker.run()
        walker.hash_pending(hashes)
        status["rows"] = files.rows
    status["truncated"] = stats.truncated
    status["reason"] = stats.reason
    status["counts"] = stats.counts()
    status["facts"] = {"fs_type": fs.fs_type}


def _collect(img: Any, out: Path, args: dict[str, Any], status: dict[str, Any]) -> None:
    from disk_worker.probe import collect  # noqa: PLC0415
    from disk_worker.probe.tsk import Fs  # noqa: PLC0415

    fs = Fs(img, int(args["offset"]), str(args["family"]))
    with rows.RowWriter(
        out, "collected.jsonl", max_rows=len(args["items"]) + 1, max_bytes=64 * MiB
    ) as manifest:
        stats = collect.collect(fs, out, args, manifest)
        status["rows"] = manifest.rows
    status["truncated"], status["reason"] = stats.truncated, stats.reason
    status["counts"] = stats.counts()


def _extract(img: Any, out: Path, args: dict[str, Any], status: dict[str, Any]) -> None:
    from disk_worker.probe import collect  # noqa: PLC0415
    from disk_worker.probe.tsk import Fs  # noqa: PLC0415

    fs = Fs(img, int(args["offset"]), str(args["family"]))
    status["facts"] = collect.extract(fs, out, args)


def _scan(img: Any, out: Path, args: dict[str, Any], status: dict[str, Any]) -> None:
    from disk_worker.probe import scan_stage  # noqa: PLC0415

    with rows.RowWriter(
        out, "hits.jsonl", max_rows=int(args["max_rows"]), max_bytes=128 * MiB
    ) as hits:
        status["counts"] = scan_stage.run(img, args, hits.write)
        status["rows"], status["truncated"] = hits.rows, hits.truncated


def _verify(opened: Any, args: dict[str, Any], status: dict[str, Any]) -> None:
    from disk_worker.probe import verify  # noqa: PLC0415

    reader = opened.reader
    handle = getattr(reader, "handle", None)
    if handle is None:
        raise ValueError("verify runs on EWF images only")
    status["facts"] = verify.verify(reader.read, reader.size, handle, float(args["deadline_s"]))
    status["facts"]["sector_size"] = reader.sector_size


def _engines() -> None:
    """Import every native engine before the audit hook goes in."""
    import pyewf  # noqa: F401, PLC0415
    import pytsk3  # noqa: F401, PLC0415


def run(stage: str, args: dict[str, Any], status: dict[str, Any]) -> int:
    from disk_worker.probe import collect, image  # noqa: PLC0415
    from disk_worker.probe.tsk import EngineMissing  # noqa: PLC0415

    out = Path(args["out"])
    try:
        opened = image.open_image(args["image"])
    except image.ImageError as exc:
        status.update(status="unsupported", error_code=exc.code, reason=exc.reason)
        return EXIT_UNSUPPORTED
    try:
        if stage == "verify":
            _verify(opened, args, status)
        elif stage == "layout":
            _layout(opened.img, opened.reader, out, args, status)
        elif stage == "walk":
            _walk(opened.img, out, args, status)
        elif stage == "collect":
            _collect(opened.img, out, args, status)
        elif stage == "scan":
            _scan(opened.img, out, args, status)
        else:
            _extract(opened.img, out, args, status)
    except collect.Refused as exc:
        status.update(status="failed", error_code="disk_export_not_allowed", reason=exc.reason)
        return EXIT_FAILED
    except EngineMissing:
        status.update(status="failed", error="EngineMissing", error_code="engine_unavailable")
        return EXIT_FAILED
    except MemoryError:
        status.update(status="failed", error="MemoryError", error_code="walk_memory")
        return EXIT_FAILED
    finally:
        opened.close()
    status["status"] = "ok"
    return EXIT_OK


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] not in STAGES:
        print("usage: disk_worker.probe <stage> <args.json>", file=sys.stderr)
        return EXIT_USAGE
    stage, args_path = argv[0], Path(argv[1])
    try:
        args = rows.read_args(args_path)
        out = Path(args["out"])
    except (OSError, ValueError, KeyError):
        print("unreadable stage arguments", file=sys.stderr)
        return EXIT_USAGE
    if not (args_path.is_absolute() and out.is_absolute()):
        return EXIT_USAGE
    _take_stdout()
    status: dict[str, Any] = {
        "stage": stage,
        "status": "failed",
        "error": None,
        "error_code": None,
        "reason": None,
        "rows": 0,
        "truncated": False,
        "counts": {},
        "facts": {},
    }
    code = EXIT_FAILED
    try:
        _engines()
        GUARD.install()
        code = run(stage, args, status)
    except Exception as exc:  # noqa: BLE001 - mapped to a status, never re-raised
        status["error"] = type(exc).__name__[:64]
        if isinstance(exc, ImportError):
            status["error_code"] = "engine_unavailable"
        code = EXIT_FAILED
    finally:
        if status["error_code"] not in PROBE_ERROR_CODES:
            status["error_code"] = None
        status["audit"] = GUARD.snapshot()
        rows.write_status(out, status)
    return code


__all__ = ["EXIT_FAILED", "EXIT_OK", "EXIT_UNSUPPORTED", "EXIT_USAGE", "STAGES", "main"]
