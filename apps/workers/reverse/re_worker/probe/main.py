"""Probe command line (tool uid only): one stage per process.

    python -I -s -B -m re_worker.probe analyze   --sample S --loader pe|elf --project P ...
    python -I -s -B -m re_worker.probe decompile --project P --out O --heap N --list L

Root starts it through `sandbox.run_tool` with cwd = the root-owned, read-only input dir and
the stage environment (`engines/spec.py`). Outputs, both in `--out`:
- stdout (`rows.jsonl`, created by root, O_EXCL): one JSON object per row, nothing else ever
  reaches it (fd 1 is taken before the JVM starts and then pointed at stderr, so neither a
  Python library nor the JVM's `System.out` can inject a row);
- `status.json`: `status` (`ok` / `failed`), `error` (an exception class name only, never a
  message that may quote sample bytes), `error_code` / `reason` (fixed tokens), the JVM facts,
  the audit counts, the per-kind `truncated` flags and counts, and the stage's own facts.

Exit codes: 0 ok, 4 failed (the status says why), 2 usage. 3 is never used by the probe: it
is the JVM's `ExitOnOutOfMemoryError` exit code, which root maps to `re_out_of_memory`.
"""

import argparse
import os
import re
import sys
from collections.abc import Callable
from typing import Any, TextIO

from re_worker.probe.guard import GUARD
from re_worker.probe.out import RowWriter, StageFailure, write_status

EXIT_OK, EXIT_USAGE, EXIT_FAILED = 0, 2, 4
SAFE_NAME = re.compile(r"[^A-Za-z0-9_]")
PATH_FLAGS = ("sample", "project", "out", "list", "input")


def _parser() -> argparse.ArgumentParser:
    from re_worker.probe import analyze, decompile

    parser = argparse.ArgumentParser(prog="re_worker.probe")
    sub = parser.add_subparsers(dest="stage", required=True)
    analyze.add_arguments(sub.add_parser("analyze"))
    decompile.add_arguments(sub.add_parser("decompile"))
    return parser


def _take_stdout() -> TextIO:
    """The rows stream: a private handle on fd 1; fd 1 itself then points at stderr."""
    rows = os.fdopen(os.dup(1), "w", encoding="ascii", buffering=1024 * 1024)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    return rows


def error_name(exc: BaseException) -> str:
    """`java.lang.OutOfMemoryError` -> `OutOfMemoryError` (a status-safe token)."""
    name = type(exc).__name__.rsplit(".", 1)[-1]
    name = SAFE_NAME.sub("_", name)[:64]
    return name if name and not name[0].isdigit() else "Error"


def _stage(stage: str) -> tuple[Callable[..., None], Callable[..., dict[str, int]]]:
    if stage == "analyze":
        from re_worker.probe import analyze

        return analyze.run, analyze.caps
    from re_worker.probe import decompile

    return decompile.run, decompile.caps


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    for flag in PATH_FLAGS:
        value = getattr(args, flag, None)
        if value is not None and not value.is_absolute():
            print("probe paths must be absolute", file=sys.stderr)
            return EXIT_USAGE
    run, caps = _stage(args.stage)
    rows = _take_stdout()
    writer = RowWriter(rows, caps(args))
    status: dict[str, Any] = {"status": "failed", "error": None, "jvm_started": False}
    code = EXIT_FAILED
    try:
        run(args, writer, status)
        status["status"], code = "ok", EXIT_OK
    except StageFailure as exc:
        status["error_code"], status["reason"] = exc.code, exc.reason
    except Exception as exc:  # noqa: BLE001 - mapped to a status, never re-raised
        status["error"] = error_name(exc)
    finally:
        try:
            writer.finish()
            rows.close()
        except OSError:  # RLIMIT_FSIZE reached: the rows file is cut, the status says so
            status["truncated"] = {**status.get("truncated", {}), "rows": True}
        status["truncated"] = {**writer.truncated, **status.get("truncated", {})}
        status.setdefault("counts", dict(writer.counts))
        status["audit"] = {**GUARD.snapshot(), **status.pop("child_counts", {})}
        write_status(args.out, status)
    return code


__all__ = ["EXIT_FAILED", "EXIT_OK", "EXIT_USAGE", "error_name", "main"]
