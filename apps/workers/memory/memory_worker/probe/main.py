"""Probe command line (tool uid only): `identify` or `run <plugin>` on one image.

    python -I -s -B -m memory_worker.probe identify --image I --symbols S --out O [--os-hint H]
    python -I -s -B -m memory_worker.probe run <plugin> --image I --symbols S --out O --max-rows N

The analyzer starts it with cwd = the root-owned, read-only input dir and a reduced env
(`PATH`, `TMPDIR` = its out dir, `XDG_CACHE_HOME` = `<out>/cache` seeded with the store's
identifier cache, `HOME` = `XDG_CONFIG_HOME` = /nonexistent). Outputs, both in `--out`:
- stdout (`rows.jsonl`, created by root): one JSON object per row, `{"_truncated": true}` last
  when the cap stopped the grid; nothing else ever reaches it (Python's stdout is pointed at
  stderr before Volatility is imported);
- `status.json`, one object: `status` (`ok` / `failed` / `unsupported`), `error` (exception
  class name only, never a message that may quote image bytes), `rows`, `truncated`, the
  audit-hook counts, the offline / path facts, and `identify` or the plugin's ISF and layers.

Exit codes: 0 ok, 3 unsupported (a requirement Volatility cannot satisfy), 4 failed, 2 usage.
A plugin name outside the allow-list is refused before Volatility is imported.
"""

import argparse
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO

from cyberlab_jobs.memory import OsHint

from memory_worker.probe.guard import GUARD
from memory_worker.probe.plugins import UnknownPlugin, spec_for

STATUS = "status.json"
EXIT_OK, EXIT_USAGE, EXIT_UNSUPPORTED, EXIT_FAILED = 0, 2, 3, 4
MAX_ROWS_CEILING = 1_000_000


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="memory_worker.probe")
    sub = parser.add_subparsers(dest="mode", required=True)
    for mode in ("identify", "run"):
        p = sub.add_parser(mode)
        if mode == "run":
            p.add_argument("plugin")
            p.add_argument("--max-rows", type=int, required=True)
        else:
            p.add_argument("--os-hint", choices=[h.value for h in OsHint], default="auto")
        p.add_argument("--image", type=Path, required=True)
        p.add_argument("--symbols", type=Path, required=True)
        p.add_argument("--out", type=Path, required=True)
    return parser


def _take_stdout() -> TextIO:
    """The rows stream: a private handle on fd 1; fd 1 itself then points at stderr, so a
    stray print in a library can never inject a row."""
    rows = os.fdopen(os.dup(1), "w", encoding="ascii", buffering=1024 * 1024)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    return rows


def _write_status(out: Path, status: dict[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    dir_fd = os.open(out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(STATUS, flags, 0o600, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(json.dumps(status, ensure_ascii=True, allow_nan=False, default=str) + "\n")


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    if not (args.image.is_absolute() and args.symbols.is_absolute() and args.out.is_absolute()):
        print("probe paths must be absolute", file=sys.stderr)
        return EXIT_USAGE
    spec = None
    if args.mode == "run":
        try:
            spec = spec_for(args.plugin)
        except UnknownPlugin:
            print("plugin outside the allow-list", file=sys.stderr)
            return EXIT_USAGE
        if not 0 < args.max_rows <= MAX_ROWS_CEILING:
            return EXIT_USAGE
    rows = _take_stdout()
    status: dict[str, Any] = {"status": "failed", "error": None, "rows": 0, "truncated": False}
    code = EXIT_FAILED
    writer = None
    unsatisfied: Callable[[BaseException], bool] = lambda _exc: False  # noqa: E731
    try:
        from memory_worker.probe import vol  # Volatility is imported here, never earlier

        unsatisfied = vol.unsatisfied
        status.update(vol.configure(args.symbols))
        if spec is None:
            status["identify"] = vol.identify(args.image, OsHint(args.os_hint))
        else:
            from memory_worker.probe.encode import Encoder, RowWriter

            writer = RowWriter(rows, [], args.max_rows, Encoder(vol.vol_types()))
            vol.run_plugin(spec, args.image, args.symbols, writer, status)
        status["status"], code = "ok", EXIT_OK
    except Exception as exc:  # noqa: BLE001 - mapped to a status, never re-raised
        status["error"] = type(exc).__name__[:64]
        if unsatisfied(exc):
            status["status"], code = "unsupported", EXIT_UNSUPPORTED
    finally:
        if writer is not None:
            status["rows"] = writer.rows
            status["truncated"] = writer.truncated
        status["audit"] = GUARD.snapshot()
        rows.flush()
        rows.close()
        _write_status(args.out, status)
    return code


__all__ = ["EXIT_FAILED", "EXIT_OK", "EXIT_UNSUPPORTED", "EXIT_USAGE", "STATUS", "main"]
