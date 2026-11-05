"""The render subprocess: `python -I -B -m report_worker.render <format> <in_dir> <out_file>`.

Runs as uid 10004 under the worker-kit sandbox (seccomp without inet / netlink / packet
sockets or io_uring, rlimits, empty environment, root-owned read-only cwd; see
`report_worker.sandbox`). It reads only the root-owned, read-only input dir:

    snapshot.json       the verified snapshot bytes (sha256 checked by the parent)
    manifest.json       the signed manifest bytes, embedded as is
    manifest.sig.json   `ReportSignatureFile`, embedded as is
    job.json            {"format", "sha256", "finalized_at"}

and writes `<out_file>` plus `render.json` ({"pages": n}) next to it. The exit status is
the only other channel (`EXIT_CODES`); nothing else it prints reaches the result.
"""

import errno
import json
import os
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

EXIT_OK = 0
EXIT_RENDERER_ERROR = 1
EXIT_FETCH_BLOCKED = 10
EXIT_TOO_MANY_PAGES = 11
EXIT_TOO_LARGE = 12
EXIT_OOM = 13
EXIT_INVALID_OUTPUT = 14
EXIT_CODES: dict[int, str] = {
    EXIT_RENDERER_ERROR: "renderer_error",
    EXIT_FETCH_BLOCKED: "fetch_blocked",
    EXIT_TOO_MANY_PAGES: "too_many_pages",
    EXIT_TOO_LARGE: "too_large",
    EXIT_OOM: "oom",
    EXIT_INVALID_OUTPUT: "invalid_output",
}
META_NAME = "render.json"


def _write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def render_to(fmt: str, in_dir: Path, out_file: Path) -> None:
    from cyberlab_jobs.report import parse_snapshot

    from report_worker import checks

    job = json.loads((in_dir / "job.json").read_text(encoding="utf-8"))
    if job["format"] != fmt:
        raise ValueError("format mismatch")
    snapshot_bytes = (in_dir / "snapshot.json").read_bytes()
    snapshot = parse_snapshot(snapshot_bytes)
    sha256 = str(job["sha256"])
    pages: int | None = None
    if fmt == "pdf":
        from report_worker import render_pdf

        data, pages = render_pdf.render(
            render_pdf.PdfInputs(
                snapshot=snapshot,
                snapshot_bytes=snapshot_bytes,
                sha256=sha256,
                manifest_bytes=(in_dir / "manifest.json").read_bytes(),
                signature_bytes=(in_dir / "manifest.sig.json").read_bytes(),
                finalized_at=datetime.fromisoformat(job["finalized_at"]),
            )
        )
    elif fmt == "html":
        from report_worker import render_html

        data = render_html.render(snapshot, sha256=sha256, mode="html").encode("utf-8")
    elif fmt == "md":
        from report_worker import render_md

        data = render_md.render(snapshot, sha256=sha256).encode("utf-8")
    else:
        raise ValueError("unknown format")
    checks.check_bytes(fmt, data, pages)
    _write_new(out_file, data)
    _write_new(out_file.parent / META_NAME, json.dumps({"pages": pages}).encode())


def run_guarded(work: Callable[[], object]) -> int:
    """Map what a render raises to the exit status the parent understands."""
    from cyberlab_worker.errors import JobFailed

    try:
        from report_worker.fetch import FetchBlocked
        from report_worker.render_pdf import TooManyPages
    except MemoryError:
        return EXIT_OOM
    try:
        work()
    except FetchBlocked:
        return EXIT_FETCH_BLOCKED
    except TooManyPages:
        return EXIT_TOO_MANY_PAGES
    except MemoryError:
        return EXIT_OOM
    except JobFailed as exc:
        code = {"too_large": EXIT_TOO_LARGE, "too_many_pages": EXIT_TOO_MANY_PAGES}
        return code.get(exc.code, EXIT_INVALID_OUTPUT)
    except OSError as exc:
        # RLIMIT_FSIZE makes a write past the cap fail with EFBIG (SIGXFSZ is ignored
        # by Python).
        return EXIT_TOO_LARGE if exc.errno == errno.EFBIG else EXIT_RENDERER_ERROR
    except Exception:  # noqa: BLE001 - the type is the only thing reported (stderr)
        print(f"render failed: {type(sys.exc_info()[1]).__name__}", file=sys.stderr)
        return EXIT_RENDERER_ERROR
    return EXIT_OK


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        return EXIT_RENDERER_ERROR
    fmt, in_dir, out_file = argv
    return run_guarded(lambda: render_to(fmt, Path(in_dir), Path(out_file)))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
