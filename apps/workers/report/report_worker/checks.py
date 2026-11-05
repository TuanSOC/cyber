"""Output checks before upload (the trusted ingest re-checks magic and size and re-hashes).

- PDF: starts with `%PDF-`, 1 … `MAX_ARTIFACT_BYTES`, 1 … `MAX_PAGES` pages (RT1);
- HTML / Markdown: valid UTF-8 (strict), 1 … `MAX_ARTIFACT_BYTES`; HTML starts with the
  doctype the template writes.

The artifact is read by root only through `cyberlab_worker.sandbox.open_output` (single
name in out/, `O_NOFOLLOW`, regular file) and copied into the root-owned job dir, so a
compromised render cannot make root read or upload anything else.
"""

import codecs
import contextlib
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from cyberlab_jobs.report import MAX_ARTIFACT_BYTES, MAX_PAGES
from cyberlab_worker import sandbox
from cyberlab_worker.errors import JobFailed

PDF_MAGIC = b"%PDF-"
HTML_PREFIX = b"<!DOCTYPE html>"
CHUNK = 1024 * 1024
OUTPUT_NAMES = {"pdf": "report.pdf", "html": "report.html", "md": "report.md"}
META_NAME = "render.json"
MAX_META_BYTES = 4096


@dataclass(frozen=True)
class Artifact:
    path: Path
    sha256: str
    size: int


def copy_checked(dirs: sandbox.JobDirs, fmt: str, dest: Path) -> Artifact:
    """Copy out/<artifact> to the root-owned `dest`, checking it on the way."""
    digest = hashlib.sha256()
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    size = 0
    head = b""
    with contextlib.ExitStack() as stack:
        try:
            f = stack.enter_context(sandbox.open_output(dirs, OUTPUT_NAMES[fmt]))
        except (OSError, ValueError) as exc:
            raise JobFailed("invalid_output", "artifact missing or not a regular file") from exc
        out = stack.enter_context(open(dest, "xb"))
        while chunk := f.read(CHUNK):
            size += len(chunk)
            if size > MAX_ARTIFACT_BYTES:
                raise JobFailed("too_large", "artifact over the cap")
            if len(head) < 16:
                head = (head + chunk)[:16]
            if fmt != "pdf":
                try:
                    decoder.decode(chunk)
                except UnicodeDecodeError as exc:
                    raise JobFailed("invalid_output", "artifact is not UTF-8") from exc
            digest.update(chunk)
            out.write(chunk)
    os.chmod(dest, 0o400)
    if size == 0:
        raise JobFailed("invalid_output", "empty artifact")
    if fmt == "pdf" and not head.startswith(PDF_MAGIC):
        raise JobFailed("invalid_output", "not a PDF")
    if fmt != "pdf":
        try:
            decoder.decode(b"", final=True)
        except UnicodeDecodeError as exc:
            raise JobFailed("invalid_output", "artifact is not UTF-8") from exc
    if fmt == "html" and not head.startswith(HTML_PREFIX):
        raise JobFailed("invalid_output", "not the template's HTML")
    return Artifact(dest, digest.hexdigest(), size)


def check_pages(fmt: str, pages: object) -> int | None:
    """The page count the render reported (PDF only): an int in 1 … MAX_PAGES."""
    if fmt != "pdf":
        return None
    if not isinstance(pages, int) or isinstance(pages, bool) or pages < 1:
        raise JobFailed("invalid_output", "no page count")
    if pages > MAX_PAGES:
        raise JobFailed("too_many_pages")
    return pages


def check_bytes(fmt: str, data: bytes, pages: int | None) -> None:
    """The render subprocess's own check of what it is about to write."""
    if not data or len(data) > MAX_ARTIFACT_BYTES:
        raise JobFailed("too_large" if data else "invalid_output")
    if fmt == "pdf":
        if not data.startswith(PDF_MAGIC):
            raise JobFailed("invalid_output")
        check_pages(fmt, pages)
    else:
        data.decode("utf-8")
