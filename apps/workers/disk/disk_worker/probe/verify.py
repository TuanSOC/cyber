"""`verify` (EWF only, probe side): our MD5 / SHA-1 over the whole media vs the stored ones.

- The media is read in 4 MiB chunks through libewf within a soft deadline (root's budget for
  the stage minus a margin): a timeout gives `not_verified`, never a failure (RT6).
- The **stored** values come from `handle.get_hash_value("MD5")` / `("SHA1")` (RT16): status
  `matched` / `mismatch` / `absent` / `not_verified`. libewf zero-fills or passes through a
  chunk with a bad Adler-32 without failing the read, so `absent` means content corruption
  cannot be detected (RT17; the UI says so).
- The media sha256 is computed in the same pass (`ImageInfo.media_sha256`).
- The header values (case number, description, examiner, evidence number, notes, acquiry
  date, acquiry software) are bounded (256 bytes), NUL-free and control-escaped.
"""

import hashlib
import re
import time
from collections.abc import Callable
from typing import Any

from disk_worker.probe import names

CHUNK = 4 * 1024**2
HEADER_VALUES = (
    "case_number",
    "description",
    "examiner_name",
    "evidence_number",
    "notes",
    "acquiry_date",
    "acquiry_software",
    "acquiry_software_version",
)
_HEX = re.compile(r"^[0-9a-f]+$")


def _stored(handle: Any, name: str, length: int) -> str | None:
    try:
        value = handle.get_hash_value(name)
    except (OSError, RuntimeError, TypeError, ValueError, AttributeError):
        return None
    if not value:
        return None
    text = str(value).strip().lower()
    return text if len(text) == length and _HEX.match(text) else None


def header_values(handle: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for key in HEADER_VALUES:
        try:
            value = handle.get_header_value(key)
        except (OSError, RuntimeError, TypeError, ValueError, AttributeError, KeyError):
            continue
        if value is None:
            continue
        raw = value if isinstance(value, bytes) else str(value).encode("utf-8", "replace")
        raw = raw.replace(b"\x00", b"")
        text, _ = names.display_name(raw)
        text, _ = names.cut_utf8(text, 256)
        if text:
            out[key] = text[:256]
    return out


def status_of(
    stored_md5: str | None, stored_sha1: str | None, md5: str | None, sha1: str | None
) -> str:
    if stored_md5 is None and stored_sha1 is None:
        return "absent"
    if md5 is None or sha1 is None:
        return "not_verified"
    if (stored_md5 is not None and stored_md5 != md5) or (
        stored_sha1 is not None and stored_sha1 != sha1
    ):
        return "mismatch"
    return "matched"


def stored_hashes(handle: Any) -> dict[str, Any]:
    """The acquisition-time values only (no media read): `layout` reports them for EWF so the
    header is complete even when `verify` is skipped or killed."""
    return {
        "stored_md5": _stored(handle, "MD5", 32),
        "stored_sha1": _stored(handle, "SHA1", 40),
        "ewf_meta": header_values(handle),
    }


def verify(
    read: Callable[[int, int], bytes],
    size: int,
    handle: Any,
    deadline_s: float,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    stored_md5 = _stored(handle, "MD5", 32)
    stored_sha1 = _stored(handle, "SHA1", 40)
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()  # noqa: S324
    deadline = clock() + deadline_s
    offset = 0
    complete = True
    while offset < size:
        if clock() > deadline:
            complete = False
            break
        chunk = read(offset, min(CHUNK, size - offset))
        if not chunk:
            complete = False
            break
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)
        offset += len(chunk)
    ours = (md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()) if complete else None
    return {
        "media_size": size,
        "bytes_read": offset,
        "stored_md5": stored_md5,
        "stored_sha1": stored_sha1,
        "media_hash_status": status_of(
            stored_md5, stored_sha1, ours[0] if ours else None, ours[1] if ours else None
        ),
        "media_sha256": ours[2] if ours else None,
        "ewf_meta": header_values(handle),
    }


__all__ = ["CHUNK", "HEADER_VALUES", "header_values", "status_of", "stored_hashes", "verify"]
