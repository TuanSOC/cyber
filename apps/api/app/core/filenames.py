"""Untrusted evidence filenames: stored as metadata only, never used as paths or keys."""

import re
import unicodedata
from urllib.parse import quote

MAX_FILENAME = 255
FALLBACK = "evidence.bin"

# Control chars, bidi overrides/isolates and other invisible format characters.
_UNSAFE = re.compile(r"[\x00-\x1f\x7f​-‏‪-‮⁦-⁩﻿]")


def sanitize_filename(raw: str) -> str:
    """Keep the basename, drop unsafe characters, cap the length (preserving the extension)."""
    name = unicodedata.normalize("NFC", raw)
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = _UNSAFE.sub("", name).strip().strip(".")
    if not name:
        return FALLBACK
    if len(name) > MAX_FILENAME:
        stem, dot, ext = name.rpartition(".")
        if dot and 0 < len(ext) <= 16:
            name = stem[: MAX_FILENAME - len(ext) - 1] + "." + ext
        else:
            name = name[:MAX_FILENAME]
    return name


def content_disposition(filename: str) -> str:
    """`attachment` header with an ASCII fallback and an RFC 5987 UTF-8 name."""
    safe = sanitize_filename(filename)
    ascii_name = safe.encode("ascii", "ignore").decode().replace('"', "").replace(";", "")
    ascii_name = ascii_name or FALLBACK
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(safe, safe='')}"
