"""`strings` mode: printable ASCII and UTF-16LE runs, deduplicated, capped (count + length)."""

import re
from pathlib import Path

from static_worker.probe.common import emit, text

MAX_VALUE = 512  # contract Text512


def _collect(
    data: bytes, pattern: re.Pattern[bytes], encoding: str, limit: int
) -> tuple[list[tuple[int, str, str]], bool]:
    seen: set[str] = set()
    found: list[tuple[int, str, str]] = []
    width = 2 if encoding == "utf16le" else 1
    for match in pattern.finditer(data):
        # Slice instead of match.group(): a 60 MiB run never becomes one giant string.
        raw = data[match.start() : min(match.end(), match.start() + MAX_VALUE * width)]
        value = text(raw.decode("utf-16-le" if width == 2 else "ascii", "replace"), MAX_VALUE)
        if value in seen:
            continue
        if len(found) >= limit:
            return found, True
        seen.add(value)
        found.append((match.start(), value, encoding))
    return found, False


def run(sample: Path, *, max_strings: int, min_length: int) -> None:
    data = sample.read_bytes()
    n = max(1, min(min_length, 64))
    ascii_re = re.compile(rb"[\x20-\x7e\t]{%d,}" % n)
    wide_re = re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}" % n)
    ascii_found, ascii_capped = _collect(data, ascii_re, "ascii", max_strings)
    wide_found, wide_capped = _collect(data, wide_re, "utf16le", max_strings)
    merged = sorted(ascii_found + wide_found)
    for offset, value, encoding in merged[:max_strings]:
        emit({"kind": "string", "value": value, "encoding": encoding, "offset": offset})
    capped = ascii_capped or wide_capped or len(merged) > max_strings
    emit({"kind": "summary", "truncated": {"strings": capped}, "total": len(merged)})
