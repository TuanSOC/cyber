"""`capa` / `floss` modes: turn the tool's JSON document into bounded JSON lines.

capa and FLOSS write one JSON document (capa's can be tens of MiB). Parsing that in the root
process could exhaust the worker's memory, so it is parsed here, as the tool uid under the
probe's RLIMIT_AS, and reduced to `capability` / `string` records (one per line, each
re-validated by root against `static.v1`). Root never parses large tool output.
"""

import json
import os
import re
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from static_worker.probe.common import emit, error, text

CAPA_MAX_BYTES = 64 * 1024**2
FLOSS_MAX_BYTES = 32 * 1024**2
ATTACK = re.compile(r"^T\d{4}(\.\d{3})?$")
MBC = re.compile(r"^[A-Z]{1,2}\d{4}(\.[a-z0-9]{3})?$")
FLOSS_MIN_LENGTH = 6
FLOSS_KINDS = {
    "decoded_strings": "floss_decoded",
    "stack_strings": "floss_stack",
    "tight_strings": "floss_tight",
}


def load(path: Path, limit: int, tool: str) -> Any:
    """The tool's document, or None (error already emitted). Regular files only."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        error(f"{tool}_failed", "no output")
        return None
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            error(f"{tool}_failed", "output is not a regular file")
            return None
        data = f.read(limit + 1)
    if len(data) > limit:
        error(f"{tool}_output_too_large")
        emit({"kind": "summary", "truncated": {f"{tool}_output": True}})
        return None
    try:
        return json.loads(data)
    except (ValueError, RecursionError):
        error(f"{tool}_failed", "invalid JSON")
        return None


def _ids(entries: object, pattern: re.Pattern[str]) -> list[str]:
    if not isinstance(entries, list):
        return []
    ids: list[str] = []
    for entry in entries[:20]:
        value = entry.get("id") if isinstance(entry, dict) else None
        if isinstance(value, str) and pattern.match(value) and value not in ids:
            ids.append(value)
    return ids


def capa_records(document: Any) -> Iterator[dict[str, Any]]:
    rules = document.get("rules") if isinstance(document, dict) else None
    if not isinstance(rules, dict):
        error("capa_failed", "no rules object")
        return
    for name, rule in sorted(rules.items()):
        meta = rule.get("meta") if isinstance(rule, dict) else None
        if not isinstance(meta, dict) or meta.get("lib") is True:
            continue  # library rules are internal building blocks
        matches = rule.get("matches")
        namespace = meta.get("namespace")
        yield {
            "kind": "capability",
            "name": text(name, 255),
            "namespace": text(namespace, 255) if isinstance(namespace, str) else None,
            "attack": _ids(meta.get("attack"), ATTACK),
            "mbc": _ids(meta.get("mbc"), MBC),
            "matches": max(1, len(matches)) if isinstance(matches, list | dict) else 1,
        }


def floss_records(document: Any) -> Iterator[dict[str, Any]]:
    strings = document.get("strings") if isinstance(document, dict) else None
    if not isinstance(strings, dict):
        error("floss_failed", "no strings object")
        return
    seen: set[tuple[str, str]] = set()
    for key, encoding in FLOSS_KINDS.items():
        entries = strings.get(key)
        for entry in entries if isinstance(entries, list) else []:
            value = entry.get("string") if isinstance(entry, dict) else None
            if not isinstance(value, str):
                continue
            value = text(value, 512)
            if len(value) < FLOSS_MIN_LENGTH or (value, encoding) in seen:
                continue
            seen.add((value, encoding))
            yield {"kind": "string", "value": value, "encoding": encoding}


def run(mode: str, path: Path, *, max_records: int) -> None:
    limit = CAPA_MAX_BYTES if mode == "capa" else FLOSS_MAX_BYTES
    document = load(path, limit, mode)
    if document is None:
        return
    records = capa_records(document) if mode == "capa" else floss_records(document)
    emitted = 0
    for record in records:
        if emitted >= max_records:
            key = "capabilities" if mode == "capa" else "strings"
            emit({"kind": "summary", "truncated": {key: True}})
            return
        emit(record)
        emitted += 1
