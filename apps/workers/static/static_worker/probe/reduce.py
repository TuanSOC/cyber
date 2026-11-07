"""`capa` / `floss` modes: turn the tool's JSON document into bounded JSON lines.

capa and FLOSS write one JSON document (capa's can be tens of MiB). Parsing that in the root
process could exhaust the worker's memory, so it is parsed here, as the tool uid under the
probe's RLIMIT_AS, and reduced to `capability` / `string` records (one per line, each
re-validated by root against `static.v1`). Root never parses large tool output.

M10 phase 6: each capability also carries capa's match locations (absolute addresses only,
deduplicated, sorted, at most 32: `static.v1` `CapabilityRecord.locations`), and one
`capa_meta` line reports the base address capa analysed the file at
(`meta.analysis.base_address`, a capa `Address` `{type, value}`; only `absolute` is accepted)
and how many match addresses of other kinds were dropped. Root puts the base into
`StaticResultHeader.capa_base_address`; the RE ingest normalizes both to file virtual
addresses (RT8).
"""

import json
import os
import re
import stat
from collections.abc import Iterator
from pathlib import Path
from dataclasses import dataclass
from typing import Any

from static_worker.probe.common import emit, error, text

CAPA_MAX_BYTES = 64 * 1024**2
FLOSS_MAX_BYTES = 32 * 1024**2
ATTACK = re.compile(r"^T\d{4}(\.\d{3})?$")
MBC = re.compile(r"^[A-Z]{1,2}\d{4}(\.[a-z0-9]{3})?$")
FLOSS_MIN_LENGTH = 6
MAX_LOCATIONS = 32  # = static.v1 MAX_CAPA_LOCATIONS
ADDRESS_MAX = 2**64 - 1
CAPA_META = "capa_meta"
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


@dataclass
class LocationStats:
    """Match addresses capa reported that are not kept (any kind but `absolute`, or out of
    range) and whether a rule had more than MAX_LOCATIONS absolute ones."""

    dropped: int = 0
    truncated: bool = False


def absolute(address: object) -> int | None:
    """A capa frozen `Address` of type `absolute` with an unsigned 64-bit value, else None
    (`relative`, `file`, `no address`, the .NET and dynamic kinds, malformed values)."""
    if not isinstance(address, dict) or address.get("type") != "absolute":
        return None
    value = address.get("value")
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= ADDRESS_MAX:
        return None
    return value


def capa_locations(matches: object, stats: LocationStats) -> list[int]:
    """The absolute addresses of a rule's matches (`rules.*.matches[*][0]`), deduplicated,
    sorted and capped at MAX_LOCATIONS (the lowest ones are kept)."""
    if not isinstance(matches, list):
        return []
    found: set[int] = set()
    for entry in matches:
        address = entry[0] if isinstance(entry, list | tuple) and entry else None
        value = absolute(address)
        if value is None:
            stats.dropped += 1
        else:
            found.add(value)
    ordered = sorted(found)
    if len(ordered) > MAX_LOCATIONS:
        stats.truncated = True
    return ordered[:MAX_LOCATIONS]


def capa_base(document: Any) -> int | None:
    """`meta.analysis.base_address` (capa 10.x: an `Address` object), absolute only."""
    meta = document.get("meta") if isinstance(document, dict) else None
    analysis = meta.get("analysis") if isinstance(meta, dict) else None
    return absolute(analysis.get("base_address")) if isinstance(analysis, dict) else None


def capa_records(document: Any, stats: LocationStats | None = None) -> Iterator[dict[str, Any]]:
    stats = LocationStats() if stats is None else stats
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
            "locations": capa_locations(matches, stats),
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


def _emit_capped(records: Iterator[dict[str, Any]], max_records: int, key: str) -> None:
    emitted = 0
    for record in records:
        if emitted >= max_records:
            emit({"kind": "summary", "truncated": {key: True}})
            return
        emit(record)
        emitted += 1


def run(mode: str, path: Path, *, max_records: int) -> None:
    limit = CAPA_MAX_BYTES if mode == "capa" else FLOSS_MAX_BYTES
    document = load(path, limit, mode)
    if document is None:
        return
    if mode != "capa":
        _emit_capped(floss_records(document), max_records, "strings")
        return
    stats = LocationStats()
    _emit_capped(capa_records(document, stats), max_records, "capabilities")
    emit(
        {
            "kind": CAPA_META,
            "base_address": capa_base(document),
            "dropped_locations": stats.dropped,
        }
    )
    if stats.truncated:
        emit({"kind": "summary", "truncated": {"capability_locations": True}})
