"""IOCs of an RE run (M10 phase 5): URLs, domains and IPs from strings **referenced by code**
only (an unreferenced string in the file is not evidence of use), through the shared
extractor `cyberlab_worker.iocs`. Observables, never verdicts; enrichment happens later.

Context: `IocRecord` (the shared, frozen `results.v1` line) has no context field, only a
16-character `source`; every RE IOC carries `source = "re_string"`, and the referencing
functions (at most 3, by entry) are kept in `IocHit.functions` for the network rule and the
priority, and are recoverable after ingest from `re_strings` / `re_string_refs` (phase 8's
strings route lists each string's referencing functions).
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import cast

from cyberlab_jobs.results import IocRecord, IocType
from cyberlab_worker.iocs import IocCollector

from re_worker.view import ReView

KINDS = frozenset({"url", "domain", "ip"})
SOURCE = "re_string"
MAX_PER_STRING = 64
MAX_CONTEXT_FUNCTIONS = 3


@dataclass
class IocHit:
    count: int = 0
    functions: set[int] = field(default_factory=set)

    def context(self) -> tuple[int, ...]:
        return tuple(sorted(self.functions)[:MAX_CONTEXT_FUNCTIONS])


def string_iocs(view: ReView) -> dict[int, list[tuple[str, str, int]]]:
    """Per referenced string index: its (kind, value, occurrences) observables."""
    out: dict[int, list[tuple[str, str, int]]] = {}
    for index, record in view.strings.items():
        if not view.string_referrers(index):
            continue
        collector = IocCollector(MAX_PER_STRING)
        collector.observe(record.value, SOURCE)
        found = [
            (kind, value, seen.count)
            for (kind, value), seen in sorted(collector.entries.items())
            if kind in KINDS
        ]
        if found:
            out[index] = found
    return out


def collect(
    view: ReView, limit: int, per_string: dict[int, list[tuple[str, str, int]]] | None = None
) -> tuple[dict[tuple[str, str], IocHit], bool]:
    """Deduplicated (kind, value) -> count and referencing functions; capped at `limit`."""
    per_string = string_iocs(view) if per_string is None else per_string
    table: dict[tuple[str, str], IocHit] = {}
    capped = False
    for index in sorted(per_string):
        referrers = view.string_referrers(index)
        for kind, value, count in per_string[index]:
            key = (kind, value[:2048])
            hit = table.get(key)
            if hit is None:
                if len(table) >= limit:
                    capped = True
                    continue
                hit = table[key] = IocHit()
            hit.count += count
            hit.functions.update(referrers)
    return table, capped


def records(table: dict[tuple[str, str], IocHit], ts: datetime) -> list[IocRecord]:
    return [
        IocRecord(
            type=cast(IocType, kind),
            value=value,
            first_seen=ts,
            last_seen=ts,
            count=hit.count,
            source=SOURCE,
        )
        for (kind, value), hit in sorted(table.items())
    ]
