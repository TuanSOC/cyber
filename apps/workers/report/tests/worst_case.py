"""Worst-case snapshots at a given render budget (RT1 calibration).

`worst_case(units, shape, style)` returns a valid `ReportSnapshot` (the golden snapshot plus
generated IOCs, timeline entries and citations) whose `render_units` is `units` (within a
row). Shapes:

- `caps`: the IOCs, the timeline and the citations at their item caps (2 000 / 1 000 /
  2 000), the remaining budget spread evenly over their text fields; when the rows alone
  exceed the budget (about 1.4 M units at the caps), as many rows as fit, in the same
  proportions, with short fields (the many-rows worst case);
- `iocs`, `timeline`, `citations`: one section filled with 4 096-character fields until
  the budget is spent (a citation carries several 4 096-character fields).

`style`: `prose` (words and spaces), `run` (unbroken runs, the line-breaking worst case),
or `mixed` (IOC-like tokens, URLs and prose, with vis markers).
"""

import hashlib
import random
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from cyberlab_jobs.report import (
    BOUNDED_TEXT_CHARS,
    CAPS,
    Citation,
    IocItem,
    ReportSnapshot,
    TimelineItem,
    render_units,
)

from tests.conftest import load_snapshot

SHAPES = ("caps", "iocs", "timeline", "citations")
STYLES = ("prose", "run", "mixed")
BASE_TS = datetime(2026, 11, 1, tzinfo=UTC)
FIELDS_PER_CITATION = 4
MIN_ROW_TEXT = 24


def _text(rng: random.Random, n: int, style: str) -> str:
    if n <= 0:
        return ""
    if style == "run":
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789/._-"
        return "".join(rng.choice(alphabet) for _ in range(n))
    if style == "prose":
        words: list[str] = []
        size = 0
        while size < n:
            word = "".join(rng.choice("etaoinshrdlucmfwyp") for _ in range(rng.randint(2, 11)))
            words.append(word)
            size += len(word) + 1
        return " ".join(words)[:n]
    parts: list[str] = []
    size = 0
    while size < n:
        kind = rng.randint(0, 3)
        if kind == 0:
            part = hashlib.sha256(rng.randbytes(8)).hexdigest()
        elif kind == 1:
            part = f"hxxps://host{rng.randint(1, 999)}[.]example/" + "a/b" * rng.randint(1, 30)
        elif kind == 2:
            part = "evil‮gnp.exe zero​width"
        else:
            part = " ".join("lorem" for _ in range(rng.randint(3, 15)))
        parts.append(part)
        size += len(part) + 1
    return " ".join(parts)[:n]


def _uuid(rng: random.Random) -> uuid.UUID:
    return uuid.UUID(int=rng.getrandbits(128), version=4)


def _build(
    base: ReportSnapshot,
    counts: dict[str, int],
    length: int,
    style: str,
    fields_per_citation: int,
    seed: int,
) -> ReportSnapshot:
    rng = random.Random(seed)
    length = max(1, min(length, BOUNDED_TEXT_CHARS))
    iocs = [
        IocItem(
            ioc_type="url",
            value=_text(rng, length, style),
            ioc_key=hashlib.sha256(f"ioc{i}".encode()).hexdigest(),
            count_jobs=rng.randint(1, 9),
            first_seen=BASE_TS + timedelta(minutes=i),
            last_seen=BASE_TS + timedelta(minutes=i + 5),
        )
        for i in range(counts["iocs"])
    ]
    timeline = [
        TimelineItem(
            ts=BASE_TS + timedelta(seconds=i),
            ts_source="capture",
            kind="alert",
            title=_text(rng, length, style),
            severity="high",
            ref_kind="alert",
            ref_id=f"alert-{i}",
        )
        for i in range(counts["timeline"])
    ]
    first = len(base.citations.items) + 1
    citations = list(base.citations.items) + [
        Citation(
            cite_no=first + i,
            kind="finding",
            ref_table="pcap_findings",
            ref_id=f"finding-{i}",
            job_id=_uuid(rng),
            source="selection",
            fields={f"field_{k}": _text(rng, length, style) for k in range(fields_per_citation)},
            fields_sha256=hashlib.sha256(f"c{i}".encode()).hexdigest(),
            path=f"/o/{_uuid(rng)}/pcap/{_uuid(rng)}?tab=findings&ref={_uuid(rng)}",
        )
        for i in range(counts["citations"])
    ]
    update: dict[str, Any] = {
        "iocs": base.iocs.model_copy(update={"items": iocs, "total": max(len(iocs), 1)}),
        "timeline": base.timeline.model_copy(
            update={"items": timeline, "total": max(len(timeline), 1)}
        ),
        "citations": base.citations.model_copy(
            update={"items": citations, "total": len(citations)}
        ),
    }
    # Re-validate: the result is exactly what the API could have signed.
    return ReportSnapshot.model_validate(base.model_copy(update=update).model_dump())


def worst_case(units: int, shape: str = "caps", style: str = "mixed") -> ReportSnapshot:
    base = load_snapshot("golden_snapshot.json")
    base = base.model_copy(
        update={
            "iocs": base.iocs.model_copy(update={"items": [], "total": 0}),
            "timeline": base.timeline.model_copy(update={"items": [], "total": 0}),
        }
    )
    if shape == "caps":
        counts = {
            "iocs": CAPS["iocs"],
            "timeline": CAPS["timeline"],
            "citations": CAPS["citations"] - len(base.citations.items),
        }
        # units(L) is linear in the field length L: solve from two probes.
        u1 = render_units(_build(base, counts, 10, style, FIELDS_PER_CITATION, 1))
        u2 = render_units(_build(base, counts, 20, style, FIELDS_PER_CITATION, 1))
        per_char = (u2 - u1) / 10
        length = int(10 + (units - u1) / per_char)
        if length >= MIN_ROW_TEXT:
            return _build(base, counts, length, style, FIELDS_PER_CITATION, 7)
        # The row structure alone (ids, keys, paths, timestamps, ROW_UNITS) is over the
        # budget: keep short fields and scale the three sections down together.
        low, high = 0.0, 1.0
        for _ in range(12):
            mid = (low + high) / 2
            scaled = {k: max(1, int(v * mid)) for k, v in counts.items()}
            if render_units(_build(base, scaled, MIN_ROW_TEXT, style, 2, 1)) > units:
                high = mid
            else:
                low = mid
        scaled = {k: max(1, int(v * low)) for k, v in counts.items()}
        return _build(base, scaled, MIN_ROW_TEXT, style, 2, 7)
    if shape not in SHAPES:
        raise ValueError(shape)
    counts = {"iocs": 0, "timeline": 0, "citations": 0}
    counts[shape] = 1
    one = render_units(_build(base, counts, BOUNDED_TEXT_CHARS, style, FIELDS_PER_CITATION, 1))
    counts[shape] = 0
    empty = render_units(_build(base, counts, BOUNDED_TEXT_CHARS, style, FIELDS_PER_CITATION, 1))
    limit = CAPS[shape] - (len(base.citations.items) if shape == "citations" else 0)
    counts[shape] = min(limit, max(1, (units - empty) // (one - empty)))
    return _build(base, counts, BOUNDED_TEXT_CHARS, style, FIELDS_PER_CITATION, 7)
