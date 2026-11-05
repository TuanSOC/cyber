"""Canonical bytes of the signed snapshot (M6 phase 3): re-parsing and re-serializing a stored
snapshot gives identical bytes (whatever the key order or whitespace of the input), the
citation field copy and its `fields_sha256` are deterministic, and the builder's first-use
numbering assigns `C1…Cn` in document order."""

import json
import random
import uuid
from typing import Any

from cyberlab_jobs.report import canonical_json, parse_snapshot, render_units

from app.modules.ai.context.fields import HostList
from app.modules.reports.citations import cite_key, field_copy, field_text, fields_sha256
from app.modules.reports.snapshot import _apply_numbers, _number
from tests.report_helpers import fake_snapshot, golden_data, hostile_snapshot


def _shuffled(value: Any, rng: random.Random) -> Any:
    if isinstance(value, dict):
        items = list(value.items())
        rng.shuffle(items)
        return {k: _shuffled(v, rng) for k, v in items}
    if isinstance(value, list):
        return [_shuffled(v, rng) for v in value]
    return value


def test_stored_bytes_round_trip_identically() -> None:
    for snapshot in (fake_snapshot(), hostile_snapshot()):
        data = canonical_json(snapshot)
        assert canonical_json(parse_snapshot(data)) == data
        assert render_units(parse_snapshot(data)) == render_units(snapshot)


def test_key_order_and_whitespace_do_not_change_the_bytes() -> None:
    expected = canonical_json(fake_snapshot())
    rng = random.Random(6)  # noqa: S311 - a reproducible shuffle, not a secret
    for _ in range(5):
        noisy = json.dumps(_shuffled(golden_data(), rng), indent=2, ensure_ascii=True)
        assert canonical_json(parse_snapshot(noisy.encode())) == expected


def test_vietnamese_analyst_text_is_utf8_and_whole() -> None:
    data = golden_data()
    summary = ("Tóm tắt: máy trạm gửi tín hiệu định kỳ. " * 600)[:20_000]
    data["sections"]["executive_summary"] = summary
    raw = canonical_json(parse_snapshot(json.dumps(data).encode()))
    assert summary.encode("utf-8") in raw
    assert parse_snapshot(raw).sections.executive_summary == summary


def test_field_copies_are_deterministic_strings() -> None:
    raw = {
        "title": "Beacon to http://evil.example/x",
        "confidence": 0.8,
        "count": 15,
        "flag": True,
        "empty": "",
        "none": None,
        "hosts": HostList((("a.example", 2),)),
        "bad key!": "dropped",
    }
    copy = field_copy(raw)
    assert copy == {
        "confidence": "0.8",
        "count": "15",
        "flag": "true",
        "title": "Beacon to hxxp[:]//evil[.]example/x",
    }
    assert field_copy(dict(reversed(list(raw.items())))) == copy
    assert fields_sha256(copy) == fields_sha256(dict(sorted(copy.items(), reverse=True)))
    cut = field_text("x" * 5000) or ""
    assert len(cut) <= 4096 and cut.endswith("]") and "…[truncated " in cut
    assert field_copy({f"f{i:02d}": "v" for i in range(40)}).keys() == {
        f"f{i:02d}" for i in range(32)
    }


def test_first_use_numbering_follows_document_order() -> None:
    job = uuid.uuid4()
    k_ev, k_job, k_f1, k_f2, k_sel = (
        cite_key("evidence", "e1", None),
        cite_key("job", str(job), None),
        cite_key("finding", "f1", None),
        cite_key("finding", "f2", None),
        cite_key("custody", "c1", None),
    )
    data: dict[str, Any] = {
        "evidence": {"items": [{"_cite": k_ev}]},
        "jobs": {"items": [{"_cite": k_job}]},
        "findings": {"items": [{"_cite": k_f2}, {"_cite": k_f1}]},
        "alerts": {"items": []},
        "ti": {"items": []},
        "attack": {"items": [{"_cites": [k_f1, k_f2, k_f1]}]},
        "timeline": {"items": []},
        "notes": {"items": []},
        "ai": {"items": [{"claims": [{"_cites": [k_sel, k_job]}]}]},
    }
    resolved = {k: object() for k in (k_ev, k_job, k_f1, k_f2, k_sel)}
    # The job and evidence are known but the evidence row did not resolve.
    del resolved[k_ev]
    numbers = _number(data, resolved, [k_sel, k_f1])  # type: ignore[arg-type]
    assert numbers == {k_job: 1, k_f2: 2, k_f1: 3, k_sel: 4}
    _apply_numbers(data, numbers)
    assert data["evidence"]["items"][0]["cite_no"] is None
    assert [f["cite_no"] for f in data["findings"]["items"]] == [2, 3]
    assert data["attack"]["items"][0]["cite_nos"] == [3, 2]
    assert data["ai"]["items"][0]["claims"][0]["cite_nos"] == [4, 1]
    assert "_cite" not in json.dumps(data)
    # Flows are keyed by (job, flow_ref); every other kind by its row id alone.
    assert cite_key("flow", "C1", job) != cite_key("flow", "C1", uuid.uuid4())
    assert cite_key("finding", "f1", job) == cite_key("finding", "f1", None)
