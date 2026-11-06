"""The additive `ReportSnapshot.omissions` field (M8 phase 1, RT10) changes no signed byte: every
M6 snapshot fixture re-validates and re-serializes to the same bytes and sha256 as before M8
(pinned below, computed on the pre-M8 contract), and a snapshot with `omissions` round-trips.

M9 phase 1 (RT23) adds `Omissions.disk_restricted: int | None = None`: the M8 snapshots with
memory omissions (pinned below, computed on the M8 contract before the field existed) keep their
bytes, and a snapshot with both counts round-trips.

Pure Python: `PYTHONPATH=../../packages/py-jobs/src python -m pytest --noconftest <this file>`.
"""

import hashlib
import json
from pathlib import Path

import pytest
from cyberlab_jobs.report import Omissions, canonical_json, parse_snapshot

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "report"
# sha256 of canonical_json(parse_snapshot(fixture)) on the M7 contract (commit b6f117b).
PRE_M8 = {
    "golden_snapshot.json": "2704a7f98d215b820bd3eb558e7e1c533ad2452c442f5c5bab56e03d8fbbe78b",
    "hostile_snapshot.json": "414c7e22d5515466fb935598046095aaa28956ac7c31f212aac44a8cf7f0ca5d",
}


# sha256 of the M8-contract canonical bytes (feat/m8-memory-forensics 7b5db93, before M9).
PRE_M9 = {
    "m8_omissions_snapshot.json": (
        "8cb90399352c27ee6aef2afa65b10312dc6d980763a29ed35c860f643dcacb7c"
    ),
    "m8_omissions_zero_snapshot.json": (
        "a1d22cb3d06d77354b67db697a6a3c1cc7214a1a0bd871920704271b8777adb1"
    ),
}


@pytest.mark.parametrize("name", sorted(PRE_M8))
def test_pre_m8_snapshots_keep_their_bytes(name: str) -> None:
    snapshot = parse_snapshot((FIXTURES / name).read_bytes())
    assert snapshot.omissions is None
    data = canonical_json(snapshot)
    assert hashlib.sha256(data).hexdigest() == PRE_M8[name]
    assert b'"omissions"' not in data
    assert canonical_json(parse_snapshot(data)) == data


def test_a_snapshot_with_omissions_round_trips() -> None:
    snapshot = parse_snapshot((FIXTURES / "golden_snapshot.json").read_bytes())
    marked = snapshot.model_copy(update={"omissions": Omissions(memory_restricted=3)})
    data = canonical_json(marked)
    assert json.loads(data)["omissions"] == {"memory_restricted": 3}
    again = parse_snapshot(data)
    assert again.omissions == Omissions(memory_restricted=3)
    assert canonical_json(again) == data


def test_omissions_refuses_negative_and_unknown_fields() -> None:
    raw = json.loads((FIXTURES / "golden_snapshot.json").read_bytes())
    for bad in ({"memory_restricted": -1}, {"memory_restricted": 1, "other": 2}):
        with pytest.raises(ValueError):
            parse_snapshot(json.dumps({**raw, "omissions": bad}).encode())


@pytest.mark.parametrize("name", sorted(PRE_M9))
def test_m8_snapshots_with_omissions_keep_their_bytes(name: str) -> None:
    raw = (FIXTURES / name).read_bytes()
    snapshot = parse_snapshot(raw)
    assert snapshot.omissions is not None
    assert snapshot.omissions.disk_restricted is None
    data = canonical_json(snapshot)
    assert data == raw
    assert hashlib.sha256(data).hexdigest() == PRE_M9[name]
    assert b'"disk_restricted"' not in data


def test_a_snapshot_with_both_counts_round_trips() -> None:
    snapshot = parse_snapshot((FIXTURES / "golden_snapshot.json").read_bytes())
    both = Omissions(memory_restricted=2, disk_restricted=5)
    data = canonical_json(snapshot.model_copy(update={"omissions": both}))
    assert json.loads(data)["omissions"] == {"memory_restricted": 2, "disk_restricted": 5}
    again = parse_snapshot(data)
    assert again.omissions == both
    assert canonical_json(again) == data
    zero = canonical_json(
        snapshot.model_copy(update={"omissions": Omissions(memory_restricted=0, disk_restricted=0)})
    )
    assert json.loads(zero)["omissions"] == {"memory_restricted": 0, "disk_restricted": 0}
    with pytest.raises(ValueError):
        parse_snapshot(
            json.dumps({**json.loads(data), "omissions": {"disk_restricted": -1}}).encode()
        )
