"""Pure retention rules (M7 phase 3): run trees, candidate counting and limits, holds, the
effective policy and its delay (RT1), and the worker's tree-preserving batches."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.core.config import get_settings
from app.core.errors import PolicyFloor, RetentionAcknowledgementRequired
from app.modules.retention import policy
from app.modules.retention.holds import HoldSet
from app.modules.retention.models import OrgRetentionPolicy
from app.modules.retention.schemas import RetentionPolicyIn
from app.modules.retention.select import (
    Candidate,
    CandidateSet,
    EffectivePolicy,
    _add,
    _components,
    cutoff,
)
from app.workers.retention import _batches

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)


def _ids(n: int) -> list[uuid.UUID]:
    return sorted(uuid.uuid4() for _ in range(n))


def test_run_trees_are_connected_components() -> None:
    a, b, c, d, e = _ids(5)
    # b is a child of a, c supersedes b; d alone; e links to an id outside the set.
    edges = {a: [], b: [a], c: [b], d: [], e: []}
    trees = _components(edges)
    assert sorted(map(tuple, trees)) == sorted([(a, b, c), (d,), (e,)])
    assert trees == sorted(trees, key=lambda g: g[0])  # deterministic order


def _cand(category: str, n: int) -> Candidate:
    return Candidate(category, "t", str(n), None, None, rows=2, bytes=3)


def test_counts_cover_everything_but_the_list_is_bounded() -> None:
    out = CandidateSet()
    _add(out, [_cand("ti_results", i) for i in range(5)], 2)
    assert out.truncated and len(out.candidates) == 2
    assert (out.counts["ti_results"].candidates, out.counts["ti_results"].rows) == (5, 10)
    assert out.counts["ti_results"].bytes == 15
    fresh = CandidateSet()
    _add(fresh, [_cand("ai_runs", 1)], 2)
    assert not fresh.truncated and fresh.counts["ai_runs"].candidates == 1


def test_holds_and_the_empty_policy() -> None:
    case = uuid.uuid4()
    assert HoldSet(investigation_ids=frozenset({case})).covers(case)
    assert not HoldSet(investigation_ids=frozenset({case})).covers(uuid.uuid4())
    assert not HoldSet().covers(None)
    assert HoldSet(org_wide=True).covers(None)
    assert EffectivePolicy(None, None, None, enforce=True).empty
    assert not EffectivePolicy(None, 30, None, enforce=False).empty
    assert cutoff(NOW, 30) == NOW - timedelta(days=30)


def _row(**values: object) -> OrgRetentionPolicy:
    row = OrgRetentionPolicy(organization_id=uuid.uuid4(), updated_by=uuid.uuid4())
    for f in policy.FIELDS:
        setattr(row, f, None)
        setattr(row, f"pending_{f}", None)
    row.effective_at = None
    row.enforce = False
    row.pending_enforce = False
    row.enforce_effective_at = None
    for key, value in values.items():
        setattr(row, key, value)
    return row


def _put(**values: object) -> RetentionPolicyIn:
    body: dict[str, object] = dict.fromkeys(policy.FIELDS)
    body["enforce"] = False
    body.update(values)
    return RetentionPolicyIn.model_validate(body)


def test_matured_pending_values_are_in_force() -> None:
    row = _row(
        ti_results_days=90,
        pending_ti_results_days=60,
        effective_at=NOW - timedelta(seconds=1),
        pending_enforce=True,
        enforce_effective_at=NOW + timedelta(days=1),
    )
    effective = policy.effective(row, NOW)
    assert effective.ti_results_days == 60 and effective.enforce is False
    assert policy.effective(row, NOW + timedelta(days=2)).enforce is True
    assert policy.effective(None, NOW) == EffectivePolicy(None, None, None, enforce=False)
    not_yet = _row(ti_results_days=90, pending_ti_results_days=60, effective_at=NOW)
    assert policy.effective(not_yet, NOW - timedelta(seconds=1)).ti_results_days == 90


def test_put_rules() -> None:
    delay = timedelta(days=get_settings().retention_policy_delay_days)
    empty = policy.state(None, NOW)
    lowered = policy.apply(empty, _put(ai_runs_days=60), NOW)
    assert lowered.values["ai_runs_days"] is None and lowered.pending["ai_runs_days"] == 60
    assert lowered.effective_at == NOW + delay
    later = NOW + timedelta(days=2)
    kept = policy.apply(lowered, _put(ai_runs_days=60), later)
    assert kept.effective_at == NOW + delay  # an unchanged pending value keeps its date
    more = policy.apply(lowered, _put(ai_runs_days=60, ti_results_days=90), later)
    assert more.effective_at == later + delay  # a new lowering never shortens the wait
    raised = policy.apply(lowered, _put(), later)
    assert raised.pending["ai_runs_days"] is None and raised.effective_at is None
    with pytest.raises(PolicyFloor):
        policy.apply(empty, _put(ti_results_days=29), NOW)
    with pytest.raises(RetentionAcknowledgementRequired):
        policy.apply(empty, _put(enforce=True), NOW)
    armed = policy.apply(empty, _put(enforce=True, acknowledge_destruction=True), NOW)
    assert (armed.enforce, armed.pending_enforce, armed.enforce_effective_at) == (
        False,
        True,
        NOW + delay,
    )
    off = policy.apply(armed, _put(enforce=False), later)
    assert (off.enforce, off.pending_enforce, off.enforce_effective_at) == (False, False, None)


def test_batches_never_split_a_tree() -> None:
    def c(rows: int) -> Candidate:
        return Candidate("ai_runs", "ai_runs", str(uuid.uuid4()), None, None, rows, 0)

    trees = [[c(3), c(3)], [c(5)], [c(1), c(1), c(1)]]
    batches = _batches(trees, 6)
    assert [len(b) for b in batches] == [2, 1, 3]
    assert [c for b in batches for c in b] == [c for t in trees for c in t]
    assert _batches([], 10) == []
