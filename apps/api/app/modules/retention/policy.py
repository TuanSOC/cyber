"""Retention policy values: floors, effective values and the delay (RT1).

The row keeps the values in force (`*_days`, `enforce`) and the loosening changes waiting
for their delay (`pending_*` until `effective_at`, `pending_enforce` until
`enforce_effective_at`). A change whose time has passed is in force even if no PUT has
folded it into the row yet, so readers (the API, the selector, the worker) always go through
`effective()`; a PUT folds matured changes first, then applies the new request:

- lowering a value (a number below the current one, or null -> a number) waits for the delay
  in `pending_<field>`; a pending value that does not change keeps its date;
- raising a value, or setting it to null, applies at once and cancels a pending lower;
- turning `enforce` on (with `acknowledge_destruction`) waits in `pending_enforce`; turning it
  off applies at once and cancels a pending on.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from app.core.config import get_settings
from app.core.errors import PolicyFloor, RetentionAcknowledgementRequired
from app.modules.retention.models import FLOOR_DAYS, OrgRetentionPolicy
from app.modules.retention.schemas import RetentionPolicyIn, RetentionPolicyOut, RetentionValues
from app.modules.retention.select import EffectivePolicy

FIELDS = ("ti_results_days", "ai_runs_days", "closed_case_days")


def delay() -> timedelta:
    return timedelta(days=get_settings().retention_policy_delay_days)


def floors() -> RetentionValues:
    closed = max(FLOOR_DAYS, get_settings().evidence_lock_days)
    return RetentionValues(
        ti_results_days=FLOOR_DAYS, ai_runs_days=FLOOR_DAYS, closed_case_days=closed
    )


def check_floors(values: dict[str, int | None]) -> None:
    minimum = floors().model_dump()
    below = sorted(f for f, v in values.items() if v is not None and v < minimum[f])
    if below:
        raise PolicyFloor(
            f"Below the minimum of {', '.join(f'{f} >= {minimum[f]}' for f in below)}",
            extra={"fields": below},
        )


@dataclass(frozen=True)
class PolicyState:
    """A policy row's meaning at one instant (no row: every value null, enforce off)."""

    values: dict[str, int | None]
    pending: dict[str, int | None]
    effective_at: datetime | None
    enforce: bool
    pending_enforce: bool
    enforce_effective_at: datetime | None

    def as_effective(self) -> EffectivePolicy:
        return EffectivePolicy(
            ti_results_days=self.values["ti_results_days"],
            ai_runs_days=self.values["ai_runs_days"],
            closed_case_days=self.values["closed_case_days"],
            enforce=self.enforce,
        )


EMPTY = PolicyState(
    values=dict.fromkeys(FIELDS),
    pending=dict.fromkeys(FIELDS),
    effective_at=None,
    enforce=False,
    pending_enforce=False,
    enforce_effective_at=None,
)


def state(row: OrgRetentionPolicy | None, now: datetime) -> PolicyState:
    """Fold the matured pending changes of `row` into its values."""
    if row is None:
        return EMPTY
    values = {f: getattr(row, f) for f in FIELDS}
    pending = {f: getattr(row, f"pending_{f}") for f in FIELDS}
    effective_at = row.effective_at
    if effective_at is not None and effective_at <= now:
        values = {f: pending[f] if pending[f] is not None else values[f] for f in FIELDS}
        pending, effective_at = dict.fromkeys(FIELDS), None
    enforce, pending_enforce, enforce_at = (
        row.enforce,
        row.pending_enforce,
        row.enforce_effective_at,
    )
    if pending_enforce and enforce_at is not None and enforce_at <= now:
        enforce, pending_enforce, enforce_at = True, False, None
    return PolicyState(values, pending, effective_at, enforce, pending_enforce, enforce_at)


def effective(row: OrgRetentionPolicy | None, now: datetime) -> EffectivePolicy:
    return state(row, now).as_effective()


def _is_lower(new: int | None, current: int | None) -> bool:
    return new is not None and (current is None or new < current)


def apply(current: PolicyState, body: RetentionPolicyIn, now: datetime) -> PolicyState:
    """The state after a PUT (floors and the acknowledgement checked first)."""
    requested = {f: getattr(body, f) for f in FIELDS}
    check_floors(requested)
    values, pending = dict(current.values), dict(current.pending)
    new_lower = False
    for f in FIELDS:
        new = requested[f]
        if _is_lower(new, current.values[f]):
            if pending[f] != new:
                pending[f], new_lower = new, True
        else:
            values[f], pending[f] = new, None
    if not any(v is not None for v in pending.values()):
        effective_at = None
    elif new_lower or current.effective_at is None:
        effective_at = now + delay()
    else:
        effective_at = current.effective_at

    enforce, pending_enforce, enforce_at = (
        current.enforce,
        current.pending_enforce,
        current.enforce_effective_at,
    )
    if not body.enforce:
        enforce, pending_enforce, enforce_at = False, False, None
    elif not current.enforce and not current.pending_enforce:
        if body.acknowledge_destruction is not True:
            raise RetentionAcknowledgementRequired()
        pending_enforce, enforce_at = True, now + delay()
    return PolicyState(values, pending, effective_at, enforce, pending_enforce, enforce_at)


def write(row: OrgRetentionPolicy, new: PolicyState) -> None:
    for f in FIELDS:
        setattr(row, f, new.values[f])
        setattr(row, f"pending_{f}", new.pending[f])
    row.effective_at = new.effective_at
    row.enforce = new.enforce
    row.pending_enforce = new.pending_enforce
    row.enforce_effective_at = new.enforce_effective_at


def snapshot(s: PolicyState) -> dict[str, Any]:
    """The audit / run form (values and dates only)."""
    return {
        **s.values,
        "enforce": s.enforce,
        "pending": {f: v for f, v in s.pending.items() if v is not None},
        "effective_at": s.effective_at.isoformat() if s.effective_at else None,
        "pending_enforce": s.pending_enforce,
        "enforce_effective_at": (
            s.enforce_effective_at.isoformat() if s.enforce_effective_at else None
        ),
    }


def run_policy(p: EffectivePolicy) -> dict[str, Any]:
    """What a run records in `retention_runs.policy` (the effective values and mode)."""
    return {
        "ti_results_days": p.ti_results_days,
        "ai_runs_days": p.ai_runs_days,
        "closed_case_days": p.closed_case_days,
        "enforce": p.enforce,
    }


def to_out(row: OrgRetentionPolicy | None, now: datetime) -> RetentionPolicyOut:
    s = state(row, now)
    return RetentionPolicyOut(
        **s.values,
        pending_ti_results_days=s.pending["ti_results_days"],
        pending_ai_runs_days=s.pending["ai_runs_days"],
        pending_closed_case_days=s.pending["closed_case_days"],
        effective_at=s.effective_at,
        enforce=s.enforce,
        pending_enforce=s.pending_enforce,
        enforce_effective_at=s.enforce_effective_at,
        delay_days=get_settings().retention_policy_delay_days,
        floors=floors(),
        updated_by=row.updated_by if row else None,
        updated_at=row.updated_at if row else None,
    )
