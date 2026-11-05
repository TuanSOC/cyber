"""Retention sweep, per-org run and S3 legal-hold sync (M7; frozen signatures, phase 3
implements them).

- `sweep()`: the daily beat task. Orgs come from the system lookup `retention_policy_index`
  (system session, RT3); each org with an effective policy gets a run (dry-run unless the
  DB says `enforce` is effective, RT1). Returns the number of runs started.
- `run_org(org_id, run_id)`: one run under a per-org advisory lock, time-sliced
  (`RETENTION_RUN_SLICE_S`), in per-org tenant sessions only. Enforce order per evidence:
  tombstone + custody `purged` + audit (commit), then delete the object version.
- `sync_holds(org_id)`: mirror the org's case holds as S3 legal holds (RT5). Returns the
  number of object versions changed.

Phase 1: the sweep finds nothing to do and the sync changes nothing.
"""

import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RunOutcome:
    run_id: uuid.UUID
    status: str
    counts: dict[str, Any] = field(default_factory=dict)


async def sweep() -> int:
    return 0


async def run_org(org_id: uuid.UUID, run_id: uuid.UUID) -> RunOutcome:
    raise NotImplementedError("workers.retention.run_org is implemented in M7 phase 3")


async def sync_holds(org_id: uuid.UUID) -> int:
    return 0
