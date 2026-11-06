"""IDOR state owned by M9 phase 9 (disk sensitivity and the batch release, RT20).

The generic sensitivity routes are cased in `idor_cases_memory_sensitivity` (phase 1); this
module adds no route. Its victim extender seeds a disk job over two restricted disk segments
and a restricted derived item in the victim case, and its state hook snapshots their
sensitivity rows: no cross-org request of the suite (the generic release included) may
release or change any of them. The batch arm with another org's `job_id` is covered in
`tests/integration/test_disk_batch_release.py` (404, nothing changed).
"""

import uuid
from typing import Any

from tests.disk_helpers import restricted_disk_evidence, seed_disk_job, seed_segment_set
from tests.factories import Registered
from tests.integration.seed import Tenant
from tests.security.idor_types import (
    PathOverrides,
    RouteCases,
    StateHook,
    Victim,
    VictimExtender,
)

ROUTE_CASES: RouteCases = {}
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ()
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset()

_KEYS = ("disk_segment_0", "disk_segment_1", "disk_derived")


async def _extend(owner: Registered, victim: Victim) -> dict[str, str]:
    tenant = Tenant(victim.org_id, owner.user_id, uuid.UUID(victim.investigation_id))
    segments = await seed_segment_set(tenant, 2, stem="victim")
    for segment in segments:
        await restricted_disk_evidence(tenant, segment)
    job_id = await seed_disk_job(tenant, segments, fixture=None)
    derived = await restricted_disk_evidence(tenant, source="derived")
    return {
        "disk_job_id": str(job_id),
        "disk_segment_0": str(segments[0]),
        "disk_segment_1": str(segments[1]),
        "disk_derived": str(derived),
    }


async def _disk_sensitivity_state(owner: Registered, victim: Victim) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in _KEYS:
        evidence_id = victim.extra[key]
        response = await owner.client.get(
            f"/api/v1/orgs/{victim.org_id}/evidence/{evidence_id}/sensitivity"
        )
        assert response.status_code == 200, response.text
        body = response.json()
        out[key] = (body["state"], body["source"], body["released_at"], body["release_reason"])
    return {"disk_sensitivity": out}


VICTIM_EXTENDERS: list[VictimExtender] = [_extend]
STATE_HOOKS: list[StateHook] = [_disk_sensitivity_state]
