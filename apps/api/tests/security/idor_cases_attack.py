"""IDOR cases owned by M6 phase 5 (ATT&CK case mappings and the timeline export).

The victim extender seeds an ATT&CK mapping on the victim case (`{mapping_id}`); the state
hook snapshots the victim's mappings, so a cross-org write that slipped through would show
up as a changed status, rationale or a new row.
"""

import uuid
from typing import Any

from tests.case_helpers import seed_mapping
from tests.factories import Registered
from tests.integration.seed import Tenant
from tests.security.idor_types import (
    PathOverrides,
    RouteCases,
    StateHook,
    Victim,
    VictimExtender,
)

_ORG = "/api/v1/orgs/{org_id}"
_CASE = f"{_ORG}/investigations/{{investigation_id}}"

ROUTE_CASES: RouteCases = {
    ("GET", f"{_CASE}/attack"): lambda v: {},
    ("GET", f"{_CASE}/attack/suggestions"): lambda v: {},
    ("POST", f"{_CASE}/attack"): lambda v: {
        "json": {"technique_id": "T1059", "status": "suspected", "rationale": "Injected"}
    },
    ("PATCH", f"{_ORG}/attack-mappings/{{mapping_id}}"): lambda v: {
        "json": {"status": "rejected", "rationale": "Hijacked"}
    },
    ("GET", f"{_CASE}/timeline/export"): lambda v: {
        "params": {"format": "json", "kinds": ["custody", "note"]}
    },
}
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ("{mapping_id}",)


async def _extend(owner: Registered, victim: Victim) -> dict[str, str]:
    tenant = Tenant(victim.org_id, owner.user_id, uuid.UUID(victim.investigation_id))
    mapping_id = await seed_mapping(tenant, technique_id="T1071.001", status="confirmed")
    return {"mapping_id": str(mapping_id)}


async def _attack_state(owner: Registered, victim: Victim) -> dict[str, Any]:
    c = owner.client
    url = f"/api/v1/orgs/{victim.org_id}/investigations/{victim.investigation_id}/attack"
    body = (await c.get(url)).json()
    return {
        "attack_mappings": sorted(
            (m["id"], m["technique_id"], m["status"], m["rationale"], m["updated_at"])
            for m in body["mappings"]
        )
    }


VICTIM_EXTENDERS: list[VictimExtender] = [_extend]
STATE_HOOKS: list[StateHook] = [_attack_state]
# Every route of this module has its cases (phase 9 asserts the set stays empty).
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset()
