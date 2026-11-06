"""IDOR cases owned by M8 phase 8 (memory sensitivity, RT24).

The victim extender seeds a restricted memory image in the victim case
(`tests/memory_helpers.restricted_memory_evidence`) on its own evidence row, so the M6 share
policy case of `idor_cases_case` keeps working on `{evidence_id}`; both routes target it
through `PATH_OVERRIDES`. The state hook snapshots its sensitivity row, so a cross-org release
that changed anything fails the "nothing changed" check.

M9 phase 1 (RT2): the generic `GET …/sensitivity` and `POST …/sensitivity/release` routes
(every source, implemented) target the same restricted evidence.
"""

import uuid
from typing import Any

from tests.factories import Registered
from tests.integration.seed import Tenant
from tests.memory_helpers import restricted_memory_evidence
from tests.security.idor_types import (
    PathOverrides,
    RouteCases,
    StateHook,
    Victim,
    VictimExtender,
)

_EVIDENCE = "/api/v1/orgs/{org_id}/evidence/{evidence_id}"
_GET = f"{_EVIDENCE}/memory-sensitivity"
_RELEASE = f"{_EVIDENCE}/memory-sensitivity/release"
_GENERIC_GET = f"{_EVIDENCE}/sensitivity"
_GENERIC_RELEASE = f"{_EVIDENCE}/sensitivity/release"


def _memory_evidence(victim: Victim) -> dict[str, str]:
    return {"evidence_id": victim.extra["memory_evidence_id"]}


ROUTE_CASES: RouteCases = {
    ("GET", _GET): lambda v: {},
    ("POST", _RELEASE): lambda v: {
        "json": {"acknowledge": True, "reason": "Hijacked release of a victim memory image"}
    },
    ("GET", _GENERIC_GET): lambda v: {},
    ("POST", _GENERIC_RELEASE): lambda v: {
        "json": {"acknowledge": True, "reason": "Hijacked release of victim evidence"}
    },
}
PATH_OVERRIDES: PathOverrides = {
    _GET: _memory_evidence,
    _RELEASE: _memory_evidence,
    _GENERIC_GET: _memory_evidence,
    _GENERIC_RELEASE: _memory_evidence,
}
RESOURCE_PARAMS: tuple[str, ...] = ()
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset()


async def _extend(owner: Registered, victim: Victim) -> dict[str, str]:
    tenant = Tenant(victim.org_id, owner.user_id, uuid.UUID(victim.investigation_id))
    evidence_id = await restricted_memory_evidence(tenant)
    return {"memory_evidence_id": str(evidence_id)}


async def _sensitivity_state(owner: Registered, victim: Victim) -> dict[str, Any]:
    evidence_id = victim.extra["memory_evidence_id"]
    response = await owner.client.get(
        f"/api/v1/orgs/{victim.org_id}/evidence/{evidence_id}/memory-sensitivity"
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {"memory_sensitivity": (body["state"], body["released_at"], body["release_reason"])}


VICTIM_EXTENDERS: list[VictimExtender] = [_extend]
STATE_HOOKS: list[StateHook] = [_sensitivity_state]
