"""IDOR cases owned by M8 phase 7 (the memory read API).

The victim extender seeds a succeeded memory job in the victim org
(`tests/memory_helpers.seed_memory_job`, the phase-1 Windows fixture) and every route of this
module points `{job_id}` at it through `PATH_OVERRIDES` (the default `{job_id}` is the
victim's pcap job); `{pid}` is the fixture's psscan-only process. The routes are reads, so
no state hook is needed. The pcap-job and unknown-pid cases are in
`tests/integration/test_memory_reads.py`.
"""

import uuid

from tests.factories import Registered
from tests.integration.seed import Tenant
from tests.memory_helpers import seed_memory_job
from tests.security.idor_types import (
    PathOverrides,
    RouteCases,
    StateHook,
    Victim,
    VictimExtender,
)

_JOB = "/api/v1/orgs/{org_id}/analyses/{job_id}/memory"
_PID = "6112"  # svch0st.exe in windows_triage.ndjson (a connection, a region, an artifact)

ROUTE_CASES: RouteCases = {
    ("GET", _JOB): lambda v: {},
    ("GET", f"{_JOB}/processes"): lambda v: {"params": {"q": "exe", "hidden": "false"}},
    ("GET", f"{_JOB}/processes/{{pid}}"): lambda v: {},
    ("GET", f"{_JOB}/connections"): lambda v: {"params": {"pid": _PID, "q": "203.0.113"}},
    ("GET", f"{_JOB}/injections"): lambda v: {"params": {"pid": _PID}},
    ("GET", f"{_JOB}/artifacts"): lambda v: {"params": {"type": "service", "q": "svc"}},
}


def _memory_job(victim: Victim) -> dict[str, str]:
    return {"job_id": victim.extra["memory_job_id"], "pid": _PID}


PATH_OVERRIDES: PathOverrides = {template: _memory_job for _, template in ROUTE_CASES}
RESOURCE_PARAMS: tuple[str, ...] = ()


async def _extend(owner: Registered, victim: Victim) -> dict[str, str]:
    tenant = Tenant(victim.org_id, owner.user_id, uuid.UUID(victim.investigation_id))
    return {"memory_job_id": str(await seed_memory_job(tenant))}


VICTIM_EXTENDERS: list[VictimExtender] = [_extend]
STATE_HOOKS: list[StateHook] = []
# Every route of this module has its case (phase 11 asserts the set stays empty).
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset()
