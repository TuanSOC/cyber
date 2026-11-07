"""IDOR cases owned by M10 phase 8 (the RE read API and the capability-functions route).

The victim extender seeds, in the victim org, a static `full` source job with capability
locations (`tests/reverse_helpers.seed_static_source_job`) and a succeeded RE job on it with
the phase-1 `pe_full` fixture's rows (`seed_re_job`), plus one capa link so the capability
route has a function to leak. The RE routes point `{job_id}` at the RE job, the capability
route at the static source job, through `PATH_OVERRIDES`; `{entry}` is `inject_remote`
(decompiled `ok`, a caller, imports, strings and the link) and `{capability_id}` the linked
capability. The routes are reads, so no state hook is needed. The static-job-on-RE-route,
RE-job-on-capability-route and unknown-entry cases are in
`tests/integration/test_re_reads.py`.
"""

import uuid

from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.reverse_engineering.models import ReFunctionCapability
from app.modules.static_analysis.models import MalwareCapability
from tests.factories import Registered
from tests.integration.seed import Tenant
from tests.reverse_helpers import seed_re_job, seed_static_source_job
from tests.security.idor_types import (
    PathOverrides,
    RouteCases,
    StateHook,
    Victim,
    VictimExtender,
)

_JOB = "/api/v1/orgs/{org_id}/analyses/{job_id}/reverse"
_STATIC = "/api/v1/orgs/{org_id}/analyses/{job_id}"
_CAPABILITY = f"{_STATIC}/capabilities/{{capability_id}}/functions"
INJECT_REMOTE = 0x1400011E0  # pe_full.ndjson
_ENTRY = f"0x{INJECT_REMOTE:x}"

ROUTE_CASES: RouteCases = {
    ("GET", _JOB): lambda v: {},
    ("GET", f"{_JOB}/functions"): lambda v: {"params": {"q": "inject", "decompiled": "true"}},
    ("GET", f"{_JOB}/functions/{{entry}}"): lambda v: {},
    ("GET", f"{_JOB}/functions/{{entry}}/code"): lambda v: {},
    ("GET", f"{_JOB}/imports"): lambda v: {"params": {"q": "Process"}},
    ("GET", f"{_JOB}/strings"): lambda v: {"params": {"referenced": "true"}},
    ("GET", _CAPABILITY): lambda v: {},
}


def _re_job(victim: Victim) -> dict[str, str]:
    return {"job_id": victim.extra["re_job_id"], "entry": _ENTRY}


def _static_job(victim: Victim) -> dict[str, str]:
    return {
        "job_id": victim.extra["re_static_job_id"],
        "capability_id": victim.extra["re_capability_id"],
    }


PATH_OVERRIDES: PathOverrides = {
    template: (_static_job if template == _CAPABILITY else _re_job) for _, template in ROUTE_CASES
}
RESOURCE_PARAMS: tuple[str, ...] = ("{capability_id}",)


async def _extend(owner: Registered, victim: Victim) -> dict[str, str]:
    tenant = Tenant(victim.org_id, owner.user_id, uuid.UUID(victim.investigation_id))
    static_job = await seed_static_source_job(tenant)
    re_job = await seed_re_job(tenant, static_job)
    async with tenant_session(victim.org_id, owner.user_id) as s:
        capability = await s.scalar(
            select(MalwareCapability.id).where(
                MalwareCapability.job_id == static_job, MalwareCapability.name == "inject thread"
            )
        )
        assert capability is not None
        s.add(
            ReFunctionCapability(
                organization_id=victim.org_id,
                job_id=re_job,
                capability_id=capability,
                function_entry=INJECT_REMOTE,
                file_va=0x140001280,
            )
        )
    return {
        "re_job_id": str(re_job),
        "re_static_job_id": str(static_job),
        "re_capability_id": str(capability),
    }


VICTIM_EXTENDERS: list[VictimExtender] = [_extend]
STATE_HOOKS: list[StateHook] = []
# Every route of this module has its case (phase 12 asserts the set stays empty).
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset()
