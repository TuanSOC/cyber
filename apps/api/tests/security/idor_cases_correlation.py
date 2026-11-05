"""IDOR cases owned by M7 phase 4 (correlation reads and org search).

The victim extender indexes a shared key into the victim org: the victim's pcap job and its
static job both carry `victim-shared.example.net` (as `correlation_keys` rows written in a
victim tenant session), so the owner's positive controls read real correlations and an
attack that slipped through would have rows to leak. The cases: the victim job's keys, a
lookup of the victim value (POST body), the victim case's related cases, and a search for the victim
case title. All four routes are reads, so no state hook is needed (the shared snapshot of
`test_idor_routes.py` still runs).
"""

import uuid

from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob
from app.modules.correlation.models import CorrelationJobState, CorrelationKey
from app.modules.correlation.normalize import correlation_key
from app.modules.evidence.models import Evidence
from tests.factories import Registered
from tests.security.idor_types import (
    PathOverrides,
    RouteCases,
    StateHook,
    Victim,
    VictimExtender,
)

_ORG = "/api/v1/orgs/{org_id}"
VICTIM_VALUE = "victim-shared.example.net"

ROUTE_CASES: RouteCases = {
    # `include_unique` and `kind` widen the pivot to every victim key of that kind.
    ("GET", f"{_ORG}/analyses/{{job_id}}/correlations"): lambda v: {
        "params": {"kind": "domain", "include_unique": "true"}
    },
    # The value travels in the body (RT13).
    ("POST", f"{_ORG}/correlations/lookup"): lambda v: {
        "json": {"kind": "domain", "value": VICTIM_VALUE}
    },
    ("GET", f"{_ORG}/investigations/{{investigation_id}}/related"): lambda v: {},
    ("POST", f"{_ORG}/search"): lambda v: {"json": {"q": "Victim case"}},
}
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ()


async def _extend(owner: Registered, victim: Victim) -> dict[str, str]:
    key = correlation_key("domain", VICTIM_VALUE)
    assert key is not None
    kind, digest, value_norm = key
    async with tenant_session(victim.org_id, owner.user_id) as s:
        jobs = await s.execute(
            select(AnalysisJob.id, AnalysisJob.evidence_id, Evidence.investigation_id)
            .join(Evidence, Evidence.id == AnalysisJob.evidence_id)
            .where(AnalysisJob.id.in_([uuid.UUID(victim.job_id), uuid.UUID(victim.static_job_id)]))
        )
        for job_id, evidence_id, investigation_id in jobs:
            s.add(
                CorrelationKey(
                    organization_id=victim.org_id,
                    investigation_id=investigation_id,
                    evidence_id=evidence_id,
                    job_id=job_id,
                    kind=kind,
                    key=digest,
                    value_norm=value_norm,
                    source_table="iocs",
                    source_id=str(uuid.uuid4()),
                )
            )
            s.add(CorrelationJobState(job_id=job_id, organization_id=victim.org_id, keys=1))
    return {}


VICTIM_EXTENDERS: list[VictimExtender] = [_extend]
STATE_HOOKS: list[StateHook] = []
# Every route of this module has its cases (phase 11 asserts the set stays empty).
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset()
