"""IDOR cases owned by M7 phase 4 (correlation reads and org search).

Created by phase 1 with every route PENDING (501 stubs). Phase 4 adds the cases (the victim
job's keys, a lookup of a victim value, the victim case's related cases, a search for a
victim title) and empties `PENDING_ROUTES`. Phase 11 asserts it is empty.
"""

from tests.security.idor_types import PathOverrides, RouteCases, StateHook, VictimExtender

_ORG = "/api/v1/orgs/{org_id}"

ROUTE_CASES: RouteCases = {}
VICTIM_EXTENDERS: list[VictimExtender] = []
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ()
STATE_HOOKS: list[StateHook] = []
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", f"{_ORG}/analyses/{{job_id}}/correlations"),
        ("GET", f"{_ORG}/correlations"),
        ("GET", f"{_ORG}/investigations/{{investigation_id}}/related"),
        ("POST", f"{_ORG}/search"),
    }
)
