"""IDOR cases owned by M7 phase 3 (retention policy, preview, runs and legal holds).

Created by phase 1 with every route PENDING (501 stubs). Phase 3 adds the cases, the victim
extender (a policy, a run `{retention_run_id}` and a hold `{hold_id}`), the resource
parameters and a state hook, and empties `PENDING_ROUTES`. Phase 11 asserts it is empty.
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
        ("GET", f"{_ORG}/retention/policy"),
        ("PUT", f"{_ORG}/retention/policy"),
        ("POST", f"{_ORG}/retention/preview"),
        ("GET", f"{_ORG}/retention/runs"),
        ("POST", f"{_ORG}/retention/runs"),
        ("GET", f"{_ORG}/retention/runs/{{retention_run_id}}"),
        ("GET", f"{_ORG}/legal-holds"),
        ("POST", f"{_ORG}/legal-holds"),
        ("POST", f"{_ORG}/legal-holds/{{hold_id}}/release"),
    }
)
