"""IDOR cases owned by M7 phase 5 (the org operations metrics).

Created by phase 1 with its route PENDING (a 501 stub). Phase 5 adds the case and empties
`PENDING_ROUTES`. `/internal/metrics` is not org-scoped (bearer token, outside /api): phase 5
tests it in `test_internal_metrics.py`. Phase 11 asserts the set is empty.
"""

from tests.security.idor_types import PathOverrides, RouteCases, StateHook, VictimExtender

_ORG = "/api/v1/orgs/{org_id}"

ROUTE_CASES: RouteCases = {}
VICTIM_EXTENDERS: list[VictimExtender] = []
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ()
STATE_HOOKS: list[StateHook] = []
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset({("GET", f"{_ORG}/ops/metrics")})
