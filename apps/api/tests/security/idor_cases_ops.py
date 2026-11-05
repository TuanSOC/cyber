"""IDOR cases owned by M7 phase 5 (the org operations metrics).

`GET /orgs/{org}/ops/metrics` reads only the org's own tenant tables (RLS plus an explicit
org filter); the victim's org already has analysis jobs, so the owner's answer is non-empty.
`/internal/metrics` is not org-scoped (bearer token, outside /api): it is tested in
`test_internal_metrics.py`. `PENDING_ROUTES` is empty (phase 11 asserts it).
"""

from tests.security.idor_types import PathOverrides, RouteCases, StateHook, VictimExtender

_ORG = "/api/v1/orgs/{org_id}"

ROUTE_CASES: RouteCases = {
    ("GET", f"{_ORG}/ops/metrics"): lambda v: {"params": {"window": "7d"}},
}
VICTIM_EXTENDERS: list[VictimExtender] = []
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ()
STATE_HOOKS: list[StateHook] = []
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset()
