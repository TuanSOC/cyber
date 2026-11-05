"""IDOR cases owned by M6 phase 4 (report renditions and downloads).

Created in phase 1 with no cases: every route below is listed in `PENDING_ROUTES`, which
`test_idor_routes.py` skips and reports. Phase 4 adds the cases, the victim extender (a
render) and the resource parameter `{render_id}`, and empties `PENDING_ROUTES`.
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
        ("POST", f"{_ORG}/reports/{{report_id}}/versions/{{version}}/renders"),
        ("GET", f"{_ORG}/reports/{{report_id}}/versions/{{version}}/renders"),
        ("GET", f"{_ORG}/report-renders/{{render_id}}"),
        ("GET", f"{_ORG}/report-renders/{{render_id}}/download"),
    }
)
