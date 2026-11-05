"""IDOR cases owned by M6 phase 5 (ATT&CK case mappings and the timeline export).

Created in phase 1 with no cases: every route below is listed in `PENDING_ROUTES`, which
`test_idor_routes.py` skips and reports. Phase 5 adds the cases, the victim extender (a
mapping) and the resource parameter `{mapping_id}`, and empties `PENDING_ROUTES`.
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
        ("GET", f"{_ORG}/investigations/{{investigation_id}}/attack"),
        ("GET", f"{_ORG}/investigations/{{investigation_id}}/attack/suggestions"),
        ("POST", f"{_ORG}/investigations/{{investigation_id}}/attack"),
        ("PATCH", f"{_ORG}/attack-mappings/{{mapping_id}}"),
        ("GET", f"{_ORG}/investigations/{{investigation_id}}/timeline/export"),
    }
)
