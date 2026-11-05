"""IDOR cases owned by phase 4 (M5, RT11): the investigation timeline route
`GET /api/v1/orgs/{org_id}/investigations/{investigation_id}/timeline`.

Created empty in phase 1; `test_idor_routes.py` merges every name below. Add cases only for
routes of the owning phase. The victim's case already has evidence, a pcap job with results
and a static job with results, so the owner's page is non-empty."""

from tests.security.idor_types import PathOverrides, RouteCases, StateHook, VictimExtender

ROUTE_CASES: RouteCases = {
    ("GET", "/api/v1/orgs/{org_id}/investigations/{investigation_id}/timeline"): lambda v: {
        "params": {"limit": 50}
    },
}
VICTIM_EXTENDERS: list[VictimExtender] = []
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ()
STATE_HOOKS: list[StateHook] = []
