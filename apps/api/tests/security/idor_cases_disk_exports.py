"""IDOR cases owned by M9 phase 10 (file exports to derived evidence; RT29).

M9 phase 1 froze the routes as 501 stubs: every one is in `PENDING_ROUTES`. Phase 10 seeds a
succeeded disk job and a `ready` export in the victim org, adds the cases (with a state hook:
a cross-org promote must change nothing) and empties `PENDING_ROUTES`.
"""

from tests.security.idor_types import PathOverrides, RouteCases, StateHook, VictimExtender

_ORG = "/api/v1/orgs/{org_id}"

ROUTE_CASES: RouteCases = {}
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ()
VICTIM_EXTENDERS: list[VictimExtender] = []
STATE_HOOKS: list[StateHook] = []
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", f"{_ORG}/analyses/{{job_id}}/disk/file-exports"),
        ("GET", f"{_ORG}/disk-exports/{{export_id}}"),
        ("POST", f"{_ORG}/disk-exports/{{export_id}}/promote"),
    }
)
