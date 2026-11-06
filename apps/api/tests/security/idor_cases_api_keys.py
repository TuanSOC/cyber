"""IDOR cases owned by M11 phase 9 (platform API keys).

M11 phase 1 froze the routes as 501 stubs (`PENDING_ROUTES`). Phase 9 adds a victim extender
that creates a key in the victim org (`tests/identity_helpers.seed_api_key`), points
`{key_id}` at it, moves the routes into `ROUTE_CASES`, and adds the second principal kind to
the enumerator: every org route is also called with an API key of ANOTHER org (`404`, never
the victim's data).
"""

from tests.security.idor_types import PathOverrides, RouteCases, StateHook, VictimExtender

_ORG = "/api/v1/orgs/{org_id}/api-keys"

ROUTE_CASES: RouteCases = {}
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ()
VICTIM_EXTENDERS: list[VictimExtender] = []
STATE_HOOKS: list[StateHook] = []
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {("GET", _ORG), ("POST", _ORG), ("POST", f"{_ORG}/{{key_id}}/revoke")}
)
