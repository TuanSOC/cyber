"""IDOR cases owned by M11 phase 3 (org invitations).

M11 phase 1 froze the routes as 501 stubs: every one is in `PENDING_ROUTES` (skipped and
reported, never silently passed). Phase 3 adds a victim extender that creates a pending
invitation in the victim org (`tests/identity_helpers.seed_invitation`), points
`{invitation_id}` at it through `PATH_OVERRIDES`, moves each route into `ROUTE_CASES`, adds a
state hook (the victim's invitations unchanged) and empties `PENDING_ROUTES`.
"""

from tests.security.idor_types import PathOverrides, RouteCases, StateHook, VictimExtender

_ORG = "/api/v1/orgs/{org_id}/invitations"

ROUTE_CASES: RouteCases = {}
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ()
VICTIM_EXTENDERS: list[VictimExtender] = []
STATE_HOOKS: list[StateHook] = []
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", _ORG),
        ("POST", _ORG),
        ("POST", f"{_ORG}/{{invitation_id}}/resend"),
        ("POST", f"{_ORG}/{{invitation_id}}/revoke"),
    }
)
