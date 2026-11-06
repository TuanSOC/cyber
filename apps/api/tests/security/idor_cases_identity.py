"""IDOR cases owned by M11 phases 6 and 7: two sections in one module, each phase editing its
own list only (file-disjoint in practice).

- Policy (phase 6): `GET` / `PUT /orgs/{org_id}/security-policy`.
- SSO administration (phase 7): the IdP config and the domains (`{domain_id}` from a victim
  extender seeding a pending domain, `tests/identity_helpers.seed_domain`).
M11 phase 1 froze them as 501 stubs; each phase moves its routes into its `*_ROUTE_CASES`
and empties its `*_PENDING_ROUTES`. Phase 13 asserts both are empty.
"""

from tests.security.idor_types import PathOverrides, RouteCases, StateHook, VictimExtender

_ORG = "/api/v1/orgs/{org_id}"

# --- phase 6: org security policy -----------------------------------------------------------
POLICY_ROUTE_CASES: RouteCases = {}
POLICY_PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {("GET", f"{_ORG}/security-policy"), ("PUT", f"{_ORG}/security-policy")}
)

# --- phase 7: SSO administration ------------------------------------------------------------
SSO_ADMIN_ROUTE_CASES: RouteCases = {}
SSO_ADMIN_PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", f"{_ORG}/sso"),
        ("PUT", f"{_ORG}/sso"),
        ("DELETE", f"{_ORG}/sso/secret"),
        ("POST", f"{_ORG}/sso/refresh-metadata"),
        ("GET", f"{_ORG}/domains"),
        ("POST", f"{_ORG}/domains"),
        ("POST", f"{_ORG}/domains/{{domain_id}}/verify"),
        ("DELETE", f"{_ORG}/domains/{{domain_id}}"),
    }
)

ROUTE_CASES: RouteCases = {**POLICY_ROUTE_CASES, **SSO_ADMIN_ROUTE_CASES}
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ()
VICTIM_EXTENDERS: list[VictimExtender] = []
STATE_HOOKS: list[StateHook] = []
PENDING_ROUTES: frozenset[tuple[str, str]] = POLICY_PENDING_ROUTES | SSO_ADMIN_PENDING_ROUTES
