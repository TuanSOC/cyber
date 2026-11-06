"""IDOR cases owned by M8 phase 8 (memory sensitivity; phase-1 501 stubs, RT24).

Phase 8 seeds restricted memory evidence in the victim org
(`tests/memory_helpers.restricted_memory_evidence`) and adds a case per route plus a state
hook over the victim's sensitivity row (a cross-org release must change nothing); until then
both routes are pending (phase 11 asserts `PENDING_ROUTES` is empty).
"""

from tests.security.idor_types import PathOverrides, RouteCases, StateHook, VictimExtender

_EVIDENCE = "/api/v1/orgs/{org_id}/evidence/{evidence_id}"

ROUTE_CASES: RouteCases = {}
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ()
VICTIM_EXTENDERS: list[VictimExtender] = []
STATE_HOOKS: list[StateHook] = []
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", f"{_EVIDENCE}/memory-sensitivity"),
        ("POST", f"{_EVIDENCE}/memory-sensitivity/release"),
    }
)
