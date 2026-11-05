"""IDOR cases owned by M6 phase 2 (case management): status history, the evidence share
policy, notes, IOC collections and the case-wide IOC read.

Created in phase 1 with no cases: every route below is listed in `PENDING_ROUTES`, which
`test_idor_routes.py` skips and reports. Phase 2 adds the cases, the victim extenders (a
note, a collection with an item, an evidence policy) and the resource parameters
(`{note_id}`, `{collection_id}`, `{item_id}`), and empties `PENDING_ROUTES`.
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
        ("GET", f"{_ORG}/investigations/{{investigation_id}}/status-events"),
        ("GET", f"{_ORG}/evidence/{{evidence_id}}/share-policy"),
        ("PUT", f"{_ORG}/evidence/{{evidence_id}}/share-policy"),
        ("GET", f"{_ORG}/investigations/{{investigation_id}}/notes"),
        ("POST", f"{_ORG}/investigations/{{investigation_id}}/notes"),
        ("GET", f"{_ORG}/notes/{{note_id}}"),
        ("PUT", f"{_ORG}/notes/{{note_id}}"),
        ("DELETE", f"{_ORG}/notes/{{note_id}}"),
        ("GET", f"{_ORG}/investigations/{{investigation_id}}/ioc-collections"),
        ("POST", f"{_ORG}/investigations/{{investigation_id}}/ioc-collections"),
        ("GET", f"{_ORG}/ioc-collections/{{collection_id}}"),
        ("PATCH", f"{_ORG}/ioc-collections/{{collection_id}}"),
        ("GET", f"{_ORG}/ioc-collections/{{collection_id}}/items"),
        ("POST", f"{_ORG}/ioc-collections/{{collection_id}}/items"),
        ("DELETE", f"{_ORG}/ioc-collections/{{collection_id}}/items/{{item_id}}"),
        ("GET", f"{_ORG}/ioc-collections/{{collection_id}}/export"),
        ("GET", f"{_ORG}/investigations/{{investigation_id}}/iocs"),
    }
)
