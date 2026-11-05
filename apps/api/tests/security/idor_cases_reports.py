"""IDOR cases owned by M6 phase 3 (report drafts, finalize, versions, citations).

Created in phase 1 with no cases: every route below is listed in `PENDING_ROUTES`, which
`test_idor_routes.py` skips and reports. Phase 3 adds the cases, the victim extender (a
report with a finalized version) and the resource parameters (`{report_id}`,
`{version}`), and empties `PENDING_ROUTES`.
"""

from tests.security.idor_types import PathOverrides, RouteCases, StateHook, VictimExtender

_ORG = "/api/v1/orgs/{org_id}"
_VERSION = f"{_ORG}/reports/{{report_id}}/versions/{{version}}"

ROUTE_CASES: RouteCases = {}
VICTIM_EXTENDERS: list[VictimExtender] = []
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ()
STATE_HOOKS: list[StateHook] = []
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", f"{_ORG}/reports"),
        ("GET", f"{_ORG}/investigations/{{investigation_id}}/reports"),
        ("POST", f"{_ORG}/investigations/{{investigation_id}}/reports"),
        ("GET", f"{_ORG}/reports/{{report_id}}"),
        ("PATCH", f"{_ORG}/reports/{{report_id}}"),
        ("POST", f"{_ORG}/reports/{{report_id}}/discard"),
        ("POST", f"{_ORG}/reports/{{report_id}}/preview"),
        ("POST", f"{_ORG}/reports/{{report_id}}/finalize"),
        ("GET", f"{_ORG}/reports/{{report_id}}/versions"),
        ("GET", _VERSION),
        ("GET", f"{_VERSION}/content"),
        ("GET", f"{_VERSION}/snapshot"),
        ("GET", f"{_VERSION}/signature"),
        ("GET", f"{_ORG}/cited-by"),
    }
)
