"""IDOR cases owned by M8 phase 7 (the memory read API; phase-1 501 stubs).

Phase 7 adds a victim extender that seeds a succeeded memory job in the victim org
(`tests/memory_helpers.seed_memory_job`, resource param `{memory_job_id}` through
`PATH_OVERRIDES`, since `{job_id}` is the victim's pcap job) and a case per route; until then
every route is pending (phase 11 asserts `PENDING_ROUTES` is empty).
"""

from tests.security.idor_types import PathOverrides, RouteCases, StateHook, VictimExtender

_JOB = "/api/v1/orgs/{org_id}/analyses/{job_id}/memory"

ROUTE_CASES: RouteCases = {}
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ()
VICTIM_EXTENDERS: list[VictimExtender] = []
STATE_HOOKS: list[StateHook] = []
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", _JOB),
        ("GET", f"{_JOB}/processes"),
        ("GET", f"{_JOB}/processes/{{pid}}"),
        ("GET", f"{_JOB}/connections"),
        ("GET", f"{_JOB}/injections"),
        ("GET", f"{_JOB}/artifacts"),
    }
)
