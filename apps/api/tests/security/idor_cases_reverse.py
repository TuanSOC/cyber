"""IDOR cases owned by M10 phase 8 (the RE read API and the capability-functions route).

M10 phase 1 froze the routes as 501 stubs: every one is in `PENDING_ROUTES` (skipped and
reported, never silently passed). Phase 8 adds a victim extender that seeds a succeeded RE job
(`tests/reverse_helpers.seed_re_job`, the phase-1 `pe_full` fixture) and its source static job
with capability locations (`seed_static_source_job`), points `{job_id}` / `{entry}` /
`{capability_id}` at them through `PATH_OVERRIDES`, moves each route into `ROUTE_CASES` and
empties `PENDING_ROUTES` (phase 12 asserts it stays empty).
"""

from tests.security.idor_types import PathOverrides, RouteCases, StateHook, VictimExtender

_JOB = "/api/v1/orgs/{org_id}/analyses/{job_id}/reverse"
_STATIC = "/api/v1/orgs/{org_id}/analyses/{job_id}"

ROUTE_CASES: RouteCases = {}
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ()
VICTIM_EXTENDERS: list[VictimExtender] = []
STATE_HOOKS: list[StateHook] = []
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", _JOB),
        ("GET", f"{_JOB}/functions"),
        ("GET", f"{_JOB}/functions/{{entry}}"),
        ("GET", f"{_JOB}/functions/{{entry}}/code"),
        ("GET", f"{_JOB}/imports"),
        ("GET", f"{_JOB}/strings"),
        ("GET", f"{_STATIC}/capabilities/{{capability_id}}/functions"),
    }
)
