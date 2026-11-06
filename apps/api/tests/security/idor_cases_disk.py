"""IDOR cases owned by M9 phase 8 (the disk read API).

M9 phase 1 froze the routes as 501 stubs: every one is in `PENDING_ROUTES` (skipped and
reported, never silently passed). Phase 8 adds a victim extender that seeds a succeeded disk
job (`tests/disk_helpers.seed_disk_job`, the phase-1 Windows fixture), points `{job_id}` at it
through `PATH_OVERRIDES` (`{file_id}` at a listed file, `{name}` at `bodyfile`), moves each
route into `ROUTE_CASES` and empties `PENDING_ROUTES` (phase 13 asserts it stays empty).
"""

from tests.security.idor_types import PathOverrides, RouteCases, StateHook, VictimExtender

_JOB = "/api/v1/orgs/{org_id}/analyses/{job_id}/disk"

ROUTE_CASES: RouteCases = {}
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ()
VICTIM_EXTENDERS: list[VictimExtender] = []
STATE_HOOKS: list[StateHook] = []
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", _JOB),
        ("GET", f"{_JOB}/partitions"),
        ("GET", f"{_JOB}/files"),
        ("GET", f"{_JOB}/files/{{file_id}}"),
        ("GET", f"{_JOB}/dirs"),
        ("GET", f"{_JOB}/events"),
        ("GET", f"{_JOB}/timeline"),
        ("GET", f"{_JOB}/exports/{{name}}"),
    }
)
