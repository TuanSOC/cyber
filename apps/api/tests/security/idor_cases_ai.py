"""IDOR cases owned by phase 7 (M5, RT11): every `/api/v1/orgs/{org_id}/ai/*` route, plus
the AI victim extenders (provider config, settings, a run with its context).

Created empty in phase 1; `test_idor_routes.py` merges every name below. Add cases only for
routes of the owning phase. AI run routes use `{run_id}` like the TI run routes: override it
for your templates with `PATH_OVERRIDES` (e.g. `lambda v: {"run_id": v.extra["ai_run_id"]}`)."""

from tests.security.idor_types import PathOverrides, RouteCases, StateHook, VictimExtender

ROUTE_CASES: RouteCases = {}
VICTIM_EXTENDERS: list[VictimExtender] = []
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ()
STATE_HOOKS: list[StateHook] = []
