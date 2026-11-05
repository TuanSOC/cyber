"""IDOR cases owned by M7 phase 3 (retention policy, preview, runs and legal holds).

The victim extender seeds, in the victim org, a retention policy (with its index row), a
finished run (`{retention_run_id}`) and an active org hold (`{hold_id}`). The owner's
requests are valid (a PUT that changes nothing, a preview, a dry-run request: no active run
exists, a case hold on the victim case, a release of the seeded hold). The state hook
snapshots the victim's policy, holds and runs, so a cross-org write that slipped through
would show up. Every route has its case (phase 11 asserts `PENDING_ROUTES` is empty).
"""

import uuid
from typing import Any

from app.core.tenancy import tenant_session
from app.modules.retention.models import RetentionRun
from tests.factories import Registered
from tests.integration.seed import Tenant
from tests.ops_helpers import seed_hold, seed_retention_policy
from tests.security.idor_types import PathOverrides, RouteCases, StateHook, Victim, VictimExtender

_ORG = "/api/v1/orgs/{org_id}"
_POLICY = {"ti_results_days": 400, "ai_runs_days": None, "closed_case_days": None, "enforce": False}

ROUTE_CASES: RouteCases = {
    ("GET", f"{_ORG}/retention/policy"): lambda v: {},
    ("PUT", f"{_ORG}/retention/policy"): lambda v: {"json": _POLICY},
    ("POST", f"{_ORG}/retention/preview"): lambda v: {"json": {}},
    ("GET", f"{_ORG}/retention/runs"): lambda v: {},
    ("POST", f"{_ORG}/retention/runs"): lambda v: {"json": {"dry_run": True}},
    ("GET", f"{_ORG}/retention/runs/{{retention_run_id}}"): lambda v: {
        "params": {"outcome": "purged", "limit": 10, "offset": 0}
    },
    ("GET", f"{_ORG}/legal-holds"): lambda v: {},
    ("POST", f"{_ORG}/legal-holds"): lambda v: {
        "json": {
            "scope": "investigation",
            "investigation_id": v.investigation_id,
            "reason": "Injected hold",
        }
    },
    ("POST", f"{_ORG}/legal-holds/{{hold_id}}/release"): lambda v: {
        "json": {"reason": "Hijacked release"}
    },
}
PATH_OVERRIDES: PathOverrides = {}
RESOURCE_PARAMS: tuple[str, ...] = ("{retention_run_id}", "{hold_id}")


async def _extend(owner: Registered, victim: Victim) -> dict[str, str]:
    tenant = Tenant(victim.org_id, owner.user_id, uuid.UUID(victim.investigation_id))
    await seed_retention_policy(tenant, ti_results_days=400)
    async with tenant_session(victim.org_id, owner.user_id) as session:
        run = RetentionRun(
            organization_id=victim.org_id,
            mode="dry_run",
            trigger="manual",
            status="completed",
            requested_by=owner.user_id,
            policy={"ti_results_days": 400, "enforce": False},
        )
        session.add(run)
    hold_id = await seed_hold(tenant, reason="Victim hold")
    return {"retention_run_id": str(run.id), "hold_id": str(hold_id)}


async def _retention_state(owner: Registered, victim: Victim) -> dict[str, Any]:
    c = owner.client
    base = f"/api/v1/orgs/{victim.org_id}"
    policy = (await c.get(f"{base}/retention/policy")).json()
    holds = (await c.get(f"{base}/legal-holds")).json()
    runs = (await c.get(f"{base}/retention/runs")).json()
    return {
        "retention_policy": sorted((k, str(v)) for k, v in policy.items()),
        "legal_holds": sorted(
            (h["id"], h["scope"], h["released_at"], h["investigation_id"]) for h in holds["items"]
        ),
        "retention_runs": sorted((r["id"], r["status"], r["mode"]) for r in runs["items"]),
    }


VICTIM_EXTENDERS: list[VictimExtender] = [_extend]
STATE_HOOKS: list[StateHook] = [_retention_state]
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset()
