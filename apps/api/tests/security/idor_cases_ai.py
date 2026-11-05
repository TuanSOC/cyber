"""IDOR cases owned by phase 7 (M5, RT11): every `/api/v1/orgs/{org_id}/ai/*` route, plus
the AI victim extender (AI on, a keyed provider config, settings, and a completed run with
its context, output and citations) and a state hook over the victim's AI state.

AI run routes use `{run_id}` like the TI run routes: `PATH_OVERRIDES` points them at the
victim's AI run. `{provider}` is the catalog name `mock` (not an org-owned id).

Until phase 4's context builder is merged, `ai.context.builder` is the phase-1 stub; the
extender then installs the `tests/ai_doubles.py` builder stand-ins (RT12), so the owner's
positive controls for the run and preview routes exercise the routes, not the stub. With
the real builder present it is left alone.
"""

import uuid
from typing import Any

from app.modules.ai.context import builder
from app.modules.ai.contracts import (
    AiRunRequest,
    AiTask,
    CitationResult,
    CitationStatus,
    ClaimStatus,
    ClaimVerdict,
    OutputVerification,
)
from tests.ai_api_helpers import API, enable_ai, finish_run
from tests.ai_doubles import fake_build_run, fake_preview, make_context
from tests.ai_helpers import seed_ai_run
from tests.factories import Registered
from tests.integration.seed import Tenant
from tests.security.idor_types import (
    PathOverrides,
    RouteCases,
    StateHook,
    Victim,
    VictimExtender,
)

_AI = "/api/v1/orgs/{org_id}/ai"

ROUTE_CASES: RouteCases = {
    ("GET", f"{_AI}/providers"): lambda v: {},
    ("PUT", f"{_AI}/providers/{{provider}}"): lambda v: {
        "json": {"enabled": False, "model": "mock-1"}
    },
    ("DELETE", f"{_AI}/providers/{{provider}}/key"): lambda v: {},
    ("POST", f"{_AI}/providers/{{provider}}/verify"): lambda v: {},
    ("GET", f"{_AI}/settings"): lambda v: {},
    ("PUT", f"{_AI}/settings"): lambda v: {
        "json": {"internal_suffixes": ["hijacked.example.net"], "include_ti": False}
    },
    ("GET", f"{_AI}/usage"): lambda v: {},
    ("POST", f"{_AI}/context-preview"): lambda v: {
        "json": {"task": "summarize_pcap", "job_id": v.job_id}
    },
    ("POST", f"{_AI}/runs"): lambda v: {
        "json": {"task": "summarize_pcap", "job_id": v.job_id, "regenerate": True}
    },
    ("GET", f"{_AI}/runs"): lambda v: {"params": {"status": "completed"}},
    ("GET", f"{_AI}/runs/{{run_id}}"): lambda v: {"params": {"pseudonyms": "keep"}},
    ("GET", f"{_AI}/runs/{{run_id}}/context"): lambda v: {"params": {"reveal": "true"}},
}


def _ai_run(victim: Victim) -> dict[str, str]:
    return {"run_id": victim.extra["ai_run_id"]}


PATH_OVERRIDES: PathOverrides = {
    f"{_AI}/runs/{{run_id}}": _ai_run,
    f"{_AI}/runs/{{run_id}}/context": _ai_run,
}
RESOURCE_PARAMS: tuple[str, ...] = ()


async def _builder_is_stub() -> bool:
    req = AiRunRequest(task=AiTask.SUMMARIZE_PCAP, job_id=uuid.uuid4())
    try:
        await builder.preview(None, uuid.uuid4(), uuid.uuid4(), req, None)  # type: ignore[arg-type]
    except NotImplementedError:
        return True
    except Exception:  # noqa: BLE001 - a real builder rejects the dummy call some other way
        return False
    return False


async def _extend(owner: Registered, victim: Victim) -> dict[str, str]:
    if await _builder_is_stub():
        builder.build_run = fake_build_run
        builder.preview = fake_preview
    await enable_ai(owner.client, victim.org_id)
    job_id = uuid.UUID(victim.job_id)
    ctx = make_context(job_id=job_id)
    tenant = Tenant(victim.org_id, owner.user_id, uuid.UUID(victim.investigation_id))
    run_id = await seed_ai_run(tenant, job_id=job_id, ctx=ctx)
    f1 = next(r for r in ctx.refs if r.label == "F1")
    await finish_run(
        victim.org_id,
        run_id,
        body={
            "observed": [
                {
                    "id": "o1",
                    "text": "Victim beacon from INT_IP_1",
                    "confidence": "high",
                    "citations": [{"ref": "F1", "field": "title", "quote": "Periodic beacon"}],
                }
            ],
            "overall_confidence": {"level": "medium", "rationale": "victim rationale"},
        },
        citations=[
            CitationResult(
                claim_path="observed[0].citations[0]",
                section="observed",
                claim_id="o1",
                label="F1",
                kind=f1.kind,
                ref_id=f1.ref_id,
                job_id=job_id,
                field="title",
                quote="Periodic beacon",
                status=CitationStatus.VERIFIED,
            )
        ],
        verification=OutputVerification(claims={"o1": ClaimVerdict(status=ClaimStatus.SUPPORTED)}),
    )
    return {"ai_run_id": str(run_id)}


async def _ai_state(owner: Registered, victim: Victim) -> dict[str, Any]:
    c = owner.client
    base = f"{API}/{victim.org_id}/ai"
    providers = (await c.get(f"{base}/providers")).json()
    settings = (await c.get(f"{base}/settings")).json()
    runs = (await c.get(f"{base}/runs")).json()
    return {
        "ai_providers": sorted(
            (p["name"], p["configured"], p["enabled"], p["key_last4"], p["model"])
            for p in providers["items"]
        ),
        "ai_settings": (
            settings["ai_enabled"],
            settings["include_ti"],
            settings["internal_suffixes"],
            settings["daily_token_budget"],
        ),
        "ai_runs": sorted((r["id"], r["status"]) for r in runs["items"]),
    }


VICTIM_EXTENDERS: list[VictimExtender] = [_extend]
STATE_HOOKS: list[StateHook] = [_ai_state]
