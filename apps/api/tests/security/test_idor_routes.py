"""Route-wide IDOR / tenant-isolation coverage.

Every API route with an `{org_id}` path parameter must have an entry in ROUTE_CASES; the test
fails when a new org-scoped route is added without one, so coverage cannot silently drift.
Each case is also replayed by the resource owner (positive control): a request that fails for
everyone would otherwise pass the 404 assertions vacuously.

M5 (RT11): the cases of later phases live in per-owner modules (`idor_cases_reads.py`,
`idor_cases_ai.py`), merged here with their victim extenders, path overrides, resource
parameters and state hooks; the cases and assertions below are unchanged.
"""

import ast
import dataclasses
import uuid
import warnings
from pathlib import Path
from typing import Any

import pytest
from httpx import AsyncClient

from app.core.config import get_settings
from app.main import app
from app.modules.organizations.models import MemberRole
from app.modules.reports import dispatch
from app.modules.reports import signing as report_signing
from tests import static_results
from tests.factories import Registered, add_member, csrf, make_user, new_client, register
from tests.pcap_results import seed_results
from tests.security import (
    idor_cases_ai,
    idor_cases_attack,
    idor_cases_case,
    idor_cases_correlation,
    idor_cases_ops,
    idor_cases_reads,
    idor_cases_renders,
    idor_cases_reports,
    idor_cases_retention,
)
from tests.security.idor_types import (
    PathOverrides,
    Request,
    RouteCases,
    StateHook,
    Victim,
    VictimExtender,
)
from tests.ti_api_helpers import add_result, capture_sends, enable, lookup

CASE_MODULES = (idor_cases_reads, idor_cases_ai)
# M6: the per-owner modules of phases 2-5. Each also exports `PENDING_ROUTES`: frozen 501
# stubs whose cases land with their phase. They are skipped here and reported (never
# silently passed); phase 9 asserts every set is empty.
M6_CASE_MODULES = (idor_cases_case, idor_cases_reports, idor_cases_renders, idor_cases_attack)
# M7: the per-owner modules of phases 3, 4 and 5 (same `PENDING_ROUTES` rule; phase 11
# asserts every set is empty).
M7_CASE_MODULES = (idor_cases_retention, idor_cases_correlation, idor_cases_ops)
PENDING_MODULES = (*M6_CASE_MODULES, *M7_CASE_MODULES)
CASE_MODULES = (*CASE_MODULES, *PENDING_MODULES)
PENDING_ROUTES: frozenset[tuple[str, str]] = frozenset().union(
    *(module.PENDING_ROUTES for module in PENDING_MODULES)
)

# (method, path template) -> request kwargs that are valid for the resource owner.
ROUTE_CASES: RouteCases = {
    ("GET", "/api/v1/orgs/{org_id}"): lambda v: {},
    ("PATCH", "/api/v1/orgs/{org_id}"): lambda v: {"json": {"name": "Hijacked"}},
    ("GET", "/api/v1/orgs/{org_id}/storage"): lambda v: {},
    ("GET", "/api/v1/orgs/{org_id}/members"): lambda v: {},
    ("POST", "/api/v1/orgs/{org_id}/members"): lambda v: {
        "json": {"email": v.outsider_email, "role": "viewer"}
    },
    ("PATCH", "/api/v1/orgs/{org_id}/members/{member_id}"): lambda v: {"json": {"role": "viewer"}},
    ("DELETE", "/api/v1/orgs/{org_id}/members/{member_id}"): lambda v: {},
    ("GET", "/api/v1/orgs/{org_id}/audit-logs"): lambda v: {},
    ("GET", "/api/v1/orgs/{org_id}/investigations"): lambda v: {},
    ("POST", "/api/v1/orgs/{org_id}/investigations"): lambda v: {
        "json": {"title": "Injected case", "severity": "low"}
    },
    ("GET", "/api/v1/orgs/{org_id}/investigations/{investigation_id}"): lambda v: {},
    ("PATCH", "/api/v1/orgs/{org_id}/investigations/{investigation_id}"): lambda v: {
        "json": {"title": "Hijacked case"}
    },
    ("POST", "/api/v1/orgs/{org_id}/investigations/{investigation_id}/evidence"): lambda v: {
        "params": {"filename": "planted.bin"},
        "content": b"planted",
        "headers": {"Content-Type": "application/octet-stream"},
    },
    ("GET", "/api/v1/orgs/{org_id}/investigations/{investigation_id}/evidence"): lambda v: {},
    ("GET", "/api/v1/orgs/{org_id}/evidence/{evidence_id}"): lambda v: {},
    ("GET", "/api/v1/orgs/{org_id}/evidence/{evidence_id}/download"): lambda v: {},
    ("POST", "/api/v1/orgs/{org_id}/evidence/{evidence_id}/verify"): lambda v: {},
    ("POST", "/api/v1/orgs/{org_id}/evidence/{evidence_id}/archive"): lambda v: {},
    ("GET", "/api/v1/orgs/{org_id}/evidence/{evidence_id}/custody"): lambda v: {},
    ("POST", "/api/v1/orgs/{org_id}/evidence/{evidence_id}/analyses"): lambda v: {
        "json": {"analyzer": "pcap"}
    },
    ("GET", "/api/v1/orgs/{org_id}/evidence/{evidence_id}/analyses"): lambda v: {},
    ("GET", "/api/v1/orgs/{org_id}/analyses"): lambda v: {},
    ("GET", "/api/v1/orgs/{org_id}/analyses/{job_id}"): lambda v: {},
    ("GET", "/api/v1/orgs/{org_id}/analyses/{job_id}/findings"): lambda v: {
        "params": {"severity": "high"}
    },
    ("GET", "/api/v1/orgs/{org_id}/analyses/{job_id}/flows"): lambda v: {
        "params": {"sort": "ts", "proto": "tcp"}
    },
    ("GET", "/api/v1/orgs/{org_id}/analyses/{job_id}/records"): lambda v: {
        "params": {"kind": "dns", "q": "example"}
    },
    ("GET", "/api/v1/orgs/{org_id}/analyses/{job_id}/alerts"): lambda v: {},
    ("GET", "/api/v1/orgs/{org_id}/analyses/{job_id}/iocs"): lambda v: {"params": {"q": "192"}},
    ("GET", "/api/v1/orgs/{org_id}/analyses/{job_id}/timeline"): lambda v: {},
    ("GET", "/api/v1/orgs/{org_id}/analyses/{job_id}/sample"): lambda v: {},
    ("GET", "/api/v1/orgs/{org_id}/analyses/{job_id}/sections"): lambda v: {},
    ("GET", "/api/v1/orgs/{org_id}/analyses/{job_id}/imports"): lambda v: {
        "params": {"library": "kernel32.dll", "q": "Virtual"}
    },
    ("GET", "/api/v1/orgs/{org_id}/analyses/{job_id}/exports"): lambda v: {"params": {"q": "Dll"}},
    ("GET", "/api/v1/orgs/{org_id}/analyses/{job_id}/resources"): lambda v: {},
    ("GET", "/api/v1/orgs/{org_id}/analyses/{job_id}/strings"): lambda v: {
        "params": {"encoding": "ascii", "q": "http"}
    },
    ("GET", "/api/v1/orgs/{org_id}/analyses/{job_id}/signatures"): lambda v: {
        "params": {"engine": "yara"}
    },
    ("GET", "/api/v1/orgs/{org_id}/analyses/{job_id}/capabilities"): lambda v: {
        "params": {"namespace": "host-interaction", "attack": "T1055"}
    },
    ("GET", "/api/v1/orgs/{org_id}/analyses/{job_id}/report"): lambda v: {},
    # Threat intel (M4).
    ("GET", "/api/v1/orgs/{org_id}/integrations"): lambda v: {},
    ("PUT", "/api/v1/orgs/{org_id}/integrations/{provider}"): lambda v: {
        "json": {"limits": {"per_minute": 5}, "enabled": False}
    },
    ("DELETE", "/api/v1/orgs/{org_id}/integrations/{provider}/key"): lambda v: {},
    ("POST", "/api/v1/orgs/{org_id}/integrations/{provider}/verify"): lambda v: {},
    ("GET", "/api/v1/orgs/{org_id}/ti/settings"): lambda v: {},
    ("PUT", "/api/v1/orgs/{org_id}/ti/settings"): lambda v: {
        "json": {"excluded_suffixes": ["hijacked.example.net"]}
    },
    ("POST", "/api/v1/orgs/{org_id}/analyses/{job_id}/enrichments"): lambda v: {"json": {}},
    ("POST", "/api/v1/orgs/{org_id}/ti/lookups"): lambda v: {
        "json": {"values": [{"value": "hit.example.com"}]}
    },
    ("GET", "/api/v1/orgs/{org_id}/ti/runs"): lambda v: {"params": {"status": "queued"}},
    ("GET", "/api/v1/orgs/{org_id}/ti/runs/{run_id}"): lambda v: {},
    ("GET", "/api/v1/orgs/{org_id}/ti/results"): lambda v: {"params": {"value": "hit.example.com"}},
    ("GET", "/api/v1/orgs/{org_id}/ti/results/{result_id}"): lambda v: {},
}
# Routes of static jobs only: replayed against the victim's static job.
STATIC_JOB_ROUTES = {
    f"/api/v1/orgs/{{org_id}}/analyses/{{job_id}}/{name}"
    for name in (
        "sample",
        "sections",
        "imports",
        "exports",
        "resources",
        "strings",
        "signatures",
        "capabilities",
        "report",
    )
}


# Merged per-owner case modules (RT11): a duplicate route would be a plan bug.
VICTIM_EXTENDERS: list[VictimExtender] = []
PATH_OVERRIDES: PathOverrides = {}
STATE_HOOKS: list[StateHook] = []
for _module in CASE_MODULES:
    assert not set(_module.ROUTE_CASES) & set(ROUTE_CASES), _module.__name__
    ROUTE_CASES.update(_module.ROUTE_CASES)
    VICTIM_EXTENDERS.extend(_module.VICTIM_EXTENDERS)
    PATH_OVERRIDES.update(_module.PATH_OVERRIDES)
    STATE_HOOKS.extend(_module.STATE_HOOKS)

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
RESOURCE_PARAMS = (
    "{member_id}",
    "{investigation_id}",
    "{evidence_id}",
    "{job_id}",
    "{run_id}",
    "{result_id}",
    *(param for module in CASE_MODULES for param in module.RESOURCE_PARAMS),
)
APP_DIR = Path(__file__).resolve().parents[2] / "app"


def org_scoped_routes() -> set[tuple[str, str]]:
    """From the OpenAPI schema (the public contract; FastAPI nests included routers)."""
    return {
        (method.upper(), path)
        for path, item in app.openapi()["paths"].items()
        if "{org_id}" in path
        for method in item
        if method in HTTP_METHODS
    }


@pytest.fixture(autouse=True)
def _no_publish(monkeypatch: pytest.MonkeyPatch) -> None:
    """Threat intel publishes (`ti.enrich`, `ti.verify`) are captured: no live enrich worker
    takes part in these tests (analysis jobs are still queued for real, as before).

    The M6 victim extenders may install stand-ins by plain assignment (the report signing
    key loader, the render dispatch; `idor_cases_reports._install_stand_ins`; the seeded
    version's public key, `_publish_seed_key`): registering the current objects with
    monkeypatch first restores them after every test, so no stand-in outlives this module
    (it broke `report_signing.reset_cache` in later tests)."""
    capture_sends(monkeypatch, analyses=False)
    settings = get_settings()
    monkeypatch.setattr(settings, "report_signing_public_keys", settings.report_signing_public_keys)
    monkeypatch.setattr(report_signing, "_private_keys", report_signing._private_keys)
    monkeypatch.setattr(dispatch, "create_render", dispatch.create_render)
    monkeypatch.setattr(dispatch, "dispatch_render", dispatch.dispatch_render)


def test_route_enumeration_is_not_empty() -> None:
    assert len(org_scoped_routes()) >= 22


def test_every_org_scoped_route_has_an_idor_case() -> None:
    missing = org_scoped_routes() - set(ROUTE_CASES) - PENDING_ROUTES
    stale = set(ROUTE_CASES) - org_scoped_routes()
    assert missing == set(), f"add IDOR cases for: {sorted(missing)}"
    assert stale == set(), f"remove stale IDOR cases: {sorted(stale)}"


def test_pending_routes_are_real_routes_without_cases() -> None:
    """M6: a pending route must exist (a 501 stub) and must not also have a case; the count
    is reported so a pending route is never silently passed."""
    assert PENDING_ROUTES <= org_scoped_routes(), sorted(PENDING_ROUTES - org_scoped_routes())
    assert PENDING_ROUTES.isdisjoint(ROUTE_CASES), sorted(PENDING_ROUTES & set(ROUTE_CASES))
    for module in PENDING_MODULES:
        assert module.PENDING_ROUTES.isdisjoint(module.ROUTE_CASES), module.__name__
    if PENDING_ROUTES:
        warnings.warn(
            f"{len(PENDING_ROUTES)} routes have no IDOR case yet (PENDING_ROUTES)",
            stacklevel=1,
        )


def test_no_route_is_hidden_from_the_schema() -> None:
    """Enumeration relies on OpenAPI, so routes must not opt out of it or bypass the routers."""
    offenders = []
    for path in APP_DIR.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.keyword) and node.arg == "include_in_schema":
                offenders.append(f"{path.name}:{node.value.lineno}")
            if isinstance(node, ast.Attribute) and node.attr in {"add_api_route", "add_route"}:
                offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []


async def _victim() -> tuple[Registered, Victim]:
    owner = await register(org_name="Victim Org")
    c = owner.client
    analyst_id = await make_user()
    await add_member(owner.org_id, analyst_id, MemberRole.ANALYST)
    outsider = await register(org_name="Outsider Org")
    members = (await c.get(f"/api/v1/orgs/{owner.org_id}/members")).json()["items"]
    member = next(m for m in members if m["user_id"] == str(analyst_id))
    case = (
        await c.post(
            f"/api/v1/orgs/{owner.org_id}/investigations",
            json={"title": "Victim case", "severity": "high"},
            headers=csrf(c),
        )
    ).json()
    evidence = (
        await c.post(
            f"/api/v1/orgs/{owner.org_id}/investigations/{case['id']}/evidence",
            params={"filename": "victim.pcap"},
            content=b"victim evidence bytes",
            headers={"Content-Type": "application/octet-stream", **csrf(c)},
        )
    ).json()
    second = (
        await c.post(
            f"/api/v1/orgs/{owner.org_id}/investigations/{case['id']}/evidence",
            params={"filename": "second.bin"},
            content=b"second evidence",
            headers={"Content-Type": "application/octet-stream", **csrf(c)},
        )
    ).json()
    job = (
        await c.post(
            f"/api/v1/orgs/{owner.org_id}/evidence/{second['id']}/analyses",
            json={"analyzer": "pcap"},
            headers=csrf(c),
        )
    ).json()
    # The job has persisted results, so the result routes have real rows to leak.
    await seed_results(owner.org_id, uuid.UUID(job["id"]))
    # The upload of the second evidence queued a static `av` run: give it results too.
    jobs = (await c.get(f"/api/v1/orgs/{owner.org_id}/evidence/{second['id']}/analyses")).json()
    [static_job] = [j for j in jobs["items"] if j["analyzer"] == "static"]
    await static_results.seed_results(owner.org_id, uuid.UUID(static_job["id"]))
    # Threat intel: a configured provider, settings, a run and one of its answers.
    await enable(c, owner.org_id)
    settings = await c.put(
        f"/api/v1/orgs/{owner.org_id}/ti/settings",
        json={"excluded_suffixes": ["victim-corp.net"]},
        headers=csrf(c),
    )
    assert settings.status_code == 200, settings.text
    run = await lookup(c, owner.org_id, "hit.example.com")
    assert run.status_code == 202, run.text
    run_id = run.json()["run"]["id"]
    result_id = await add_result(owner.org_id, run_id)
    victim = Victim(
        owner.org_id,
        member["id"],
        case["id"],
        evidence["id"],
        job["id"],
        static_job["id"],
        outsider_email=outsider.email,
        run_id=run_id,
        result_id=str(result_id),
    )
    for extend in VICTIM_EXTENDERS:  # resources of the later-phase case modules (RT11)
        victim = dataclasses.replace(victim, extra={**victim.extra, **await extend(owner, victim)})
    return owner, victim


def _url(template: str, org_id: uuid.UUID, victim: Victim) -> str:
    static = template in STATIC_JOB_ROUTES
    params = {
        "member_id": victim.member_id,
        "investigation_id": victim.investigation_id,
        "evidence_id": victim.evidence_id,
        "job_id": victim.static_job_id if static else victim.job_id,
        "run_id": victim.run_id,
        "result_id": victim.result_id,
        "provider": victim.provider,
        **victim.extra,
    }
    override = PATH_OVERRIDES.get(template)
    if override is not None:
        params.update(override(victim))
    return template.format(org_id=org_id, **params)


async def _call(client: AsyncClient, method: str, url: str, request: Request) -> int:
    headers = {**csrf(client), **request.get("headers", {})}
    response = await client.request(
        method,
        url,
        json=request.get("json"),
        content=request.get("content"),
        params=request.get("params"),
        headers=headers,
    )
    return response.status_code


async def _victim_state(owner: Registered, victim: Victim) -> dict[str, Any]:
    c = owner.client
    base = f"/api/v1/orgs/{victim.org_id}"
    org = (await c.get(base)).json()
    members = (await c.get(f"{base}/members")).json()
    cases = (await c.get(f"{base}/investigations")).json()
    case_evidence = (
        await c.get(f"{base}/investigations/{victim.investigation_id}/evidence")
    ).json()
    evidence = (await c.get(f"{base}/evidence/{victim.evidence_id}")).json()
    jobs = (await c.get(f"{base}/analyses")).json()
    integrations = (await c.get(f"{base}/integrations")).json()
    ti_settings = (await c.get(f"{base}/ti/settings")).json()
    ti_runs = (await c.get(f"{base}/ti/runs")).json()
    extra: dict[str, Any] = {}
    for hook in STATE_HOOKS:
        extra.update(await hook(owner, victim))
    return {
        **extra,
        "integrations": sorted(
            (i["name"], i["configured"], i["enabled"], i["key_last4"], str(i["limits"]))
            for i in integrations["items"]
        ),
        "ti_settings": ti_settings["excluded_suffixes"],
        "ti_runs": sorted((r["id"], r["status"]) for r in ti_runs["items"]),
        "jobs": sorted((j["id"], j["evidence_id"]) for j in jobs["items"]),
        "name": org["name"],
        "members": sorted((m["email"], m["role"]) for m in members["items"]),
        "cases": sorted((i["id"], i["title"], i["status"]) for i in cases["items"]),
        "case_evidence": sorted(e["id"] for e in case_evidence["items"]),
        "evidence": (evidence["status"], evidence["hashes"]),
    }


@pytest.mark.parametrize("route", sorted(ROUTE_CASES))
async def test_owner_request_succeeds(route: tuple[str, str]) -> None:
    """Positive control: the exact request the attack tests replay works for the owner."""
    owner, victim = await _victim()
    method, template = route
    status = await _call(
        owner.client, method, _url(template, victim.org_id, victim), ROUTE_CASES[route](victim)
    )
    assert status < 400, (method, template, status)


@pytest.mark.parametrize("route", sorted(ROUTE_CASES))
async def test_other_org_member_gets_404(route: tuple[str, str]) -> None:
    owner, victim = await _victim()
    before = await _victim_state(owner, victim)
    attacker = await register(org_name="Attacker Org")
    method, template = route

    status = await _call(
        attacker.client, method, _url(template, victim.org_id, victim), ROUTE_CASES[route](victim)
    )

    assert status == 404, (method, template, status)
    assert await _victim_state(owner, victim) == before  # nothing changed


@pytest.mark.parametrize(
    "route",
    sorted(r for r in ROUTE_CASES if any(p in r[1] for p in RESOURCE_PARAMS)),
)
async def test_own_org_with_foreign_resource_ids_gets_404(route: tuple[str, str]) -> None:
    owner, victim = await _victim()
    before = await _victim_state(owner, victim)
    attacker = await register(org_name="Attacker Org")
    method, template = route

    url = _url(template, attacker.org_id, victim)  # attacker's own org, victim's resource ids
    status = await _call(attacker.client, method, url, ROUTE_CASES[route](victim))

    assert status == 404, (method, template, status)
    assert await _victim_state(owner, victim) == before


@pytest.mark.parametrize("route", sorted(ROUTE_CASES))
async def test_unauthenticated_gets_401(route: tuple[str, str]) -> None:
    _, victim = await _victim()
    method, template = route
    client = new_client()
    # A matching CSRF pair, so the request reaches authentication rather than CSRF rejection.
    client.cookies.set("cl_csrf", "probe", domain="api.test", path="/")
    status = await _call(
        client, method, _url(template, victim.org_id, victim), ROUTE_CASES[route](victim)
    )
    assert status == 401, (method, template, status)
