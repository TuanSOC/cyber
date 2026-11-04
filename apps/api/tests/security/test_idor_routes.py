"""Route-wide IDOR / tenant-isolation coverage.

Every API route with an `{org_id}` path parameter must have an entry in ROUTE_CASES; the test
fails when a new org-scoped route is added without one, so coverage cannot silently drift.
Each case is also replayed by the resource owner (positive control): a request that fails for
everyone would otherwise pass the 404 assertions vacuously.
"""

import ast
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from httpx import AsyncClient

from app.main import app
from app.modules.organizations.models import MemberRole
from tests import static_results
from tests.factories import Registered, add_member, csrf, make_user, new_client, register
from tests.pcap_results import seed_results


@dataclass(frozen=True)
class Victim:
    """Resources owned by another organization."""

    org_id: uuid.UUID
    member_id: str  # an analyst in the victim org (not the owner, so the owner may change it)
    investigation_id: str
    evidence_id: str
    job_id: str  # an analysis job (on a second evidence, so the first can still be analyzed)
    static_job_id: str  # the second evidence's automatic static job, with results
    outsider_email: str  # a real user who is not a member of the victim org


Request = dict[str, Any]
CaseBuilder = Callable[[Victim], Request]

# (method, path template) -> request kwargs that are valid for the resource owner.
ROUTE_CASES: dict[tuple[str, str], CaseBuilder] = {
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


HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
RESOURCE_PARAMS = ("{member_id}", "{investigation_id}", "{evidence_id}", "{job_id}")
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


def test_route_enumeration_is_not_empty() -> None:
    assert len(org_scoped_routes()) >= 22


def test_every_org_scoped_route_has_an_idor_case() -> None:
    missing = org_scoped_routes() - set(ROUTE_CASES)
    stale = set(ROUTE_CASES) - org_scoped_routes()
    assert missing == set(), f"add IDOR cases for: {sorted(missing)}"
    assert stale == set(), f"remove stale IDOR cases: {sorted(stale)}"


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
    return owner, Victim(
        owner.org_id,
        member["id"],
        case["id"],
        evidence["id"],
        job["id"],
        static_job["id"],
        outsider_email=outsider.email,
    )


def _url(template: str, org_id: uuid.UUID, victim: Victim) -> str:
    static = template in STATIC_JOB_ROUTES
    return template.format(
        org_id=org_id,
        member_id=victim.member_id,
        investigation_id=victim.investigation_id,
        evidence_id=victim.evidence_id,
        job_id=victim.static_job_id if static else victim.job_id,
    )


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
    return {
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
