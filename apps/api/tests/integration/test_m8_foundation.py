"""M8 plumbing, final state: every memory route exists, checks membership first and none is a
501 stub any more (phases 7 and 8 landed them); a memory analysis request is accepted by
schema (profile and OS hint defaults, the `memory` queue); a `kind=memory` upload gets no
automatic analysis (RT3)."""

import uuid

from app.core.tenancy import tenant_session
from app.main import app
from app.modules.analysis.models import AnalysisJobIndex
from tests.analysis_helpers import new_case, upload
from tests.factories import csrf, register
from tests.security import idor_cases_memory, idor_cases_memory_sensitivity

MODULES = (idor_cases_memory, idor_cases_memory_sensitivity)
ROUTES: frozenset[tuple[str, str]] = frozenset().union(*(m.ROUTE_CASES for m in MODULES))


def _org_routes() -> set[tuple[str, str]]:
    return {
        (method.upper(), path)
        for path, item in app.openapi()["paths"].items()
        if path.startswith("/api/v1/orgs/{org_id}")
        for method in item
    }


def test_every_m8_route_exists_and_none_is_pending() -> None:
    assert len(ROUTES) == 8
    assert ROUTES <= _org_routes(), sorted(ROUTES - _org_routes())
    assert all(not module.PENDING_ROUTES for module in MODULES)


async def test_m8_routes_check_membership_first_and_none_answers_501() -> None:
    owner = await register(org_name="M8 Org")
    outsider = await register(org_name="M8 Outsider")
    ids = {
        "org_id": str(owner.org_id),
        "job_id": str(uuid.uuid4()),
        "evidence_id": str(uuid.uuid4()),
        "pid": "4",
    }
    for method, template in sorted(ROUTES):
        url = template.format(**ids)
        body = {"acknowledge": True, "reason": "case closed"} if method == "POST" else None
        response = await owner.client.request(
            method,
            url,
            **({"json": body, "headers": csrf(owner.client)} if body is not None else {}),
        )
        # Unknown job / evidence ids: implemented, so a 404 rather than the 501 stub.
        assert response.status_code != 501, (url, response.text)
        assert response.status_code < 500, (url, response.text)
        foreign = await outsider.client.request(
            method,
            url,
            **({"json": body, "headers": csrf(outsider.client)} if body is not None else {}),
        )
        assert foreign.status_code in (403, 404), (url, foreign.status_code)


async def test_a_memory_request_is_accepted_with_its_defaults() -> None:
    owner = await register(org_name="M8 Run Org")
    case_id = await new_case(owner)
    evidence = await upload(owner.client, owner.org_id, case_id, b"\0" * 4096, "memory.raw")
    response = await owner.client.post(
        f"/api/v1/orgs/{owner.org_id}/evidence/{evidence['id']}/analyses",
        json={"analyzer": "memory"},
        headers=csrf(owner.client),
    )
    assert response.status_code == 201, response.text
    job = response.json()
    assert (job["analyzer"], job["profile"], job["os_hint"]) == ("memory", "triage", "auto")
    assert job["auto"] is False
    async with tenant_session(None, None) as s:
        index = await s.get(AnalysisJobIndex, uuid.UUID(job["id"]))
    assert index is not None and index.analyzer == "memory"


async def test_memory_profiles_are_refused_for_other_analyzers() -> None:
    owner = await register(org_name="M8 Refusal Org")
    case_id = await new_case(owner)
    evidence = await upload(owner.client, owner.org_id, case_id, b"data" * 64, "x.bin")
    for body in (
        {"analyzer": "static", "profile": "triage"},
        {"analyzer": "memory", "profile": "av"},
        {"analyzer": "pcap", "os_hint": "linux"},
    ):
        response = await owner.client.post(
            f"/api/v1/orgs/{owner.org_id}/evidence/{evidence['id']}/analyses",
            json=body,
            headers=csrf(owner.client),
        )
        assert response.status_code == 422, (body, response.text)


async def test_a_memory_upload_gets_no_automatic_analysis() -> None:
    """RT3: a small file would otherwise get an automatic static `av` run."""
    owner = await register(org_name="M8 Upload Org")
    case_id = await new_case(owner)
    response = await owner.client.post(
        f"/api/v1/orgs/{owner.org_id}/investigations/{case_id}/evidence",
        params={"filename": "workstation.mem", "kind": "memory"},
        content=b"\x01" * (1024 * 1024),
        headers={"Content-Type": "application/octet-stream", **csrf(owner.client)},
    )
    assert response.status_code == 201, response.text
    evidence_id = response.json()["id"]
    jobs = await owner.client.get(f"/api/v1/orgs/{owner.org_id}/evidence/{evidence_id}/analyses")
    assert jobs.json()["items"] == []
    # The same bytes without `kind=memory` still get the M3 automatic AV scan.
    plain = await upload(owner.client, owner.org_id, case_id, b"\x01" * 1024, "other.bin")
    jobs = await owner.client.get(f"/api/v1/orgs/{owner.org_id}/evidence/{plain['id']}/analyses")
    assert [j["profile"] for j in jobs.json()["items"]] == ["av"]
