"""M8 phase 1 plumbing: the frozen memory routes exist, check membership and answer 501 until
their phase lands; a memory analysis request is accepted by schema (profile and OS hint
defaults, the `memory` queue); a `kind=memory` upload gets no automatic analysis (RT3)."""

import uuid

from app.core.tenancy import tenant_session
from app.main import app
from app.modules.analysis.models import AnalysisJobIndex
from tests.analysis_helpers import new_case, upload
from tests.factories import csrf, register
from tests.security import idor_cases_memory, idor_cases_memory_sensitivity

PENDING = idor_cases_memory.PENDING_ROUTES | idor_cases_memory_sensitivity.PENDING_ROUTES


def _org_routes() -> set[tuple[str, str]]:
    return {
        (method.upper(), path)
        for path, item in app.openapi()["paths"].items()
        if path.startswith("/api/v1/orgs/{org_id}")
        for method in item
    }


def test_every_m8_route_is_frozen() -> None:
    assert len(PENDING) == 8
    assert PENDING <= _org_routes(), sorted(PENDING - _org_routes())


async def test_m8_routes_answer_501_to_members_and_404_to_outsiders() -> None:
    owner = await register(org_name="M8 Org")
    outsider = await register(org_name="M8 Outsider")
    ids = {
        "org_id": str(owner.org_id),
        "job_id": str(uuid.uuid4()),
        "evidence_id": str(uuid.uuid4()),
        "pid": "4",
    }
    for method, template in sorted(PENDING):
        url = template.format(**ids)
        kwargs = (
            {"json": {"acknowledge": True, "reason": "case closed"}, "headers": csrf(owner.client)}
            if method == "POST"
            else {}
        )
        response = await owner.client.request(method, url, **kwargs)
        assert response.status_code == 501, (url, response.text)
        assert response.json()["error"]["code"] == "not_implemented"
        foreign = await outsider.client.request(
            method,
            url,
            **(
                {"json": kwargs["json"], "headers": csrf(outsider.client)}
                if method == "POST"
                else {}
            ),
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
