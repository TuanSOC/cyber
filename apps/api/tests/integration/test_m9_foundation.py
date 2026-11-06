"""M9 phase 1 plumbing: the frozen disk routes exist, check membership and answer 501 until their
phase lands; a disk analysis request is validated by schema (segments required) and answers 501
until phase 7; the generic evidence sensitivity routes (RT2) serve every source, with the
`disk` / `derived` codes and audit actions, while M8's memory routes keep theirs."""

import uuid

from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.main import app
from app.modules.audit.models import AuditLog
from tests.analysis_helpers import new_case, upload
from tests.disk_helpers import restricted_disk_evidence
from tests.factories import csrf, register
from tests.integration.seed import Tenant
from tests.memory_helpers import restricted_memory_evidence
from tests.security import idor_cases_disk, idor_cases_disk_exports

PENDING = idor_cases_disk.PENDING_ROUTES | idor_cases_disk_exports.PENDING_ROUTES


def _org_routes() -> set[tuple[str, str]]:
    return {
        (method.upper(), path)
        for path, item in app.openapi()["paths"].items()
        if path.startswith("/api/v1/orgs/{org_id}")
        for method in item
    }


def test_every_m9_route_is_frozen() -> None:
    assert len(PENDING) == 11
    assert PENDING <= _org_routes(), sorted(PENDING - _org_routes())
    generic = {
        ("GET", "/api/v1/orgs/{org_id}/evidence/{evidence_id}/sensitivity"),
        ("POST", "/api/v1/orgs/{org_id}/evidence/{evidence_id}/sensitivity/release"),
    }
    assert generic <= _org_routes()


async def test_m9_routes_answer_501_to_members_and_404_to_outsiders() -> None:
    owner = await register(org_name="M9 Org")
    outsider = await register(org_name="M9 Outsider")
    ids = {
        "org_id": str(owner.org_id),
        "job_id": str(uuid.uuid4()),
        "file_id": str(uuid.uuid4()),
        "export_id": str(uuid.uuid4()),
        "name": "bodyfile",
    }
    body = {"file_ids": [str(uuid.uuid4())]}
    for method, template in sorted(PENDING):
        url = template.format(**ids)
        kwargs = {"json": body, "headers": csrf(owner.client)} if method == "POST" else {}
        response = await owner.client.request(method, url, **kwargs)
        assert response.status_code == 501, (url, response.text)
        assert response.json()["error"]["code"] == "not_implemented"
        foreign = await outsider.client.request(
            method,
            url,
            **({"json": body, "headers": csrf(outsider.client)} if method == "POST" else {}),
        )
        assert foreign.status_code in (403, 404), (url, foreign.status_code)


async def test_a_disk_request_needs_segments_and_answers_501_until_phase_7() -> None:
    owner = await register(org_name="M9 Run Org")
    case_id = await new_case(owner)
    evidence = await upload(owner.client, owner.org_id, case_id, b"\0" * 4096, "disk.raw")
    url = f"/api/v1/orgs/{owner.org_id}/evidence/{evidence['id']}/analyses"
    for bad in (
        {"analyzer": "disk"},
        {"analyzer": "disk", "segments": []},
        {"analyzer": "disk", "segments": [evidence["id"]], "profile": "extract"},
        {"analyzer": "static", "segments": [evidence["id"]]},
    ):
        response = await owner.client.post(url, json=bad, headers=csrf(owner.client))
        assert response.status_code == 422, (bad, response.text)
    response = await owner.client.post(
        url, json={"analyzer": "disk", "segments": [evidence["id"]]}, headers=csrf(owner.client)
    )
    assert response.status_code == 501, response.text
    jobs = await owner.client.get(f"/api/v1/orgs/{owner.org_id}/evidence/{evidence['id']}/analyses")
    assert all(j["analyzer"] != "disk" for j in jobs.json()["items"])


async def _actions(org_id: uuid.UUID, evidence_id: uuid.UUID) -> list[str]:
    async with tenant_session(org_id, None) as s:
        rows = await s.scalars(
            select(AuditLog.action).where(
                AuditLog.organization_id == org_id, AuditLog.target_id == evidence_id
            )
        )
        return list(rows)


async def test_generic_sensitivity_serves_disk_and_derived_sources() -> None:
    owner = await register(org_name="M9 Sensitivity Org")
    case_id = uuid.UUID(await new_case(owner))
    t = Tenant(owner.org_id, owner.user_id, case_id)
    base = f"/api/v1/orgs/{owner.org_id}/evidence"
    for source in ("disk", "derived"):
        evidence_id = await restricted_disk_evidence(t, source=source)  # type: ignore[arg-type]
        got = await owner.client.get(f"{base}/{evidence_id}/sensitivity")
        assert got.status_code == 200, got.text
        assert (got.json()["state"], got.json()["source"]) == ("restricted", source)
        listed = await owner.client.get(f"/api/v1/orgs/{owner.org_id}/evidence/{evidence_id}")
        assert listed.json()["sensitivity"] == {"state": "restricted", "source": source}
        assert listed.json()["memory_sensitivity"] is None  # M8's field: memory images only
        # The share-policy guard answers the generic code for disk / derived evidence.
        put = await owner.client.put(
            f"{base}/{evidence_id}/share-policy",
            json={"ai_excluded": False, "ti_excluded": True},
            headers=csrf(owner.client),
        )
        assert put.status_code == 409, put.text
        assert put.json()["error"]["code"] == "evidence_sensitivity_restricted"
        release = {"acknowledge": True, "reason": "Reviewed with the data owner"}
        done = await owner.client.post(
            f"{base}/{evidence_id}/sensitivity/release", json=release, headers=csrf(owner.client)
        )
        assert done.status_code == 200, done.text
        assert done.json()["state"] == "released"
        again = await owner.client.post(
            f"{base}/{evidence_id}/sensitivity/release", json=release, headers=csrf(owner.client)
        )
        assert again.status_code == 409
        assert again.json()["error"]["code"] == "evidence_sensitivity_released"
        assert "disk.sensitivity_released" in await _actions(owner.org_id, evidence_id)


async def test_generic_routes_keep_m8_codes_for_memory_evidence() -> None:
    owner = await register(org_name="M9 Memory Org")
    case_id = uuid.UUID(await new_case(owner))
    t = Tenant(owner.org_id, owner.user_id, case_id)
    evidence_id = await restricted_memory_evidence(t)
    base = f"/api/v1/orgs/{owner.org_id}/evidence/{evidence_id}"
    got = await owner.client.get(f"{base}/sensitivity")
    assert (got.json()["state"], got.json()["source"]) == ("restricted", "memory")
    put = await owner.client.put(
        f"{base}/share-policy",
        json={"ai_excluded": False, "ti_excluded": True},
        headers=csrf(owner.client),
    )
    assert put.json()["error"]["code"] == "memory_sensitivity_restricted"
    release = {"acknowledge": True, "reason": "Reviewed with the data owner"}
    done = await owner.client.post(
        f"{base}/sensitivity/release", json=release, headers=csrf(owner.client)
    )
    assert done.status_code == 200, done.text
    again = await owner.client.post(
        f"{base}/sensitivity/release", json=release, headers=csrf(owner.client)
    )
    assert again.json()["error"]["code"] == "memory_sensitivity_released"
    assert "memory.sensitivity_released" in await _actions(owner.org_id, evidence_id)


async def test_batch_release_of_an_unknown_job_is_404() -> None:
    """Phase 9 implements the batch arm (RT20; `test_disk_batch_release.py`)."""
    owner = await register(org_name="M9 Batch Org")
    case_id = uuid.UUID(await new_case(owner))
    evidence_id = await restricted_disk_evidence(Tenant(owner.org_id, owner.user_id, case_id))
    response = await owner.client.post(
        f"/api/v1/orgs/{owner.org_id}/evidence/{evidence_id}/sensitivity/release",
        json={"acknowledge": True, "reason": "batch", "job_id": str(uuid.uuid4())},
        headers=csrf(owner.client),
    )
    assert response.status_code == 404, response.text
