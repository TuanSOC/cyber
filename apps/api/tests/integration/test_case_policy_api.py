"""The share policy set through the API (M6 phase 2): `PATCH /investigations/{id}` flags and
TLP, and `GET / PUT /evidence/{id}/share-policy`.

A flag set through these routes blocks the AI preview, the AI run and the TI enrichment of
that case or evidence (the phase-1 call sites; nothing is published, so no provider is ever
called). Turning a flag off needs `integrations.manage`; the evidence row is never touched.
"""

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob
from app.modules.evidence.models import Evidence
from app.modules.organizations.models import MemberRole
from tests.ai_api_helpers import (
    capture_ai_sends,
    enable_ai,
    incident_builder,
    preview,
    request_run,
    use_fake_builder,
)
from tests.factories import Registered, add_member, csrf, login, make_user, register, unique_email
from tests.integration.test_case_status import API, move, patch
from tests.ti_api_helpers import capture_sends, enrich_job, succeeded_job
from tests.ti_api_helpers import enable as enable_ti


async def _job_evidence_and_case(org_id: uuid.UUID, job_id: uuid.UUID) -> tuple[str, str]:
    async with tenant_session(org_id, None) as s:
        row = (
            await s.execute(
                select(Evidence.id, Evidence.investigation_id)
                .join(AnalysisJob, AnalysisJob.evidence_id == Evidence.id)
                .where(AnalysisJob.id == job_id)
            )
        ).one()
    return str(row[0]), str(row[1])


async def put_policy(
    client: AsyncClient, org_id: uuid.UUID, evidence_id: str, **flags: bool
) -> Any:
    body = {"ai_excluded": False, "ti_excluded": False, **flags}
    return await client.put(
        f"{API}/{org_id}/evidence/{evidence_id}/share-policy", json=body, headers=csrf(client)
    )


async def _member(reg: Registered, role: str) -> AsyncClient:
    email = unique_email(role)
    await add_member(reg.org_id, await make_user(email), MemberRole(role))
    return await login(email)


@pytest.mark.parametrize(
    ("where", "flags", "reason"),
    [
        ("case", {"ai_excluded": True}, "case_ai_excluded"),
        ("case", {"tlp": "red"}, "tlp_red"),
        ("evidence", {"ai_excluded": True}, "evidence_ai_excluded"),
    ],
)
async def test_ai_flag_set_through_the_api_blocks_preview_and_run(
    monkeypatch: pytest.MonkeyPatch, where: str, flags: dict[str, Any], reason: str
) -> None:
    sent = capture_ai_sends(monkeypatch)
    reg = await register(org_name="Policy API AI")
    await enable_ai(reg.client, reg.org_id)
    job = await succeeded_job(reg)
    use_fake_builder(monkeypatch, build=incident_builder([job]))
    evidence_id, case_id = await _job_evidence_and_case(reg.org_id, job)
    body = {"task": "summarize_pcap", "job_id": str(job)}
    assert (await preview(reg.client, reg.org_id, **body)).status_code == 200

    if where == "case":
        response = await patch(reg.client, reg.org_id, case_id, **flags)
    else:
        response = await put_policy(reg.client, reg.org_id, evidence_id, **flags)
    assert response.status_code == 200, response.text

    for call in (preview, request_run):
        refused = await call(reg.client, reg.org_id, **body)
        assert refused.status_code == 409, refused.text
        assert refused.json()["error"]["code"] == "policy_blocked"
        assert refused.json()["error"]["reason"] == reason
    assert sent.runs == []  # no run was ever dispatched to a provider


@pytest.mark.parametrize(
    ("where", "flags", "reason"),
    [
        ("case", {"ti_excluded": True}, "case_ti_excluded"),
        ("case", {"tlp": "red"}, "tlp_red"),
        ("evidence", {"ti_excluded": True}, "evidence_ti_excluded"),
    ],
)
async def test_ti_flag_set_through_the_api_blocks_enrichment(
    monkeypatch: pytest.MonkeyPatch, where: str, flags: dict[str, Any], reason: str
) -> None:
    sent = capture_sends(monkeypatch)
    reg = await register(org_name="Policy API TI")
    await enable_ti(reg.client, reg.org_id)
    job = await succeeded_job(reg)
    evidence_id, case_id = await _job_evidence_and_case(reg.org_id, job)
    if where == "case":
        response = await patch(reg.client, reg.org_id, case_id, **flags)
    else:
        response = await put_policy(reg.client, reg.org_id, evidence_id, **flags)
    assert response.status_code == 200, response.text

    refused = await enrich_job(reg.client, reg.org_id, job)
    assert refused.status_code == 409, refused.text
    assert refused.json()["error"]["reason"] == reason
    assert sent.runs == []


async def test_turning_a_flag_off_through_the_api_unblocks(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = capture_sends(monkeypatch)
    reg = await register(org_name="Policy API off")
    await enable_ti(reg.client, reg.org_id)
    job = await succeeded_job(reg)
    evidence_id, _ = await _job_evidence_and_case(reg.org_id, job)
    assert (
        await put_policy(reg.client, reg.org_id, evidence_id, ti_excluded=True)
    ).status_code == 200
    assert (await enrich_job(reg.client, reg.org_id, job)).status_code == 409
    assert (await put_policy(reg.client, reg.org_id, evidence_id)).status_code == 200  # owner
    allowed = await enrich_job(reg.client, reg.org_id, job)
    assert allowed.status_code == 202, allowed.text
    assert len(sent.runs) == 1


async def test_evidence_policy_read_write_and_effective_policy() -> None:
    reg = await register()
    job = await succeeded_job(reg)
    evidence_id, case_id = await _job_evidence_and_case(reg.org_id, job)
    url = f"{API}/{reg.org_id}/evidence/{evidence_id}/share-policy"

    initial = (await reg.client.get(url)).json()
    assert initial == {
        "evidence_id": evidence_id,
        "ai_excluded": False,
        "ti_excluded": False,
        "effective": {"ai_blocked": False, "ti_blocked": False, "reasons": []},
        "updated_by": None,
        "updated_at": None,
    }
    put = await put_policy(reg.client, reg.org_id, evidence_id, ai_excluded=True)
    assert put.status_code == 200, put.text
    body = put.json()
    assert (body["ai_excluded"], body["ti_excluded"]) == (True, False)
    assert body["effective"] == {
        "ai_blocked": True,
        "ti_blocked": False,
        "reasons": ["evidence_ai_excluded"],
    }
    assert body["updated_by"] == str(reg.user_id) and body["updated_at"]
    assert (await reg.client.get(url)).json() == body

    # The case's TLP shows in the evidence's effective policy.
    assert (await patch(reg.client, reg.org_id, case_id, tlp="red")).status_code == 200
    effective = (await reg.client.get(url)).json()["effective"]
    assert effective["reasons"] == ["tlp_red", "evidence_ai_excluded"]

    # EvidenceOut reads carry the flags.
    one = (await reg.client.get(f"{API}/{reg.org_id}/evidence/{evidence_id}")).json()
    assert (one["ai_excluded"], one["ti_excluded"]) == (True, False)
    listed = (await reg.client.get(f"{API}/{reg.org_id}/investigations/{case_id}/evidence")).json()
    [item] = [e for e in listed["items"] if e["id"] == evidence_id]
    assert (item["ai_excluded"], item["ti_excluded"]) == (True, False)


async def test_evidence_row_and_custody_are_untouched() -> None:
    reg = await register()
    job = await succeeded_job(reg)
    evidence_id, _ = await _job_evidence_and_case(reg.org_id, job)
    base = f"{API}/{reg.org_id}/evidence/{evidence_id}"
    before = (await reg.client.get(base)).json()
    custody_before = (await reg.client.get(f"{base}/custody")).json()
    await put_policy(reg.client, reg.org_id, evidence_id, ai_excluded=True, ti_excluded=True)
    after = (await reg.client.get(base)).json()
    assert {k: v for k, v in after.items() if not k.endswith("_excluded")} == {
        k: v for k, v in before.items() if not k.endswith("_excluded")
    }
    assert (await reg.client.get(f"{base}/custody")).json() == custody_before


async def test_evidence_policy_role_rules_and_audit() -> None:
    reg = await register()
    job = await succeeded_job(reg)
    evidence_id, _ = await _job_evidence_and_case(reg.org_id, job)
    analyst = await _member(reg, "analyst")
    viewer = await _member(reg, "viewer")

    assert (await put_policy(viewer, reg.org_id, evidence_id, ai_excluded=True)).status_code == 403
    on = await put_policy(analyst, reg.org_id, evidence_id, ai_excluded=True, ti_excluded=True)
    assert on.status_code == 200, on.text
    off = await put_policy(analyst, reg.org_id, evidence_id, ti_excluded=True)
    assert off.status_code == 403, off.text
    current = (await viewer.get(f"{API}/{reg.org_id}/evidence/{evidence_id}/share-policy")).json()
    assert (current["ai_excluded"], current["ti_excluded"]) == (True, True)
    same = await put_policy(analyst, reg.org_id, evidence_id, ai_excluded=True, ti_excluded=True)
    assert same.status_code == 200  # nothing turned off
    assert (await put_policy(reg.client, reg.org_id, evidence_id)).status_code == 200

    logs = (
        await reg.client.get(
            f"{API}/{reg.org_id}/audit-logs", params={"action": "evidence.share_policy_updated"}
        )
    ).json()
    assert logs["total"] == 2  # the no-op wrote nothing
    newest = logs["items"][0]["details"]
    assert newest == {
        "from": {"ai_excluded": True, "ti_excluded": True},
        "to": {"ai_excluded": False, "ti_excluded": False},
    }


async def test_evidence_policy_of_an_archived_case_is_read_only() -> None:
    reg = await register()
    job = await succeeded_job(reg)
    evidence_id, case_id = await _job_evidence_and_case(reg.org_id, job)
    await move(reg.client, reg.org_id, case_id, "closed", "archived")
    response = await put_policy(reg.client, reg.org_id, evidence_id, ai_excluded=True)
    assert (response.status_code, response.json()["error"]["code"]) == (
        409,
        "investigation_archived",
    )
    assert (
        await reg.client.get(f"{API}/{reg.org_id}/evidence/{evidence_id}/share-policy")
    ).status_code == 200


async def test_evidence_policy_is_tenant_scoped() -> None:
    reg = await register()
    other = await register()
    job = await succeeded_job(reg)
    evidence_id, _ = await _job_evidence_and_case(reg.org_id, job)
    for org_id in (reg.org_id, other.org_id):
        url = f"{API}/{org_id}/evidence/{evidence_id}/share-policy"
        assert (await other.client.get(url)).status_code == 404
        put = await put_policy(other.client, org_id, evidence_id, ai_excluded=True)
        assert put.status_code == 404
    unknown = await reg.client.get(f"{API}/{reg.org_id}/evidence/{uuid.uuid4()}/share-policy")
    assert unknown.status_code == 404
    bad = await reg.client.put(
        f"{API}/{reg.org_id}/evidence/{evidence_id}/share-policy",
        json={"ai_excluded": True},
        headers=csrf(reg.client),
    )
    assert bad.status_code == 422
