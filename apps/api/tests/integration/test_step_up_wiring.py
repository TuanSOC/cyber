"""Integration tests for Step-Up wiring across M4-M7 services (M11 phase 6)."""

import uuid

import pytest

from app.core.tenancy import tenant_session
from app.modules.evidence.models import Evidence
from app.modules.investigations.models import (
    EvidenceSharePolicy,
)
from app.modules.retention.models import LegalHold
from tests.ai_api_helpers import capture_ai_sends, put_provider
from tests.ai_helpers import AI_SENTINEL_KEY
from tests.factories import csrf, register
from tests.identity_helpers import session_id_of, set_step_up
from tests.ti_api_helpers import capture_sends, put_integration
from tests.ti_helpers import SENTINEL_KEY


@pytest.fixture
def ti_sent(monkeypatch: pytest.MonkeyPatch):
    return capture_sends(monkeypatch)


@pytest.fixture
def ai_sent(monkeypatch: pytest.MonkeyPatch):
    return capture_ai_sends(monkeypatch)


async def test_step_up_wiring_threat_intel(ti_sent) -> None:
    reg = await register(org_name="StepUp TI Org")
    sid = session_id_of(reg.client)

    # 1. PUT integration with api_key without step-up -> 403 step_up_required
    resp1 = await put_integration(
        reg.client,
        reg.org_id,
        "mock",
        api_key=SENTINEL_KEY,
        enabled=True,
        acknowledge_terms=True,
        auto_step_up=False,
    )
    assert resp1.status_code == 403
    assert resp1.json()["error"]["code"] == "step_up_required"
    assert resp1.json()["error"]["action"] == "provider_key_change"

    # Step up -> succeeds
    await set_step_up(sid, seconds_ago=5)
    resp2 = await put_integration(
        reg.client, reg.org_id, "mock", api_key=SENTINEL_KEY, enabled=True, acknowledge_terms=True
    )
    assert resp2.status_code == 200

    # 2. DELETE key with expired step-up -> 403 step_up_required
    await set_step_up(sid, seconds_ago=1000)
    del_resp1 = await reg.client.delete(
        f"/api/v1/orgs/{reg.org_id}/integrations/mock/key", headers=csrf(reg.client)
    )
    assert del_resp1.status_code == 403
    assert del_resp1.json()["error"]["code"] == "step_up_required"

    # Step up -> succeeds
    await set_step_up(sid, seconds_ago=5)
    del_resp2 = await reg.client.delete(
        f"/api/v1/orgs/{reg.org_id}/integrations/mock/key", headers=csrf(reg.client)
    )
    assert del_resp2.status_code == 204


async def test_step_up_wiring_ai(ai_sent) -> None:
    reg = await register(org_name="StepUp AI Org")
    sid = session_id_of(reg.client)

    # 1. PUT provider with api_key without step-up -> 403 step_up_required
    resp1 = await put_provider(
        reg.client,
        reg.org_id,
        "mock",
        api_key=AI_SENTINEL_KEY,
        enabled=True,
        acknowledge_terms=True,
        auto_step_up=False,
    )
    assert resp1.status_code == 403
    assert resp1.json()["error"]["code"] == "step_up_required"
    assert resp1.json()["error"]["action"] == "provider_key_change"

    # Step up -> succeeds
    await set_step_up(sid, seconds_ago=5)
    resp2 = await put_provider(
        reg.client,
        reg.org_id,
        "mock",
        api_key=AI_SENTINEL_KEY,
        enabled=True,
        acknowledge_terms=True,
    )
    assert resp2.status_code == 200

    # 2. DELETE key with expired step-up -> 403 step_up_required
    await set_step_up(sid, seconds_ago=1000)
    del_resp1 = await reg.client.delete(
        f"/api/v1/orgs/{reg.org_id}/ai/providers/mock/key", headers=csrf(reg.client)
    )
    assert del_resp1.status_code == 403
    assert del_resp1.json()["error"]["code"] == "step_up_required"

    # Step up -> succeeds
    await set_step_up(sid, seconds_ago=5)
    del_resp2 = await reg.client.delete(
        f"/api/v1/orgs/{reg.org_id}/ai/providers/mock/key", headers=csrf(reg.client)
    )
    assert del_resp2.status_code == 204


async def test_step_up_wiring_investigations() -> None:
    reg = await register(org_name="StepUp Case Org")
    sid = session_id_of(reg.client)

    # Create case with severity medium, then set ai_excluded=True
    case_resp = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations",
        json={"title": "Step-up Case", "severity": "medium"},
        headers=csrf(reg.client),
    )
    assert case_resp.status_code == 201
    case_id = case_resp.json()["id"]

    await reg.client.patch(
        f"/api/v1/orgs/{reg.org_id}/investigations/{case_id}",
        json={"ai_excluded": True},
        headers=csrf(reg.client),
    )

    # 1. PATCH lowering TLP without step-up -> 403 step_up_required (tlp_downgrade)
    patch_tlp_blocked = await reg.client.patch(
        f"/api/v1/orgs/{reg.org_id}/investigations/{case_id}",
        json={"tlp": "green", "acknowledge_tlp_downgrade": True},
        headers=csrf(reg.client),
    )
    assert patch_tlp_blocked.status_code == 403
    assert patch_tlp_blocked.json()["error"]["code"] == "step_up_required"
    assert patch_tlp_blocked.json()["error"]["action"] == "tlp_downgrade"

    # Step up -> succeeds
    await set_step_up(sid, seconds_ago=5)
    patch_tlp_ok = await reg.client.patch(
        f"/api/v1/orgs/{reg.org_id}/investigations/{case_id}",
        json={"tlp": "green", "acknowledge_tlp_downgrade": True},
        headers=csrf(reg.client),
    )
    assert patch_tlp_ok.status_code == 200

    # 2. PATCH turning ai_excluded off without step-up ->
    # 403 step_up_required (share_policy_release)
    await set_step_up(sid, seconds_ago=1000)
    patch_flag_blocked = await reg.client.patch(
        f"/api/v1/orgs/{reg.org_id}/investigations/{case_id}",
        json={"ai_excluded": False},
        headers=csrf(reg.client),
    )
    assert patch_flag_blocked.status_code == 403
    assert patch_flag_blocked.json()["error"]["code"] == "step_up_required"
    assert patch_flag_blocked.json()["error"]["action"] == "share_policy_release"

    # Step up -> succeeds
    await set_step_up(sid, seconds_ago=5)
    patch_flag_ok = await reg.client.patch(
        f"/api/v1/orgs/{reg.org_id}/investigations/{case_id}",
        json={"ai_excluded": False},
        headers=csrf(reg.client),
    )
    assert patch_flag_ok.status_code == 200


async def test_step_up_wiring_reports() -> None:
    reg = await register(org_name="StepUp Report Org")
    sid = session_id_of(reg.client)

    # Create case with severity high, then set TLP to RED
    case_resp = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations",
        json={"title": "Report Case", "severity": "high"},
        headers=csrf(reg.client),
    )
    assert case_resp.status_code == 201
    case_id = case_resp.json()["id"]

    await reg.client.patch(
        f"/api/v1/orgs/{reg.org_id}/investigations/{case_id}",
        json={"tlp": "red"},
        headers=csrf(reg.client),
    )

    # 1. Create report lowering TLP (amber vs red) without step-up -> 403 step_up_required
    create_blocked = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations/{case_id}/reports",
        json={
            "title": "Downgraded Report",
            "tlp": "amber",
            "acknowledge_tlp_downgrade": True,
        },
        headers=csrf(reg.client),
    )
    assert create_blocked.status_code == 403
    assert create_blocked.json()["error"]["code"] == "step_up_required"
    assert create_blocked.json()["error"]["action"] == "tlp_downgrade"

    # Step up -> succeeds
    await set_step_up(sid, seconds_ago=5)
    create_ok = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations/{case_id}/reports",
        json={
            "title": "Downgraded Report",
            "tlp": "amber",
            "acknowledge_tlp_downgrade": True,
        },
        headers=csrf(reg.client),
    )
    assert create_ok.status_code == 201
    report_id = create_ok.json()["id"]

    # 2. Patch draft lowering TLP further (green vs red case) without step-up -> 403
    await set_step_up(sid, seconds_ago=1000)
    patch_blocked = await reg.client.patch(
        f"/api/v1/orgs/{reg.org_id}/reports/{report_id}",
        json={"revision": 1, "tlp": "green", "acknowledge_tlp_downgrade": True},
        headers=csrf(reg.client),
    )
    assert patch_blocked.status_code == 403
    assert patch_blocked.json()["error"]["code"] == "step_up_required"

    # Step up -> succeeds
    await set_step_up(sid, seconds_ago=5)
    patch_ok = await reg.client.patch(
        f"/api/v1/orgs/{reg.org_id}/reports/{report_id}",
        json={"revision": 1, "tlp": "green", "acknowledge_tlp_downgrade": True},
        headers=csrf(reg.client),
    )
    assert patch_ok.status_code == 200


async def test_step_up_wiring_evidence_share_policy() -> None:
    reg = await register(org_name="StepUp Evidence Org")
    sid = session_id_of(reg.client)

    # Create case and seed evidence with ai_excluded = True
    case_resp = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations",
        json={"title": "Evidence Case", "severity": "low"},
        headers=csrf(reg.client),
    )
    case_id = uuid.UUID(case_resp.json()["id"])
    ev_id = uuid.uuid4()

    async with tenant_session(reg.org_id, reg.user_id) as session:
        ev = Evidence(
            id=ev_id,
            organization_id=reg.org_id,
            investigation_id=case_id,
            original_filename="capture.pcap",
            detected_mime="application/vnd.tcpdump.pcap",
            detected_description="tcpdump capture file",
            size_bytes=100,
            storage_bucket="cyberlab-evidence",
            storage_key=f"test/{ev_id}",
            storage_version_id="v1",
            uploaded_by=reg.user_id,
        )
        session.add(ev)
        pol = EvidenceSharePolicy(
            evidence_id=ev_id,
            organization_id=reg.org_id,
            ai_excluded=True,
            ti_excluded=False,
            updated_by=reg.user_id,
        )
        session.add(pol)

    # PUT share policy turning ai_excluded off without step-up -> 403 step_up_required
    put_blocked = await reg.client.put(
        f"/api/v1/orgs/{reg.org_id}/evidence/{ev_id}/share-policy",
        json={"ai_excluded": False, "ti_excluded": False},
        headers=csrf(reg.client),
    )
    assert put_blocked.status_code == 403
    assert put_blocked.json()["error"]["code"] == "step_up_required"
    assert put_blocked.json()["error"]["action"] == "share_policy_release"

    # Step up -> succeeds
    await set_step_up(sid, seconds_ago=5)
    put_ok = await reg.client.put(
        f"/api/v1/orgs/{reg.org_id}/evidence/{ev_id}/share-policy",
        json={"ai_excluded": False, "ti_excluded": False},
        headers=csrf(reg.client),
    )
    assert put_ok.status_code == 200
    assert put_ok.json()["ai_excluded"] is False


async def test_step_up_wiring_retention() -> None:
    reg = await register(org_name="StepUp Retention Org")
    sid = session_id_of(reg.client)

    # 1. PUT retention policy lowering value without step-up ->
    # 403 step_up_required (retention_destructive)
    retention_payload = {
        "ti_results_days": 100,
        "ai_runs_days": None,
        "closed_case_days": None,
        "enforce": False,
    }
    put_blocked = await reg.client.put(
        f"/api/v1/orgs/{reg.org_id}/retention/policy",
        json=retention_payload,
        headers=csrf(reg.client),
    )
    assert put_blocked.status_code == 403
    assert put_blocked.json()["error"]["code"] == "step_up_required"
    assert put_blocked.json()["error"]["action"] == "retention_destructive"

    # Step up -> succeeds
    await set_step_up(sid, seconds_ago=5)
    put_ok = await reg.client.put(
        f"/api/v1/orgs/{reg.org_id}/retention/policy",
        json=retention_payload,
        headers=csrf(reg.client),
    )
    assert put_ok.status_code == 200

    # 2. Seed active hold and test legal hold release
    hold_id = uuid.uuid4()
    async with tenant_session(reg.org_id, reg.user_id) as session:
        hold = LegalHold(
            id=hold_id,
            organization_id=reg.org_id,
            scope="org",
            reason="Litigation hold",
            placed_by=reg.user_id,
        )
        session.add(hold)

    # Release without step-up -> 403 step_up_required (legal_hold_release)
    await set_step_up(sid, seconds_ago=1000)
    rel_blocked = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/legal-holds/{hold_id}/release",
        json={"reason": "Settled"},
        headers=csrf(reg.client),
    )
    assert rel_blocked.status_code == 403
    assert rel_blocked.json()["error"]["code"] == "step_up_required"
    assert rel_blocked.json()["error"]["action"] == "legal_hold_release"

    # Step up -> succeeds
    await set_step_up(sid, seconds_ago=5)
    rel_ok = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/legal-holds/{hold_id}/release",
        json={"reason": "Settled"},
        headers=csrf(reg.client),
    )
    assert rel_ok.status_code == 200
    assert rel_ok.json()["released_at"] is not None

