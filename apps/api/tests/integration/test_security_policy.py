"""Integration tests for Org Security Policy CRUD and preconditions (M11 phase 6)."""

from datetime import UTC, datetime

from app.modules.identity import totp
from app.modules.mail.templates import MailTemplate
from app.modules.organizations.models import MemberRole
from tests.factories import add_membership, csrf, login, make_user, register, unique_email
from tests.identity_helpers import (
    mark_email_verified,
    outbox_rows,
    seed_domain,
    seed_idp_config,
    session_id_of,
    set_step_up,
)


async def test_get_security_policy_defaults() -> None:
    reg = await register(org_name="Policy Defaults Org")
    resp = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/security-policy")
    assert resp.status_code == 200
    data = resp.json()
    assert data["require_mfa"] is False
    assert data["sso_enforced"] is False
    assert data["owners_break_glass"] is True
    assert data["api_keys_enabled"] is False
    assert data["invite_domain_allowlist"] == []
    assert data["updated_by"] is None
    assert data["updated_at"] is None


async def test_put_security_policy_step_up_required() -> None:
    reg = await register(org_name="Policy StepUp Org")
    # No step-up performed -> 403 step_up_required
    body = {
        "require_mfa": False,
        "sso_enforced": False,
        "owners_break_glass": True,
        "api_keys_enabled": True,
        "invite_domain_allowlist": [],
    }
    resp = await reg.client.put(
        f"/api/v1/orgs/{reg.org_id}/security-policy",
        json=body,
        headers=csrf(reg.client),
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "step_up_required"


async def test_put_security_policy_requires_security_manage() -> None:
    reg = await register(org_name="Policy RBAC Org")
    analyst_email = unique_email("analyst")
    analyst_user = await make_user(analyst_email)
    await add_membership(reg.org_id, analyst_user, MemberRole.ANALYST)

    analyst_client = await login(analyst_email)
    sid = session_id_of(analyst_client)
    await set_step_up(sid, seconds_ago=5)

    body = {
        "require_mfa": False,
        "sso_enforced": False,
        "owners_break_glass": True,
        "api_keys_enabled": True,
        "invite_domain_allowlist": [],
    }
    resp = await analyst_client.put(
        f"/api/v1/orgs/{reg.org_id}/security-policy",
        json=body,
        headers=csrf(analyst_client),
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "forbidden"


async def test_put_security_policy_require_mfa_precondition() -> None:
    reg = await register(org_name="Policy MFA Actor Precondition Org")
    sid = session_id_of(reg.client)
    await set_step_up(sid, seconds_ago=5)

    # Actor has no OTP in AMR -> cannot enable require_mfa
    body = {
        "require_mfa": True,
        "sso_enforced": False,
        "owners_break_glass": True,
        "api_keys_enabled": False,
        "invite_domain_allowlist": [],
    }
    resp = await reg.client.put(
        f"/api/v1/orgs/{reg.org_id}/security-policy",
        json=body,
        headers=csrf(reg.client),
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "mfa_required_for_actor"


async def test_put_security_policy_sso_enforced_precondition() -> None:
    reg = await register(org_name="Policy SSO Precondition Org")
    await mark_email_verified(reg.user_id)
    sid = session_id_of(reg.client)
    await set_step_up(sid, seconds_ago=5)

    # Enroll TOTP so actor has OTP in AMR
    setup_resp = await reg.client.post("/api/v1/auth/mfa/totp/setup", headers=csrf(reg.client))
    secret_bytes = totp.decode_b32(setup_resp.json()["secret"])
    step = int(datetime.now(UTC).timestamp() // 30)
    await reg.client.post(
        "/api/v1/auth/mfa/totp/confirm",
        json={"code": totp.code_at(secret_bytes, step - 1)},
        headers=csrf(reg.client),
    )
    await set_step_up(sid, seconds_ago=5)

    # Case 1: No IdP config and no verified domain -> 409 sso_not_ready
    body = {
        "require_mfa": False,
        "sso_enforced": True,
        "owners_break_glass": True,
        "api_keys_enabled": False,
        "invite_domain_allowlist": [],
    }
    resp = await reg.client.put(
        f"/api/v1/orgs/{reg.org_id}/security-policy",
        json=body,
        headers=csrf(reg.client),
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "sso_not_ready"

    # Case 2: Seed IdP config and verified domain using identity_helpers
    await seed_idp_config(reg.org_id, reg.user_id, enabled=True)
    await seed_domain(reg.org_id, reg.user_id, "corp.example", verified=True)

    # Now with break_glass=True and actor has OTP in AMR -> succeeds!
    resp2 = await reg.client.put(
        f"/api/v1/orgs/{reg.org_id}/security-policy",
        json=body,
        headers=csrf(reg.client),
    )
    assert resp2.status_code == 200
    assert resp2.json()["sso_enforced"] is True


async def test_put_security_policy_domain_allowlist_validation() -> None:
    reg = await register(org_name="Policy Domain Validation Org")
    sid = session_id_of(reg.client)
    await set_step_up(sid, seconds_ago=5)

    # Invalid domain format -> 422
    body = {
        "require_mfa": False,
        "sso_enforced": False,
        "owners_break_glass": True,
        "api_keys_enabled": False,
        "invite_domain_allowlist": ["not-a-domain", "https://bad.com"],
    }
    resp = await reg.client.put(
        f"/api/v1/orgs/{reg.org_id}/security-policy",
        json=body,
        headers=csrf(reg.client),
    )
    assert resp.status_code == 422


async def test_put_security_policy_success_and_owner_notifications() -> None:
    reg = await register(org_name="Policy Success Org")
    await mark_email_verified(reg.user_id)
    sid = session_id_of(reg.client)
    await set_step_up(sid, seconds_ago=5)

    # Enroll TOTP
    setup_resp = await reg.client.post("/api/v1/auth/mfa/totp/setup", headers=csrf(reg.client))
    secret_bytes = totp.decode_b32(setup_resp.json()["secret"])
    step = int(datetime.now(UTC).timestamp() // 30)
    await reg.client.post(
        "/api/v1/auth/mfa/totp/confirm",
        json={"code": totp.code_at(secret_bytes, step - 1)},
        headers=csrf(reg.client),
    )
    await set_step_up(sid, seconds_ago=5)

    # Add a second owner
    owner2 = await make_user("second_owner@policy.example")
    await add_membership(reg.org_id, owner2, MemberRole.OWNER)

    body = {
        "require_mfa": True,
        "sso_enforced": False,
        "owners_break_glass": True,
        "api_keys_enabled": True,
        "invite_domain_allowlist": ["corp.example", "sub.corp.example"],
    }
    resp = await reg.client.put(
        f"/api/v1/orgs/{reg.org_id}/security-policy",
        json=body,
        headers=csrf(reg.client),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["require_mfa"] is True
    assert data["api_keys_enabled"] is True
    assert data["invite_domain_allowlist"] == ["corp.example", "sub.corp.example"]
    assert data["updated_by"] == str(reg.user_id)
    assert data["updated_at"] is not None

    # Check notification email enqueued for all owners
    emails = await outbox_rows(reg.email)
    owner1_notices = [e for e in emails if e.template == MailTemplate.NEW_OWNER_SECURITY_CHANGE]
    assert len(owner1_notices) == 1

    emails2 = await outbox_rows("second_owner@policy.example")
    owner2_notices = [e for e in emails2 if e.template == MailTemplate.NEW_OWNER_SECURITY_CHANGE]
    assert len(owner2_notices) == 1

