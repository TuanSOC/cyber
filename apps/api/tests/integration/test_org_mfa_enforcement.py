"""Integration tests for Org MFA Enforcement via check_org_access (M11 phase 6)."""

from datetime import UTC, datetime

from app.core.tenancy import tenant_session
from app.modules.identity import totp
from app.modules.identity.models import OrgSecurityPolicy
from app.modules.organizations.models import MemberRole
from tests.factories import PASSWORD, add_membership, csrf, new_client, register
from tests.identity_helpers import mark_email_verified, session_id_of, set_step_up


async def test_mfa_enforcement_blocks_password_session() -> None:
    reg = await register(org_name="Enforce MFA Org")

    # Set require_mfa = True on Org
    async with tenant_session(reg.org_id, reg.user_id) as session:
        pol = OrgSecurityPolicy(organization_id=reg.org_id, require_mfa=True)
        session.add(pol)

    # 1. Member without factor -> 403 mfa_required {enroll: true}
    resp = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/investigations")
    assert resp.status_code == 403
    err = resp.json()["error"]
    assert err["code"] == "mfa_required"
    assert err["enroll"] is True

    # 2. Enroll TOTP factor
    await mark_email_verified(reg.user_id)
    sid = session_id_of(reg.client)
    await set_step_up(sid, seconds_ago=5)
    setup_resp = await reg.client.post("/api/v1/auth/mfa/totp/setup", headers=csrf(reg.client))
    secret_bytes = totp.decode_b32(setup_resp.json()["secret"])
    step = int(datetime.now(UTC).timestamp() // 30)
    await reg.client.post(
        "/api/v1/auth/mfa/totp/confirm",
        json={"code": totp.code_at(secret_bytes, step - 1)},
        headers=csrf(reg.client),
    )

    # Now with factor confirmed, session has "otp" in AMR -> passes!
    resp_ok = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/investigations")
    assert resp_ok.status_code == 200

    # 3. Simulate another password-only session of the same user (e.g. without MFA verify)
    async with new_client() as client2:
        # A password login returns 202 challenge because factor exists
        login_resp = await client2.post(
            "/api/v1/auth/login",
            json={"email": reg.email, "password": PASSWORD},
        )
        assert login_resp.status_code == 202


async def test_mfa_enforcement_exempt_routes() -> None:
    reg = await register(org_name="Exempt Routes Org")

    # Set require_mfa = True
    async with tenant_session(reg.org_id, reg.user_id) as session:
        pol = OrgSecurityPolicy(organization_id=reg.org_id, require_mfa=True)
        session.add(pol)

    # Regular org route is blocked (403)
    resp_blocked = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/investigations")
    assert resp_blocked.status_code == 403
    assert resp_blocked.json()["error"]["code"] == "mfa_required"

    # Exempt routes are accessible:
    # 1. GET /orgs/{org_id}
    resp_org = await reg.client.get(f"/api/v1/orgs/{reg.org_id}")
    assert resp_org.status_code == 200
    assert resp_org.json()["id"] == str(reg.org_id)

    # 2. GET /orgs/{org_id}/security-policy
    resp_pol = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/security-policy")
    assert resp_pol.status_code == 200
    assert resp_pol.json()["require_mfa"] is True


async def test_mfa_enforcement_cross_org_isolation() -> None:
    reg_a = await register(org_name="MFA Org A")
    reg_b = await register(org_name="No MFA Org B")

    # Add user from Org A to Org B as analyst
    await add_membership(reg_b.org_id, reg_a.user_id, MemberRole.ANALYST)

    # Enable require_mfa on Org A only
    async with tenant_session(reg_a.org_id, reg_a.user_id) as session:
        pol = OrgSecurityPolicy(organization_id=reg_a.org_id, require_mfa=True)
        session.add(pol)

    # Client of user on Org A is blocked
    resp_a = await reg_a.client.get(f"/api/v1/orgs/{reg_a.org_id}/investigations")
    assert resp_a.status_code == 403
    assert resp_a.json()["error"]["code"] == "mfa_required"

    # Same client on Org B is allowed!
    resp_b = await reg_a.client.get(f"/api/v1/orgs/{reg_b.org_id}/investigations")
    assert resp_b.status_code == 200

