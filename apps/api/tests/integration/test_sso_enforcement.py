"""Integration tests for SSO enforcement and break-glass via check_org_access (M11 phase 6)."""

import uuid
from datetime import UTC, datetime

import pytest

from app.core.cookies import ACCESS_COOKIE
from app.core.deps import CurrentUser
from app.core.security import create_access_token
from app.core.tenancy import tenant_session
from app.modules.identity import policy as identity_policy
from app.modules.identity.errors import ApiKeysDisabled
from app.modules.identity.models import OrgSecurityPolicy
from app.modules.organizations.models import MemberRole
from tests.factories import add_membership, register
from tests.identity_helpers import session_id_of


async def test_sso_session_scope_rt2() -> None:
    # User belongs to both Org A and Org B
    reg_a = await register(org_name="Scope Org A")
    reg_b = await register(org_name="Scope Org B")
    await add_membership(reg_b.org_id, reg_a.user_id, MemberRole.ANALYST)

    sid = session_id_of(reg_a.client)
    # 1. User has password, and token has sso_org_id = reg_a.org_id
    token, _ = create_access_token(
        reg_a.user_id,
        sid,
        amr=["sso"],
        sso_org_id=reg_a.org_id,
    )
    reg_a.client.cookies.set(ACCESS_COOKIE, token, path="/api")

    # Request to Org A (own SSO org) -> succeeds
    resp_a = await reg_a.client.get(f"/api/v1/orgs/{reg_a.org_id}/investigations")
    assert resp_a.status_code == 200

    # Request to Org B (different org) -> 403 sso_session_scope
    resp_b = await reg_a.client.get(f"/api/v1/orgs/{reg_b.org_id}/investigations")
    assert resp_b.status_code == 403
    assert resp_b.json()["error"]["code"] == "sso_session_scope"

    # 2. SSO-provisioned user without password (has_password = False)
    # Direct check_org_access call
    async with tenant_session(reg_b.org_id, reg_a.user_id) as session:
        no_pwd_principal = CurrentUser(
            id=reg_a.user_id,
            email=reg_a.email,
            display_name="SSO User",
            jti="dummy",
            family_id=sid,
            token_expires_at=datetime.now(UTC),
            amr=frozenset({"sso"}),
            sso_org_id=reg_a.org_id,
            has_password=False,
        )
        # Does NOT raise SsoSessionScope because user has no local password!
        await identity_policy.check_org_access(
            session, reg_b.org_id, no_pwd_principal, role=MemberRole.ANALYST
        )


async def test_sso_enforcement_blocks_non_sso_session() -> None:
    reg = await register(org_name="SSO Enforced Org")

    # Enforce SSO on org
    async with tenant_session(reg.org_id, reg.user_id) as session:
        pol = OrgSecurityPolicy(
            organization_id=reg.org_id,
            sso_enforced=True,
            owners_break_glass=False,
        )
        session.add(pol)

    # Regular session without sso_org_id == reg.org_id -> 403 sso_required {sso_start: true}
    resp = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/investigations")
    assert resp.status_code == 403
    err = resp.json()["error"]
    assert err["code"] == "sso_required"
    assert err["sso_start"] is True


async def test_sso_enforcement_break_glass() -> None:
    reg = await register(org_name="SSO Break Glass Org")

    # Enforce SSO with owners_break_glass = True
    async with tenant_session(reg.org_id, reg.user_id) as session:
        pol = OrgSecurityPolicy(
            organization_id=reg.org_id,
            sso_enforced=True,
            owners_break_glass=True,
        )
        session.add(pol)

    sid = session_id_of(reg.client)

    # Case 1: Owner without OTP in AMR -> blocked
    resp_no_otp = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/investigations")
    assert resp_no_otp.status_code == 403
    assert resp_no_otp.json()["error"]["code"] == "sso_required"

    # Case 2: Owner with OTP in AMR -> break-glass allowed!
    token_otp, _ = create_access_token(
        reg.user_id,
        sid,
        amr=["pwd", "otp"],
        sso_org_id=None,
    )
    reg.client.cookies.set(ACCESS_COOKIE, token_otp, path="/api")

    resp_bg = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/investigations")
    assert resp_bg.status_code == 200

    # Repeat call: break-glass audit dedupe prevents duplicate audits
    resp_bg2 = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/investigations")
    assert resp_bg2.status_code == 200


async def test_api_keys_disabled_by_policy() -> None:
    reg = await register(org_name="API Keys Policy Org")
    sid = session_id_of(reg.client)

    api_key_principal = CurrentUser(
        id=uuid.uuid4(),
        email="svc-test@service.invalid",
        display_name="Service Key",
        jti="",
        family_id=sid,
        token_expires_at=datetime.now(UTC),
        amr=frozenset(),
        kind="api_key",
        has_password=False,
    )

    # 1. Default policy (api_keys_enabled = False) -> raises ApiKeysDisabled (403)
    async with tenant_session(reg.org_id, reg.user_id) as session:
        with pytest.raises(ApiKeysDisabled) as exc_info:
            await identity_policy.check_org_access(
                session, reg.org_id, api_key_principal, role=MemberRole.ANALYST
            )
        assert exc_info.value.status_code == 403
        assert exc_info.value.code == "api_keys_disabled"

    # 2. Policy with api_keys_enabled = True -> passes
    async with tenant_session(reg.org_id, reg.user_id) as session:
        pol = OrgSecurityPolicy(organization_id=reg.org_id, api_keys_enabled=True)
        session.add(pol)

    async with tenant_session(reg.org_id, reg.user_id) as session:
        await identity_policy.check_org_access(
            session, reg.org_id, api_key_principal, role=MemberRole.ANALYST
        )

