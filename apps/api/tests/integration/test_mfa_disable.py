"""Integration tests for disabling MFA and org policy enforcement (M11 phase 5)."""

from datetime import UTC, datetime
from sqlalchemy import insert

from app.core.tenancy import tenant_session
from app.modules.identity import totp
from app.modules.identity.models import OrgSecurityPolicy
from app.modules.mail.templates import MailTemplate
from tests.factories import PASSWORD, csrf, login, register
from tests.identity_helpers import mark_email_verified, outbox_rows, session_id_of, set_step_up


async def test_mfa_disable_happy_path() -> None:
    reg = await register(org_name="MFA Disable Org")
    await mark_email_verified(reg.user_id)
    sid = session_id_of(reg.client)
    await set_step_up(sid, seconds_ago=5)

    setup_resp = await reg.client.post("/api/v1/auth/mfa/totp/setup", headers=csrf(reg.client))
    secret_bytes = totp.decode_b32(setup_resp.json()["secret"])
    step = int(datetime.now(UTC).timestamp() // 30)
    confirm_resp = await reg.client.post(
        "/api/v1/auth/mfa/totp/confirm",
        json={"code": totp.code_at(secret_bytes, step)},
        headers=csrf(reg.client),
    )
    recovery_code = confirm_resp.json()["codes"][0]

    # Expire step-up
    await set_step_up(sid, seconds_ago=1000)

    # Without step-up -> 403 step_up_required
    denied = await reg.client.request(
        "DELETE",
        "/api/v1/auth/mfa/totp",
        json={"code": totp.code_at(secret_bytes, step + 1)},
        headers=csrf(reg.client),
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "step_up_required"

    # Step up and disable using recovery code
    await set_step_up(sid, seconds_ago=5)
    disable_resp = await reg.client.request(
        "DELETE",
        "/api/v1/auth/mfa/totp",
        json={"recovery_code": recovery_code},
        headers=csrf(reg.client),
    )
    assert disable_resp.status_code == 204

    # Status shows none
    st_resp = await reg.client.get("/api/v1/auth/mfa")
    assert st_resp.json()["totp"] == "none"

    # Mail sent
    emails = await outbox_rows(reg.email)
    dis_emails = [e for e in emails if e.template == MailTemplate.MFA_DISABLED]
    assert len(dis_emails) == 1

    # Next login does not ask for MFA challenge
    new_login = await login(reg.email, PASSWORD)
    me_resp = await new_login.get("/api/v1/auth/me")
    assert me_resp.status_code == 200


async def test_mfa_disable_refused_when_org_requires_mfa() -> None:
    reg = await register(org_name="Org Requires MFA")
    await mark_email_verified(reg.user_id)
    sid = session_id_of(reg.client)
    await set_step_up(sid, seconds_ago=5)

    setup_resp = await reg.client.post("/api/v1/auth/mfa/totp/setup", headers=csrf(reg.client))
    secret_bytes = totp.decode_b32(setup_resp.json()["secret"])
    step = int(datetime.now(UTC).timestamp() // 30)
    confirm_resp = await reg.client.post(
        "/api/v1/auth/mfa/totp/confirm",
        json={"code": totp.code_at(secret_bytes, step)},
        headers=csrf(reg.client),
    )
    recovery_code = confirm_resp.json()["codes"][0]

    # Seed an org_security_policies row with require_mfa = True for reg.org_id
    async with tenant_session(reg.org_id, reg.user_id) as session:
        await session.execute(
            insert(OrgSecurityPolicy).values(
                organization_id=reg.org_id,
                require_mfa=True,
                sso_enforced=False,
                owners_break_glass=True,
                api_keys_enabled=False,
                invite_domain_allowlist=[],
            )
        )

    # Disable should now be refused with 409 mfa_required_by_org (RT13)
    await set_step_up(sid, seconds_ago=5)
    dis_resp = await reg.client.request(
        "DELETE",
        "/api/v1/auth/mfa/totp",
        json={"recovery_code": recovery_code},
        headers=csrf(reg.client),
    )
    assert dis_resp.status_code == 409
    assert dis_resp.json()["error"]["code"] == "mfa_required_by_org"
