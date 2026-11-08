"""Integration tests for recovery code normalization, single-use, and regeneration (M11 phase 5)."""

from datetime import UTC, datetime

from app.core.cookies import ACCESS_COOKIE
from app.core.security import decode_access_token
from app.modules.identity import totp
from app.modules.mail.templates import MailTemplate
from tests.factories import PASSWORD, csrf, new_client, register
from tests.identity_helpers import mark_email_verified, outbox_rows, session_id_of, set_step_up


async def test_recovery_code_usage_and_normalization() -> None:
    reg = await register(org_name="Recovery Codes Normalization")
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
    assert confirm_resp.status_code == 200
    codes = confirm_resp.json()["codes"]
    first_code = codes[0]

    # Convert code to lowercase and remove hyphens
    normalized_input = first_code.lower().replace("-", "")

    # Login challenge
    client = new_client("10.9.8.1")
    login_resp = await client.post("/api/v1/auth/login", json={"email": reg.email, "password": PASSWORD})
    assert login_resp.status_code == 202

    # Verify with normalized recovery code succeeds
    verify_resp = await client.post(
        "/api/v1/auth/mfa/verify",
        json={"recovery_code": normalized_input},
        headers=csrf(client),
    )
    assert verify_resp.status_code == 200

    token = client.cookies.get(ACCESS_COOKIE)
    claims = decode_access_token(token)
    assert claims.amr == ("pwd", "recovery")

    # Recovery notice email enqueued with remaining = 9
    emails = await outbox_rows(reg.email)
    rec_emails = [e for e in emails if e.template == MailTemplate.RECOVERY_CODE_USED]
    assert len(rec_emails) == 1
    assert rec_emails[0].params["remaining"] == 9

    # Check status shows 9 recovery codes remaining
    st_resp = await client.get("/api/v1/auth/mfa")
    assert st_resp.json()["recovery_codes_remaining"] == 9

    # Reusing the same recovery code fails
    c2 = new_client("10.9.8.2")
    await c2.post("/api/v1/auth/login", json={"email": reg.email, "password": PASSWORD})
    reuse_resp = await c2.post(
        "/api/v1/auth/mfa/verify",
        json={"recovery_code": first_code},
        headers=csrf(c2),
    )
    assert reuse_resp.status_code == 401
    assert reuse_resp.json()["error"]["code"] == "mfa_code_invalid"


async def test_recovery_code_regeneration() -> None:
    reg = await register(org_name="Recovery Regen")
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
    assert confirm_resp.status_code == 200
    old_code = confirm_resp.json()["codes"][0]

    # Clear/expire step-up
    await set_step_up(sid, seconds_ago=1000)

    # Without step-up -> 403 step_up_required
    regen_denied = await reg.client.post("/api/v1/auth/mfa/recovery-codes", headers=csrf(reg.client))
    assert regen_denied.status_code == 403
    assert regen_denied.json()["error"]["code"] == "step_up_required"

    # Step up and regenerate
    await set_step_up(sid, seconds_ago=5)
    regen_resp = await reg.client.post("/api/v1/auth/mfa/recovery-codes", headers=csrf(reg.client))
    assert regen_resp.status_code == 200
    assert regen_resp.headers.get("Cache-Control") == "no-store"
    new_codes = regen_resp.json()["codes"]
    assert len(new_codes) == 10

    # Old code from previous batch is now dead
    c = new_client("10.9.8.3")
    await c.post("/api/v1/auth/login", json={"email": reg.email, "password": PASSWORD})
    dead_resp = await c.post(
        "/api/v1/auth/mfa/verify",
        json={"recovery_code": old_code},
        headers=csrf(c),
    )
    assert dead_resp.status_code == 401
    assert dead_resp.json()["error"]["code"] == "mfa_code_invalid"

    # New code works
    good_resp = await c.post(
        "/api/v1/auth/mfa/verify",
        json={"recovery_code": new_codes[0]},
        headers=csrf(c),
    )
    assert good_resp.status_code == 200
