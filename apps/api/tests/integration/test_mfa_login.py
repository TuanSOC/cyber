"""Integration tests for MFA login challenge and verification (M11 phase 5)."""

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from httpx import AsyncClient

from app.core.cookies import ACCESS_COOKIE, CSRF_COOKIE, MFA_COOKIE, REFRESH_COOKIE
from app.core.security import decode_access_token
from app.core.tenancy import tenant_session
from app.modules.identity import totp
from app.modules.identity.models import ActionPurpose, ActionToken
from tests.factories import PASSWORD, csrf, new_client, register
from tests.identity_helpers import mark_email_verified, session_id_of, set_step_up


async def _enroll_totp(client: AsyncClient, user_id) -> str:
    await mark_email_verified(user_id)
    sid = session_id_of(client)
    await set_step_up(sid, seconds_ago=5)
    setup_resp = await client.post("/api/v1/auth/mfa/totp/setup", headers=csrf(client))
    assert setup_resp.status_code == 200
    secret_b32 = setup_resp.json()["secret"]

    secret_bytes = totp.decode_b32(secret_b32)
    step = int(datetime.now(UTC).timestamp() // 30)
    # Confirm with step - 1 so that current step is fresh for subsequent login
    confirm_code = totp.code_at(secret_bytes, step - 1)

    confirm_resp = await client.post(
        "/api/v1/auth/mfa/totp/confirm",
        json={"code": confirm_code},
        headers=csrf(client),
    )
    assert confirm_resp.status_code == 200
    return secret_b32


async def test_mfa_login_challenge_and_verify_success() -> None:
    reg = await register(org_name="MFA Login Challenge")
    secret_b32 = await _enroll_totp(reg.client, reg.user_id)

    # Now attempt a new login from a fresh client
    login_client = new_client("10.9.5.1")
    login_resp = await login_client.post(
        "/api/v1/auth/login",
        json={"email": reg.email, "password": PASSWORD},
    )
    assert login_resp.status_code == 202
    body = login_resp.json()
    assert body["methods"] == ["totp", "recovery_code"]

    # Challenge cookie and CSRF cookie set; NO access or refresh cookies
    assert MFA_COOKIE in login_client.cookies
    assert CSRF_COOKIE in login_client.cookies
    assert ACCESS_COOKIE not in login_client.cookies
    assert REFRESH_COOKIE not in login_client.cookies

    # Verify with wrong code -> 401
    bad_resp = await login_client.post(
        "/api/v1/auth/mfa/verify",
        json={"code": "999999"},
        headers=csrf(login_client),
    )
    assert bad_resp.status_code == 401
    assert bad_resp.json()["error"]["code"] == "mfa_code_invalid"

    # Verify with correct TOTP code
    secret_bytes = totp.decode_b32(secret_b32)
    step = int(datetime.now(UTC).timestamp() // 30)
    valid_code = totp.code_at(secret_bytes, step)

    verify_resp = await login_client.post(
        "/api/v1/auth/mfa/verify",
        json={"code": valid_code},
        headers=csrf(login_client),
    )
    assert verify_resp.status_code == 200
    me_data = verify_resp.json()
    assert me_data["user"]["email"] == reg.email

    # cl_mfa cleared, auth cookies set
    assert ACCESS_COOKIE in login_client.cookies
    assert REFRESH_COOKIE in login_client.cookies

    token = login_client.cookies.get(ACCESS_COOKIE)
    assert token is not None
    claims = decode_access_token(token)
    assert claims.amr == ("pwd", "otp")

    # Can now query /auth/me successfully
    me_resp = await login_client.get("/api/v1/auth/me")
    assert me_resp.status_code == 200


async def test_mfa_verify_refuses_when_password_changed_since_challenge() -> None:
    reg = await register(org_name="MFA Password Invalidate")
    secret_b32 = await _enroll_totp(reg.client, reg.user_id)

    # Client initiates login -> gets challenge
    login_client = new_client("10.9.5.2")
    challenge_resp = await login_client.post(
        "/api/v1/auth/login",
        json={"email": reg.email, "password": PASSWORD},
    )
    assert challenge_resp.status_code == 202

    # Meanwhile, the user resets or changes password
    new_pw = "BrandNewPassw0rd!"
    raw_token = "A" * 43
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    async with tenant_session(None, None) as session:
        session.add(
            ActionToken(
                id=uuid.uuid4(),
                user_id=reg.user_id,
                purpose=ActionPurpose.PASSWORD_RESET.value,
                token_hash=token_hash,
                email=reg.email,
                expires_at=datetime.now(UTC) + timedelta(minutes=30),
            )
        )
    reset_resp = await new_client("10.9.5.3").post(
        "/api/v1/auth/password/reset",
        json={"token": raw_token, "new_password": new_pw},
    )
    assert reset_resp.status_code == 204

    # Now trying to verify the old challenge -> 401 mfa_challenge_invalid (RT26)
    secret_bytes = totp.decode_b32(secret_b32)
    step = int(datetime.now(UTC).timestamp() // 30)
    valid_code = totp.code_at(secret_bytes, step)

    verify_resp = await login_client.post(
        "/api/v1/auth/mfa/verify",
        json={"code": valid_code},
        headers=csrf(login_client),
    )
    assert verify_resp.status_code == 401
    assert verify_resp.json()["error"]["code"] == "mfa_challenge_invalid"
