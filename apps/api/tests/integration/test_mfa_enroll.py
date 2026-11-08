"""Integration tests for MFA enrollment and status (M11 phase 5)."""

from datetime import UTC, datetime
import pytest

from app.core.cookies import ACCESS_COOKIE
from app.core.security import decode_access_token
from app.modules.auth.models import AuthEventType
from app.modules.identity import totp
from app.modules.mail.models import EmailOutbox
from app.modules.mail.templates import MailTemplate
from tests.factories import csrf, login, register
from tests.identity_helpers import (
    mark_email_verified,
    outbox_rows,
    session_id_of,
    set_step_up,
)


async def test_mfa_setup_refused_for_unverified_email() -> None:
    reg = await register(org_name="MFA Setup Unverified")
    sid = session_id_of(reg.client)
    await set_step_up(sid, seconds_ago=10)

    # Email not verified -> 403 email_verification_required (RT8)
    response = await reg.client.post("/api/v1/auth/mfa/totp/setup", headers=csrf(reg.client))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "email_verification_required"


async def test_mfa_setup_requires_step_up() -> None:
    reg = await register(org_name="MFA Setup StepUp")
    await mark_email_verified(reg.user_id)

    # Without step-up -> 403 step_up_required
    response = await reg.client.post("/api/v1/auth/mfa/totp/setup", headers=csrf(reg.client))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "step_up_required"


async def test_mfa_setup_and_confirm_happy_path() -> None:
    reg = await register(org_name="MFA Happy Path")
    await mark_email_verified(reg.user_id)
    sid = session_id_of(reg.client)
    await set_step_up(sid, seconds_ago=5)

    # Second session for user to verify other sessions are revoked on confirmation
    second_client = await login(reg.email)
    second_sid = session_id_of(second_client)
    assert second_sid != sid

    # 1. Setup TOTP
    setup_resp = await reg.client.post("/api/v1/auth/mfa/totp/setup", headers=csrf(reg.client))
    assert setup_resp.status_code == 200
    assert setup_resp.headers.get("Cache-Control") == "no-store"
    data = setup_resp.json()
    assert "otpauth_uri" in data
    assert "secret" in data
    secret_b32 = data["secret"]
    assert "otpauth://totp/CyberLab:" in data["otpauth_uri"]

    # Status shows pending
    status_resp = await reg.client.get("/api/v1/auth/mfa")
    assert status_resp.status_code == 200
    assert status_resp.json()["totp"] == "pending"

    # 2. Confirm with bad code -> 401
    bad_resp = await reg.client.post(
        "/api/v1/auth/mfa/totp/confirm",
        json={"code": "000000"},
        headers=csrf(reg.client),
    )
    assert bad_resp.status_code == 401
    assert bad_resp.json()["error"]["code"] == "mfa_code_invalid"

    # 3. Confirm with valid code
    secret_bytes = totp.decode_b32(secret_b32)
    step = int(datetime.now(UTC).timestamp() // 30)
    valid_code = totp.code_at(secret_bytes, step)

    confirm_resp = await reg.client.post(
        "/api/v1/auth/mfa/totp/confirm",
        json={"code": valid_code},
        headers=csrf(reg.client),
    )
    assert confirm_resp.status_code == 200
    codes_data = confirm_resp.json()
    assert "codes" in codes_data
    recovery_codes = codes_data["codes"]
    assert len(recovery_codes) == 10
    for code in recovery_codes:
        assert len(code) == 19  # XXXX-XXXX-XXXX-XXXX
        assert code.count("-") == 3

    # Check updated access token cookie has "otp" in amr
    new_token = reg.client.cookies.get(ACCESS_COOKIE)
    assert new_token is not None
    claims = decode_access_token(new_token)
    assert "otp" in claims.amr
    assert "pwd" in claims.amr

    # Check other session was revoked
    second_me = await second_client.get("/api/v1/auth/me")
    assert second_me.status_code == 401

    # Check status now shows active with 10 recovery codes
    status_active = await reg.client.get("/api/v1/auth/mfa")
    assert status_active.status_code == 200
    st_json = status_active.json()
    assert st_json["totp"] == "active"
    assert st_json["recovery_codes_remaining"] == 10
    assert st_json["confirmed_at"] is not None

    # Check notice email enqueued
    emails = await outbox_rows(reg.email)
    mfa_emails = [e for e in emails if e.template == MailTemplate.MFA_ENABLED]
    assert len(mfa_emails) == 1

    # Attempting setup again while active returns 409
    await set_step_up(sid, seconds_ago=5)
    conflict_resp = await reg.client.post("/api/v1/auth/mfa/totp/setup", headers=csrf(reg.client))
    assert conflict_resp.status_code == 409
    assert conflict_resp.json()["error"]["code"] == "mfa_already_active"

