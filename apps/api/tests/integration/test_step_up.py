"""Integration tests for POST /auth/step-up (M11 phase 5)."""

from datetime import UTC, datetime

from app.core.stepup import StepUpAction, has_recent_step_up
from app.core.tenancy import tenant_session
from app.modules.identity import totp
from tests.factories import PASSWORD, csrf, register
from tests.identity_helpers import (
    bearer,
    get_session_row,
    mark_email_verified,
    seed_api_key,
    session_id_of,
    set_step_up,
)


async def test_step_up_with_password_for_user_without_mfa() -> None:
    reg = await register(org_name="Step Up Password")
    sid = session_id_of(reg.client)

    # Initially step-up is not set on session row
    row = await get_session_row(sid)
    assert row is not None and row.step_up_at is None

    # Wrong password -> 401
    bad_resp = await reg.client.post(
        "/api/v1/auth/step-up",
        json={"password": "WrongPassword123!"},
        headers=csrf(reg.client),
    )
    assert bad_resp.status_code == 401
    assert bad_resp.json()["error"]["code"] == "step_up_failed"

    # Correct password -> 204
    good_resp = await reg.client.post(
        "/api/v1/auth/step-up",
        json={"password": PASSWORD},
        headers=csrf(reg.client),
    )
    assert good_resp.status_code == 204

    # Now step-up is active on session row
    row_after = await get_session_row(sid)
    assert row_after is not None and row_after.step_up_at is not None


async def test_step_up_with_code_for_user_with_mfa() -> None:
    reg = await register(org_name="Step Up TOTP")
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

    # Sending password when MFA factor exists -> 400
    pw_resp = await reg.client.post(
        "/api/v1/auth/step-up",
        json={"password": PASSWORD},
        headers=csrf(reg.client),
    )
    assert pw_resp.status_code == 400
    assert pw_resp.json()["error"]["code"] == "step_up_mfa_required"

    # Step-up using recovery code -> 204
    rec_resp = await reg.client.post(
        "/api/v1/auth/step-up",
        json={"recovery_code": recovery_code},
        headers=csrf(reg.client),
    )
    assert rec_resp.status_code == 204


async def test_step_up_refused_for_api_keys() -> None:
    reg = await register(org_name="Step Up API Keys")
    seeded = await seed_api_key(reg.org_id, reg.user_id)
    # API key calling step-up is refused at dependency / route level
    response = await reg.client.post(
        "/api/v1/auth/step-up",
        json={"password": PASSWORD},
        headers=bearer(seeded.key),
    )
    assert response.status_code in (401, 403)
