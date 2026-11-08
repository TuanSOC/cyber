"""Integration tests for MFA throttling, attempt caps, and factor locking (M11 phase 5)."""

from datetime import UTC, datetime
from sqlalchemy import select, update

from app.core.tenancy import tenant_session
from app.modules.identity import totp
from app.modules.identity.models import MfaFactor, MfaStatus
from app.modules.mail.templates import MailTemplate
from tests.factories import PASSWORD, csrf, new_client, register
from tests.identity_helpers import mark_email_verified, outbox_rows, session_id_of, set_step_up


async def test_challenge_max_5_attempts() -> None:
    reg = await register(org_name="MFA Attempt Cap")
    await mark_email_verified(reg.user_id)
    sid = session_id_of(reg.client)
    await set_step_up(sid, seconds_ago=5)

    setup_resp = await reg.client.post("/api/v1/auth/mfa/totp/setup", headers=csrf(reg.client))
    secret_bytes = totp.decode_b32(setup_resp.json()["secret"])
    step = int(datetime.now(UTC).timestamp() // 30)
    await reg.client.post(
        "/api/v1/auth/mfa/totp/confirm",
        json={"code": totp.code_at(secret_bytes, step)},
        headers=csrf(reg.client),
    )

    client = new_client("10.9.7.1")
    login_resp = await client.post("/api/v1/auth/login", json={"email": reg.email, "password": PASSWORD})
    assert login_resp.status_code == 202

    # Attempt 1 to 5 with wrong code fail with 401 mfa_code_invalid
    for i in range(5):
        resp = await client.post("/api/v1/auth/mfa/verify", json={"code": "000000"}, headers=csrf(client))
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "mfa_code_invalid"

    # 6th attempt fails because challenge was exhausted/deleted -> 401 mfa_challenge_invalid
    sixth = await client.post("/api/v1/auth/mfa/verify", json={"code": "000000"}, headers=csrf(client))
    assert sixth.status_code == 401
    assert sixth.json()["error"]["code"] == "mfa_challenge_invalid"


async def test_factor_locks_at_100_failures() -> None:
    reg = await register(org_name="MFA Lock 100")
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
    recovery_code = confirm_resp.json()["codes"][0]

    # Advance consecutive_failures to 99 in DB
    async with tenant_session(None, reg.user_id) as session:
        await session.execute(
            update(MfaFactor)
            .where(MfaFactor.user_id == reg.user_id)
            .values(consecutive_failures=99)
        )

    # Login challenge
    client = new_client("10.9.7.2")
    login_resp = await client.post("/api/v1/auth/login", json={"email": reg.email, "password": PASSWORD})
    assert login_resp.status_code == 202

    # 100th failure locks factor
    resp = await client.post("/api/v1/auth/mfa/verify", json={"code": "000000"}, headers=csrf(client))
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "mfa_code_invalid"

    # Status check confirms factor is locked and lock notice email enqueued
    async with tenant_session(None, reg.user_id) as session:
        factor = (
            await session.execute(
                select(MfaFactor.status).where(MfaFactor.user_id == reg.user_id)
            )
        ).scalar_one()
        assert factor == MfaStatus.LOCKED.value

    emails = await outbox_rows(reg.email)
    lock_emails = [e for e in emails if e.template == MailTemplate.MFA_LOCKED]
    assert len(lock_emails) == 1

    # New login challenge shows only recovery_code as method
    client2 = new_client("10.9.7.3")
    l2 = await client2.post("/api/v1/auth/login", json={"email": reg.email, "password": PASSWORD})
    assert l2.status_code == 202
    assert l2.json()["methods"] == ["recovery_code"]

    # TOTP code rejected for locked factor
    step_now = int(datetime.now(UTC).timestamp() // 30)
    good_totp = totp.code_at(secret_bytes, step_now)
    totp_attempt = await client2.post("/api/v1/auth/mfa/verify", json={"code": good_totp}, headers=csrf(client2))
    assert totp_attempt.status_code == 401
    assert totp_attempt.json()["error"]["code"] == "mfa_code_invalid"

    # Recovery code unlocks login
    rec_attempt = await client2.post(
        "/api/v1/auth/mfa/verify",
        json={"recovery_code": recovery_code},
        headers=csrf(client2),
    )
    assert rec_attempt.status_code == 200
