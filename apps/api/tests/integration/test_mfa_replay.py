"""Integration tests for TOTP replay protection and concurrency (M11 phase 5)."""

import asyncio
from datetime import UTC, datetime

from app.core.cookies import MFA_COOKIE
from app.modules.identity import totp
from tests.factories import PASSWORD, csrf, new_client, register
from tests.identity_helpers import mark_email_verified, session_id_of, set_step_up


async def test_totp_code_reuse_rejected() -> None:
    reg = await register(org_name="MFA Replay Guard")
    await mark_email_verified(reg.user_id)
    sid = session_id_of(reg.client)
    await set_step_up(sid, seconds_ago=5)

    setup_resp = await reg.client.post("/api/v1/auth/mfa/totp/setup", headers=csrf(reg.client))
    secret_b32 = setup_resp.json()["secret"]
    secret_bytes = totp.decode_b32(secret_b32)
    step = int(datetime.now(UTC).timestamp() // 30)
    code = totp.code_at(secret_bytes, step)

    confirm_resp = await reg.client.post(
        "/api/v1/auth/mfa/totp/confirm",
        json={"code": code},
        headers=csrf(reg.client),
    )
    assert confirm_resp.status_code == 200

    # Start login challenge
    client = new_client("10.9.6.1")
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": reg.email, "password": PASSWORD},
    )
    assert login_resp.status_code == 202

    # Attempting to use the SAME step code used for confirmation -> rejected by replay guard
    verify_resp = await client.post(
        "/api/v1/auth/mfa/verify",
        json={"code": code},
        headers=csrf(client),
    )
    assert verify_resp.status_code == 401
    assert verify_resp.json()["error"]["code"] == "mfa_code_invalid"


async def test_concurrent_replay_race_condition() -> None:
    """Two simultaneous verify requests with the same code: exactly one succeeds."""
    reg = await register(org_name="MFA Concurrency")
    await mark_email_verified(reg.user_id)
    sid = session_id_of(reg.client)
    await set_step_up(sid, seconds_ago=5)

    setup_resp = await reg.client.post("/api/v1/auth/mfa/totp/setup", headers=csrf(reg.client))
    secret_b32 = setup_resp.json()["secret"]
    secret_bytes = totp.decode_b32(secret_b32)
    step = int(datetime.now(UTC).timestamp() // 30)
    # Confirm with step - 1 so step is fresh
    confirm_code = totp.code_at(secret_bytes, step - 1)
    confirm_resp = await reg.client.post(
        "/api/v1/auth/mfa/totp/confirm",
        json={"code": confirm_code},
        headers=csrf(reg.client),
    )
    assert confirm_resp.status_code == 200

    # Two separate clients get challenge
    c1 = new_client("10.9.6.2")
    c2 = new_client("10.9.6.3")

    r1 = await c1.post("/api/v1/auth/login", json={"email": reg.email, "password": PASSWORD})
    r2 = await c2.post("/api/v1/auth/login", json={"email": reg.email, "password": PASSWORD})
    assert r1.status_code == 202 and r2.status_code == 202

    # Use same current code concurrently
    current_code = totp.code_at(secret_bytes, step)

    async def _verify(c):
        return await c.post("/api/v1/auth/mfa/verify", json={"code": current_code}, headers=csrf(c))

    res1, res2 = await asyncio.gather(_verify(c1), _verify(c2))
    status_codes = sorted([res1.status_code, res2.status_code])
    assert status_codes == [200, 401]

