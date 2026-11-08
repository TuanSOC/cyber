"""Integration tests for identity operator MFA reset CLI (M11 phase 5)."""

import argparse
from datetime import UTC, datetime

from app.modules.identity import admin_mfa, totp
from app.modules.mail.templates import MailTemplate
from tests.factories import csrf, register
from tests.identity_helpers import mark_email_verified, outbox_rows, session_id_of, set_step_up


async def test_admin_mfa_reset_operator_script() -> None:
    reg = await register(org_name="Admin MFA Reset")
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

    # 1. Run without --yes -> exits 2
    args_no_yes = argparse.Namespace(email=reg.email, yes=False)
    assert await admin_mfa.run_async(args_no_yes) == 2

    # Factor is still active
    st_resp = await reg.client.get("/api/v1/auth/mfa")
    assert st_resp.status_code == 200
    assert st_resp.json()["totp"] == "active"

    # 2. Run with --yes -> exits 0
    args_yes = argparse.Namespace(email=reg.email, yes=True)
    assert await admin_mfa.run_async(args_yes) == 0

    # Every session of the user is revoked
    me_resp = await reg.client.get("/api/v1/auth/me")
    assert me_resp.status_code == 401

    # Status check after login shows factor is disabled/none
    emails = await outbox_rows(reg.email)
    reset_emails = [e for e in emails if e.template == MailTemplate.MFA_RESET_BY_OPERATOR]
    assert len(reset_emails) == 1


async def test_admin_mfa_reset_unknown_user_fails() -> None:
    args = argparse.Namespace(email="nobody@example.com", yes=True)
    assert await admin_mfa.run_async(args) == 1
