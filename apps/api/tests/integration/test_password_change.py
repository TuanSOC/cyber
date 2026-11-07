"""Integration tests for authenticated password change (M11 phase 4)."""

import uuid

import pytest
from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.auth.models import AuthEvent, AuthEventType
from app.modules.mail.templates import MailTemplate
from tests.factories import csrf, login, new_client, register
from tests.identity_helpers import (
    outbox_rows,
    session_id_of,
    set_amr,
    set_step_up,
)


async def test_password_change_requires_step_up_and_current_password() -> None:
    """Password change needs recent re-auth (step-up) and the valid current password."""
    reg = await register()
    client = reg.client
    sid = session_id_of(client)

    url = "/api/v1/auth/password/change"
    new_pw = "new horse battery staple 999"

    # 1. No step-up -> 403 step_up_required
    await set_step_up(sid, seconds_ago=None)
    resp_no_stepup = await client.post(
        url,
        json={"current_password": "correct horse battery staple", "new_password": new_pw},
        headers=csrf(client),
    )
    assert resp_no_stepup.status_code == 403
    assert resp_no_stepup.json()["error"]["code"] == "step_up_required"

    # 2. With step-up, but wrong current password -> 401 invalid_credentials
    await set_step_up(sid, seconds_ago=0)
    resp_bad_pw = await client.post(
        url,
        json={"current_password": "wrong password", "new_password": new_pw},
        headers=csrf(client),
    )
    assert resp_bad_pw.status_code == 401
    assert resp_bad_pw.json()["error"]["code"] == "invalid_credentials"

    # 3. Happy path: step-up + valid current password -> 204
    await set_step_up(sid, seconds_ago=0)
    resp_ok = await client.post(
        url,
        json={"current_password": "correct horse battery staple", "new_password": new_pw},
        headers=csrf(client),
    )
    assert resp_ok.status_code == 204

    # 4. Current session remains valid
    me = await client.get("/api/v1/auth/me")
    assert me.status_code == 200

    # 5. Can login with new password; old password fails
    client2 = await login(reg.email, new_pw)
    assert (await client2.get("/api/v1/auth/me")).status_code == 200

    client_bad = new_client()
    resp_old = await client_bad.post(
        "/api/v1/auth/login", json={"email": reg.email, "password": "correct horse battery staple"}
    )
    assert resp_old.status_code == 401

    # 6. Mail password_changed enqueued
    rows = await outbox_rows(to=reg.email)
    assert any(r.template == MailTemplate.PASSWORD_CHANGED.value for r in rows)

    # 7. Auth event recorded
    async with tenant_session(None, None) as session:
        events = (
            await session.execute(
                select(AuthEvent).where(
                    AuthEvent.user_id == reg.user_id,
                    AuthEvent.event == AuthEventType.PASSWORD_CHANGED,
                )
            )
        ).scalars().all()
        assert len(events) >= 1


async def test_password_change_revokes_other_sessions() -> None:
    """Changing password revokes all other sessions of the user, keeping current."""
    reg = await register()
    c1 = reg.client
    sid1 = session_id_of(c1)

    # Open a second session
    c2 = await login(reg.email, "correct horse battery staple")
    assert (await c2.get("/api/v1/auth/me")).status_code == 200

    # Change password from c1
    await set_step_up(sid1, seconds_ago=0)
    resp = await c1.post(
        "/api/v1/auth/password/change",
        json={
            "current_password": "correct horse battery staple",
            "new_password": "fresh password 12345",
        },
        headers=csrf(c1),
    )
    assert resp.status_code == 204

    # c1 is still valid
    assert (await c1.get("/api/v1/auth/me")).status_code == 200

    # c2 is dead immediately (denylisted in Redis)
    assert (await c2.get("/api/v1/auth/me")).status_code == 401
