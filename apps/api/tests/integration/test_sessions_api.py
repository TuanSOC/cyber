"""Integration tests for user session management API (M11 phase 4)."""

import uuid

import pytest

from app.core.cookies import ACCESS_COOKIE
from tests.factories import csrf, login, new_client, register
from tests.identity_helpers import session_id_of


async def test_list_sessions_shows_caller_sessions_only() -> None:
    """Users list their own active sessions with coarse UA and current flag."""
    u1 = await register(email="user1_sessions@example.com")
    u2 = await register(email="user2_sessions@example.com")

    # u1 signs in from a second client
    u1_second = await login("user1_sessions@example.com", ip="10.20.0.2")

    # u1 lists sessions from second client
    resp = await u1_second.get("/api/v1/auth/sessions")
    assert resp.status_code == 200
    data = resp.json()
    items = data["items"]
    assert len(items) == 2

    # Check fields and current flag
    current_sid = session_id_of(u1_second)
    for s in items:
        assert "id" in s
        assert s["method"] in ("password", "sso")
        assert isinstance(s["amr"], list)
        assert s["user_agent"] is not None
        if s["id"] == str(current_sid):
            assert s["current"] is True
        else:
            assert s["current"] is False

    # u2 lists sessions: sees only their own
    u2_resp = await u2.client.get("/api/v1/auth/sessions")
    assert u2_resp.status_code == 200
    u2_items = u2_resp.json()["items"]
    assert len(u2_items) == 1
    assert u2_items[0]["id"] == str(session_id_of(u2.client))


async def test_revoke_single_session() -> None:
    """Revoking a session invalidates its access token immediately; other user's session is 404."""
    u1 = await register(email="u1_revoke@example.com")
    u2 = await register(email="u2_revoke@example.com")
    u2_sid = session_id_of(u2.client)

    # 1. Attacker (u1) attempts to revoke u2's session -> 404
    del_foreign = await u1.client.delete(
        f"/api/v1/auth/sessions/{u2_sid}", headers=csrf(u1.client)
    )
    assert del_foreign.status_code == 404
    assert del_foreign.json()["error"]["code"] == "not_found"

    # 2. u1 logs in a second device
    u1_device2 = await login("u1_revoke@example.com", ip="10.30.0.1")
    dev2_sid = session_id_of(u1_device2)

    # u1 revokes device 2 from primary client -> 204
    del_ok = await u1.client.delete(
        f"/api/v1/auth/sessions/{dev2_sid}", headers=csrf(u1.client)
    )
    assert del_ok.status_code == 204

    # Device 2 access token is dead immediately
    assert (await u1_device2.get("/api/v1/auth/me")).status_code == 401

    # Primary client is still active
    assert (await u1.client.get("/api/v1/auth/me")).status_code == 200

    # 3. Revoking current session clears cookies
    del_current = await u1.client.delete(
        f"/api/v1/auth/sessions/{session_id_of(u1.client)}", headers=csrf(u1.client)
    )
    assert del_current.status_code == 204
    # Access cookie cleared or expired
    assert u1.client.cookies.get(ACCESS_COOKIE) in ("", None)


async def test_revoke_other_sessions() -> None:
    """POST /auth/sessions/revoke-others terminates all sessions except caller's."""
    reg = await register(email="revoke_others@example.com")
    c1 = reg.client
    c2 = await login("revoke_others@example.com", ip="10.40.0.1")
    c3 = await login("revoke_others@example.com", ip="10.40.0.2")

    # c1 revokes others
    resp = await c1.post("/api/v1/auth/sessions/revoke-others", headers=csrf(c1))
    assert resp.status_code == 204

    # c1 remains active
    assert (await c1.get("/api/v1/auth/me")).status_code == 200

    # c2 and c3 are dead
    assert (await c2.get("/api/v1/auth/me")).status_code == 401
    assert (await c3.get("/api/v1/auth/me")).status_code == 401
