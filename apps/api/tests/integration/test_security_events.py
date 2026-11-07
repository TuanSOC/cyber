"""Integration tests for personal security events log API (M11 phase 4)."""

import pytest

from tests.factories import login, register


async def test_security_events_list_and_isolation() -> None:
    """Users list only their own security events, newest first."""
    u1 = await register(email="events_u1@example.com")
    u2 = await register(email="events_u2@example.com")

    # u1 signs in again to create more events
    await login("events_u1@example.com", ip="10.50.0.1")

    # u1 queries events
    resp = await u1.client.get("/api/v1/auth/events?limit=50")
    assert resp.status_code == 200
    events = resp.json()["items"]
    assert len(events) >= 1

    # Verify event structure
    event_types = set()
    for e in events:
        assert "id" in e
        assert "event" in e
        assert "occurred_at" in e
        event_types.add(e["event"])

    assert "register" in event_types or "login_success" in event_types

    # Verify chronological descending order
    dates = [e["occurred_at"] for e in events]
    assert dates == sorted(dates, reverse=True)

    # u2 queries events: only sees own events
    u2_resp = await u2.client.get("/api/v1/auth/events")
    assert u2_resp.status_code == 200
    u2_events = u2_resp.json()["items"]
    u1_ids = {e["id"] for e in events}
    u2_ids = {e["id"] for e in u2_events}
    assert u1_ids.isdisjoint(u2_ids)


async def test_security_events_limit_clamping() -> None:
    """GET /auth/events clamps limit between 1 and 100."""
    u = await register(email="events_limit@example.com")

    # Query with limit=1
    r1 = await u.client.get("/api/v1/auth/events?limit=1")
    assert r1.status_code == 200
    assert len(r1.json()["items"]) <= 1

    # Query with limit > 100 -> 422 validation error
    r_bad = await u.client.get("/api/v1/auth/events?limit=101")
    assert r_bad.status_code == 422
