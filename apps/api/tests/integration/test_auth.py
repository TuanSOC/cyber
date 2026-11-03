import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from argon2 import PasswordHasher
from httpx import AsyncClient
from sqlalchemy import select, update

from app.core.cookies import ACCESS_COOKIE, CSRF_COOKIE, REFRESH_COOKIE
from app.core.security import SESSION_MAX_AGE, hash_token
from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.auth.models import AuthEvent, AuthEventType, RefreshToken, RevokedReason
from app.modules.users.models import User
from tests.factories import PASSWORD, csrf, login, new_client, register, unique_email

REFRESH = "/api/v1/auth/refresh"


async def _auth_events(event: AuthEventType) -> list[AuthEvent]:
    async with tenant_session(None, None) as s:
        return list((await s.execute(select(AuthEvent).where(AuthEvent.event == event))).scalars())


async def _family_rows(refresh_token: str) -> list[RefreshToken]:
    async with tenant_session(None, None) as s:
        token = (
            await s.execute(
                select(RefreshToken).where(RefreshToken.token_hash == hash_token(refresh_token))
            )
        ).scalar_one()
        stmt = select(RefreshToken).where(RefreshToken.family_id == token.family_id)
        return list((await s.execute(stmt)).scalars())


def _set_cookie_headers(response_headers: list[str], name: str) -> str:
    return next(h for h in response_headers if h.startswith(f"{name}="))


def _client_with(cookies: dict[str, str], ip: str = "10.0.0.1") -> AsyncClient:
    """Client sending exactly these cookies (bypasses the jar), plus a matching CSRF header."""
    client = new_client(ip)
    header = "; ".join(f"{k}={v}" for k, v in cookies.items())
    client.headers["Cookie"] = header
    if CSRF_COOKIE in cookies:
        client.headers["X-CSRF-Token"] = cookies[CSRF_COOKIE]
    return client


# --- register / login ---------------------------------------------------------------------


async def test_register_creates_user_org_owner_and_sets_cookies() -> None:
    client = new_client()
    email = unique_email()
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": PASSWORD,
            "display_name": "Ana",
            "organization_name": "Blue Team",
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["user"]["email"] == email
    assert body["memberships"][0]["role"] == "owner"
    assert body["memberships"][0]["organization_name"] == "Blue Team"

    headers = response.headers.get_list("set-cookie")
    access = _set_cookie_headers(headers, ACCESS_COOKIE)
    refresh = _set_cookie_headers(headers, REFRESH_COOKIE)
    csrf_cookie = _set_cookie_headers(headers, CSRF_COOKIE)
    assert "HttpOnly" in access and "Path=/api;" in access and "SameSite=strict" in access
    assert "HttpOnly" in refresh and "Path=/api/v1/auth" in refresh
    assert "HttpOnly" not in csrf_cookie and "Path=/;" in csrf_cookie
    for cookie in (ACCESS_COOKIE, REFRESH_COOKIE):
        value = client.cookies.get(cookie)
        assert value and value not in response.text

    async with tenant_session(None, None) as s:
        user = (await s.execute(select(User).where(User.email == email))).scalar_one()
    assert user.password_hash.startswith("$argon2id$") and PASSWORD not in user.password_hash

    org_id = body["memberships"][0]["organization_id"]
    async with tenant_session(org_id, user.id) as s:
        actions = (await s.execute(select(AuditLog.action))).scalars().all()
    assert actions == ["org.created"]
    assert len(await _auth_events(AuthEventType.REGISTER)) == 1


async def test_duplicate_email_is_rejected_generically() -> None:
    first = await register()
    response = await new_client().post(
        "/api/v1/auth/register",
        json={
            "email": first.email.upper(),
            "password": PASSWORD,
            "display_name": "x",
            "organization_name": "Other",
        },
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "registration_failed"


@pytest.mark.parametrize(
    "overrides",
    [{"password": "short"}, {"password": "same@example.com", "email": "same@example.com"}],
)
async def test_password_policy(overrides: dict[str, str]) -> None:
    payload = {
        "email": unique_email(),
        "password": PASSWORD,
        "display_name": "x",
        "organization_name": "Org",
    } | overrides
    response = await new_client().post("/api/v1/auth/register", json=payload)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


async def test_login_failures_look_identical_and_are_recorded() -> None:
    reg = await register()
    wrong_pw = await new_client().post(
        "/api/v1/auth/login", json={"email": reg.email, "password": "wrong password 123"}
    )
    unknown = await new_client().post(
        "/api/v1/auth/login", json={"email": "ghost@example.com", "password": PASSWORD}
    )
    assert wrong_pw.status_code == unknown.status_code == 401
    assert wrong_pw.json() == unknown.json()
    # Events were committed even though the requests failed.
    failures = await _auth_events(AuthEventType.LOGIN_FAILURE)
    assert {e.email_attempted for e in failures} == {reg.email, "ghost@example.com"}
    assert {e.user_id for e in failures} == {reg.user_id, None}


async def test_login_is_case_insensitive_and_returns_memberships() -> None:
    reg = await register()
    client = await login(reg.email.upper())
    me = await client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["memberships"][0]["organization_id"] == str(reg.org_id)
    assert len(await _auth_events(AuthEventType.LOGIN_SUCCESS)) == 1


async def test_me_requires_authentication() -> None:
    response = await new_client().get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


# --- refresh rotation -----------------------------------------------------------------------


async def test_refresh_rotates_tokens() -> None:
    reg = await register()
    old_refresh = reg.client.cookies.get(REFRESH_COOKIE)
    response = await reg.client.post(REFRESH, headers=csrf(reg.client))
    assert response.status_code == 204
    new_refresh = reg.client.cookies.get(REFRESH_COOKIE)
    assert new_refresh and new_refresh != old_refresh
    rows = await _family_rows(new_refresh)
    old = next(r for r in rows if r.token_hash == hash_token(old_refresh))
    assert old.revoked_reason == RevokedReason.ROTATED and old.replaced_by is not None
    assert (await reg.client.get("/api/v1/auth/me")).status_code == 200


async def test_reuse_after_grace_revokes_whole_family() -> None:
    reg = await register()
    old = {k: reg.client.cookies.get(k) or "" for k in (REFRESH_COOKIE, CSRF_COOKIE)}
    assert (await reg.client.post(REFRESH, headers=csrf(reg.client))).status_code == 204
    current_refresh = reg.client.cookies.get(REFRESH_COOKIE) or ""

    # Age the rotation beyond the grace window.
    async with tenant_session(None, None) as s:
        await s.execute(
            update(RefreshToken)
            .where(RefreshToken.token_hash == hash_token(old[REFRESH_COOKIE]))
            .values(revoked_at=datetime.now(UTC) - timedelta(minutes=1))
        )

    replay = await _client_with(old).post(REFRESH)
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "refresh_reused"
    # Revocation was committed despite the 401: the legitimate newest token is dead too.
    assert all(r.revoked_at is not None for r in await _family_rows(current_refresh))
    assert len(await _auth_events(AuthEventType.REFRESH_REUSE_DETECTED)) == 1
    victim = await reg.client.post(REFRESH, headers=csrf(reg.client))
    assert victim.status_code == 401


async def test_reuse_within_grace_is_stale_not_theft() -> None:
    reg = await register()
    old = {k: reg.client.cookies.get(k) or "" for k in (REFRESH_COOKIE, CSRF_COOKIE)}
    assert (await reg.client.post(REFRESH, headers=csrf(reg.client))).status_code == 204

    other_tab = await _client_with(old).post(REFRESH)
    assert other_tab.status_code == 401
    assert other_tab.json()["error"]["code"] == "stale_refresh"
    assert "set-cookie" not in other_tab.headers  # must not wipe the fresh cookies
    # Family still valid for the tab holding the new token.
    assert (await reg.client.post(REFRESH, headers=csrf(reg.client))).status_code == 204
    assert await _auth_events(AuthEventType.REFRESH_REUSE_DETECTED) == []


async def test_concurrent_refresh_with_same_token_has_one_winner() -> None:
    reg = await register()
    cookies = {k: reg.client.cookies.get(k) or "" for k in (REFRESH_COOKIE, CSRF_COOKIE)}
    results = await asyncio.gather(*(_client_with(cookies).post(REFRESH) for _ in range(5)))
    statuses = sorted(r.status_code for r in results)
    assert statuses.count(204) == 1
    assert {r.json()["error"]["code"] for r in results if r.status_code == 401} == {"stale_refresh"}
    rows = await _family_rows(cookies[REFRESH_COOKIE])
    assert len([r for r in rows if r.revoked_at is None]) == 1  # no forked family


async def test_refresh_without_cookie_is_rejected() -> None:
    client = _client_with({CSRF_COOKIE: "abc"})
    response = await client.post(REFRESH)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_refresh"


# --- logout / csrf --------------------------------------------------------------------------


async def test_logout_kills_access_and_refresh() -> None:
    reg = await register()
    stolen = {
        k: reg.client.cookies.get(k) or "" for k in (ACCESS_COOKIE, REFRESH_COOKIE, CSRF_COOKIE)
    }
    response = await reg.client.post("/api/v1/auth/logout", headers=csrf(reg.client))
    assert response.status_code == 204

    replayed = _client_with(stolen)
    assert (await replayed.get("/api/v1/auth/me")).status_code == 401  # access denylisted
    assert (await replayed.post(REFRESH)).status_code == 401  # family revoked
    assert len(await _auth_events(AuthEventType.LOGOUT)) == 1


@pytest.mark.parametrize("header", [None, "wrong-token"])
async def test_mutation_without_valid_csrf_is_forbidden(header: str | None) -> None:
    reg = await register()
    headers = {"X-CSRF-Token": header} if header else {}
    response = await reg.client.post("/api/v1/auth/logout", headers=headers)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"
    # Session untouched.
    assert (await reg.client.get("/api/v1/auth/me")).status_code == 200


async def test_inactive_user_cannot_use_access_token() -> None:
    reg = await register()
    async with tenant_session(None, None) as s:
        await s.execute(update(User).where(User.id == reg.user_id).values(is_active=False))
    me = await reg.client.get("/api/v1/auth/me")
    assert (me.status_code, me.json()["error"]["code"]) == (401, "invalid_token")
    refreshed = await reg.client.post(REFRESH, headers=csrf(reg.client))
    assert (refreshed.status_code, refreshed.json()["error"]["code"]) == (401, "invalid_refresh")


# --- review follow-ups -----------------------------------------------------------------------


async def test_csrf_survives_malformed_cookie_before_it() -> None:
    """A JSON/space cookie from another script must not hide cl_csrf (SimpleCookie would)."""
    reg = await register()
    token = reg.client.cookies.get(CSRF_COOKIE) or ""
    refresh = reg.client.cookies.get(REFRESH_COOKIE) or ""
    client = new_client()
    client.headers["Cookie"] = (
        f'theme={{"d":1}}; pref=a b; {CSRF_COOKIE}={token}; {REFRESH_COOKIE}={refresh}'
    )
    response = await client.post(REFRESH, headers={"X-CSRF-Token": token})
    assert response.status_code == 204


async def test_refresh_requires_csrf() -> None:
    reg = await register()
    response = await reg.client.post(REFRESH)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"


async def test_expired_refresh_token_is_invalid() -> None:
    reg = await register()
    refresh = reg.client.cookies.get(REFRESH_COOKIE) or ""
    async with tenant_session(None, None) as s:
        await s.execute(
            update(RefreshToken)
            .where(RefreshToken.token_hash == hash_token(refresh))
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
    response = await reg.client.post(REFRESH, headers=csrf(reg.client))
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_refresh"


async def test_deactivated_user_refresh_revokes_family_cleanly() -> None:
    reg = await register()
    refresh = reg.client.cookies.get(REFRESH_COOKIE) or ""
    async with tenant_session(None, None) as s:
        await s.execute(update(User).where(User.id == reg.user_id).values(is_active=False))
    response = await reg.client.post(REFRESH, headers=csrf(reg.client))
    assert response.status_code == 401
    rows = await _family_rows(refresh)
    assert all(r.revoked_at is not None for r in rows)
    assert all(r.replaced_by is None for r in rows)


async def test_reuse_detection_also_kills_access_tokens_of_the_family() -> None:
    reg = await register()
    attacker = {
        k: reg.client.cookies.get(k) or "" for k in (ACCESS_COOKIE, REFRESH_COOKIE, CSRF_COOKIE)
    }
    assert (await reg.client.post(REFRESH, headers=csrf(reg.client))).status_code == 204
    async with tenant_session(None, None) as s:
        await s.execute(
            update(RefreshToken)
            .where(RefreshToken.token_hash == hash_token(attacker[REFRESH_COOKIE]))
            .values(revoked_at=datetime.now(UTC) - timedelta(minutes=1))
        )
    assert (await _client_with(attacker).post(REFRESH)).status_code == 401
    # Both the attacker's old access token and the victim's fresh one are dead now.
    assert (await _client_with(attacker).get("/api/v1/auth/me")).status_code == 401
    assert (await reg.client.get("/api/v1/auth/me")).status_code == 401


async def test_logout_without_session_is_a_noop() -> None:
    client = _client_with({CSRF_COOKIE: "token-123"})
    response = await client.post("/api/v1/auth/logout")
    assert response.status_code == 204
    assert await _auth_events(AuthEventType.LOGOUT) == []


async def test_login_rehashes_outdated_password_hash() -> None:
    reg = await register()
    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(PASSWORD)
    async with tenant_session(None, None) as s:
        await s.execute(update(User).where(User.id == reg.user_id).values(password_hash=weak))
    await login(reg.email)
    async with tenant_session(None, None) as s:
        stored = (
            await s.execute(select(User.password_hash).where(User.id == reg.user_id))
        ).scalar()
    assert stored != weak and stored.startswith("$argon2id$")


async def test_session_lifetime_is_capped() -> None:
    reg = await register()
    refresh = reg.client.cookies.get(REFRESH_COOKIE) or ""
    async with tenant_session(None, None) as s:
        await s.execute(
            update(RefreshToken)
            .where(RefreshToken.token_hash == hash_token(refresh))
            .values(created_at=datetime.now(UTC) - SESSION_MAX_AGE + timedelta(days=1))
        )
    assert (await reg.client.post(REFRESH, headers=csrf(reg.client))).status_code == 204
    newest = max(
        await _family_rows(reg.client.cookies.get(REFRESH_COOKIE) or ""), key=lambda r: r.created_at
    )
    assert newest.expires_at - datetime.now(UTC) < timedelta(days=1, minutes=1)


@pytest.mark.parametrize("field", ["display_name", "organization_name"])
@pytest.mark.parametrize("value", ["a\u0000b", "   ", "line\nbreak"])
async def test_names_reject_control_characters_and_blank(field: str, value: str) -> None:
    payload = {
        "email": unique_email(),
        "password": PASSWORD,
        "display_name": "Ana",
        "organization_name": "Blue Team",
    }
    payload[field] = value.encode().decode("unicode_escape")
    response = await new_client().post("/api/v1/auth/register", json=payload)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


async def test_unknown_route_and_method_use_error_envelope() -> None:
    client = new_client()
    missing = await client.get("/api/v1/nope")
    wrong_method = await client.get("/api/v1/auth/login")
    assert (missing.status_code, missing.json()["error"]["code"]) == (404, "not_found")
    assert (wrong_method.status_code, wrong_method.json()["error"]["code"]) == (
        405,
        "method_not_allowed",
    )
