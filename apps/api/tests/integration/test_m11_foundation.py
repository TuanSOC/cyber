"""M11 phase 1 plumbing: the frozen identity routes exist, check membership / permission and
answer 501 until their phase; sessions carry `sid` / `amr` through login, refresh and logout
(and a family without a session row is refused, RT7); the four public POSTs pass CSRF without
a session (RT4); registration modes; API keys are parsed, refused and never mixed with a
cookie; `revoke_all` kills every other session (RT17); `policy_exempt` routes."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.routing import APIRoute
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.config import get_settings
from app.core.cookies import ACCESS_COOKIE
from app.core.rbac import Permission, require
from app.main import app
from app.modules.auth.models import RevokedReason
from app.modules.identity import sessions_store
from app.modules.organizations.models import MemberRole
from tests.factories import (
    PASSWORD,
    add_membership,
    csrf,
    login,
    make_user,
    new_client,
    register,
    unique_email,
)
from tests.identity_helpers import (
    M11_NON_ORG_STUBS,
    get_session_row,
    seed_api_key,
    session_id_of,
    set_password_hash,
)
from tests.security import idor_cases_api_keys, idor_cases_identity, idor_cases_invitations

ORG_PENDING = (
    idor_cases_invitations.PENDING_ROUTES
    | idor_cases_identity.PENDING_ROUTES
    | idor_cases_api_keys.PENDING_ROUTES
)
SECURITY_MANAGE_ROUTES = {
    ("PUT", "/api/v1/orgs/{org_id}/security-policy"),
    ("PUT", "/api/v1/orgs/{org_id}/sso"),
    ("DELETE", "/api/v1/orgs/{org_id}/sso/secret"),
    ("POST", "/api/v1/orgs/{org_id}/sso/refresh-metadata"),
    ("POST", "/api/v1/orgs/{org_id}/domains"),
    ("POST", "/api/v1/orgs/{org_id}/domains/{domain_id}/verify"),
    ("DELETE", "/api/v1/orgs/{org_id}/domains/{domain_id}"),
    ("GET", "/api/v1/orgs/{org_id}/api-keys"),
    ("POST", "/api/v1/orgs/{org_id}/api-keys"),
    ("POST", "/api/v1/orgs/{org_id}/api-keys/{key_id}/revoke"),
}
_IDS = {
    "invitation_id": str(uuid.uuid4()),
    "domain_id": str(uuid.uuid4()),
    "key_id": str(uuid.uuid4()),
    "session_id": str(uuid.uuid4()),
}


def _routes() -> set[tuple[str, str]]:
    return {
        (method.upper(), path)
        for path, item in app.openapi()["paths"].items()
        for method in item
    }


def test_every_m11_route_is_frozen() -> None:
    assert len(ORG_PENDING) == 17
    assert ORG_PENDING <= _routes(), sorted(ORG_PENDING - _routes())
    non_org = {(m, f"/api/v1{p}") for m, p in M11_NON_ORG_STUBS}
    assert non_org <= _routes(), sorted(non_org - _routes())


def test_policy_exempt_routes_are_exactly_two() -> None:
    """RT13: only the org page and the policy GET skip `check_org_access`."""
    exempt = sorted(
        (sorted(route.methods)[0], route.path)
        for route in app.routes
        if isinstance(route, APIRoute)
        for dep in route.dependant.dependencies
        if getattr(dep.call, "policy_exempt", False)
    )
    assert exempt == [
        ("GET", "/api/v1/orgs/{org_id}"),
        ("GET", "/api/v1/orgs/{org_id}/security-policy"),
    ]
    assert require(Permission.ORG_READ, policy_exempt=True) is not require(Permission.ORG_READ)


async def test_org_routes_answer_501_to_owners_403_to_admins_404_to_outsiders() -> None:
    owner = await register(org_name="M11 Org")
    outsider = await register(org_name="M11 Outsider")
    admin_email = unique_email("m11admin")
    await add_membership(owner.org_id, await make_user(admin_email), MemberRole.ADMIN)
    admin = await login(admin_email)
    for method, template in sorted(ORG_PENDING):
        url = template.format(org_id=owner.org_id, **_IDS)
        response = await owner.client.request(method, url, headers=csrf(owner.client))
        # 422 when the stub's body schema refuses the empty body: the route still exists.
        assert response.status_code in (501, 422), (url, response.text)
        if response.status_code == 501:
            assert response.json()["error"]["code"] == "not_implemented"
        foreign = await outsider.client.request(method, url, headers=csrf(outsider.client))
        assert foreign.status_code in (404, 422), (url, foreign.status_code)
        if (method, template) in SECURITY_MANAGE_ROUTES:
            denied = await admin.request(method, url, headers=csrf(admin))
            assert denied.status_code in (403, 422), (url, denied.status_code)


async def test_non_org_stubs_answer_501() -> None:
    reg = await register(org_name="M11 Stubs")
    for method, path in sorted(M11_NON_ORG_STUBS):
        if path == "/auth/sso/callback":
            continue  # a redirect route; phase 8
        url = f"/api/v1{path}".format(**_IDS)
        response = await reg.client.request(method, url, headers=csrf(reg.client))
        assert response.status_code in (501, 422), (url, response.text)


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/v1/auth/sso/start", {"email": "a@corp.example"}),
        ("/api/v1/auth/password/forgot", {"email": "a@corp.example"}),
        ("/api/v1/auth/password/reset", {"token": "x" * 43, "new_password": "p" * 16}),
        ("/api/v1/invitations/inspect", {"token": "x" * 43}),
    ],
)
async def test_the_public_posts_pass_csrf_without_a_session(
    path: str, body: dict[str, str]
) -> None:
    """RT4: a signed-out browser has no `cl_csrf`: 501 (the stub), never 403 csrf_failed."""
    response = await new_client().post(path, json=body)
    assert response.status_code == 501, response.text


async def test_accept_and_mfa_verify_stay_csrf_checked() -> None:
    reg = await register()
    for path, body in (
        ("/api/v1/invitations/accept", {"token": "x" * 43}),
        ("/api/v1/auth/mfa/verify", {"code": "123456"}),
        ("/api/v1/auth/step-up", {"password": PASSWORD}),
    ):
        response = await reg.client.post(path, json=body)
        assert response.status_code == 403, (path, response.text)
        assert response.json()["error"]["code"] == "csrf_failed"


# --- sessions ----------------------------------------------------------------------------------


def _claims(client: object) -> dict[str, object]:
    token = client.cookies.get(ACCESS_COOKIE)  # type: ignore[attr-defined]
    return dict(jwt.decode(token, options={"verify_signature": False}))


async def test_login_refresh_and_logout_follow_the_session_row() -> None:
    reg = await register()
    claims = _claims(reg.client)
    assert claims["sid"] == claims["fid"] and claims["amr"] == ["pwd"] and "sso" not in claims
    sid = session_id_of(reg.client)
    row = await get_session_row(sid)
    assert row is not None and row.user_id == reg.user_id and row.method == "password"
    assert row.expires_at - row.created_at == timedelta(days=30)
    refreshed = await reg.client.post("/api/v1/auth/refresh")
    assert refreshed.status_code == 204
    assert session_id_of(reg.client) == sid and _claims(reg.client)["amr"] == ["pwd"]
    await reg.client.post("/api/v1/auth/logout", headers=csrf(reg.client))
    row = await get_session_row(sid)
    assert row is not None and row.revoked_at is not None
    assert row.revoked_reason == RevokedReason.LOGOUT


async def test_a_family_without_a_session_row_cannot_refresh(owner_engine: AsyncEngine) -> None:
    """RT7: after the 0019 backfill only forged or expired families lack a row."""
    reg = await register()
    sid = session_id_of(reg.client)
    async with owner_engine.begin() as conn:
        await conn.execute(text("DELETE FROM user_sessions WHERE id = :id"), {"id": sid})
    response = await reg.client.post("/api/v1/auth/refresh")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_refresh"


async def test_a_pre_m11_access_token_is_refused_then_refreshed() -> None:
    """Old tokens (no `sid` / `amr`) are refused once; the refresh re-issues them."""
    reg = await register()
    claims = _claims(reg.client)
    now = datetime.now(UTC)
    old = jwt.encode(
        {
            "sub": claims["sub"],
            "fid": claims["fid"],
            "jti": "old",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "typ": "access",
        },
        get_settings().need("jwt_secret"),
        algorithm="HS256",
    )
    reg.client.cookies.set(ACCESS_COOKIE, old, path="/api")
    response = await reg.client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert (await reg.client.post("/api/v1/auth/refresh")).status_code == 204
    assert (await reg.client.get("/api/v1/auth/me")).status_code == 200


async def test_revoke_all_keeps_only_the_named_session() -> None:
    reg = await register()
    second = await login(reg.email)
    third = await login(reg.email)
    keep = session_id_of(second)
    revoked = await sessions_store.revoke_all(
        reg.user_id, reason=RevokedReason.USER_REVOKED, keep=keep
    )
    assert keep not in revoked and len(revoked) == 2
    assert (await second.get("/api/v1/auth/me")).status_code == 200
    for client in (reg.client, third):
        assert (await client.get("/api/v1/auth/me")).status_code == 401
        assert (await client.post("/api/v1/auth/refresh")).status_code == 401


# --- password login of accounts without a password (RT5) and registration --------------------


async def test_an_sso_only_account_answers_like_an_unknown_email() -> None:
    reg = await register()
    await set_password_hash(reg.user_id, "!sso")
    for email in (reg.email, unique_email("nobody")):
        response = await new_client("10.9.0.1").post(
            "/api/v1/auth/login", json={"email": email, "password": PASSWORD}
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "invalid_credentials"


async def test_invite_only_refuses_uninvited_registration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(get_settings(), "registration_mode", "invite_only")
    body = {
        "email": unique_email("closed"),
        "password": PASSWORD,
        "display_name": "Closed",
        "organization_name": "Closed Org",
    }
    response = await new_client("10.9.0.2").post("/api/v1/auth/register", json=body)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "registration_closed"


async def test_register_with_an_invitation_is_frozen_until_phase_3() -> None:
    email = unique_email("invited")
    body = {
        "email": email,
        "password": PASSWORD,
        "display_name": "Invited",
        "invitation_token": "x" * 43,
    }
    response = await new_client("10.9.0.3").post("/api/v1/auth/register", json=body)
    assert response.status_code == 501
    login_attempt = await new_client("10.9.0.3").post(
        "/api/v1/auth/login", json={"email": email, "password": PASSWORD}
    )
    assert login_attempt.status_code == 401  # nothing was created


# --- API keys (refused until phase 9) ----------------------------------------------------------


async def test_api_keys_are_parsed_refused_and_never_mixed_with_cookies() -> None:
    owner = await register(org_name="M11 Keys")
    seeded = await seed_api_key(owner.org_id, owner.user_id)
    url = f"/api/v1/orgs/{owner.org_id}/investigations"
    headers = {"Authorization": f"Bearer {seeded.key}"}
    keyed = new_client("10.9.1.1")
    response = await keyed.get(url, headers=headers)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_api_key"  # resolve() is phase 9's
    me = await keyed.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 401 and me.json()["error"]["code"] == "invalid_token"
    both = await owner.client.get(url, headers=headers)
    assert both.status_code == 400
    assert both.json()["error"]["code"] == "ambiguous_credentials"
    bad = await keyed.get(url, headers={"Authorization": "Bearer clk_nope"})
    assert bad.status_code == 401 and bad.json()["error"]["code"] == "invalid_api_key"


async def test_malformed_keys_hit_the_per_ip_failure_limit() -> None:
    client = new_client("10.9.1.2")
    url = f"/api/v1/orgs/{uuid.uuid4()}/investigations"
    limit = get_settings().rate_limit_api_key_failures_per_ip_per_min
    for _ in range(limit):
        response = await client.get(url, headers={"Authorization": "Bearer junk"})
        assert response.status_code == 401
    response = await client.get(url, headers={"Authorization": "Bearer junk"})
    assert response.status_code == 429
