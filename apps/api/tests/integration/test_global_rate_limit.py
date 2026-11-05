"""Global per-user API rate limit (M7 phase 6): `RATE_LIMIT_USER_PER_MIN` (600) hits per user
per 60 s fixed window, counted in `current_user` after the token is validated.

- Exempt: `GET /auth/me` (shell polling); the health routes and `GET /report-signing-keys`
  never resolve the user (the keys route keeps its own per-IP limit).
- There is no anonymous per-IP limiter (RT14, cut): login, register and refresh keep their
  own limits.
- The web polling hooks stay well under 600 / min: AI runs every 2 s while active (then back
  off), analyses and renders every 3 s, TI runs with back-off, settings every 60 s. One open
  view polls at most about 1 request per 2 s (30 / min), so even ten busy tabs stay below
  the limit.
- The api-test and e2e environments raise the limit (100 000); these tests lower it through
  the settings object.
"""

import asyncio
import uuid

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from app.core.clients import get_redis
from app.core.config import get_settings
from app.core.deps import USER_LIMIT_PREFIX
from tests.factories import csrf, login, new_client, register

LIMIT = 5


@pytest.fixture
def low_limit(monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setattr(get_settings(), "rate_limit_user_per_min", LIMIT)
    return LIMIT


async def test_test_env_default_is_high() -> None:
    # The suites run with the raised test value; dev / prod default to 600.
    assert get_settings().rate_limit_user_per_min >= 100_000
    assert type(get_settings()).model_fields["rate_limit_user_per_min"].default == 600


async def test_request_over_the_limit_is_429_with_retry_after(low_limit: int) -> None:
    reg = await register()
    statuses = [(await reg.client.get("/api/v1/orgs")).status_code for _ in range(low_limit)]
    assert statuses == [200] * low_limit
    over = await reg.client.get("/api/v1/orgs")
    assert over.status_code == 429
    assert 0 < int(over.headers["retry-after"]) <= 60
    assert over.json()["error"]["code"] == "rate_limited"
    # Every authenticated route shares the one per-user budget.
    other = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/investigations")
    assert other.status_code == 429


async def test_the_601st_request_in_a_window_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "rate_limit_user_per_min", 600)
    reg = await register()
    key = f"rl:{USER_LIMIT_PREFIX}{reg.user_id}"
    # 599 requests already counted in this window (seeded instead of sent, for speed).
    await get_redis().set(key, 599, ex=60)
    assert (await reg.client.get("/api/v1/orgs")).status_code == 200  # the 600th
    assert (await reg.client.get("/api/v1/orgs")).status_code == 429  # the 601st
    assert int(await get_redis().get(key)) == 601


async def test_the_limit_is_per_user(low_limit: int) -> None:
    first, second = await register(), await register()
    for _ in range(low_limit):
        await first.client.get("/api/v1/orgs")
    assert (await first.client.get("/api/v1/orgs")).status_code == 429
    assert (await second.client.get("/api/v1/orgs")).status_code == 200


async def test_the_key_is_the_user_not_the_client(low_limit: int) -> None:
    reg = await register()
    other_session = await login(reg.email, ip="10.9.9.9")  # same user, another IP and token
    for _ in range(low_limit):
        await reg.client.get("/api/v1/orgs")
    assert (await other_session.get("/api/v1/orgs")).status_code == 429


async def test_auth_me_and_health_are_exempt(low_limit: int) -> None:
    reg = await register()
    for _ in range(low_limit):
        await reg.client.get("/api/v1/orgs")
    assert (await reg.client.get("/api/v1/orgs")).status_code == 429
    for _ in range(low_limit * 2):
        assert (await reg.client.get("/api/v1/auth/me")).status_code == 200
    assert (await reg.client.get("/api/v1/health")).status_code == 200
    keys = (await reg.client.get("/api/v1/report-signing-keys")).status_code
    assert keys == 200


async def test_a_request_counts_once_however_many_dependencies(low_limit: int) -> None:
    """A route with both `CurrentUserDep` and an org permission dependency counts one hit."""
    reg = await register()
    case = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations",
        json={"title": "Limit case", "severity": "low"},
        headers=csrf(reg.client),
    )
    assert case.status_code == 201
    upload = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations/{case.json()['id']}/evidence",
        params={"filename": "a.txt"},
        content=b"x" * 10_000,
        headers={"Content-Type": "application/octet-stream", **csrf(reg.client)},
    )
    assert upload.status_code == 201
    url = f"/api/v1/orgs/{reg.org_id}/evidence/{upload.json()['id']}"
    # 2 hits so far (case, upload); the download streams its body in one request.
    statuses = [(await reg.client.get(f"{url}/download")).status_code for _ in range(3)]
    assert statuses == [200, 200, 200]
    assert (await reg.client.get(url)).status_code == 429


async def test_concurrent_requests_cannot_exceed_the_limit(low_limit: int) -> None:
    reg = await register()
    results = await asyncio.gather(*(reg.client.get("/api/v1/orgs") for _ in range(12)))
    codes = [r.status_code for r in results]
    assert codes.count(200) == low_limit
    assert codes.count(429) == 12 - low_limit


async def test_unauthenticated_requests_do_not_touch_the_user_budget(low_limit: int) -> None:
    anonymous = new_client("10.8.8.8")
    for _ in range(low_limit + 2):
        assert (await anonymous.get("/api/v1/orgs")).status_code == 401
    assert [k async for k in get_redis().scan_iter(match=f"rl:{USER_LIMIT_PREFIX}*")] == []


async def test_redis_outage_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = await register()

    class DownRedis:
        def pipeline(self, *args: object, **kwargs: object) -> None:
            raise RedisConnectionError("redis is down")

    monkeypatch.setattr("app.core.rate_limit.get_redis", lambda: DownRedis())
    response = await reg.client.get("/api/v1/orgs")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "service_unavailable"


async def test_window_counter_key_and_ttl(low_limit: int) -> None:
    reg = await register()
    await reg.client.get("/api/v1/orgs")
    key = f"rl:{USER_LIMIT_PREFIX}{reg.user_id}"
    assert int(await get_redis().get(key)) == 1
    assert 0 < await get_redis().ttl(key) <= 60
    assert uuid.UUID(key.rsplit(":", 1)[-1]) == reg.user_id
