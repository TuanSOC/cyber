import asyncio

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from app.core.config import get_settings
from tests.factories import PASSWORD, new_client, register, unique_email


async def _login(ip: str, email: str, password: str) -> int:
    response = await new_client(ip).post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    return response.status_code


async def test_login_rate_limit_per_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "rate_limit_login_per_ip_per_min", 3)
    reg = await register()
    statuses = [await _login("10.1.1.1", reg.email, PASSWORD) for _ in range(4)]
    assert statuses == [200, 200, 200, 429]
    # A different client IP is unaffected.
    assert await _login("10.1.1.2", reg.email, PASSWORD) == 200


async def test_rate_limit_response_has_retry_after(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "rate_limit_login_per_ip_per_min", 0)
    response = await new_client("10.1.1.3").post(
        "/api/v1/auth/login", json={"email": "a@example.com", "password": PASSWORD}
    )
    assert response.status_code == 429
    assert int(response.headers["retry-after"]) > 0
    assert response.json()["error"]["code"] == "rate_limited"


async def test_failed_logins_lock_only_that_email_and_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "rate_limit_login_failures_per_15min", 2)
    reg = await register()
    attacker, victim = "10.2.2.2", "10.3.3.3"
    assert [await _login(attacker, reg.email, "wrong password 1") for _ in range(2)] == [401, 401]
    # Attacker's (email, ip) pair is now locked, even with the right password.
    assert await _login(attacker, reg.email, PASSWORD) == 429
    # The real user from another IP is not locked out.
    assert await _login(victim, reg.email, PASSWORD) == 200


async def test_concurrent_bad_guesses_cannot_exceed_failure_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(get_settings(), "rate_limit_login_failures_per_15min", 3)
    reg = await register()
    results = await asyncio.gather(
        *(_login("10.6.6.6", reg.email, f"wrong password {i}") for i in range(10))
    )
    assert results.count(401) == 3
    assert results.count(429) == 7


async def test_successful_logins_do_not_count_as_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "rate_limit_login_failures_per_15min", 1)
    reg = await register()
    assert [await _login("10.4.4.4", reg.email, PASSWORD) for _ in range(3)] == [200, 200, 200]


async def test_register_rate_limit_per_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "rate_limit_register_per_ip_per_10min", 1)
    payload = {"password": PASSWORD, "display_name": "x", "organization_name": "Org"}
    first = await new_client("10.5.5.5").post(
        "/api/v1/auth/register", json={"email": unique_email(), **payload}
    )
    second = await new_client("10.5.5.5").post(
        "/api/v1/auth/register", json={"email": unique_email(), **payload}
    )
    assert (first.status_code, second.status_code) == (201, 429)


async def test_redis_outage_fails_closed_with_503(monkeypatch: pytest.MonkeyPatch) -> None:
    class DownRedis:
        def pipeline(self, *args: object, **kwargs: object) -> None:
            raise RedisConnectionError("redis is down")

    monkeypatch.setattr("app.core.rate_limit.get_redis", lambda: DownRedis())
    response = await new_client().post(
        "/api/v1/auth/login", json={"email": "a@example.com", "password": PASSWORD}
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "service_unavailable"
