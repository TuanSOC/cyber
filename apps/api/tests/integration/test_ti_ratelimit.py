"""Broker-side provider limits (M4 phase 2, RT2/RT8): token bucket, daily cap, cooldowns."""

import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from redis.asyncio import Redis

from app.core.config import get_settings
from app.modules.threat_intel.catalog import ProviderLimits
from app.modules.threat_intel.providers.base import ProviderName
from app.modules.threat_intel.ratelimit import (
    STRIKE_TTL_S,
    VERIFY_DEDUPE_S,
    Decision,
    Limiter,
    LimiterUnavailable,
    broker_redis,
    effective_limits,
    seconds_to_next_minute,
    seconds_to_utc_midnight,
)

MOCK = ProviderName.MOCK


class Clock:
    def __init__(self, at: datetime) -> None:
        self.now = at.timestamp()

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest_asyncio.fixture(loop_scope="session")
async def broker() -> AsyncIterator[Redis]:
    client = broker_redis(get_settings().broker_url)
    yield client
    await client.aclose()


def _limiter(broker: Redis, clock: Clock) -> Limiter:
    return Limiter(broker, get_settings().queue_prefix, clock=clock)


async def test_keys_live_under_the_enrich_prefix(broker: Redis) -> None:
    limiter = _limiter(broker, Clock(datetime(2026, 11, 5, 12, tzinfo=UTC)))
    org = uuid.uuid4()
    assert limiter.keys(MOCK, org) == (
        f"test.enrich.ti:rl:mock:{org}",
        f"test.enrich.ti:day:mock:{org}:20261105",
        f"test.enrich.ti:cool:mock:{org}",
    )


async def test_bucket_refill(broker: Redis) -> None:
    clock = Clock(datetime(2026, 11, 5, 12, tzinfo=UTC))
    limiter = _limiter(broker, clock)
    org = uuid.uuid4()
    limits = ProviderLimits(per_minute=2, per_day=None)
    assert (await limiter.acquire(MOCK, org, limits)).decision is Decision.OK
    assert (await limiter.acquire(MOCK, org, limits)).decision is Decision.OK
    waiting = await limiter.acquire(MOCK, org, limits)
    assert waiting.decision is Decision.WAIT
    assert waiting.wait_s == pytest.approx(30, abs=0.01)  # one token per 30 s
    clock.advance(15)
    assert (await limiter.acquire(MOCK, org, limits)).wait_s == pytest.approx(15, abs=0.01)
    clock.advance(15)
    assert (await limiter.acquire(MOCK, org, limits)).decision is Decision.OK
    assert (await limiter.acquire(MOCK, org, limits)).decision is Decision.WAIT
    # Orgs and providers have separate buckets.
    assert (await limiter.acquire(MOCK, uuid.uuid4(), limits)).decision is Decision.OK
    assert (await limiter.acquire(ProviderName.OTX, org, limits)).decision is Decision.OK


async def test_daily_cap_rolls_over_at_utc_midnight(broker: Redis) -> None:
    clock = Clock(datetime(2026, 11, 5, 23, 59, 50, tzinfo=UTC))
    limiter = _limiter(broker, clock)
    org = uuid.uuid4()
    limits = ProviderLimits(per_minute=600, per_day=2)
    assert (await limiter.acquire(MOCK, org, limits)).decision is Decision.OK
    assert (await limiter.acquire(MOCK, org, limits)).decision is Decision.OK
    exhausted = await limiter.acquire(MOCK, org, limits)
    assert exhausted.decision is Decision.DAILY_EXHAUSTED
    assert exhausted.wait_s == pytest.approx(10, abs=0.01)  # until 00:00 UTC
    day_key = limiter.keys(MOCK, org)[1]
    assert 0 < await broker.ttl(day_key) <= 48 * 3600
    clock.advance(15)  # 00:00:05 the next day: a new counter
    assert (await limiter.acquire(MOCK, org, limits)).decision is Decision.OK


async def test_cooldowns_extend_but_never_shorten(broker: Redis) -> None:
    limiter = _limiter(broker, Clock(datetime(2026, 11, 5, 12, tzinfo=UTC)))
    org = uuid.uuid4()
    limits = ProviderLimits(per_minute=600, per_day=None)
    await limiter.set_cooldown(MOCK, org, 20)
    blocked = await limiter.acquire(MOCK, org, limits)
    assert blocked.decision is Decision.COOLDOWN
    assert 19 < blocked.wait_s <= 20
    await limiter.set_cooldown(MOCK, org, 2)
    assert (await limiter.acquire(MOCK, org, limits)).wait_s > 19
    # A cooldown consumes no token and no daily count.
    assert await broker.get(limiter.keys(MOCK, org)[1]) is None


async def test_429_strikes_count_a_burst_once_and_reset(broker: Redis) -> None:
    limiter = _limiter(broker, Clock(datetime(2026, 11, 5, 12, tzinfo=UTC)))
    org, vt = uuid.uuid4(), ProviderName.VIRUSTOTAL
    cool, strikes = limiter.keys(vt, org)[2], limiter.strikes_key(vt, org)
    assert strikes == f"test.enrich.ti:strikes:virustotal:{org}"
    assert await limiter.rate_limited(vt, org, 60) == 1
    assert await limiter.rate_limited(vt, org, 60) == 1  # in flight with the first: same burst
    blocked = await limiter.acquire(vt, org, ProviderLimits(per_minute=4, per_day=None))
    assert blocked.decision is Decision.COOLDOWN and 59 < blocked.wait_s <= 60
    await broker.delete(cool)  # the cooldown ran out
    assert await limiter.rate_limited(vt, org, 60) == 2
    assert 0 < await broker.ttl(strikes) <= STRIKE_TTL_S
    await limiter.clear_strikes(vt, org)
    await broker.delete(cool)
    assert await limiter.rate_limited(vt, org, 60) == 1
    assert await limiter.rate_limited(vt, uuid.uuid4(), 60) == 1  # per org


async def test_verify_claims_dedupe_one_stored_key(broker: Redis) -> None:
    limiter = _limiter(broker, Clock(datetime(2026, 11, 5, 12, tzinfo=UTC)))
    org = uuid.uuid4()
    key = limiter.verify_key(MOCK, org, 1)
    assert key == f"test.enrich.ti:verify:{org}:mock:1"
    assert await limiter.claim_verify(MOCK, org, 1) is True
    assert await limiter.claim_verify(MOCK, org, 1) is False
    assert 0 < await broker.ttl(key) <= VERIFY_DEDUPE_S
    assert await limiter.claim_verify(MOCK, org, 2) is True  # a new key is checked at once
    assert await limiter.claim_verify(ProviderName.OTX, org, 1) is True
    assert await limiter.claim_verify(MOCK, uuid.uuid4(), 1) is True


async def test_the_enrich_acl_user_can_run_the_limiter() -> None:
    client = Redis.from_url(os.environ["TEST_BROKER_ENRICH_URL"], socket_timeout=3)
    try:
        limiter = Limiter(client, "test.", clock=Clock(datetime(2026, 11, 5, tzinfo=UTC)))
        org = uuid.uuid4()
        limits = ProviderLimits(per_minute=5, per_day=10)
        assert (await limiter.acquire(MOCK, org, limits)).decision is Decision.OK
        await limiter.set_cooldown(MOCK, org, 1)
        assert await limiter.rate_limited(MOCK, org, 1) >= 0
        await limiter.clear_strikes(MOCK, org)
        assert await limiter.claim_verify(MOCK, org, 1) is True
        # Outside its prefix the same scripts are refused: the limiter fails closed.
        outside = Limiter(client, "test.ingest.", clock=Clock(datetime(2026, 11, 5, tzinfo=UTC)))
        with pytest.raises(LimiterUnavailable):
            await outside.acquire(MOCK, org, limits)
    finally:
        await client.aclose()


async def test_broker_unavailable_fails_closed() -> None:
    client = broker_redis("redis://127.0.0.1:1/1")
    try:
        limiter = Limiter(client, "test.")
        with pytest.raises(LimiterUnavailable):
            await limiter.acquire(MOCK, uuid.uuid4(), ProviderLimits(per_minute=5, per_day=None))
        with pytest.raises(LimiterUnavailable):
            await limiter.set_cooldown(MOCK, uuid.uuid4(), 5)
        with pytest.raises(LimiterUnavailable):
            await limiter.claim_verify(MOCK, uuid.uuid4(), 1)
    finally:
        await client.aclose()


def test_effective_limits_never_exceed_the_ceiling() -> None:
    ceiling = ProviderLimits(per_minute=4, per_day=500, concurrency=4)
    assert effective_limits({}, ceiling) == ceiling
    assert effective_limits(None, ceiling) == ceiling
    assert effective_limits({"per_minute": 2, "per_day": 100}, ceiling) == ProviderLimits(2, 100, 4)
    assert effective_limits({"per_minute": 400, "per_day": 10**6}, ceiling) == ceiling
    for bad in ({"per_minute": 0}, {"per_minute": -1}, {"per_minute": "9"}, {"per_minute": True}):
        assert effective_limits(bad, ceiling) == ceiling
    uncapped = ProviderLimits(per_minute=120, per_day=None)
    assert effective_limits({"per_day": 50}, uncapped).per_day == 50
    assert effective_limits({"concurrency": 1}, uncapped).concurrency == 1


def test_default_backoffs() -> None:
    noon = datetime(2026, 11, 5, 12, 0, 45, tzinfo=UTC).timestamp()
    assert seconds_to_next_minute(noon) == pytest.approx(15)
    late = datetime(2026, 11, 5, 23, 0, 0, tzinfo=UTC).timestamp()
    assert seconds_to_utc_midnight(late) == pytest.approx(3600)
