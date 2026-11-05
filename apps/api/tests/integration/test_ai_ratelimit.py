"""AI analyst request limiter (M5 phase 2): token bucket, cooldowns, verify dedupe, repair
scratch, all under `{prefix}analyst.ai:*` and run as the broker's `analyst` user."""

import math
import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from redis.asyncio import Redis

from app.core.config import AiCeilings, get_settings
from app.modules.ai.contracts import AiProviderName
from app.modules.ai.ratelimit import (
    VERIFY_DEDUPE_S,
    AiLimiter,
    Decision,
    LimiterUnavailable,
    broker_redis,
    cooldown_seconds,
    effective_per_minute,
    seconds_to_next_minute,
    seconds_to_utc_midnight,
)

MOCK = AiProviderName.MOCK


class Clock:
    def __init__(self, at: datetime) -> None:
        self.now = at.timestamp()

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest_asyncio.fixture(loop_scope="session")
async def broker() -> AsyncIterator[Redis]:
    """The analyst's own broker user: every key must be inside its ACL pattern."""
    client = broker_redis(os.environ["TEST_BROKER_ANALYST_URL"])
    yield client
    await client.aclose()


def _limiter(broker: Redis, clock: Clock | None = None) -> AiLimiter:
    clock = clock or Clock(datetime(2026, 11, 5, 12, tzinfo=UTC))
    return AiLimiter(broker, get_settings().queue_prefix, clock=clock)


async def test_keys_live_under_the_analyst_prefix(broker: Redis) -> None:
    limiter = _limiter(broker)
    org = uuid.uuid4()
    run = uuid.uuid4()
    assert limiter.keys(MOCK, org) == (
        f"test.analyst.ai:rl:mock:{org}",
        f"test.analyst.ai:cool:mock:{org}",
    )
    assert limiter.verify_key("anthropic", org, 3) == f"test.analyst.ai:verify:{org}:anthropic:3"
    assert limiter.repair_key(run) == f"test.analyst.ai:repair:{run}"


async def test_token_bucket_refills_per_minute(broker: Redis) -> None:
    clock = Clock(datetime(2026, 11, 5, 12, tzinfo=UTC))
    limiter = _limiter(broker, clock)
    org = uuid.uuid4()
    assert (await limiter.acquire(MOCK, org, 2)).decision is Decision.OK
    assert (await limiter.acquire(MOCK, org, 2)).decision is Decision.OK
    waiting = await limiter.acquire(MOCK, org, 2)
    assert waiting.decision is Decision.WAIT
    assert 29 <= waiting.wait_s <= 30
    clock.advance(30)
    assert (await limiter.acquire(MOCK, org, 2)).decision is Decision.OK
    # Buckets are per org and per provider.
    assert (await limiter.acquire(MOCK, uuid.uuid4(), 2)).decision is Decision.OK
    assert (await limiter.acquire("gemini", org, 2)).decision is Decision.OK


async def test_cooldown_blocks_and_is_never_shortened(broker: Redis) -> None:
    limiter = _limiter(broker)
    org = uuid.uuid4()
    await limiter.set_cooldown(MOCK, org, 5)
    await limiter.set_cooldown(MOCK, org, 1)  # a shorter one never shortens it
    blocked = await limiter.acquire(MOCK, org, 100)
    assert blocked.decision is Decision.COOLDOWN
    assert 4 < blocked.wait_s <= 5
    assert await broker.pttl(limiter.keys(MOCK, org)[1]) > 4000


async def test_spend_limit_cooldown_lasts_until_utc_midnight(broker: Redis) -> None:
    limiter = _limiter(broker, Clock(datetime(2026, 11, 5, 23, 59, tzinfo=UTC)))
    org = uuid.uuid4()
    assert await limiter.cooldown_until_midnight(MOCK, org) == 60
    assert (await limiter.acquire(MOCK, org, 100)).decision is Decision.COOLDOWN


def test_retry_after_is_clamped_or_defaults_to_the_next_minute() -> None:
    now = datetime(2026, 11, 5, 12, 0, 45, tzinfo=UTC).timestamp()
    assert cooldown_seconds(7, now) == 7
    assert cooldown_seconds(0.2, now) == 1
    assert cooldown_seconds(99_999, now) == 3600
    assert cooldown_seconds(None, now) == 15
    assert cooldown_seconds(0, now) == 15
    assert cooldown_seconds(math.nan, now) == 15
    assert cooldown_seconds(math.inf, now) == 15
    assert seconds_to_next_minute(now) == 15
    assert seconds_to_utc_midnight(datetime(2026, 11, 5, 23, 0, tzinfo=UTC).timestamp()) == 3600


def test_effective_per_minute_lowers_but_never_raises() -> None:
    settings = get_settings().model_copy(update={"ai_ceilings": AiCeilings()})
    assert effective_per_minute(settings, MOCK, None) == 600  # catalog default
    assert effective_per_minute(settings, MOCK, {"per_minute": 5}) == 5
    assert effective_per_minute(settings, MOCK, {"per_minute": 10**6}) == 6000  # catalog ceiling
    for bad in (0, -1, True, "7", 2.5):
        assert effective_per_minute(settings, MOCK, {"per_minute": bad}) == 600
    capped = settings.model_copy(update={"ai_ceilings": AiCeilings(per_minute={MOCK: 50})})
    assert effective_per_minute(capped, MOCK, None) == 50
    assert effective_per_minute(capped, MOCK, {"per_minute": 70}) == 50
    assert effective_per_minute(capped, "anthropic", None) == 20


async def test_verify_checks_are_deduped_per_key_version(broker: Redis) -> None:
    limiter = _limiter(broker)
    org = uuid.uuid4()
    assert await limiter.claim_verify(MOCK, org, 1) is True
    assert await limiter.claim_verify(MOCK, org, 1) is False
    assert await limiter.claim_verify(MOCK, org, 2) is True
    ttl = await broker.ttl(limiter.verify_key(MOCK, org, 1))
    assert 0 < ttl <= VERIFY_DEDUPE_S


async def test_repair_errors_round_trip(broker: Redis) -> None:
    limiter = _limiter(broker)
    run = uuid.uuid4()
    assert await limiter.load_repair(run) == []
    await limiter.save_repair(run, ["observed: list_type", "overall_confidence: missing"])
    assert await limiter.load_repair(run) == ["observed: list_type", "overall_confidence: missing"]
    await broker.set(limiter.repair_key(run), "not json")
    assert await limiter.load_repair(run) == []


async def test_broker_errors_fail_closed() -> None:
    down = broker_redis("redis://127.0.0.1:1/0")
    limiter = AiLimiter(down, "test.")
    try:
        with pytest.raises(LimiterUnavailable):
            await limiter.acquire(MOCK, uuid.uuid4(), 10)
        with pytest.raises(LimiterUnavailable):
            await limiter.set_cooldown(MOCK, uuid.uuid4(), 5)
        with pytest.raises(LimiterUnavailable):
            await limiter.claim_verify(MOCK, uuid.uuid4(), 1)
    finally:
        await down.aclose()


async def test_keys_outside_the_acl_pattern_are_refused(broker: Redis) -> None:
    """The analyst user cannot use another prefix (e.g. the enrich limiter's): fail closed."""
    outside = AiLimiter(broker, "test.enrich.")
    with pytest.raises(LimiterUnavailable):
        await outside.acquire(MOCK, uuid.uuid4(), 10)
