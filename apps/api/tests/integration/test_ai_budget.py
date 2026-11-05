"""AI token budgets (M5 phase 2, RT8/RT9/RT17): atomic reservations on the day, tree and
platform keys, settlement to actual usage, day-key seeding after a broker restart, fail
closed. Run as the broker's `analyst` user (keys inside its ACL)."""

import asyncio
import os
import secrets
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from redis.asyncio import Redis

from app.core.config import get_settings
from app.modules.ai.budget import (
    DAY_KEY_TTL_S,
    Budget,
    BudgetExhausted,
    BudgetUnavailable,
)
from app.modules.ai.ratelimit import broker_redis


class Clock:
    def __init__(self, at: datetime) -> None:
        self.now = at.timestamp()

    def __call__(self) -> float:
        return self.now


@pytest_asyncio.fixture(loop_scope="session")
async def broker() -> AsyncIterator[Redis]:
    client = broker_redis(os.environ["TEST_BROKER_ANALYST_URL"])
    yield client
    await client.aclose()


def _budget(broker: Redis, clock: Clock | None = None) -> Budget:
    return Budget(broker, get_settings().queue_prefix, clock=clock or Clock(datetime.now(UTC)))


async def _seed(value: int, calls: list[int]) -> int:
    calls.append(value)
    return value


async def test_keys_live_under_the_analyst_prefix(broker: Redis) -> None:
    budget = _budget(broker, Clock(datetime(2026, 11, 5, 12, tzinfo=UTC)))
    org = uuid.uuid4()
    root = uuid.uuid4()
    assert budget.day_key(org) == f"test.analyst.ai:day:{org}:20261105"
    assert budget.tree_key(root) == f"test.analyst.ai:tree:{root}"
    assert budget.platform_key() == "test.analyst.ai:platform:20261105"


async def test_a_missing_day_key_is_seeded_from_the_db_first(broker: Redis) -> None:
    budget = _budget(broker)
    org = uuid.uuid4()
    calls: list[int] = []
    reservation = await budget.reserve(
        org, 100, daily_limit=10_000, seed=lambda: _seed(4_000, calls)
    )
    assert calls == [4_000]
    assert reservation.amount == 100
    assert await budget.used_today(org) == 4_100
    assert 0 < await broker.ttl(budget.day_key(org)) <= DAY_KEY_TTL_S
    # A live key is never re-seeded (SET NX) and the seed is not asked again.
    await budget.reserve(org, 50, daily_limit=10_000, seed=lambda: _seed(9_999, calls))
    assert calls == [4_000]
    assert await budget.seed_day(org, 1) is False
    assert await budget.used_today(org) == 4_150


async def test_the_seed_alone_can_exhaust_the_day(broker: Redis) -> None:
    budget = _budget(broker)
    org = uuid.uuid4()
    with pytest.raises(BudgetExhausted) as exc:
        await budget.reserve(org, 100, daily_limit=1_000, seed=lambda: _seed(950, []))
    assert exc.value.scope == "day"
    assert await budget.used_today(org) == 950


async def test_daily_budget_is_all_or_nothing_and_settles_to_actual(broker: Redis) -> None:
    budget = _budget(broker)
    org = uuid.uuid4()
    first = await budget.reserve(org, 600, daily_limit=1_000, seed=lambda: _seed(0, []))
    with pytest.raises(BudgetExhausted):
        await budget.reserve(org, 600, daily_limit=1_000, seed=lambda: _seed(0, []))
    assert await budget.used_today(org) == 600
    await budget.settle(first, 150)  # actual usage below the reservation
    assert await budget.used_today(org) == 150
    second = await budget.reserve(org, 600, daily_limit=1_000, seed=lambda: _seed(0, []))
    await budget.settle(second, 700)  # above it (a larger answer than estimated)
    assert await budget.used_today(org) == 850


async def test_settle_never_goes_negative_nor_recreates_a_lost_key(broker: Redis) -> None:
    budget = _budget(broker)
    org = uuid.uuid4()
    reservation = await budget.reserve(org, 500, daily_limit=10_000, seed=lambda: _seed(0, []))
    await broker.set(budget.day_key(org), 100, keepttl=True)
    await budget.settle(reservation, 0)
    assert await budget.used_today(org) == 0
    await broker.delete(budget.day_key(org))
    await budget.settle(reservation, 0)
    assert await budget.used_today(org) is None


async def test_incident_tree_cap(broker: Redis) -> None:
    budget = _budget(broker)
    org = uuid.uuid4()
    root = uuid.uuid4()
    seed = lambda: _seed(0, [])  # noqa: E731
    await budget.reserve(org, 300, daily_limit=10_000, seed=seed, tree=(root, 500), seed_tree=seed)
    with pytest.raises(BudgetExhausted) as exc:
        await budget.reserve(
            org, 300, daily_limit=10_000, seed=seed, tree=(root, 500), seed_tree=seed
        )
    assert exc.value.scope == "tree"
    # Nothing of the refused reservation was charged anywhere.
    assert await budget.used_today(org) == 300
    assert int(await broker.get(budget.tree_key(root)) or 0) == 300
    # Another tree, or a run outside any tree, is not affected.
    await budget.reserve(
        org, 300, daily_limit=10_000, seed=seed, tree=(uuid.uuid4(), 500), seed_tree=seed
    )
    await budget.reserve(org, 300, daily_limit=10_000, seed=seed)
    assert await budget.used_today(org) == 900


async def test_platform_key_ceiling_is_global(broker: Redis) -> None:
    # A private day for this test: the platform key is shared by every org of that day.
    day = datetime(2040, 1, 1, tzinfo=UTC) + timedelta(days=secrets.randbelow(10_000))
    budget = _budget(broker, Clock(day))
    await broker.delete(budget.platform_key())
    seed = lambda: _seed(0, [])  # noqa: E731
    try:
        first = await budget.reserve(
            uuid.uuid4(), 400, daily_limit=10_000, seed=seed, platform_limit=500, seed_platform=seed
        )
        with pytest.raises(BudgetExhausted) as exc:
            await budget.reserve(
                uuid.uuid4(),
                400,
                daily_limit=10_000,
                seed=seed,
                platform_limit=500,
                seed_platform=seed,
            )
        assert exc.value.scope == "platform"
        await budget.settle(first, 100)
        assert int(await broker.get(budget.platform_key()) or 0) == 100
        await budget.reserve(
            uuid.uuid4(), 400, daily_limit=10_000, seed=seed, platform_limit=500, seed_platform=seed
        )
    finally:
        await broker.delete(budget.platform_key())


async def test_concurrent_reservations_never_overshoot() -> None:
    """Two workers (two broker connections), one org: the budget is never exceeded."""
    url = os.environ["TEST_BROKER_ANALYST_URL"]
    a, b = broker_redis(url), broker_redis(url)
    try:
        prefix = get_settings().queue_prefix
        budgets = (Budget(a, prefix), Budget(b, prefix))
        org = uuid.uuid4()
        await budgets[0].seed_day(org, 0)

        async def one(n: int) -> bool:
            try:
                await budgets[n % 2].reserve(org, 100, daily_limit=1_000, seed=lambda: _seed(0, []))
            except BudgetExhausted:
                return False
            return True

        results = await asyncio.gather(*(one(n) for n in range(25)))
        assert sum(results) == 10
        assert await budgets[1].used_today(org) == 1_000
    finally:
        await a.aclose()
        await b.aclose()


async def test_broker_errors_fail_closed() -> None:
    down = broker_redis("redis://127.0.0.1:1/0")
    try:
        with pytest.raises(BudgetUnavailable):
            await Budget(down, "test.").reserve(
                uuid.uuid4(), 1, daily_limit=10, seed=lambda: _seed(0, [])
            )
    finally:
        await down.aclose()


async def test_keys_outside_the_acl_pattern_are_refused(broker: Redis) -> None:
    with pytest.raises(BudgetUnavailable):
        await Budget(broker, "test.enrich.").reserve(
            uuid.uuid4(), 1, daily_limit=10, seed=lambda: _seed(0, [])
        )


async def test_missing_tree_and_platform_keys_are_seeded_from_the_db(broker: Redis) -> None:
    """RT8 / RT17: after a broker restart the tree cap and the platform ceiling resume from
    the DB usage instead of silently restarting at zero."""
    day = datetime(2040, 1, 1, tzinfo=UTC) + timedelta(days=secrets.randbelow(10_000))
    budget = _budget(broker, Clock(day))
    await broker.delete(budget.platform_key())
    org = uuid.uuid4()
    root = uuid.uuid4()
    calls: list[int] = []
    try:
        with pytest.raises(BudgetExhausted) as exc:
            await budget.reserve(
                org,
                300,
                daily_limit=10_000,
                seed=lambda: _seed(0, calls),
                tree=(root, 500),
                seed_tree=lambda: _seed(400, calls),
            )
        assert exc.value.scope == "tree" and calls == [0, 400]
        assert int(await broker.get(budget.tree_key(root)) or 0) == 400
        with pytest.raises(BudgetExhausted) as exc:
            await budget.reserve(
                uuid.uuid4(),
                300,
                daily_limit=10_000,
                seed=lambda: _seed(0, calls),
                platform_limit=500,
                seed_platform=lambda: _seed(450, calls),
            )
        assert exc.value.scope == "platform"
        assert int(await broker.get(budget.platform_key()) or 0) == 450
        # A live key is never re-seeded.
        await budget.reserve(
            org,
            50,
            daily_limit=10_000,
            seed=lambda: _seed(0, calls),
            tree=(root, 500),
            seed_tree=lambda: _seed(9_999, calls),
        )
        assert int(await broker.get(budget.tree_key(root)) or 0) == 450
    finally:
        await broker.delete(budget.platform_key())


async def test_missing_tree_or_platform_keys_without_a_seed_fail_closed(broker: Redis) -> None:
    budget = _budget(broker)
    org = uuid.uuid4()
    seed = lambda: _seed(0, [])  # noqa: E731
    with pytest.raises(BudgetUnavailable):
        await budget.reserve(org, 1, daily_limit=10, seed=seed, tree=(uuid.uuid4(), 10))
    day = datetime(2040, 1, 1, tzinfo=UTC) + timedelta(days=secrets.randbelow(10_000))
    other = _budget(broker, Clock(day))
    await broker.delete(other.platform_key())
    with pytest.raises(BudgetUnavailable):
        await other.reserve(org, 1, daily_limit=10, seed=seed, platform_limit=10)
    assert await budget.used_today(org) == 0  # nothing charged
