"""`core/audit_dedupe.once_per` (M7 phase 1): one Redis `SET NX EX` under `ad:` (the test
Redis db; the session fixtures flush it between tests)."""

import asyncio

import pytest

from app.core.audit_dedupe import PREFIX, once_per
from app.core.clients import get_redis


async def test_first_call_wins_until_the_ttl_expires() -> None:
    key = "evidence.viewed:user-1:evidence-1"
    assert await once_per(key, 60) is True
    assert await once_per(key, 60) is False
    assert await once_per("evidence.viewed:user-1:evidence-2", 60) is True
    ttl = await get_redis().ttl(PREFIX + key)
    assert 0 < ttl <= 60


async def test_the_key_comes_back_after_its_ttl() -> None:
    key = "evidence.custody_viewed:user-1:evidence-1"
    assert await once_per(key, 1) is True
    await asyncio.sleep(1.2)
    assert await once_per(key, 1) is True


async def test_concurrent_callers_get_exactly_one_true() -> None:
    results = await asyncio.gather(*(once_per("race:user:evidence", 30) for _ in range(20)))
    assert results.count(True) == 1


@pytest.mark.parametrize(("key", "ttl"), [("", 10), ("x" * 257, 10), ("ok", 0)])
async def test_bad_arguments_are_refused(key: str, ttl: int) -> None:
    with pytest.raises(ValueError):
        await once_per(key, ttl)
