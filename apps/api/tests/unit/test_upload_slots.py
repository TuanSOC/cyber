import time
import uuid

import pytest

from app.core.clients import get_redis
from app.core.errors import TooManyRequests
from app.core.upload_slots import SLOT_TTL_S, slot, slot_key


async def test_slots_bound_concurrency_and_release() -> None:
    user = uuid.uuid4()
    async with slot("upload", user, 2), slot("upload", user, 2):
        with pytest.raises(TooManyRequests):
            async with slot("upload", user, 2):
                pass
    assert await get_redis().zcard(slot_key("upload", user)) == 0


async def test_slot_released_when_body_raises() -> None:
    user = uuid.uuid4()
    with pytest.raises(RuntimeError):
        async with slot("upload", user, 1):
            raise RuntimeError("boom")
    assert await get_redis().zcard(slot_key("upload", user)) == 0


async def test_rejected_attempts_do_not_extend_and_leaked_slots_expire() -> None:
    user = uuid.uuid4()
    key = slot_key("upload", user)
    # A token leaked by a crashed worker long ago.
    await get_redis().zadd(key, {"leaked": time.time() - SLOT_TTL_S - 1})
    async with slot("upload", user, 1):  # leaked token is pruned, slot available
        assert await get_redis().zscore(key, "leaked") is None


async def test_kinds_are_independent() -> None:
    user = uuid.uuid4()
    async with slot("upload", user, 1), slot("verify", user, 1):
        pass
