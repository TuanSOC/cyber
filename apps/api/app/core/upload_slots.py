"""Per-user concurrency slots for expensive evidence operations (upload, verify).

Each holder is a token in a Redis sorted set scored by its start time; expired tokens are
pruned atomically on acquire. A crashed worker therefore cannot hold a slot forever, and
rejected attempts never extend anyone's lease.
"""

import logging
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import anyio
from redis.exceptions import RedisError

from app.core.clients import get_redis
from app.core.errors import TooManyRequests

log = logging.getLogger(__name__)

# Longest an operation may legitimately take before its slot is considered leaked.
SLOT_TTL_S = 6 * 3600

_ACQUIRE = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', tonumber(ARGV[1]) - tonumber(ARGV[2]))
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) then
  return 0
end
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[4])
redis.call('EXPIRE', KEYS[1], ARGV[2])
return 1
"""


def slot_key(kind: str, user_id: uuid.UUID) -> str:
    return f"slots:{kind}:{user_id}"


@asynccontextmanager
async def slot(kind: str, user_id: uuid.UUID, limit: int) -> AsyncIterator[None]:
    redis = get_redis()
    key = slot_key(kind, user_id)
    token = uuid.uuid4().hex
    acquired = await redis.eval(_ACQUIRE, 1, key, time.time(), SLOT_TTL_S, limit, token)
    if not acquired:
        raise TooManyRequests(retry_after=30)
    try:
        yield
    finally:
        # Best effort: the response must not change because releasing failed; an
        # unreleased token simply expires after SLOT_TTL_S.
        with anyio.CancelScope(shield=True):
            try:
                await redis.zrem(key, token)
            except RedisError:
                log.warning("could not release %s slot for user %s", kind, user_id)
