from app.core.clients import get_redis
from app.core.errors import TooManyRequests

_PREFIX = "rl:"


async def hit(key: str, limit: int, window_s: int) -> None:
    """Atomically count one attempt in a fixed window; raise 429 once the limit is exceeded.

    The counter is incremented before the check, so concurrent attempts cannot all slip
    through on a stale read.
    """
    redis = get_redis()
    full_key = _PREFIX + key
    async with redis.pipeline(transaction=True) as pipe:
        pipe.incr(full_key)
        pipe.expire(full_key, window_s, nx=True)
        count, _ = await pipe.execute()
    if int(count) > limit:
        raise TooManyRequests(retry_after=await _ttl(full_key, window_s))


async def release(key: str) -> None:
    """Give back a slot taken by hit() (e.g. the attempt turned out not to be a failure)."""
    await get_redis().decr(_PREFIX + key)


async def _ttl(full_key: str, window_s: int) -> int:
    ttl = await get_redis().ttl(full_key)
    return int(ttl) if ttl and ttl > 0 else window_s
