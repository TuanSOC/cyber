"""Deduplicated audit writes (M7 phase 1; used by phase 6's evidence view audit).

`once_per(key, ttl_s)` is True the first time a key is seen within `ttl_s` seconds and False
afterwards, through one Redis `SET NX EX` on the app Redis (`ad:` prefix). Callers build the
key from fixed ids only (for example `evidence.viewed:<user>:<evidence>`), never from request
text. A Redis failure raises (the API's handler answers 503): like the denylist and the rate
limits, the audit fails closed instead of silently skipping a record.
"""

from app.core.clients import get_redis

PREFIX = "ad:"


async def once_per(key: str, ttl_s: int) -> bool:
    """True when this call is the first for `key` within `ttl_s` seconds."""
    if ttl_s < 1:
        raise ValueError("ttl_s must be at least 1 second")
    if not key or len(key) > 256:
        raise ValueError("audit dedupe keys are 1..256 characters")
    return bool(await get_redis().set(PREFIX + key, b"1", nx=True, ex=ttl_s))
