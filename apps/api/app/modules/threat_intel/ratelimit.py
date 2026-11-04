"""Broker-side provider rate limits (RT2): token bucket, daily cap and cooldowns.

The enrich worker has no app Redis, so its limiter keys live on the broker, inside its ACL
(`{prefix}enrich*`):
- `{prefix}enrich.ti:rl:{provider}:{org}`: a per-minute token bucket (Lua, atomic);
- `{prefix}enrich.ti:day:{provider}:{org}:{yyyymmdd}`: the UTC daily counter (expires 48 h);
- `{prefix}enrich.ti:cool:{provider}:{org}`: a cooldown after a 429 or an exhausted quota.

Effective limits are the org's own (`ti_provider_configs.limits`) capped by the settings
ceilings. A broker error fails closed: `LimiterUnavailable` (no provider call; the run goes
`waiting` and resumes in 30 s, RT8).
"""

import asyncio
import enum
import math
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.modules.threat_intel.catalog import ProviderLimits
from app.modules.threat_intel.providers.base import ProviderName

RETRY_AFTER_MIN_S = 1.0
RETRY_AFTER_MAX_S = 3600.0
DAY_KEY_TTL_S = 48 * 3600
BROKER_TIMEOUT_S = 3.0


class LimiterUnavailable(Exception):
    """The broker could not be asked: fail closed (no provider call)."""


class Decision(enum.StrEnum):
    OK = "ok"
    WAIT = "wait"  # no token yet: `wait_s` until the next one
    COOLDOWN = "cooldown"  # a 429 / quota cooldown is active for `wait_s`
    DAILY_EXHAUSTED = "daily_exhausted"


@dataclass(frozen=True)
class Acquired:
    decision: Decision
    wait_s: float = 0.0


# KEYS: bucket, day, cool. ARGV: now_ms, per_minute, per_day (-1: none), day ttl (s).
# Returns {code, ms}: 0 ok, 1 wait ms, 2 cooldown ms, 3 daily cap reached.
_ACQUIRE = """
local now = tonumber(ARGV[1])
local cap = tonumber(ARGV[2])
local per_day = tonumber(ARGV[3])
local cool = redis.call('PTTL', KEYS[3])
if cool > 0 then return {2, cool} end
if per_day >= 0 then
  local used = tonumber(redis.call('GET', KEYS[2]) or '0')
  if used >= per_day then return {3, 0} end
end
local rate = cap / 60000.0
local state = redis.call('HMGET', KEYS[1], 't', 'ts')
local tokens = tonumber(state[1])
local ts = tonumber(state[2])
if tokens == nil or ts == nil then
  tokens = cap
  ts = now
end
if now > ts then
  tokens = math.min(cap, tokens + (now - ts) * rate)
  ts = now
end
if tokens < 1 then
  return {1, math.ceil((1 - tokens) / rate)}
end
tokens = tokens - 1
redis.call('HSET', KEYS[1], 't', tostring(tokens), 'ts', tostring(ts))
redis.call('PEXPIRE', KEYS[1], math.ceil(cap / rate) + 60000)
if per_day >= 0 then
  redis.call('INCR', KEYS[2])
  redis.call('EXPIRE', KEYS[2], tonumber(ARGV[4]))
end
return {0, 0}
"""

# KEYS: cool. ARGV: ms. Extends a cooldown, never shortens one.
_COOLDOWN = """
local ms = tonumber(ARGV[1])
if redis.call('PTTL', KEYS[1]) < ms then
  redis.call('SET', KEYS[1], '1', 'PX', ms)
end
return 1
"""


def parse_retry_after(value: str | None, *, now: datetime | None = None) -> float | None:
    """`Retry-After` as seconds (delta seconds or an HTTP date), clamped to 1-3600 s.
    None when absent or malformed (the caller applies its default backoff)."""
    if value is None:
        return None
    text = value.strip()
    if not text or len(text) > 64:
        return None
    seconds: float
    if text.isdigit():
        seconds = float(int(text[:10]))
    else:
        try:
            when = parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError, OverflowError):
            return None
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        seconds = (when - (now or datetime.now(UTC))).total_seconds()
    return min(max(seconds, RETRY_AFTER_MIN_S), RETRY_AFTER_MAX_S)


def seconds_to_next_minute(now: float) -> float:
    """The default 429 backoff (VirusTotal's per-minute window): to the next minute."""
    return max(RETRY_AFTER_MIN_S, 60.0 - (now % 60.0))


def seconds_to_utc_midnight(now: float) -> float:
    current = datetime.fromtimestamp(now, UTC)
    midnight = (current + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return max(RETRY_AFTER_MIN_S, (midnight - current).total_seconds())


def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def effective_limits(
    org_limits: Mapping[str, Any] | None, ceiling: ProviderLimits
) -> ProviderLimits:
    """The org's limits, never above the ceiling (an org may only lower them)."""
    org = org_limits or {}
    per_minute = ceiling.per_minute
    if (value := _positive_int(org.get("per_minute"))) is not None:
        per_minute = min(per_minute, value)
    per_day = ceiling.per_day
    if (value := _positive_int(org.get("per_day"))) is not None:
        per_day = value if per_day is None else min(per_day, value)
    concurrency = ceiling.concurrency
    if (value := _positive_int(org.get("concurrency"))) is not None:
        concurrency = min(concurrency, value)
    return ProviderLimits(per_minute=per_minute, per_day=per_day, concurrency=concurrency)


class Limiter:
    def __init__(
        self, redis: Redis, prefix: str, *, clock: Callable[[], float] = time.time
    ) -> None:
        self._redis = redis
        self._base = f"{prefix}enrich.ti"
        self._clock = clock

    def now(self) -> float:
        return self._clock()

    def keys(self, provider: ProviderName, org_id: object) -> tuple[str, str, str]:
        day = datetime.fromtimestamp(self._clock(), UTC).strftime("%Y%m%d")
        return (
            f"{self._base}:rl:{provider.value}:{org_id}",
            f"{self._base}:day:{provider.value}:{org_id}:{day}",
            f"{self._base}:cool:{provider.value}:{org_id}",
        )

    async def _eval(self, script: str, keys: list[str], args: list[Any]) -> Any:
        try:
            async with asyncio.timeout(BROKER_TIMEOUT_S):
                return await self._redis.eval(script, len(keys), *keys, *args)
        except (RedisError, OSError, TimeoutError) as exc:
            raise LimiterUnavailable(type(exc).__name__) from None

    async def acquire(
        self, provider: ProviderName, org_id: object, limits: ProviderLimits
    ) -> Acquired:
        bucket, day, cool = self.keys(provider, org_id)
        now_ms = int(self._clock() * 1000)
        per_day = -1 if limits.per_day is None else limits.per_day
        code, ms = await self._eval(
            _ACQUIRE, [bucket, day, cool], [now_ms, limits.per_minute, per_day, DAY_KEY_TTL_S]
        )
        if int(code) == 0:
            return Acquired(Decision.OK)
        if int(code) == 1:
            return Acquired(Decision.WAIT, int(ms) / 1000)
        if int(code) == 2:
            return Acquired(Decision.COOLDOWN, int(ms) / 1000)
        return Acquired(Decision.DAILY_EXHAUSTED, seconds_to_utc_midnight(self._clock()))

    async def set_cooldown(self, provider: ProviderName, org_id: object, seconds: float) -> None:
        cool = self.keys(provider, org_id)[2]
        await self._eval(_COOLDOWN, [cool], [max(1, math.ceil(seconds * 1000))])

    async def cooldown_until_midnight(self, provider: ProviderName, org_id: object) -> float:
        seconds = seconds_to_utc_midnight(self._clock())
        await self.set_cooldown(provider, org_id, seconds)
        return seconds


def broker_redis(url: str) -> Redis:
    return Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2)


__all__ = [
    "Acquired",
    "Decision",
    "Limiter",
    "LimiterUnavailable",
    "broker_redis",
    "effective_limits",
    "parse_retry_after",
    "seconds_to_next_minute",
    "seconds_to_utc_midnight",
]
