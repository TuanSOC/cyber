"""Broker-side request limits of the AI analyst (M5): token bucket and cooldowns.

A clone of the M4 limiter (`threat_intel/ratelimit.py`, which is hard-wired to its own
`enrich.ti` prefix and TI provider names, so it is not imported). The analyst worker has no
app Redis: its keys live on the broker inside its ACL (`{prefix}analyst*`):
- `{prefix}analyst.ai:rl:{provider}:{org}`: a per-minute request token bucket (Lua, atomic);
- `{prefix}analyst.ai:cool:{provider}:{org}`: a cooldown after a 429 (from `retry_after_s`,
  clamped 1-3600 s, else to the next minute) or a spend limit (until 00:00 UTC);
- `{prefix}analyst.ai:verify:{org}:{provider}:{key_version}`: `ai.verify` dedupe (SET NX);
- `{prefix}analyst.ai:repair:{run_id}`: the schema errors (JSON paths and error types only,
  never values) carried from a failed call to its repair call in the next message.

Effective per-minute limits are the org's own (`ai_provider_configs.limits.per_minute`)
capped by the operator ceiling (`AI_CEILINGS.per_minute`, else the catalog ceiling); with no
org value the catalog default applies. A broker error fails closed: `LimiterUnavailable`
(no provider call; the run waits and resumes).
"""

import asyncio
import enum
import json
import math
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.config import Settings
from app.modules.ai.catalog import AI_CATALOG
from app.modules.ai.contracts import AiProviderName

RETRY_AFTER_MIN_S = 1.0
RETRY_AFTER_MAX_S = 3600.0
BROKER_TIMEOUT_S = 3.0
VERIFY_DEDUPE_S = 60
REPAIR_TTL_S = 2 * 3600
MAX_REPAIR_ERRORS = 50


class LimiterUnavailable(Exception):
    """The broker could not be asked: fail closed (no provider call)."""


class Decision(enum.StrEnum):
    OK = "ok"
    WAIT = "wait"  # no token yet: `wait_s` until the next one
    COOLDOWN = "cooldown"  # a 429 / spend-limit cooldown is active for `wait_s`


@dataclass(frozen=True)
class Acquired:
    decision: Decision
    wait_s: float = 0.0


# KEYS: bucket, cool. ARGV: now_ms, per_minute.
# Returns {code, ms}: 0 ok, 1 wait ms, 2 cooldown ms.
_ACQUIRE = """
local now = tonumber(ARGV[1])
local cap = tonumber(ARGV[2])
local cool = redis.call('PTTL', KEYS[2])
if cool > 0 then return {2, cool} end
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


def seconds_to_next_minute(now: float) -> float:
    return max(RETRY_AFTER_MIN_S, 60.0 - (now % 60.0))


def seconds_to_utc_midnight(now: float) -> float:
    current = datetime.fromtimestamp(now, UTC)
    midnight = (current + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return max(RETRY_AFTER_MIN_S, (midnight - current).total_seconds())


def cooldown_seconds(retry_after_s: float | None, now: float) -> float:
    """A 429's cooldown: `retry_after_s` clamped to 1-3600 s, else to the next minute."""
    if retry_after_s is None or not math.isfinite(retry_after_s) or retry_after_s <= 0:
        return seconds_to_next_minute(now)
    return min(max(float(retry_after_s), RETRY_AFTER_MIN_S), RETRY_AFTER_MAX_S)


def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def effective_per_minute(
    settings: Settings, provider: AiProviderName | str, org_limits: Mapping[str, Any] | None
) -> int:
    """The org's per-minute limit, never above the ceiling (an org may only lower it)."""
    entry = AI_CATALOG[AiProviderName(provider)]
    ceiling = settings.ai_ceilings.per_minute.get(entry.name, entry.ceilings.per_minute)
    value = _positive_int((org_limits or {}).get("per_minute"))
    return min(ceiling, value if value is not None else entry.default_limits.per_minute)


class AiLimiter:
    def __init__(
        self, redis: Redis, prefix: str, *, clock: Callable[[], float] = time.time
    ) -> None:
        self._redis = redis
        self._base = f"{prefix}analyst.ai"
        self._clock = clock

    def now(self) -> float:
        return self._clock()

    def keys(self, provider: AiProviderName | str, org_id: object) -> tuple[str, str]:
        name = AiProviderName(provider).value
        return (f"{self._base}:rl:{name}:{org_id}", f"{self._base}:cool:{name}:{org_id}")

    def verify_key(self, provider: AiProviderName | str, org_id: object, key_version: int) -> str:
        return f"{self._base}:verify:{org_id}:{AiProviderName(provider).value}:{key_version}"

    def repair_key(self, run_id: uuid.UUID) -> str:
        return f"{self._base}:repair:{run_id}"

    async def _call(self, call: Callable[[], Awaitable[Any]]) -> Any:
        try:
            async with asyncio.timeout(BROKER_TIMEOUT_S):
                return await call()
        except (RedisError, OSError, TimeoutError) as exc:
            raise LimiterUnavailable(type(exc).__name__) from None

    async def _eval(self, script: str, keys: list[str], args: list[Any]) -> Any:
        return await self._call(lambda: self._redis.eval(script, len(keys), *keys, *args))

    async def acquire(
        self, provider: AiProviderName | str, org_id: object, per_minute: int
    ) -> Acquired:
        bucket, cool = self.keys(provider, org_id)
        now_ms = int(self._clock() * 1000)
        code, ms = await self._eval(_ACQUIRE, [bucket, cool], [now_ms, max(1, per_minute)])
        if int(code) == 0:
            return Acquired(Decision.OK)
        if int(code) == 1:
            return Acquired(Decision.WAIT, int(ms) / 1000)
        return Acquired(Decision.COOLDOWN, int(ms) / 1000)

    async def set_cooldown(
        self, provider: AiProviderName | str, org_id: object, seconds: float
    ) -> None:
        cool = self.keys(provider, org_id)[1]
        await self._eval(_COOLDOWN, [cool], [max(1, math.ceil(seconds * 1000))])

    async def cooldown_until_midnight(
        self, provider: AiProviderName | str, org_id: object
    ) -> float:
        seconds = seconds_to_utc_midnight(self._clock())
        await self.set_cooldown(provider, org_id, seconds)
        return seconds

    async def claim_verify(
        self, provider: AiProviderName | str, org_id: object, key_version: int
    ) -> bool:
        """SET NX for `VERIFY_DEDUPE_S`: False when this key version was checked moments ago."""
        key = self.verify_key(provider, org_id, key_version)
        claimed = await self._call(lambda: self._redis.set(key, "1", nx=True, ex=VERIFY_DEDUPE_S))
        return bool(claimed)

    async def save_repair(self, run_id: uuid.UUID, errors: list[str]) -> None:
        data = json.dumps([str(e)[:200] for e in errors[:MAX_REPAIR_ERRORS]])
        key = self.repair_key(run_id)
        await self._call(lambda: self._redis.set(key, data, ex=REPAIR_TTL_S))

    async def load_repair(self, run_id: uuid.UUID) -> list[str]:
        """The saved errors; [] when missing or unreadable (the hint is then generic)."""
        key = self.repair_key(run_id)
        raw = await self._call(lambda: self._redis.get(key))
        try:
            value = json.loads(raw) if raw else []
        except ValueError:
            return []
        return [str(e) for e in value][:MAX_REPAIR_ERRORS] if isinstance(value, list) else []


def broker_redis(url: str) -> Redis:
    return Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2)


__all__ = [
    "Acquired",
    "AiLimiter",
    "Decision",
    "LimiterUnavailable",
    "broker_redis",
    "cooldown_seconds",
    "effective_per_minute",
    "seconds_to_next_minute",
    "seconds_to_utc_midnight",
]
