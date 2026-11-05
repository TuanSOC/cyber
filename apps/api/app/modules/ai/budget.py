"""Daily token budgets of the AI analyst (M5, RT9, RT8, RT17): reserve, then settle.

Broker keys (inside the analyst ACL, `{prefix}analyst*`), UTC days, TTL 48 h:
- `{prefix}analyst.ai:day:{org}:{yyyymmdd}`: the org's tokens reserved or used today, against
  `ai_org_settings.daily_token_budget` (capped by `AI_CEILINGS`);
- `{prefix}analyst.ai:tree:{root_run_id}`: an incident tree's reservations, against
  `incident_token_cap` (RT8);
- `{prefix}analyst.ai:platform:{yyyymmdd}`: the dev platform key's global use, against
  `AI_PLATFORM_DAILY_TOKENS` (RT17).

Before a call the worker reserves `input_estimate + max_output_tokens` on every applicable
key in one Lua script (all or nothing), and afterwards settles each key to the actual usage
(a timeout after the request was sent keeps the full reservation: assumed billed, RT2).

The broker runs without persistence, so a restart drops the counters. A missing key is never
taken as zero (RT9; also the tree cap, RT8, and the platform ceiling, RT17): the reservation
reports which key is missing, the caller computes its usage from the DB (`seed`,
`seed_tree`, `seed_platform`) and `reserve` seeds it with SET NX before retrying. A first use
(a new day or tree) seeds the DB value too, which is then simply the usage so far. A
broker error fails closed (`BudgetUnavailable`: no call; the run waits).
"""

import asyncio
import math
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from redis.asyncio import Redis
from redis.exceptions import RedisError

DAY_KEY_TTL_S = 48 * 3600
BROKER_TIMEOUT_S = 3.0

BudgetScope = Literal["day", "tree", "platform"]


class BudgetUnavailable(Exception):
    """The broker could not be asked: fail closed (no provider call)."""


class BudgetExhausted(Exception):
    """The reservation would exceed a budget (`scope`): the run fails `budget_exhausted`."""

    def __init__(self, scope: BudgetScope) -> None:
        super().__init__(scope)
        self.scope = scope


@dataclass(frozen=True)
class Reservation:
    """What one call reserved (the keys carry the reservation's day: a settle after
    midnight still corrects the day it was charged to)."""

    amount: int
    day_key: str
    tree_key: str | None = None
    platform_key: str | None = None


# KEYS: day, tree, platform. ARGV: amount, day limit, tree limit (-1: none),
# platform limit (-1: none), ttl (s). Returns {code, used}: 0 reserved, 1 day budget,
# 2 tree cap, 4 platform ceiling; 3 / 5 / 6 the day / tree / platform key is missing (seed it).
_RESERVE = """
if redis.call('EXISTS', KEYS[1]) == 0 then return {3, 0} end
if tonumber(ARGV[3]) >= 0 and redis.call('EXISTS', KEYS[2]) == 0 then return {5, 0} end
if tonumber(ARGV[4]) >= 0 and redis.call('EXISTS', KEYS[3]) == 0 then return {6, 0} end
local amount = tonumber(ARGV[1])
local ttl = tonumber(ARGV[5])
local day = tonumber(redis.call('GET', KEYS[1]) or '0')
if day + amount > tonumber(ARGV[2]) then return {1, day} end
local tree_limit = tonumber(ARGV[3])
if tree_limit >= 0 then
  local used = tonumber(redis.call('GET', KEYS[2]) or '0')
  if used + amount > tree_limit then return {2, used} end
end
local platform_limit = tonumber(ARGV[4])
if platform_limit >= 0 then
  local used = tonumber(redis.call('GET', KEYS[3]) or '0')
  if used + amount > platform_limit then return {4, used} end
end
redis.call('INCRBY', KEYS[1], amount)
redis.call('EXPIRE', KEYS[1], ttl)
if tree_limit >= 0 then
  redis.call('INCRBY', KEYS[2], amount)
  redis.call('EXPIRE', KEYS[2], ttl)
end
if platform_limit >= 0 then
  redis.call('INCRBY', KEYS[3], amount)
  redis.call('EXPIRE', KEYS[3], ttl)
end
return {0, day + amount}
"""

# KEYS: day, tree, platform. ARGV: delta, use tree (0/1), use platform (0/1).
# Adds `delta` (actual - reserved) to every used key that still exists, never below zero.
_SETTLE = """
local delta = tonumber(ARGV[1])
local function adjust(key)
  if redis.call('EXISTS', key) == 1 then
    if redis.call('INCRBY', key, delta) < 0 then redis.call('SET', key, '0', 'KEEPTTL') end
  end
end
adjust(KEYS[1])
if ARGV[2] == '1' then adjust(KEYS[2]) end
if ARGV[3] == '1' then adjust(KEYS[3]) end
return 1
"""

_CODES: dict[int, BudgetScope] = {1: "day", 2: "tree", 4: "platform"}


class Budget:
    def __init__(
        self, redis: Redis, prefix: str, *, clock: Callable[[], float] = time.time
    ) -> None:
        self._redis = redis
        self._base = f"{prefix}analyst.ai"
        self._clock = clock

    def _day(self) -> str:
        return datetime.fromtimestamp(self._clock(), UTC).strftime("%Y%m%d")

    def day_key(self, org_id: object) -> str:
        return f"{self._base}:day:{org_id}:{self._day()}"

    def tree_key(self, root_run_id: uuid.UUID) -> str:
        return f"{self._base}:tree:{root_run_id}"

    def platform_key(self) -> str:
        return f"{self._base}:platform:{self._day()}"

    async def _call(self, call: Callable[[], Awaitable[Any]]) -> Any:
        try:
            async with asyncio.timeout(BROKER_TIMEOUT_S):
                return await call()
        except (RedisError, OSError, TimeoutError) as exc:
            raise BudgetUnavailable(type(exc).__name__) from None

    async def _eval(self, script: str, keys: list[str], args: list[Any]) -> Any:
        return await self._call(lambda: self._redis.eval(script, len(keys), *keys, *args))

    async def reserve(
        self,
        org_id: object,
        amount: int,
        *,
        daily_limit: int,
        seed: Callable[[], Awaitable[int]],
        tree: tuple[uuid.UUID, int] | None = None,
        seed_tree: Callable[[], Awaitable[int]] | None = None,
        platform_limit: int | None = None,
        seed_platform: Callable[[], Awaitable[int]] | None = None,
    ) -> Reservation:
        """Reserve `amount` tokens on the org's day key (and the tree / platform keys when
        given) atomically. A missing key is seeded (SET NX) from its DB usage first: `seed`
        (the org today), `seed_tree` (the tree), `seed_platform` (the platform key today);
        without a seed callable a missing tree / platform key fails closed
        (`BudgetUnavailable`). Raises `BudgetExhausted(scope)` or `BudgetUnavailable`."""
        amount = max(0, int(amount))
        day_key = self.day_key(org_id)
        # Unused keys are still declared (under the ACL pattern) but never touched.
        tree_key = self.tree_key(tree[0]) if tree else f"{self._base}:tree:-"
        platform_key = self.platform_key()
        args = [
            amount,
            max(0, int(daily_limit)),
            max(0, int(tree[1])) if tree else -1,
            max(0, int(platform_limit)) if platform_limit is not None else -1,
            DAY_KEY_TTL_S,
        ]
        keys = [day_key, tree_key, platform_key]
        seeds = {3: (day_key, seed), 5: (tree_key, seed_tree), 6: (platform_key, seed_platform)}
        seeded: set[int] = set()
        while True:
            code, _used = await self._eval(_RESERVE, keys, args)
            code = int(code)
            if code == 0:
                return Reservation(
                    amount=amount,
                    day_key=day_key,
                    tree_key=tree_key if tree else None,
                    platform_key=platform_key if platform_limit is not None else None,
                )
            if code in _CODES:
                raise BudgetExhausted(_CODES[code])
            key, source = seeds.get(code, (None, None))
            if key is None or source is None or code in seeded:
                raise BudgetUnavailable(f"budget key could not be seeded ({code})")
            seeded.add(code)  # a missing key (broker restart or first use): seed from the DB
            await self._seed_key(key, await source())

    async def _seed_key(self, key: str, used: int) -> bool:
        """SET NX `key` to `used` (never overwrites a live counter)."""
        value = max(0, int(used))
        return bool(
            await self._call(lambda: self._redis.set(key, value, nx=True, ex=DAY_KEY_TTL_S))
        )

    async def seed_day(self, org_id: object, used: int) -> bool:
        """SET NX the org's day key to `used` (never overwrites a live counter)."""
        return await self._seed_key(self.day_key(org_id), used)

    async def settle(self, reservation: Reservation, actual: int) -> None:
        """Correct every reserved key to the actual usage (`actual` tokens)."""
        delta = max(0, int(actual)) - reservation.amount
        if delta == 0:
            return
        keys = [
            reservation.day_key,
            reservation.tree_key or f"{self._base}:tree:-",
            reservation.platform_key or self.platform_key(),
        ]
        args = [
            delta,
            int(reservation.tree_key is not None),
            int(reservation.platform_key is not None),
        ]
        await self._eval(_SETTLE, keys, args)

    async def used_today(self, org_id: object) -> int | None:
        raw = await self._call(lambda: self._redis.get(self.day_key(org_id)))
        return None if raw is None else int(raw)


def ceil_tokens(chars: int, per_token: float = 4.0) -> int:
    return math.ceil(max(0, chars) / per_token)


__all__ = [
    "DAY_KEY_TTL_S",
    "Budget",
    "BudgetExhausted",
    "BudgetScope",
    "BudgetUnavailable",
    "Reservation",
    "ceil_tokens",
]
