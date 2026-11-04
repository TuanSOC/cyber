"""Enrich worker logic (trusted, internet-facing; M4).

`ti.enrich {run_id, org_id}` runs ONE time slice of a run (RT6):
1. the run is looked up in `ti_run_index` (system session); it must exist, belong to the
   message's org and be queued / waiting / running, else the message is dropped (ids only);
2. the DB lease is taken (`lease_until = now() + 60 s` only if free or expired), else another
   slice holds it and this one exits (RT8);
3. past `deadline_at` the run is finalized with its pending items `abandoned/deadline`;
4. the run is marked `running`;
5. pending items are processed in `seq` order until `TI_SLICE_S` elapses (asyncio, since the
   solo pool ignores Celery time limits), renewing the lease every 20 s. Per item: the cache
   (-> `cached` with the hit's `result_id`), else the cooldown and token bucket, the key
   (unsealed once per provider and slice, lazily re-sealed under the active kid), the provider
   call (up to 3 attempts for timeouts / 5xx / transport errors, full-jitter backoff), and
   one transaction inserting the `ti_results` row (ON CONFLICT DO NOTHING) and marking the
   item `done`. Concurrency: <= 4 per provider, <= 16 per slice;
6. a daily cap -> that provider's pending items `abandoned/quota_exhausted`, cooldown until
   00:00 UTC;
7. 401/403 -> `provider.verify` once inline (RT23): only a failed verify sets
   `verify_status=invalid`; the pair gets an `auth_failed` row and the provider's remaining
   items `abandoned/auth_failed`;
8. work left: re-publish `ti.enrich` to the queue tail if a token is ready within 2 s, else
   `waiting` with `resume_at` (never past the deadline); the lease is released first;
9. nothing pending: finalize (`threat_intel.lifecycle`);
10. a 429 whose cooldown ends after the deadline -> the provider's pending items
   `abandoned/rate_limited`.

`ti.resume` re-sends due runs (RT8) and `ti.verify` checks one provider key. Task return
values are always None. Logs carry ids, provider names, error kinds and counts only: never a
key, a header, a provider body or an IOC value (RT11).
"""

import asyncio
import base64
import contextlib
import logging
import random
import secrets
import time
import uuid
from collections import deque
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import SecretStr, ValidationError
from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError

from app.core.config import Settings, get_settings
from app.core.tenancy import tenant_session
from app.modules.audit import service as audit
from app.modules.threat_intel import cache, lifecycle
from app.modules.threat_intel.catalog import ProviderLimits
from app.modules.threat_intel.http import KeyAuth, ti_client
from app.modules.threat_intel.messages import TiResumeMessage, TiRunMessage, TiVerifyMessage
from app.modules.threat_intel.models import (
    RUN_ACTIVE,
    RUN_FINAL,
    TiEnrichmentRun,
    TiProviderConfig,
    TiResult,
    TiRunIndex,
    TiRunItem,
)
from app.modules.threat_intel.providers import registry
from app.modules.threat_intel.providers.base import (
    IocRef,
    IocType,
    Provider,
    ProviderError,
    ProviderErrorKind,
    ProviderName,
    ProviderResult,
    ResultStatus,
    VerifyOutcome,
    VerifyStatus,
)
from app.modules.threat_intel.ratelimit import (
    Decision,
    Limiter,
    LimiterUnavailable,
    broker_redis,
    effective_limits,
    seconds_to_next_minute,
)
from app.modules.threat_intel.seal import SealedKey, load_public_key, raw_public, seal
from app.modules.threat_intel.unseal import UnsealError, load_private_keys, open_sealed

log = logging.getLogger(__name__)

LEASE = timedelta(seconds=60)
LEASE_RENEW_S = 20.0
READY_SOON_S = 2.0
LIMITER_RETRY_S = 30.0
SHORT_WAIT_S = 1.0
MAX_ATTEMPTS = 3
BACKOFF_BASE_S = 0.5
BACKOFF_CAP_S = 4.0
GLOBAL_CONCURRENCY = 16
HARD_GRACE_S = 25.0
RESUME_BATCH = 100
REDISPATCH_AFTER = timedelta(minutes=2)
PUBLISH_TIMEOUT_S = 15.0
RETRYABLE = frozenset(
    {ProviderErrorKind.TIMEOUT, ProviderErrorKind.HTTP_5XX, ProviderErrorKind.TRANSPORT}
)

Publish = Callable[[TiRunMessage], Awaitable[None]]


def check_startup(settings: Settings) -> None:
    """Refuse to start without a usable private key for the active kid (clear message)."""
    if settings.process_role != "enrich":
        raise RuntimeError("the enrich worker needs PROCESS_ROLE=enrich")
    path = settings.ti_seal_private_keys_file
    if path is None:
        raise RuntimeError("TI_SEAL_PRIVATE_KEYS_FILE is not set")
    try:
        keys = load_private_keys(path)
    except UnsealError as exc:
        raise RuntimeError(f"seal private key file {path} is unusable ({exc.code})") from None
    kid = settings.ti_seal_active_kid
    if not kid or kid not in keys:
        raise RuntimeError(f"seal private key file {path} lacks the active kid {kid!r}")
    published = settings.ti_seal_public_keys.get(kid)
    derived = base64.b64encode(raw_public(keys[kid].public_key())).decode()
    if published != derived:
        raise RuntimeError(f"TI_SEAL_PUBLIC_KEYS[{kid!r}] does not match the private key file")


# --- dependencies (injectable for tests) ---------------------------------------------------


async def _publish_celery(message: TiRunMessage) -> None:
    from cyberlab_jobs import TI_ENRICH

    from app.workers.enrich_app import celery_app, queues  # the worker's own broker user

    def send() -> None:
        celery_app.send_task(
            TI_ENRICH,
            kwargs={"message": message.model_dump(mode="json")},
            queue=queues.enrich,
            retry=True,
            retry_policy={"max_retries": 1, "interval_start": 0, "interval_step": 0.5},
        )

    async with asyncio.timeout(PUBLISH_TIMEOUT_S):
        await asyncio.to_thread(send)


@dataclass
class Deps:
    settings: Settings
    limiter: Limiter
    private_keys: Mapping[str, X25519PrivateKey]
    publish: Publish = _publish_celery
    create_provider: Callable[[ProviderName, registry.ProviderContext], Provider] = registry.create
    transport: httpx.AsyncBaseTransport | None = None
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    jitter: Callable[[], float] = random.random


_deps: Deps | None = None


def get_deps() -> Deps:
    global _deps
    if _deps is None:
        settings = get_settings()
        if settings.ti_seal_private_keys_file is None:
            raise RuntimeError("TI_SEAL_PRIVATE_KEYS_FILE is not set")
        _deps = Deps(
            settings=settings,
            limiter=Limiter(broker_redis(settings.broker_url), settings.queue_prefix),
            private_keys=load_private_keys(settings.ti_seal_private_keys_file),
        )
    return _deps


# --- small helpers -------------------------------------------------------------------------


def _drop(reason: str, message: Mapping[str, Any]) -> None:
    # Ids only: a message never carries values or keys, but log nothing else either.
    log.warning("ti message dropped (%s): run %s", reason, str(message.get("run_id"))[:36])


def _epoch(value: datetime) -> float:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.timestamp()


def _at(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, UTC)


@dataclass(frozen=True)
class _Config:
    """A snapshot of one provider config row (no plaintext ever)."""

    id: uuid.UUID
    provider: ProviderName
    enabled: bool
    base_url: str | None
    sealed: SealedKey | None
    limits: dict[str, Any]

    @classmethod
    def of(cls, row: TiProviderConfig) -> "_Config":
        sealed = None
        if row.key_ct is not None and row.key_kid and row.key_epk and row.key_nonce:
            sealed = SealedKey(
                kid=row.key_kid,
                key_version=row.key_version,
                epk=row.key_epk,
                nonce=row.key_nonce,
                ct=row.key_ct,
                last4=row.key_last4 or "",
            )
        return cls(
            id=row.id,
            provider=ProviderName(row.provider),
            enabled=row.enabled,
            base_url=row.base_url,
            sealed=sealed,
            limits=dict(row.limits or {}),
        )


@dataclass(frozen=True)
class _Item:
    provider: ProviderName
    ioc: IocRef
    seq: int


@dataclass
class _Lane:
    provider: ProviderName
    config: _Config | None
    limits: ProviderLimits
    items: deque[_Item] = field(default_factory=deque)
    adapter: Provider | None = None
    client: httpx.AsyncClient | None = None
    key_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    auth_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    unusable: bool = False
    stopped: bool = False
    # Set once: the reason every still-pending item of this provider is abandoned with.
    abandoned: str | None = None
    # Items a lane worker holds right now: never abandoned under its feet (it may still
    # record a real answer); its own worker abandons it if it ends without one.
    in_flight: set[str] = field(default_factory=set)
    verified: bool = False
    ready_at: float | None = None


async def _open_provider(
    deps: Deps, org_id: uuid.UUID, config: _Config
) -> tuple[Provider, httpx.AsyncClient]:
    """Unseal the key (lazy re-seal under the active kid) and build the adapter's client.
    Raises `UnsealError`, `registry.ProviderUnavailable` or `ValueError`."""
    if config.sealed is None:
        raise UnsealError("no_key")
    base_url_norm = config.base_url or ""
    key = open_sealed(
        config.sealed, org_id, config.provider.value, base_url_norm, deps.private_keys
    )
    await _maybe_reseal(deps, org_id, config, key, base_url_norm)
    adapter = deps.create_provider(
        config.provider, registry.ProviderContext(deps.settings, base_url_norm)
    )
    org_host = urlsplit(base_url_norm).hostname if base_url_norm else None
    client = ti_client(
        adapter,
        auth=KeyAuth(registry.auth_header(config.provider), key),
        transport=deps.transport,
        org_host=org_host,
    )
    return adapter, client


async def _maybe_reseal(
    deps: Deps, org_id: uuid.UUID, config: _Config, key: SecretStr, base_url_norm: str
) -> None:
    """Re-seal a key opened under an old kid with the active one (same `key_version`)."""
    sealed = config.sealed
    active = deps.settings.ti_seal_active_kid
    if sealed is None or not active or sealed.kid == active:
        return
    encoded = deps.settings.ti_seal_public_keys.get(active)
    if encoded is None:
        return
    try:
        fresh = seal(
            key,
            org_id,
            config.provider.value,
            active,
            sealed.key_version,
            base_url_norm,
            load_public_key(encoded),
        )
        async with tenant_session(org_id, None) as session:
            await session.execute(
                update(TiProviderConfig)
                .where(
                    TiProviderConfig.id == config.id,
                    TiProviderConfig.key_kid == sealed.kid,
                    TiProviderConfig.key_version == sealed.key_version,
                )
                .values(
                    key_kid=fresh.kid,
                    key_epk=fresh.epk,
                    key_nonce=fresh.nonce,
                    key_ct=fresh.ct,
                    key_last4=fresh.last4,
                )
            )
        log.info("ti key re-sealed under kid %s (%s)", active, config.provider.value)
    except Exception as exc:  # noqa: BLE001 - a failed re-seal never blocks the lookup
        log.warning("ti key re-seal failed (%s): %s", config.provider.value, type(exc).__name__)


def _error_result(provider: ProviderName, code: str) -> ProviderResult:
    return ProviderResult(provider=provider, status=ResultStatus.ERROR, error_code=code)


# --- the slice -----------------------------------------------------------------------------


class _Slice:
    def __init__(
        self, deps: Deps, org_id: uuid.UUID, run_id: uuid.UUID, token: str, deadline: float
    ) -> None:
        self.deps = deps
        self.org_id = org_id
        self.run_id = run_id
        self.token = token
        self.deadline = deadline
        budget = min(float(deps.settings.ti_slice_s), max(0.0, deadline - time.time()))
        self.soft_end = time.monotonic() + budget
        self.global_sem = asyncio.Semaphore(GLOBAL_CONCURRENCY)
        self.halted = False
        self.limiter_down = False
        self.lease_lost = False

    # ---- setup

    async def prepare(self) -> list[_Lane] | None:
        settings = self.deps.settings
        async with tenant_session(self.org_id, None) as s:
            run = await s.scalar(
                select(TiEnrichmentRun)
                .where(
                    TiEnrichmentRun.id == self.run_id,
                    TiEnrichmentRun.organization_id == self.org_id,
                )
                .with_for_update()
            )
            index = await s.get(TiRunIndex, self.run_id, with_for_update=True)
            if run is None or index is None or run.status in RUN_FINAL:
                return None
            now = datetime.now(UTC)
            if run.status != "running":
                run.status = "running"
            if run.started_at is None:
                run.started_at = now
            index.status = "running"
            index.resume_at = None
            configs = {
                row.provider: _Config.of(row)
                for row in (
                    await s.scalars(
                        select(TiProviderConfig).where(
                            TiProviderConfig.organization_id == self.org_id,
                            TiProviderConfig.provider.in_(list(run.providers)),
                        )
                    )
                ).all()
            }
            pending = (
                await s.execute(
                    select(
                        TiRunItem.provider,
                        TiRunItem.ioc_type,
                        TiRunItem.value_norm,
                        TiRunItem.ioc_key,
                        TiRunItem.seq,
                    )
                    .where(TiRunItem.run_id == self.run_id, TiRunItem.state == "pending")
                    .order_by(TiRunItem.seq)
                )
            ).all()
            lanes: dict[ProviderName, _Lane] = {}
            unusable: set[str] = set()
            for provider_name, ioc_type, value_norm, ioc_key, seq in pending:
                provider = ProviderName(provider_name)
                lane = lanes.get(provider)
                if lane is None:
                    config = configs.get(provider_name)
                    usable = (
                        config is not None
                        and config.enabled
                        and config.sealed is not None
                        and registry.available(provider, settings)
                    )
                    if not usable:
                        unusable.add(provider_name)
                        continue
                    lane = lanes[provider] = _Lane(
                        provider=provider,
                        config=config,
                        limits=effective_limits(
                            config.limits if config else None, settings.ti_ceiling(provider)
                        ),
                    )
                lane.items.append(
                    _Item(provider, IocRef(IocType(ioc_type), value_norm, ioc_key), seq)
                )
            if unusable:
                # Disabled, key removed or provider unavailable since the run was planned.
                await s.execute(
                    update(TiRunItem)
                    .where(
                        TiRunItem.run_id == self.run_id,
                        TiRunItem.provider.in_(sorted(unusable)),
                        TiRunItem.state == "pending",
                    )
                    .values(state="abandoned", reason="auth_failed")
                )
                log.warning("ti run %s: providers unusable: %s", self.run_id, sorted(unusable))
        return list(lanes.values())

    # ---- lease

    async def renew_forever(self) -> None:
        while True:
            await asyncio.sleep(LEASE_RENEW_S)
            try:
                async with tenant_session(None, None) as s:
                    renewed = await s.scalar(
                        update(TiRunIndex)
                        .where(
                            TiRunIndex.run_id == self.run_id, TiRunIndex.lease_owner == self.token
                        )
                        .values(lease_until=func.now() + LEASE)
                        .returning(TiRunIndex.run_id)
                    )
            except DBAPIError as exc:
                log.warning("ti run %s: lease renewal failed (%s)", self.run_id, type(exc).__name__)
                continue
            if renewed is None:
                log.warning("ti run %s: lease lost; stopping the slice", self.run_id)
                self.lease_lost = True
                self.halted = True
                return

    # ---- lanes

    async def run_lanes(self, lanes: list[_Lane]) -> None:
        try:
            async with asyncio.timeout(self.deps.settings.ti_slice_s + HARD_GRACE_S):
                await asyncio.gather(*(self._run_lane(lane) for lane in lanes))
        except TimeoutError:
            log.warning("ti run %s: slice hard timeout", self.run_id)
        finally:
            for lane in lanes:
                if lane.client is not None:
                    await lane.client.aclose()

    async def _run_lane(self, lane: _Lane) -> None:
        workers = max(1, min(lane.limits.concurrency, 4))
        await asyncio.gather(*(self._lane_worker(lane) for _ in range(workers)))

    def _may_continue(self, lane: _Lane) -> bool:
        return not (lane.stopped or self.halted) and time.monotonic() < self.soft_end

    async def _lane_worker(self, lane: _Lane) -> None:
        while lane.items and self._may_continue(lane):
            item = lane.items.popleft()
            if await self._process(lane, item):
                lane.items.appendleft(item)

    async def _process(self, lane: _Lane, item: _Item) -> bool:
        """Handle one item; True to put it back (still pending, try again later)."""
        lane.in_flight.add(item.ioc.ioc_key)
        try:
            pending = await self._attempt(lane, item)
        finally:
            lane.in_flight.discard(item.ioc.ioc_key)
        if pending and lane.abandoned is not None:
            await self._abandon_items(lane, lane.abandoned, only=item)
            return False
        return pending

    async def _attempt(self, lane: _Lane, item: _Item) -> bool:
        """True while the item has no outcome yet (it stays pending)."""
        if await self._cache_hit(item):
            return False
        attempt = 0
        while True:
            if not await self._acquire(lane):
                return True
            if not await self._ensure_client(lane):
                return True
            if lane.adapter is None or lane.client is None:
                return False
            started = time.monotonic()
            try:
                async with self.global_sem:
                    result = await lane.adapter.lookup(lane.client, item.ioc)
            except ProviderError as exc:
                latency = int((time.monotonic() - started) * 1000)
                if exc.kind in RETRYABLE and attempt + 1 < MAX_ATTEMPTS:
                    delay = self.deps.jitter() * min(BACKOFF_CAP_S, BACKOFF_BASE_S * 2**attempt)
                    if time.monotonic() + delay < self.soft_end and not self.halted:
                        attempt += 1
                        await self.deps.sleep(delay)
                        continue
                return await self._on_error(lane, item, exc, latency)
            except Exception as exc:  # noqa: BLE001 - an adapter bug never kills the slice
                latency = int((time.monotonic() - started) * 1000)
                log.warning("ti %s adapter raised %s", lane.provider.value, type(exc).__name__)
                await self._record(item, _error_result(lane.provider, "internal_error"), latency)
                return False
            latency = int((time.monotonic() - started) * 1000)
            if result.provider is not lane.provider:
                result = _error_result(lane.provider, "internal_error")
            await self._record(item, result, latency)
            return False

    async def _acquire(self, lane: _Lane) -> bool:
        while True:
            if not self._may_continue(lane):
                return False
            try:
                got = await self.deps.limiter.acquire(lane.provider, self.org_id, lane.limits)
            except LimiterUnavailable:
                log.warning("ti limiter unavailable (run %s): failing closed", self.run_id)
                self.limiter_down = True
                self.halted = True
                return False
            now = time.time()
            if got.decision is Decision.OK:
                return True
            if got.decision is Decision.WAIT:
                if got.wait_s <= SHORT_WAIT_S and time.monotonic() + got.wait_s < self.soft_end:
                    await self.deps.sleep(got.wait_s)
                    continue
                self._stop_lane(lane, now + got.wait_s)
                return False
            if got.decision is Decision.COOLDOWN:
                await self._cooldown(lane, now + got.wait_s)
                return False
            await self._quota(lane)
            return False

    def _stop_lane(self, lane: _Lane, ready_at: float) -> None:
        lane.stopped = True
        lane.ready_at = max(lane.ready_at or 0.0, ready_at)

    async def _cooldown(self, lane: _Lane, until: float) -> None:
        if until >= self.deadline:
            await self._abandon_lane(lane, "rate_limited")
        else:
            self._stop_lane(lane, until)

    async def _quota(self, lane: _Lane) -> None:
        try:
            await self.deps.limiter.cooldown_until_midnight(lane.provider, self.org_id)
        except LimiterUnavailable:
            pass
        await self._abandon_lane(lane, "quota_exhausted")

    async def _abandon_lane(self, lane: _Lane, reason: str) -> None:
        """Abandon the provider's pending items, except those a lane worker holds."""
        lane.stopped = True
        lane.items.clear()
        if lane.abandoned is not None:
            return
        lane.abandoned = reason
        await self._abandon_items(lane, reason)
        log.info("ti run %s: %s items abandoned (%s)", self.run_id, lane.provider.value, reason)

    async def _abandon_items(self, lane: _Lane, reason: str, *, only: _Item | None = None) -> None:
        where = [
            TiRunItem.run_id == self.run_id,
            TiRunItem.provider == lane.provider.value,
            TiRunItem.state == "pending",
        ]
        if only is not None:
            where.append(TiRunItem.ioc_key == only.ioc.ioc_key)
        elif lane.in_flight:
            where.append(TiRunItem.ioc_key.not_in(sorted(lane.in_flight)))
        async with tenant_session(self.org_id, None) as s:
            await s.execute(
                update(TiRunItem).where(*where).values(state="abandoned", reason=reason)
            )

    async def _ensure_client(self, lane: _Lane) -> bool:
        async with lane.key_lock:
            if lane.client is not None:
                return True
            if lane.unusable or lane.config is None:
                return False
            try:
                lane.adapter, lane.client = await _open_provider(
                    self.deps, self.org_id, lane.config
                )
            except (UnsealError, registry.ProviderUnavailable, ValueError, ImportError) as exc:
                code = getattr(exc, "code", type(exc).__name__)
                log.warning(
                    "ti %s unusable for run %s (%s)", lane.provider.value, self.run_id, code
                )
                lane.unusable = True
            else:
                return True
        await self._abandon_lane(lane, "auth_failed")
        return False

    async def _on_error(self, lane: _Lane, item: _Item, exc: ProviderError, latency: int) -> bool:
        kind = exc.kind
        if kind is ProviderErrorKind.RATE_LIMITED:
            now = time.time()
            seconds = exc.retry_after_s or seconds_to_next_minute(now)
            try:
                await self.deps.limiter.set_cooldown(lane.provider, self.org_id, seconds)
            except LimiterUnavailable:
                self.limiter_down = True
                self.halted = True
            await self._cooldown(lane, now + seconds)
            return True
        if kind is ProviderErrorKind.QUOTA_EXHAUSTED:
            await self._quota(lane)
            return True
        if kind is ProviderErrorKind.AUTH:
            await self._auth_failed(lane, item, exc, latency)
            return False
        if kind is ProviderErrorKind.PATH_NOT_ALLOWED:
            log.error("ti %s adapter sent a request outside its allowlist", lane.provider.value)
        await self._record(item, _error_result(lane.provider, kind.value), latency)
        return False

    async def _auth_failed(
        self, lane: _Lane, item: _Item, exc: ProviderError, latency: int
    ) -> None:
        async with lane.auth_lock:
            if not lane.verified and lane.adapter is not None and lane.client is not None:
                lane.verified = True
                verdict = await _verify(lane.adapter, lane.client)
                if verdict.status is VerifyStatus.INVALID and lane.config is not None:
                    await _save_verify(self.org_id, lane.config, verdict, inline=True)
        lane.stopped = True
        code = f"auth_{exc.http_status}" if exc.http_status else "auth"
        result = ProviderResult(
            provider=lane.provider, status=ResultStatus.AUTH_FAILED, error_code=code
        )
        await self._record(item, result, latency)
        await self._abandon_lane(lane, "auth_failed")

    # ---- writes

    async def _cache_hit(self, item: _Item) -> bool:
        async with tenant_session(self.org_id, None) as s:
            hit = await cache.fresh_result(s, self.org_id, item.provider, item.ioc.ioc_key)
            if hit is None:
                return False
            await s.execute(self._item_update(item).values(state="cached", result_id=hit))
        return True

    def _item_update(self, item: _Item) -> Any:
        return update(TiRunItem).where(
            TiRunItem.run_id == self.run_id,
            TiRunItem.provider == item.provider.value,
            TiRunItem.ioc_key == item.ioc.ioc_key,
            TiRunItem.state == "pending",
        )

    async def _record(self, item: _Item, result: ProviderResult, latency: int) -> None:
        try:
            await self._insert(item, result, latency)
        except (DBAPIError, ValidationError, ValueError, TypeError) as exc:
            log.warning("ti %s result refused (%s)", item.provider.value, type(exc).__name__)
            await self._insert(item, _error_result(item.provider, "invalid_result"), latency)

    async def _insert(self, item: _Item, result: ProviderResult, latency: int) -> None:
        ttl = cache.ttl(item.provider, item.ioc.ioc_type, result.status)
        values: dict[str, Any] = {
            "organization_id": self.org_id,
            "run_id": self.run_id,
            "provider": item.provider.value,
            "ioc_type": item.ioc.ioc_type.value,
            "value_norm": item.ioc.value_norm,
            "ioc_key": item.ioc.ioc_key,
            "status": result.status.value,
            "found": result.found,
            "detections": result.detections.model_dump() if result.detections else None,
            "score": result.score,
            "score_scale": result.score_scale,
            "tags": list(result.tags),
            "families": list(result.families),
            "attack_ids": list(result.attack_ids),
            "first_seen": result.first_seen,
            "last_seen": result.last_seen,
            "summary": result.summary.model_dump(mode="json") if result.summary else None,
            "permalink": result.permalink,
            "error_code": result.error_code,
            "latency_ms": max(0, latency),
            "expires_at": func.now() + ttl if ttl is not None else None,
        }
        async with tenant_session(self.org_id, None) as s:
            result_id = await s.scalar(
                pg_insert(TiResult)
                .values(**values)
                .on_conflict_do_nothing(index_elements=["run_id", "provider", "ioc_key"])
                .returning(TiResult.id)
            )
            if result_id is None:  # a redelivered slice already wrote this pair
                result_id = await s.scalar(
                    select(TiResult.id).where(
                        TiResult.run_id == self.run_id,
                        TiResult.provider == item.provider.value,
                        TiResult.ioc_key == item.ioc.ioc_key,
                    )
                )
            await s.execute(self._item_update(item).values(state="done", result_id=result_id))

    # ---- end of slice

    async def finish(self, lanes: list[_Lane]) -> None:
        async with tenant_session(self.org_id, None) as s:
            pending = dict(
                (
                    await s.execute(
                        select(TiRunItem.provider, func.count())
                        .where(TiRunItem.run_id == self.run_id, TiRunItem.state == "pending")
                        .group_by(TiRunItem.provider)
                    )
                ).all()
            )
        if not pending:
            await _finalize(self.org_id, self.run_id, None)
            return
        now = time.time()
        if self.limiter_down:
            ready = now + LIMITER_RETRY_S
        else:
            by_provider = {lane.provider.value: lane for lane in lanes}
            readies = [
                (lane.ready_at if lane is not None and lane.ready_at else now)
                for lane in (by_provider.get(p) for p in pending)
            ]
            ready = min(readies)
        if ready - now <= READY_SOON_S:
            await self._requeue()
        else:
            await self._wait(min(ready, self.deadline))

    async def _requeue(self) -> None:
        async with tenant_session(self.org_id, None) as s:
            await s.execute(
                update(TiRunIndex)
                .where(TiRunIndex.run_id == self.run_id, TiRunIndex.lease_owner == self.token)
                .values(dispatched_at=func.now(), lease_until=None, lease_owner=None)
            )
        try:
            await self.deps.publish(TiRunMessage(run_id=self.run_id, org_id=self.org_id))
        except Exception as exc:  # noqa: BLE001 - ti.resume re-sends it after 2 minutes
            log.warning("ti run %s: re-publish failed (%s)", self.run_id, type(exc).__name__)

    async def _wait(self, resume_at: float) -> None:
        async with tenant_session(self.org_id, None) as s:
            run = await s.scalar(
                select(TiEnrichmentRun).where(TiEnrichmentRun.id == self.run_id).with_for_update()
            )
            index = await s.get(TiRunIndex, self.run_id, with_for_update=True)
            if run is None or index is None or run.status in RUN_FINAL:
                return
            if run.status != "waiting":
                run.status = "waiting"
            index.status = "waiting"
            index.resume_at = _at(resume_at)
            if index.lease_owner == self.token:
                index.lease_until = None
                index.lease_owner = None
        log.info("ti run %s waiting until %s", self.run_id, _at(resume_at).isoformat())


async def _verify(adapter: Provider, client: httpx.AsyncClient) -> VerifyOutcome:
    try:
        return await adapter.verify(client)
    except ProviderError as exc:
        if exc.kind is ProviderErrorKind.AUTH:
            return VerifyOutcome(VerifyStatus.INVALID, "auth")
        return VerifyOutcome(VerifyStatus.ERROR, exc.kind.value)
    except Exception as exc:  # noqa: BLE001
        log.warning("ti verify raised %s", type(exc).__name__)
        return VerifyOutcome(VerifyStatus.ERROR, "internal_error")


async def _save_verify(
    org_id: uuid.UUID, config: _Config, verdict: VerifyOutcome, *, inline: bool = False
) -> None:
    async with tenant_session(org_id, None) as s:
        await s.execute(
            update(TiProviderConfig)
            .where(TiProviderConfig.id == config.id)
            .values(
                verify_status=verdict.status.value,
                verified_at=func.now(),
                last_error_code=verdict.error_code,
            )
        )
        valid = verdict.status is VerifyStatus.VALID
        audit.record(
            s,
            action="integration.verified" if valid else "integration.verify_failed",
            org_id=org_id,
            actor_id=None,
            target_type="ti_provider_config",
            target_id=config.id,
            details={
                "provider": config.provider.value,
                "verify_status": verdict.status.value,
                "error_code": verdict.error_code,
                "inline": inline,
            },
        )


async def _finalize(org_id: uuid.UUID, run_id: uuid.UUID, reason: str | None) -> None:
    async with tenant_session(org_id, None) as s:
        status = await lifecycle.finalize_run(s, org_id, run_id, abandon_reason=reason)
    if status is not None:
        log.info("ti run %s %s", run_id, status)


# --- task handlers -------------------------------------------------------------------------


async def handle_enrich(message: Mapping[str, Any], deps: Deps | None = None) -> None:
    try:
        msg = TiRunMessage.model_validate(message)
    except ValidationError:
        _drop("invalid message", message)
        return
    async with tenant_session(None, None) as s:
        index = await s.get(TiRunIndex, msg.run_id)
        org_id = index.organization_id if index else None
        status = index.status if index else None
    if org_id is None or org_id != msg.org_id:
        _drop("unknown run or org mismatch", message)
        return
    if status not in RUN_ACTIVE:
        return  # already final: a redelivered or duplicated message

    token = secrets.token_hex(16)
    async with tenant_session(None, None) as s:
        lease = (
            await s.execute(
                update(TiRunIndex)
                .where(
                    TiRunIndex.run_id == msg.run_id,
                    TiRunIndex.organization_id == org_id,
                    TiRunIndex.status.in_(RUN_ACTIVE),
                    or_(TiRunIndex.lease_until.is_(None), TiRunIndex.lease_until < func.now()),
                )
                .values(lease_until=func.now() + LEASE, lease_owner=token)
                .returning(TiRunIndex.deadline_at, func.now())
            )
        ).first()
    if lease is None:
        log.info("ti run %s: lease held by another slice", msg.run_id)
        return

    deps = deps or get_deps()
    deadline_at, db_now = lease
    try:
        if db_now >= deadline_at:
            await _finalize(org_id, msg.run_id, "deadline")
            return
        work = _Slice(deps, org_id, msg.run_id, token, _epoch(deadline_at))
        lanes = await work.prepare()
        if lanes is None:
            return
        renewer = asyncio.create_task(work.renew_forever())
        try:
            await work.run_lanes(lanes)
        finally:
            renewer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await renewer
        if not work.lease_lost:
            await work.finish(lanes)
    finally:
        async with tenant_session(None, None) as s:
            await s.execute(
                update(TiRunIndex)
                .where(TiRunIndex.run_id == msg.run_id, TiRunIndex.lease_owner == token)
                .values(lease_until=None, lease_owner=None)
            )


async def handle_resume(message: Mapping[str, Any] | None = None, deps: Deps | None = None) -> int:
    """Re-send `ti.enrich` for due runs (RT8): `waiting` with `resume_at <= now()` (once,
    then at most every 2 minutes), or `queued` / `running` with a free or expired lease and
    `dispatched_at` older than 2 minutes. Bumps `dispatched_at`. Returns how many it sent."""
    try:
        TiResumeMessage.model_validate(message or {})
    except ValidationError:
        _drop("invalid message", message or {})
        return 0
    stale = func.now() - REDISPATCH_AFTER
    lease_free = or_(TiRunIndex.lease_until.is_(None), TiRunIndex.lease_until < func.now())
    never_or_stale = or_(TiRunIndex.dispatched_at.is_(None), TiRunIndex.dispatched_at < stale)
    due = (
        select(TiRunIndex.run_id)
        .where(
            or_(
                and_(
                    TiRunIndex.status == "waiting",
                    TiRunIndex.resume_at <= func.now(),
                    lease_free,
                    or_(never_or_stale, TiRunIndex.dispatched_at < TiRunIndex.resume_at),
                ),
                and_(TiRunIndex.status.in_(("queued", "running")), lease_free, never_or_stale),
            )
        )
        .order_by(TiRunIndex.dispatched_at.asc().nulls_first())
        .limit(RESUME_BATCH)
        .with_for_update(skip_locked=True)
    )
    async with tenant_session(None, None) as s:
        rows = (
            await s.execute(
                update(TiRunIndex)
                .where(TiRunIndex.run_id.in_(due.scalar_subquery()))
                .values(dispatched_at=func.now())
                .returning(TiRunIndex.run_id, TiRunIndex.organization_id)
            )
        ).all()
    if not rows:
        return 0
    deps = deps or get_deps()
    sent = 0
    for run_id, org_id in rows:
        try:
            await deps.publish(TiRunMessage(run_id=run_id, org_id=org_id))
            sent += 1
        except Exception as exc:  # noqa: BLE001 - retried on the next beat
            log.warning("ti.resume: publish failed for run %s (%s)", run_id, type(exc).__name__)
    log.info("ti.resume re-sent %d runs", sent)
    return sent


async def handle_verify(message: Mapping[str, Any], deps: Deps | None = None) -> None:
    """`ti.verify {org_id, provider}`: check a stored key, record `verify_status` (valid /
    invalid / error), `verified_at`, `last_error_code`, and audit it with a NULL actor.
    MISP URL resolution and pinning before the call are added in phase 4."""
    try:
        msg = TiVerifyMessage.model_validate(message)
        provider = ProviderName(msg.provider)
    except (ValidationError, ValueError):
        _drop("invalid verify message", message)
        return
    deps = deps or get_deps()
    async with tenant_session(msg.org_id, None) as s:
        row = await s.scalar(
            select(TiProviderConfig).where(
                TiProviderConfig.organization_id == msg.org_id,
                TiProviderConfig.provider == provider.value,
            )
        )
        config = _Config.of(row) if row is not None else None
    if config is None or config.sealed is None:
        log.info("ti.verify: no key stored for %s", provider.value)
        return
    if not registry.available(provider, deps.settings):
        verdict = VerifyOutcome(VerifyStatus.ERROR, "provider_unavailable")
    else:
        try:
            adapter, client = await _open_provider(deps, msg.org_id, config)
        except (UnsealError, registry.ProviderUnavailable, ValueError, ImportError) as exc:
            verdict = VerifyOutcome(VerifyStatus.ERROR, getattr(exc, "code", "unavailable"))
        else:
            async with client:
                verdict = await _verify(adapter, client)
    await _save_verify(msg.org_id, config, verdict)
    log.info("ti.verify %s: %s", provider.value, verdict.status.value)


__all__ = [
    "Deps",
    "check_startup",
    "get_deps",
    "handle_enrich",
    "handle_resume",
    "handle_verify",
]
