"""Harness for the "IOC enrichment success" metric (M4 phase 7, RT24).

The metric measures resilience under synthetic faults, not provider quality: with 3 attempts
per lookup it mostly measures the worker's retry, cooldown and resume logic.

- Lookups: 100 per real adapter (VirusTotal, AbuseIPDB, URLhaus, MalwareBazaar, OTX, MISP),
  600 in all, with a per-provider mix of IOC types. They run as five waves of manual runs, one
  run per provider per wave (20 eligible values plus a few ineligible ones that the planner
  must skip). A wave's six runs are driven concurrently; the waves run one after another.
- Wire: the real adapters, `ti_client`, `KeyAuth` and, for MISP, the pinned transport, in front
  of an in-process transport. That transport serves the committed fixture bodies
  (`tests/fixtures/ti/manifest.json`: the hit / not-found case for the value's type) and
  injects faults drawn from an RNG seeded per (provider, value, attempt): 10 % 5xx, 5 % 429
  (half with `Retry-After`), 2 % malformed JSON, 1 % timeout. It also checks every request:
  the value on the wire must be a planned value, eligible for that provider and unchanged
  after re-normalization, and no submitted ineligible value (or a URL query) may appear.
- Worker: `enrich.handle_enrich`, one slice per call, with the real broker limiter (test
  broker db, `test.` prefix). Nothing is published; the harness plays the queue and the
  `ti.resume` beat: a re-published run gets its next slice 0.25 s later, and a `waiting` run
  resumes at the first 30 s beat tick at or after its `resume_at`.
- Time: a virtual clock replaces `time.time` / `time.monotonic` in the worker module, the
  limiter's clock and `Deps.sleep`. Provider latency, read timeouts (10 s), retry backoff and
  token waits are virtual sleeps. A scheduler moves virtual time to the earliest sleeper once
  the event loop has been quiet for a moment, and ages the org's limiter keys (token bucket,
  cooldown, 429 strikes) by the same amount, so Redis TTLs follow virtual time.
- Deadline: each run's `deadline_at` is moved onto the virtual clock. Once virtual time passes
  it, the harness expires the deadline in the DB and the next slice finalizes the run, which
  marks its pending items `abandoned/deadline`, as in production.
- Cache: a second pass repeats every lookup at once. The cache TTLs are checked against the
  DB clock, which is real time, so the second pass reads as an immediate repeat.
"""

import asyncio
import base64
import contextlib
import heapq
import itertools
import json
import math
import random
import re
import uuid
from collections import Counter
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, unquote

import httpx
from pydantic import SecretStr
from sqlalchemy import func, select, update

from app.core.config import Settings, get_settings
from app.core.tenancy import tenant_session
from app.modules.threat_intel import runs
from app.modules.threat_intel.messages import TiRunMessage
from app.modules.threat_intel.models import (
    RUN_FINAL,
    TiEnrichmentRun,
    TiProviderConfig,
    TiResult,
    TiRunIndex,
    TiRunItem,
)
from app.modules.threat_intel.normalize import Normalized, eligible, normalize
from app.modules.threat_intel.providers import registry
from app.modules.threat_intel.providers.base import IocType, Provider, ProviderName
from app.modules.threat_intel.providers.misp import MispProvider
from app.modules.threat_intel.ratelimit import Limiter, broker_redis
from app.modules.threat_intel.seal import load_public_key, seal
from app.modules.threat_intel.ssrf import validate_base_url
from app.workers import enrich
from tests.integration.seed import Tenant, seed_tenant
from tests.ti_helpers import SENTINEL_KEY, SealKeys, new_seal_keys

SEED = 261105
PROVIDERS = (
    ProviderName.VIRUSTOTAL,
    ProviderName.ABUSEIPDB,
    ProviderName.URLHAUS,
    ProviderName.MALWAREBAZAAR,
    ProviderName.OTX,
    ProviderName.MISP,
)
LOOKUPS_PER_PROVIDER = 100
WAVES = 5
PER_WAVE = LOOKUPS_PER_PROVIDER // WAVES
HIT_SHARE = 0.4
# Cumulative fault thresholds on one uniform draw per request.
FAULT_5XX = 0.10
FAULT_429 = 0.05
FAULT_MALFORMED = 0.02
FAULT_TIMEOUT = 0.01
RETRY_AFTER_S = (5, 10, 20, 30, 60)
READ_TIMEOUT_S = 10.0  # http.TIMEOUT.read
BEAT_S = 30.0  # the `resume-ti-runs` beat schedule
REQUEUE_DELAY_S = 0.25
QUIET_S = 0.002
MAX_SLICES_PER_RUN = 500
# Median provider round trip (virtual seconds), spread log-normally (sigma 0.45, cap 9 s).
LATENCY_S = {
    ProviderName.VIRUSTOTAL: 0.45,
    ProviderName.ABUSEIPDB: 0.30,
    ProviderName.URLHAUS: 0.35,
    ProviderName.MALWAREBAZAAR: 0.35,
    ProviderName.OTX: 0.80,
    ProviderName.MISP: 0.20,
}
TYPE_MIX: dict[ProviderName, dict[IocType, int]] = {
    ProviderName.VIRUSTOTAL: {
        IocType.IPV4: 20,
        IocType.IPV6: 5,
        IocType.DOMAIN: 25,
        IocType.URL: 25,
        IocType.MD5: 8,
        IocType.SHA1: 8,
        IocType.SHA256: 9,
    },
    ProviderName.ABUSEIPDB: {IocType.IPV4: 90, IocType.IPV6: 10},
    ProviderName.URLHAUS: {
        IocType.IPV4: 20,
        IocType.DOMAIN: 30,
        IocType.URL: 30,
        IocType.MD5: 10,
        IocType.SHA256: 10,
    },
    ProviderName.MALWAREBAZAAR: {IocType.MD5: 30, IocType.SHA1: 30, IocType.SHA256: 40},
    ProviderName.OTX: {
        IocType.IPV4: 20,
        IocType.DOMAIN: 20,
        IocType.URL: 20,
        IocType.MD5: 13,
        IocType.SHA1: 13,
        IocType.SHA256: 14,
    },
    ProviderName.MISP: {
        IocType.IPV4: 20,
        IocType.DOMAIN: 20,
        IocType.URL: 15,
        IocType.MD5: 10,
        IocType.SHA1: 10,
        IocType.SHA256: 10,
        IocType.EMAIL: 15,
    },
}
# Submitted with every run; each provider gets those it may not receive (the planner skips
# them, so none may ever reach a transport).
INELIGIBLE = (
    "10.20.30.40",
    "192.168.7.9",
    "203.0.113.50",
    "fileserver.corp.local",
    "intranet",
    "www.example.com",
    "https://bob:hunter2@portal.acme-metric.net/login",
    "alice@acme-metric.net",
    "shop.acme-metric.net",
)
QUERY_MARKER = "token="
MISP_URL = "https://misp.acme-corp.net"
MISP_PUBLIC_IP = "8.8.8.8"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "ti"
MANIFEST: dict[str, Any] = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))

_KIND = {
    IocType.IPV4: "ip",
    IocType.IPV6: "ip",
    IocType.DOMAIN: "domain",
    IocType.URL: "url",
    IocType.EMAIL: "email",
    IocType.MD5: "file_md5",
    IocType.SHA1: "file_sha1",
    IocType.SHA256: "file_sha256",
}
_HASH_BITS = {IocType.MD5: 128, IocType.SHA1: 160, IocType.SHA256: 256}
_SLDS = ("acme-metric.net", "fabrikam-ops.com", "lumen-trace.org")
_FIRST_OCTETS = (23, 31, 45, 62, 77, 85, 91, 104, 141, 151, 176, 185, 193, 212)

# KEYS: limiter keys to age. ARGV: virtual milliseconds that passed.
_AGE = """
local ms = tonumber(ARGV[1])
for _, key in ipairs(KEYS) do
  local ttl = redis.call('PTTL', key)
  if ttl > 0 then
    if ttl <= ms then redis.call('DEL', key) else redis.call('PEXPIRE', key, ttl - ms) end
  end
end
return 1
"""


# --- the virtual clock ---------------------------------------------------------------------


class VirtualClock:
    """Virtual `time.time` / `time.monotonic` and a sleep that only virtual time ends."""

    def __init__(self, epoch: float) -> None:
        self.epoch = epoch
        self._now = 0.0
        self._heap: list[tuple[float, int, asyncio.Future[None]]] = []
        self._seq = itertools.count()
        self._registered = False
        self.on_advance: Callable[[float], Awaitable[None]] | None = None
        self.advances = 0

    def time(self) -> float:
        return self.epoch + self._now

    def monotonic(self) -> float:
        return self._now

    def module(self) -> SimpleNamespace:
        """Stands in for the `time` module inside `app.workers.enrich`."""
        return SimpleNamespace(time=self.time, monotonic=self.monotonic)

    async def sleep(self, seconds: float) -> None:
        if seconds <= 0:
            await asyncio.sleep(0)
            return
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        heapq.heappush(self._heap, (self._now + seconds, next(self._seq), future))
        self._registered = True
        await future

    async def run(self) -> None:
        """Advance to the earliest sleeper once nothing registered for a quiet period."""
        try:
            while True:
                await asyncio.sleep(QUIET_S)
                if self._registered:
                    self._registered = False
                    continue
                while self._heap and self._heap[0][2].done():
                    heapq.heappop(self._heap)  # its sleeper was cancelled
                if not self._heap:
                    continue
                when = self._heap[0][0]
                if when > self._now:
                    delta = when - self._now
                    self._now = when
                    self.advances += 1
                    if self.on_advance is not None:
                        await self.on_advance(delta)
                while self._heap and self._heap[0][0] <= self._now:
                    _, _, future = heapq.heappop(self._heap)
                    if not future.done():
                        future.set_result(None)
        except Exception as exc:
            for _, _, future in self._heap:
                if not future.done():
                    future.set_exception(exc)
            raise


# --- lookups and fixtures ------------------------------------------------------------------


@dataclass(frozen=True)
class Lookup:
    provider: ProviderName
    raw: str
    ioc_type: IocType
    value_norm: str
    hit: bool


def _candidate(rng: random.Random, ioc_type: IocType, provider: ProviderName, n: int) -> str:
    if ioc_type is IocType.IPV4:
        return ".".join(
            str(octet)
            for octet in (
                rng.choice(_FIRST_OCTETS),
                rng.randint(0, 255),
                rng.randint(0, 255),
                rng.randint(1, 254),
            )
        )
    if ioc_type is IocType.IPV6:
        groups = ":".join(f"{rng.randint(1, 0xFFFF):x}" for _ in range(3))
        return f"2a0{rng.randint(1, 9)}:{groups}::{rng.randint(1, 0xFFFF):x}"
    if ioc_type in _HASH_BITS:
        bits = _HASH_BITS[ioc_type]
        return f"{rng.getrandbits(bits):0{bits // 4}x}"
    label = f"{provider.value[:4]}{n}-{rng.randrange(16**6):06x}"
    sld = rng.choice(_SLDS)
    if ioc_type is IocType.DOMAIN:
        return f"{label}.{sld}"
    if ioc_type is IocType.EMAIL:
        return f"{label}@{sld}"
    scheme = rng.choice(("http", "https"))
    path = f"/{rng.choice(('dl', 'gate', 'panel', 'static'))}/{label}.php"
    if rng.random() < 0.25:  # the planner must drop the query before anything is sent
        path += f"?id={n}&{QUERY_MARKER}{rng.randrange(16**8):08x}"
    return f"{scheme}://{label}.{sld}{path}"


def build_lookups(provider: ProviderName) -> list[Lookup]:
    rng = random.Random(f"{SEED}:values:{provider.value}")  # noqa: S311
    types = [t for t, count in TYPE_MIX[provider].items() for _ in range(count)]
    assert len(types) == LOOKUPS_PER_PROVIDER
    rng.shuffle(types)
    seen: set[str] = set()
    lookups: list[Lookup] = []
    for n, ioc_type in enumerate(types):
        for _ in range(50):
            raw = _candidate(rng, ioc_type, provider, n)
            verdict = eligible(normalize(None, raw), provider)
            if (
                isinstance(verdict, Normalized)
                and verdict.ioc_type is ioc_type
                and verdict.value_norm not in seen
            ):
                break
        else:
            raise RuntimeError(f"no eligible {ioc_type} value for {provider}")
        seen.add(verdict.value_norm)
        lookups.append(
            Lookup(provider, raw, ioc_type, verdict.value_norm, rng.random() < HIT_SHARE)
        )
    return lookups


def ineligible_for(provider: ProviderName) -> list[str]:
    return [
        v for v in INELIGIBLE if not isinstance(eligible(normalize(None, v), provider), Normalized)
    ]


@dataclass(frozen=True)
class Canned:
    status: int
    headers: dict[str, str]
    body: bytes

    def response(self, extra: dict[str, str] | None = None) -> httpx.Response:
        headers = {k: v for k, v in self.headers.items() if k.lower() != "retry-after"}
        headers.update(extra or {})
        return httpx.Response(self.status, headers=headers, content=self.body)


class FixtureServer:
    """The manifest's hit / not-found / fault cases of one provider, per IOC kind."""

    def __init__(self, provider: ProviderName) -> None:
        self.provider = provider
        self.cases: dict[str, dict[str, Any]] = MANIFEST["providers"][provider.value]["cases"]
        self.hit: dict[str, Canned] = {}
        self.not_found: dict[str, Canned] = {}
        self.server_error: dict[str, Canned] = {}
        self.rate_limited: dict[str, Canned] = {}
        self.malformed: dict[str, Canned] = {}
        for ioc_type in TYPE_MIX[provider]:
            kind = _KIND[ioc_type]
            fallback = "file_sha256" if kind.startswith("file_") else kind
            self.hit[kind] = self._pick([f"{k}_hit" for k in (kind, fallback)], "found")
            self.not_found[kind] = self._pick(
                [
                    f"{k}_{suffix}"
                    for k in (kind, fallback)
                    for suffix in ("not_found", "no_results", "hash_not_found", "quiet")
                ],
                "not_found",
            )
            self.server_error[kind] = self._pick(
                [f"{kind}_server_error"], "unavailable", lambda c: (c["http_status"] or 0) >= 500
            )
            self.rate_limited[kind] = self._pick([f"{kind}_rate_limited"], "rate_limited")
            self.malformed[kind] = self._pick(
                [f"{kind}_bad_json"], "parse_error", lambda c: (c["file"] or "") == "malformed.txt"
            )

    def _pick(
        self,
        names: list[str],
        expect: str,
        accept: Callable[[dict[str, Any]], bool] = lambda _: True,
    ) -> Canned:
        chosen: dict[str, Any] | None = None
        for name in names:
            case = self.cases.get(name)
            if case is not None and case["expect"] == expect and accept(case):
                chosen = case
                break
        if chosen is None:  # any case of that outcome (bodies shared across kinds)
            chosen = next(c for c in self.cases.values() if c["expect"] == expect and accept(c))
        body = (FIXTURES / self.provider.value / chosen["file"]).read_bytes()
        return Canned(chosen["http_status"], dict(chosen["headers"]), body)


def wire_value(provider: ProviderName, request: httpx.Request) -> str:
    """The IOC value a provider request carries (raises on an unexpected request shape)."""
    path = unquote(request.url.raw_path.decode("ascii").split("?", 1)[0])
    if provider is ProviderName.VIRUSTOTAL:
        match = re.fullmatch(r"/api/v3/(ip_addresses|domains|urls|files)/([^/]+)", path)
        if match is None:
            raise ValueError("unexpected virustotal path")
        ident = match[2]
        if match[1] == "urls":
            return base64.urlsafe_b64decode(ident + "=" * (-len(ident) % 4)).decode()
        return ident
    if provider is ProviderName.ABUSEIPDB:
        if path != "/api/v2/check":
            raise ValueError("unexpected abuseipdb path")
        return request.url.params["ipAddress"]
    if provider is ProviderName.OTX:
        match = re.fullmatch(r"/api/v1/indicators/(IPv4|IPv6|domain|url|file)/(.+)/general", path)
        if match is None:
            raise ValueError("unexpected otx path")
        return match[2]
    if provider is ProviderName.MISP:
        value = json.loads(request.content)["value"]
        if not isinstance(value, str):
            raise ValueError("misp value is not a string")
        return value
    form = parse_qs(request.content.decode(), strict_parsing=True)
    names: tuple[str, ...] = ("url", "host", "md5_hash", "sha256_hash")
    if provider is ProviderName.MALWAREBAZAAR:
        names = ("hash",)
    (found,) = [form[name][0] for name in names if name in form]
    return found


# --- the simulation ------------------------------------------------------------------------


@dataclass
class WireCall:
    pass_no: int
    provider: ProviderName
    value: str
    start: float
    end: float
    outcome: str  # answer, 5xx, 429, 429_ra, malformed, timeout


class MetricTransport(httpx.AsyncBaseTransport):
    def __init__(self, sim: "Simulation", provider: ProviderName) -> None:
        self._sim = sim
        self._provider = provider

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await request.aread()
        return await self._sim.serve(self._provider, request)


@dataclass
class PassStats:
    provider: str
    planned: int = 0
    skipped: int = 0
    cached: int = 0
    reached: int = 0
    ok: int = 0
    not_found: int = 0
    error: int = 0
    abandoned: Counter[str] = field(default_factory=Counter)
    abandoned_reached: int = 0
    requests: int = 0
    faults: Counter[str] = field(default_factory=Counter)
    latencies_ms: list[int] = field(default_factory=list)
    answer_s: list[float] = field(default_factory=list)
    runs: Counter[str] = field(default_factory=Counter)

    @property
    def success(self) -> float:
        return (self.ok + self.not_found) / self.reached if self.reached else 1.0

    @property
    def cache_rate(self) -> float:
        return self.cached / self.planned if self.planned else 0.0

    def add(self, other: "PassStats") -> None:
        for name in (
            "planned",
            "skipped",
            "cached",
            "reached",
            "ok",
            "not_found",
            "error",
            "abandoned_reached",
            "requests",
        ):
            setattr(self, name, getattr(self, name) + getattr(other, name))
        self.abandoned.update(other.abandoned)
        self.faults.update(other.faults)
        self.latencies_ms += other.latencies_ms
        self.answer_s += other.answer_s
        self.runs.update(other.runs)


def percentile(values: list[float], pct: float) -> float | None:
    """Nearest-rank percentile."""
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(pct / 100 * len(ordered)) - 1)]


class Simulation:
    def __init__(self, tenant: Tenant, keys: SealKeys, settings: Settings) -> None:
        self.t = tenant
        self.keys = keys
        self.settings = settings
        self.clock = VirtualClock(datetime.now(UTC).timestamp())
        self.limiter = Limiter(
            broker_redis(settings.broker_url), settings.queue_prefix, clock=self.clock.time
        )
        self.clock.on_advance = self._age_limiter_keys
        self._age_carry = 0.0
        self._aged_keys = [
            key
            for p in PROVIDERS
            for key in (
                self.limiter.keys(p, tenant.org_id)[0],
                self.limiter.keys(p, tenant.org_id)[2],
                self.limiter.strikes_key(p, tenant.org_id),
            )
        ]
        self.lookups = {p: build_lookups(p) for p in PROVIDERS}
        self.planned = {p: {lk.value_norm: lk for lk in self.lookups[p]} for p in PROVIDERS}
        self.ineligible = {p: ineligible_for(p) for p in PROVIDERS}
        self.servers = {p: FixtureServer(p) for p in PROVIDERS}
        self.jitter = random.Random(f"{SEED}:jitter")  # noqa: S311
        self.deps = {p: self._deps(p) for p in PROVIDERS}
        self.attempts: Counter[tuple[ProviderName, str]] = Counter()
        self.wire: list[WireCall] = []
        self.violations: list[str] = []
        self.pass_no = 0
        self.runs: dict[int, list[tuple[ProviderName, uuid.UUID]]] = {}
        self.durations: dict[int, float] = {}
        self.slices: Counter[int] = Counter()
        self.resumes: Counter[int] = Counter()
        self.republished = 0

    @classmethod
    async def create(cls) -> "Simulation":
        tenant = await seed_tenant(f"org{uuid.uuid4().hex[:8]}")
        keys = new_seal_keys("metric-1")
        settings = get_settings().model_copy(
            update={
                "ti_seal_active_kid": keys.kid,
                "ti_seal_public_keys": {keys.kid: keys.public_b64},
                "ti_max_lookup_values": PER_WAVE + len(INELIGIBLE),
            }
        )
        sim = cls(tenant, keys, settings)
        for provider in PROVIDERS:
            await sim._seal_config(provider)
        return sim

    @contextlib.asynccontextmanager
    async def running(self) -> AsyncIterator["Simulation"]:
        scheduler = asyncio.create_task(self.clock.run())
        try:
            yield self
        finally:
            scheduler.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await scheduler
            await self.limiter._redis.aclose()  # noqa: SLF001

    # ---- setup

    async def _seal_config(self, provider: ProviderName) -> None:
        base = ""
        if provider is ProviderName.MISP:
            base = validate_base_url(
                MISP_URL, allowed_ports=(443,), allow_private=False
            ).base_url_norm
        sealed = seal(
            SecretStr(SENTINEL_KEY),
            self.t.org_id,
            provider.value,
            self.keys.kid,
            1,
            base,
            load_public_key(self.keys.public_b64),
        )
        async with tenant_session(self.t.org_id, self.t.owner_id) as s:
            s.add(
                TiProviderConfig(
                    organization_id=self.t.org_id,
                    provider=provider.value,
                    enabled=True,
                    base_url=base or None,
                    key_kid=sealed.kid,
                    key_version=sealed.key_version,
                    key_epk=sealed.epk,
                    key_nonce=sealed.nonce,
                    key_ct=sealed.ct,
                    key_last4=sealed.last4,
                    limits={},
                    verify_status="valid",
                    terms_ack_at=datetime.now(UTC),
                    terms_ack_by=self.t.owner_id,
                )
            )

    def _deps(self, provider: ProviderName) -> enrich.Deps:
        return enrich.Deps(
            settings=self.settings,
            limiter=self.limiter,
            private_keys=self.keys.private_keys,
            publish=self._publish,
            create_provider=self._create_provider,
            transport=MetricTransport(self, provider),
            sleep=self.clock.sleep,
            jitter=self.jitter.random,
        )

    @staticmethod
    def _create_provider(name: ProviderName, ctx: registry.ProviderContext) -> Provider:
        if name is ProviderName.MISP:
            # The real adapter and pinned transport; only the resolver is faked (public IP).
            base = validate_base_url(ctx.base_url_norm, allowed_ports=(443,), allow_private=False)

            async def resolve(host: str, port: int) -> list[str]:
                return [MISP_PUBLIC_IP]

            return MispProvider(base, settings=ctx.settings, resolver=resolve, allow_private=False)
        return registry.create(name, ctx)

    async def _publish(self, message: TiRunMessage) -> None:
        self.republished += 1

    async def _age_limiter_keys(self, delta: float) -> None:
        self._age_carry += delta * 1000
        ms = int(self._age_carry)
        if ms <= 0:
            return
        self._age_carry -= ms
        await self.limiter._redis.eval(_AGE, len(self._aged_keys), *self._aged_keys, ms)  # noqa: SLF001

    # ---- the wire

    async def serve(self, provider: ProviderName, request: httpx.Request) -> httpx.Response:
        try:
            value = wire_value(provider, request)
        except (ValueError, KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            self.violations.append(f"{provider.value}: unreadable request ({type(exc).__name__})")
            return httpx.Response(400, json={})
        problem = self._check(provider, value, request)
        if problem is not None:
            self.violations.append(f"{provider.value}: {problem}")
            return httpx.Response(400, json={})
        lookup = self.planned[provider][value]
        key = (provider, value)
        n = self.attempts[key]
        self.attempts[key] += 1
        rng = random.Random(f"{SEED}:wire:{provider.value}:{value}:{n}")  # noqa: S311
        draw = rng.random()
        latency = min(9.0, LATENCY_S[provider] * rng.lognormvariate(0.0, 0.45))
        server = self.servers[provider]
        kind = _KIND[lookup.ioc_type]
        start = self.clock.monotonic()
        response: httpx.Response
        if draw < FAULT_5XX:
            outcome, response = "5xx", server.server_error[kind].response()
        elif draw < FAULT_5XX + FAULT_429:
            if rng.random() < 0.5:
                seconds = rng.choice(RETRY_AFTER_S)
                outcome = "429_ra"
                response = server.rate_limited[kind].response({"Retry-After": str(seconds)})
            else:
                outcome, response = "429", server.rate_limited[kind].response()
        elif draw < FAULT_5XX + FAULT_429 + FAULT_MALFORMED:
            outcome, response = "malformed", server.malformed[kind].response()
        elif draw < FAULT_5XX + FAULT_429 + FAULT_MALFORMED + FAULT_TIMEOUT:
            await self.clock.sleep(READ_TIMEOUT_S)
            self.wire.append(
                WireCall(self.pass_no, provider, value, start, self.clock.monotonic(), "timeout")
            )
            raise httpx.ReadTimeout("simulated read timeout", request=request)
        else:
            canned = server.hit[kind] if lookup.hit else server.not_found[kind]
            outcome, response = "answer", canned.response()
        await self.clock.sleep(latency)
        self.wire.append(
            WireCall(self.pass_no, provider, value, start, self.clock.monotonic(), outcome)
        )
        return response

    def _check(self, provider: ProviderName, value: str, request: httpx.Request) -> str | None:
        if value not in self.planned[provider]:
            return "a value that was never planned"
        verdict = eligible(normalize(None, value), provider)
        if not isinstance(verdict, Normalized) or verdict.value_norm != value:
            return "an ineligible or non-normalized value"
        text = str(request.url) + request.content.decode("utf-8", "replace")
        if QUERY_MARKER in text:
            return "a URL query string"
        if any(raw in text for raw in self.ineligible[provider]):
            return "a submitted ineligible value"
        return None

    # ---- runs

    async def _create_run(self, provider: ProviderName, wave: int) -> tuple[uuid.UUID, float]:
        batch = self.lookups[provider][wave * PER_WAVE : (wave + 1) * PER_WAVE]
        values: list[str | runs.LookupValue] = [lk.raw for lk in batch]
        values[wave % 3 : wave % 3] = self.ineligible[provider]
        async with tenant_session(self.t.org_id, self.t.owner_id) as s:
            created = await runs.create_run(
                s,
                self.t.org_id,
                "manual",
                values=values,
                providers=[provider],
                requested_by=self.t.owner_id,
                settings=self.settings,
            )
        assert created.run_id is not None
        assert created.items == len(batch), (provider, created.summary)
        deadline = self.clock.time() + self.settings.ti_run_deadline_s
        await self._set_deadline(created.run_id, datetime.fromtimestamp(deadline, UTC))
        return created.run_id, deadline

    async def _set_deadline(self, run_id: uuid.UUID, when: Any) -> None:
        async with tenant_session(self.t.org_id, None) as s:
            await s.execute(
                update(TiEnrichmentRun).where(TiEnrichmentRun.id == run_id).values(deadline_at=when)
            )
            await s.execute(
                update(TiRunIndex).where(TiRunIndex.run_id == run_id).values(deadline_at=when)
            )

    def _next_tick(self, resume_epoch: float) -> float:
        offset = resume_epoch - self.clock.epoch
        return self.clock.epoch + math.ceil(offset / BEAT_S) * BEAT_S

    async def _drive(self, run_id: uuid.UUID, provider: ProviderName, deadline: float) -> None:
        message = {"run_id": str(run_id), "org_id": str(self.t.org_id)}
        deps = self.deps[provider]
        woke = False
        slices = 0
        while slices < MAX_SLICES_PER_RUN:
            async with tenant_session(None, None) as s:
                index = await s.get(TiRunIndex, run_id)
                assert index is not None
                status, resume_at = index.status, index.resume_at
            if status in RUN_FINAL:
                return
            if self.clock.time() >= deadline:
                # The DB deadline is on the real clock: move it into the past so the next
                # slice finalizes the run exactly as the worker does past `deadline_at`.
                await self._set_deadline(run_id, func.now() - timedelta(seconds=1))
            elif status == "waiting" and resume_at is not None and not woke:
                self.resumes[self.pass_no] += 1
                await self.clock.sleep(self._next_tick(resume_at.timestamp()) - self.clock.time())
                woke = True
                continue
            elif slices and status != "waiting":
                await self.clock.sleep(REQUEUE_DELAY_S)  # re-published to the queue tail
            woke = False
            await enrich.handle_enrich(message, deps)
            slices += 1
            self.slices[self.pass_no] += 1
        raise AssertionError(f"{provider.value} run {run_id} did not finish")

    async def run_pass(self, pass_no: int) -> None:
        self.pass_no = pass_no
        started = self.clock.monotonic()
        self.runs[pass_no] = []
        for wave in range(WAVES):
            created = [(p, *await self._create_run(p, wave)) for p in PROVIDERS]
            await asyncio.gather(*(self._drive(rid, p, dl) for p, rid, dl in created))
            self.runs[pass_no] += [(p, rid) for p, rid, _ in created]
        self.durations[pass_no] = self.clock.monotonic() - started

    # ---- results

    async def stats(self, pass_no: int) -> dict[str, PassStats]:
        run_ids = [rid for _, rid in self.runs[pass_no]]
        out = {p.value: PassStats(p.value) for p in PROVIDERS}
        calls: dict[tuple[str, str], list[WireCall]] = {}
        for call in self.wire:
            if call.pass_no == pass_no:
                calls.setdefault((call.provider.value, call.value), []).append(call)
                stats = out[call.provider.value]
                stats.requests += 1
                if call.outcome != "answer":
                    stats.faults[call.outcome] += 1
        async with tenant_session(self.t.org_id, self.t.owner_id) as s:
            for run in (
                await s.scalars(select(TiEnrichmentRun).where(TiEnrichmentRun.id.in_(run_ids)))
            ).all():
                (provider,) = run.providers
                stats = out[provider]
                stats.runs[run.status] += 1
                counts = run.summary.get("providers", {}).get(provider, {})
                stats.skipped += sum(v for k, v in counts.items() if k.startswith("skipped_"))
            rows = (
                await s.execute(
                    select(
                        TiRunItem.run_id,
                        TiRunItem.provider,
                        TiRunItem.value_norm,
                        TiRunItem.state,
                        TiRunItem.reason,
                        TiResult.status,
                        TiResult.latency_ms,
                        TiResult.run_id,
                    )
                    .outerjoin(TiResult, TiResult.id == TiRunItem.result_id)
                    .where(TiRunItem.run_id.in_(run_ids))
                )
            ).all()
        for run_id, provider, value, state, reason, status, latency, result_run in rows:
            stats = out[provider]
            stats.planned += 1
            seen = calls.get((provider, value), [])
            if state == "cached":
                stats.cached += 1
                continue
            if state == "abandoned":
                stats.abandoned[reason or "unknown"] += 1
                if seen:
                    stats.reached += 1
                    stats.abandoned_reached += 1
                continue
            if state != "done":
                raise AssertionError(f"item left {state}")
            stats.reached += 1
            if status == "ok":
                stats.ok += 1
            elif status == "not_found":
                stats.not_found += 1
            else:
                stats.error += 1
            if latency is not None and result_run == run_id:
                stats.latencies_ms.append(latency)
            if seen:
                stats.answer_s.append(max(c.end for c in seen) - min(c.start for c in seen))
        return out


# --- the report ----------------------------------------------------------------------------


def _ms(value: float | None) -> str:
    return "-" if value is None else f"{value / 1000:.2f} s"


def _s(value: float | None) -> str:
    return "-" if value is None else f"{value:.1f} s"


def _pct(part: int, whole: int) -> str:
    return f"{100 * part / whole:.1f} %" if whole else "-"


def render(sim: Simulation, first: dict[str, PassStats], second: dict[str, PassStats]) -> str:
    total1, total2 = PassStats("all"), PassStats("all")
    for stats in first.values():
        total1.add(stats)
    for stats in second.values():
        total2.add(stats)
    lines = [
        f"Pass 1: {total1.planned} lookups, {len(PROVIDERS)} providers, seed {SEED}; "
        "faults per request: 10 % 5xx, 5 % 429 (half with Retry-After), "
        "2 % malformed JSON, 1 % timeout",
        "",
        "| Provider | Lookups | Skipped | Cached | Reached | ok | not_found | error "
        "| Success | Abandoned rl/quota/deadline | Requests | 5xx/429 (RA)/bad JSON/timeout "
        "| p95 latency | p95 time to answer |",
        "|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|",
    ]
    for stats in [*first.values(), total1]:
        faults = stats.faults
        name = "**all**" if stats is total1 else stats.provider
        lines.append(
            f"| {name} | {stats.planned} | {stats.skipped} | {stats.cached} | {stats.reached} "
            f"| {stats.ok} | {stats.not_found} | {stats.error} | {stats.success:.3f} "
            f"| {stats.abandoned['rate_limited']}/{stats.abandoned['quota_exhausted']}"
            f"/{stats.abandoned['deadline']} | {stats.requests} "
            f"| {faults['5xx']}/{faults['429'] + faults['429_ra']} ({faults['429_ra']})"
            f"/{faults['malformed']}/{faults['timeout']} "
            f"| {_ms(percentile([float(v) for v in stats.latencies_ms], 95))} "
            f"| {_s(percentile(stats.answer_s, 95))} |"
        )
    abandoned = sum(total1.abandoned.values())
    other = sum(v for k, v in total1.abandoned.items() if k not in _REASONS)
    lines += [
        "",
        f"- Success = (ok + not_found) / lookups that reached a provider; floor 0.95 per "
        f"provider. Lowest: {min(s.success for s in first.values()):.3f}.",
        f"- Abandoned: {abandoned} of {total1.planned} ("
        + ", ".join(f"{r} {_pct(total1.abandoned[r], total1.planned)}" for r in _REASONS)
        + (f", other {other}" if other else "")
        + f"); {total1.abandoned_reached} of them had reached a provider.",
        f"- Ineligible values sent to a provider: {len(sim.violations)} "
        f"({total1.skipped} skipped values submitted; every request re-checked on the wire).",
        f"- Runs: {sum(total1.runs.values())} ("
        + ", ".join(f"{k} {v}" for k, v in sorted(total1.runs.items()))
        + f"); slices {sim.slices[1]}, beat resumes {sim.resumes[1]}; virtual duration "
        f"{sim.durations[1] / 60:.1f} min.",
        "- Latency is virtual: p95 latency is the worker's own `latency_ms` (the answering "
        "attempt); time to answer runs from the first request to the final response "
        "(retries, backoff and cooldown waits included).",
        "",
        "Pass 2: the same lookups again, right after pass 1 (cache)",
        "",
        "| Provider | Lookups | Cached | Cache hit rate | Re-queried | ok + not_found | Requests |",
        "|---|--:|--:|--:|--:|--:|--:|",
    ]
    for stats in [*second.values(), total2]:
        name = "**all**" if stats is total2 else stats.provider
        lines.append(
            f"| {name} | {stats.planned} | {stats.cached} | {stats.cache_rate:.3f} "
            f"| {stats.reached} | {stats.ok + stats.not_found} | {stats.requests} |"
        )
    lines += [
        "",
        f"- Pass 2 runs: {sum(total2.runs.values())} ("
        + ", ".join(f"{k} {v}" for k, v in sorted(total2.runs.items()))
        + f"); virtual duration {sim.durations[2] / 60:.1f} min.",
    ]
    return "\n".join(lines)


_REASONS = ("rate_limited", "quota_exhausted", "deadline")


__all__ = [
    "LOOKUPS_PER_PROVIDER",
    "PROVIDERS",
    "PassStats",
    "Simulation",
    "render",
]
