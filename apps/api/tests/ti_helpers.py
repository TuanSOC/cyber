"""Row seeding for threat-intel schema and worker tests."""

import asyncio
import base64
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import SecretStr
from sqlalchemy import text

from app.core.tenancy import tenant_session
from app.modules.threat_intel.models import (
    TiEnrichmentRun,
    TiProviderConfig,
    TiResult,
    TiRunIndex,
    TiRunItem,
)
from app.modules.threat_intel.normalize import Normalized, eligible, normalize
from app.modules.threat_intel.providers.base import IocType, ProviderName, compute_ioc_key
from app.modules.threat_intel.seal import load_public_key, raw_public, seal
from tests.integration.seed import Tenant

DOMAIN = "hit.example.com"
DOMAIN_KEY = compute_ioc_key(IocType.DOMAIN, DOMAIN)


async def seed_run(t: Tenant, *, status: str = "queued") -> uuid.UUID:
    """A manual run with one pending (mock, domain) item and its index row."""
    run_id = uuid.uuid4()
    deadline = datetime.now(UTC) + timedelta(minutes=30)
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            TiEnrichmentRun(
                id=run_id,
                organization_id=t.org_id,
                scope="manual",
                requested_by=t.owner_id,
                providers=["mock"],
                status=status,
                deadline_at=deadline,
            )
        )
        await s.flush()
        s.add_all(
            [
                TiRunIndex(
                    run_id=run_id,
                    organization_id=t.org_id,
                    status=status,
                    deadline_at=deadline,
                    dispatched_at=datetime.now(UTC),
                ),
                TiRunItem(
                    run_id=run_id,
                    organization_id=t.org_id,
                    seq=0,
                    provider="mock",
                    ioc_type="domain",
                    value_norm=DOMAIN,
                    ioc_key=DOMAIN_KEY,
                ),
            ]
        )
    return run_id


async def seed_result(t: Tenant, run_id: uuid.UUID, *, status: str = "ok") -> uuid.UUID:
    cacheable = status in ("ok", "not_found")
    async with tenant_session(t.org_id, t.owner_id) as s:
        result = TiResult(
            organization_id=t.org_id,
            run_id=run_id,
            provider="mock",
            ioc_type="domain",
            value_norm=DOMAIN,
            ioc_key=DOMAIN_KEY,
            status=status,
            found=status == "ok",
            summary={"provider": "mock", "label": "x"},
            permalink="https://ti-mock.example/x",
            expires_at=datetime.now(UTC) + timedelta(hours=1) if cacheable else None,
        )
        s.add(result)
    return result.id


async def seed_config(
    t: Tenant, *, provider: str = "otx", sealed: bool = True, version: int = 1
) -> uuid.UUID:
    async with tenant_session(t.org_id, t.owner_id) as s:
        config = TiProviderConfig(
            organization_id=t.org_id,
            provider=provider,
            base_url="https://misp.example.org" if provider == "misp" else None,
            **(sealed_columns("k1", version) if sealed else {"key_version": 0}),
        )
        s.add(config)
    return config.id


def sealed_columns(kid: str, version: int, last4: str = "abcd") -> dict[str, object]:
    return {
        "key_kid": kid,
        "key_version": version,
        "key_epk": bytes([version % 256]) * 32,
        "key_nonce": bytes([len(kid)]) * 12,
        "key_ct": f"{kid}-{version}-{uuid.uuid4()}".encode(),
        "key_last4": last4,
    }


# --- phase 2: sealed configs, the in-process mock sink and the eligibility guard ----------

SENTINEL_KEY = "CYBERLAB-TEST-SENTINEL-KEY-0000000000000000"


@dataclass(frozen=True)
class SealKeys:
    kid: str
    private: X25519PrivateKey
    public_b64: str

    @property
    def private_keys(self) -> dict[str, X25519PrivateKey]:
        return {self.kid: self.private}


@dataclass(frozen=True)
class PublicSealKey:
    """What the API holds: a kid and its public key (the pipeline test uses `dev-1`)."""

    kid: str
    public_b64: str


def new_seal_keys(kid: str = "test-1") -> SealKeys:
    private = X25519PrivateKey.generate()
    return SealKeys(kid, private, base64.b64encode(raw_public(private.public_key())).decode())


async def seal_config(
    t: Tenant,
    keys: SealKeys | PublicSealKey,
    *,
    provider: str = "mock",
    key: str = SENTINEL_KEY,
    enabled: bool = True,
    version: int = 1,
    limits: dict[str, object] | None = None,
    verify_status: str = "unverified",
) -> uuid.UUID:
    """A provider config whose key is sealed through the real `seal()` (dev/test key pair)."""
    sealed = seal(
        SecretStr(key),
        t.org_id,
        provider,
        keys.kid,
        version,
        "",
        load_public_key(keys.public_b64),
    )
    async with tenant_session(t.org_id, t.owner_id) as s:
        config = TiProviderConfig(
            organization_id=t.org_id,
            provider=provider,
            enabled=enabled,
            key_kid=sealed.kid,
            key_version=sealed.key_version,
            key_epk=sealed.epk,
            key_nonce=sealed.nonce,
            key_ct=sealed.ct,
            key_last4=sealed.last4,
            limits=limits or {},
            verify_status=verify_status,
            terms_ack_at=datetime.now(UTC),
            terms_ack_by=t.owner_id,
        )
        s.add(config)
    return config.id


def assert_eligible_request(request: httpx.Request) -> None:
    """Every IOC that reaches a transport must be one the `mock` provider may receive:
    re-normalized, it is eligible and unchanged (no private IP, internal or `.arpa` name,
    query string or email to a public provider ever gets this far)."""
    raw = request.url.raw_path.split(b"?", 1)
    assert len(raw) == 1, "a query string reached the transport"
    parts = raw[0].decode().split("/")
    if parts[1:3] != ["v1", "lookup"]:
        return
    ioc_type, value = parts[3], unquote(parts[4])
    verdict = eligible(normalize(ioc_type, value), ProviderName.MOCK)
    assert isinstance(verdict, Normalized), f"ineligible value reached a transport: {verdict}"
    assert verdict.value_norm == value
    assert "?" not in value and "#" not in value


class SafeTransport(httpx.AsyncBaseTransport):
    """`httpx.MockTransport` that asserts eligibility on every request it sees."""

    def __init__(self, handler: Callable[[httpx.Request], Any]) -> None:
        self._inner = httpx.MockTransport(handler)
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        assert_eligible_request(request)
        self.requests.append(request)
        return await self._inner.handle_async_request(request)


HIT_BODY = {"found": True, "behaviour": "hit", "label": "test-hit", "hits": 3, "tags": ["mock"]}


@dataclass
class MockSink:
    """In-process twin of `infra/ti-mock/server.py` for MockTransport tests."""

    expected_key: str = SENTINEL_KEY
    calls: Counter[str] = field(default_factory=Counter)
    verify_ok: bool | None = None  # None: like lookups (key check); False: 401
    lookup_status: int | None = None  # force a status for every lookup (401/403 tests)
    delay_s: float = 0.0
    retry_after: str | None = "600"

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.delay_s:
            await asyncio.sleep(self.delay_s)
        path = request.url.raw_path.decode().split("?")[0]
        authorized = request.headers.get("X-Mock-Key") == self.expected_key
        if path == "/v1/verify":
            self.calls["verify"] += 1
            ok = authorized if self.verify_ok is None else self.verify_ok
            return httpx.Response(200 if ok else 401, json={})
        _, _, _, ioc_type, encoded = path.split("/")
        value = unquote(encoded)
        self.calls[value] += 1
        if not authorized:
            return httpx.Response(401, json={"error": "unauthorized", "echo": "x"})
        if self.lookup_status is not None:
            return httpx.Response(self.lookup_status, json={})
        if ioc_type in ("md5", "sha1", "sha256"):
            return httpx.Response(200 if value.startswith("deadbeef") else 404, json=HIT_BODY)
        label = (urlsplit(value).hostname or "") if ioc_type == "url" else value
        label = label.rpartition("@")[2].split(".")[0]
        if label.startswith("hit"):
            return httpx.Response(200, json=HIT_BODY)
        if label.startswith("ratelimit-long"):
            return httpx.Response(429, headers={"Retry-After": "3600"})
        if label.startswith("ratelimit"):
            headers = {"Retry-After": self.retry_after} if self.retry_after else {}
            return httpx.Response(429, headers=headers)
        if label.startswith("err500"):
            return httpx.Response(500, json={})
        if label.startswith("slow"):
            raise httpx.ReadTimeout("slow", request=request)
        if label.startswith("big"):
            return httpx.Response(200, content=b'{"pad":"' + b"x" * (2 * 1024 * 1024) + b'"}')
        if label.startswith("redirect"):
            return httpx.Response(302, headers={"Location": "http://elsewhere.invalid/"})
        if label.startswith("badjson"):
            return httpx.Response(200, content=b'{"found": true, "label": "trunc')
        if label.startswith("deep"):
            return httpx.Response(200, content=b"[" * 3000 + b"]" * 3000)
        return httpx.Response(404, json={"found": False})


async def assert_key_absent(t: Tenant, key: str) -> None:
    """The plaintext key (or its tail) is in no threat-intel row and no audit row."""
    async with tenant_session(t.org_id, t.owner_id) as s:
        for table in (
            "ti_results",
            "ti_run_items",
            "ti_enrichment_runs",
            "ti_run_index",
            "ti_provider_configs",
            "audit_logs",
        ):
            dump = (
                await s.execute(
                    text(f"SELECT coalesce(string_agg(t::text, ''), '') FROM {table} t")
                )
            ).scalar_one()
            assert key not in dump, table
            assert key[-12:] not in dump, table
