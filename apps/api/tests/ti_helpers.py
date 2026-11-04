"""Row seeding for threat-intel schema and worker tests."""

import uuid
from datetime import UTC, datetime, timedelta

from app.core.tenancy import tenant_session
from app.modules.threat_intel.models import (
    TiEnrichmentRun,
    TiProviderConfig,
    TiResult,
    TiRunIndex,
    TiRunItem,
)
from app.modules.threat_intel.providers.base import IocType, compute_ioc_key
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
