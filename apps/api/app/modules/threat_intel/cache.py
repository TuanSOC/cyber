"""The per-org result cache: the newest unexpired `ok` / `not_found` row in `ti_results`.

History is the cache, so a hit is a real earlier provider answer of the same org (never
another org's, RLS plus an explicit org filter), compared with the DB clock. Errors and
auth failures have no `expires_at` and are never served; rate-limit, quota and deadline
outcomes are item states, never rows.

TTLs (plan "Cache = history"): hash 72 h; IP 12 h (AbuseIPDB 6 h); domain 24 h; URL 12 h;
MISP 1 h (every type, including email). `not_found` gets a quarter of that, hashes at most 6 h.
"""

import uuid
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.threat_intel.models import TiResult
from app.modules.threat_intel.providers.base import (
    HASH_TYPES,
    IP_TYPES,
    IocType,
    ProviderName,
    ResultStatus,
)

CACHEABLE = (ResultStatus.OK.value, ResultStatus.NOT_FOUND.value)
_HASH_NOT_FOUND_MAX = timedelta(hours=6)


def ttl(provider: ProviderName, ioc_type: IocType, status: ResultStatus) -> timedelta | None:
    """How long a result is served from the cache; None for statuses never cached."""
    if status not in (ResultStatus.OK, ResultStatus.NOT_FOUND):
        return None
    if provider is ProviderName.MISP:
        base = timedelta(hours=1)
    elif ioc_type in HASH_TYPES:
        base = timedelta(hours=72)
    elif ioc_type in IP_TYPES:
        base = timedelta(hours=6) if provider is ProviderName.ABUSEIPDB else timedelta(hours=12)
    elif ioc_type is IocType.DOMAIN:
        base = timedelta(hours=24)
    elif ioc_type is IocType.URL:
        base = timedelta(hours=12)
    else:
        base = timedelta(hours=1)
    if status is ResultStatus.OK:
        return base
    quarter = base / 4
    if ioc_type in HASH_TYPES:
        return min(quarter, _HASH_NOT_FOUND_MAX)
    return quarter


async def fresh_result(
    session: AsyncSession, org_id: uuid.UUID, provider: ProviderName | str, ioc_key: str
) -> uuid.UUID | None:
    """The id of the newest unexpired ok / not_found row for (org, provider, ioc_key)."""
    name = provider.value if isinstance(provider, ProviderName) else provider
    return await session.scalar(
        select(TiResult.id)
        .where(
            TiResult.organization_id == org_id,
            TiResult.ioc_key == ioc_key,
            TiResult.provider == name,
            TiResult.status.in_(CACHEABLE),
            TiResult.expires_at > func.now(),
        )
        .order_by(TiResult.fetched_at.desc())
        .limit(1)
    )


__all__ = ["CACHEABLE", "fresh_result", "ttl"]
