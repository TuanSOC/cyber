"""Result reads (M4 phase 5): latest answer per provider for IOC rows, history per IOC, one
result. Read-only over the append-only `ti_results` (RLS plus explicit org filters).

`iocs` rows join on `ioc_key`, computed in Python from each row's normalized value (the
`iocs` table stays unchanged). The latest row per provider prefers a real answer
(`ok` / `not_found`) over a later error, then the newest `fetched_at`.
"""

import logging
import uuid
from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

from pydantic import TypeAdapter, ValidationError
from sqlalchemy import case, func, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError, NotFound
from app.core.pagination import PageParams
from app.core.rbac import OrgContext
from app.modules.threat_intel.cache import CACHEABLE
from app.modules.threat_intel.models import TiOrgSettings, TiResult
from app.modules.threat_intel.normalize import (
    Normalized,
    Skip,
    SkipReason,
    is_excluded,
    normalize,
)
from app.modules.threat_intel.providers.base import (
    Detections,
    IocType,
    ProviderName,
    ResultStatus,
    compute_ioc_key,
)
from app.modules.threat_intel.schemas import (
    HistoryOut,
    IocEnrichmentOut,
    LookupType,
    ResultOut,
)
from app.modules.threat_intel.summaries import ProviderSummary

log = logging.getLogger(__name__)

_SUMMARY: TypeAdapter[Any] = TypeAdapter(ProviderSummary)
# Values that cannot be normalized at all (as opposed to ones no provider would receive).
UNPARSEABLE = frozenset(
    {SkipReason.INVALID, SkipReason.TOO_LONG, SkipReason.BAD_SCHEME, SkipReason.HAS_USERINFO}
)


class InvalidIoc(AppError):
    status_code = 400
    code = "invalid_ioc"
    message = "The value cannot be normalized as an indicator"


def _summary(raw: dict[str, Any] | None) -> Any:
    if raw is None:
        return None
    try:
        return _SUMMARY.validate_python(raw)
    except ValidationError:
        # A row written under an older summary model: served without its summary.
        log.warning("ti result summary does not match its provider model")
        return None


def _detections(raw: dict[str, Any] | None) -> Detections | None:
    if raw is None:
        return None
    try:
        return Detections.model_validate(raw)
    except ValidationError:
        return None


def _stale(row: TiResult, now: datetime) -> bool:
    return row.expires_at is not None and row.expires_at <= now


def _strings(value: Any) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def result_out(row: TiResult, now: datetime | None = None) -> ResultOut:
    return ResultOut(
        id=row.id,
        run_id=row.run_id,
        provider=ProviderName(row.provider),
        ioc_type=IocType(row.ioc_type),
        value_norm=row.value_norm,
        ioc_key=row.ioc_key,
        status=ResultStatus(row.status),
        found=row.found,
        score=row.score,
        score_scale=row.score_scale,
        detections=_detections(row.detections),
        tags=_strings(row.tags),
        families=_strings(row.families),
        attack_ids=_strings(row.attack_ids),
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        summary=_summary(row.summary),
        permalink=row.permalink,
        error_code=row.error_code,
        fetched_at=row.fetched_at,
        expires_at=row.expires_at,
        stale=_stale(row, now or datetime.now(UTC)),
    )


def _enrichment_out(row: TiResult, now: datetime) -> IocEnrichmentOut:
    return IocEnrichmentOut(
        provider=ProviderName(row.provider),
        status=ResultStatus(row.status),
        found=row.found,
        score=row.score,
        score_scale=row.score_scale,
        detections=_detections(row.detections),
        tags=_strings(row.tags),
        families=_strings(row.families),
        attack_ids=_strings(row.attack_ids),
        fetched_at=row.fetched_at,
        expires_at=row.expires_at,
        stale=_stale(row, now),
        permalink=row.permalink,
        result_id=row.id,
    )


async def latest_by_key(
    session: AsyncSession, org_id: uuid.UUID, keys: Iterable[str]
) -> dict[str, list[TiResult]]:
    """ioc_key -> the latest row of each provider (answers before errors, newest first)."""
    wanted = sorted(set(keys))
    if not wanted:
        return {}
    answered = case((TiResult.status.in_(CACHEABLE), 0), else_=1)
    rows = await session.scalars(
        select(TiResult)
        .where(TiResult.organization_id == org_id, TiResult.ioc_key.in_(wanted))
        .ext(distinct_on(TiResult.ioc_key, TiResult.provider))
        .order_by(TiResult.ioc_key, TiResult.provider, answered, TiResult.fetched_at.desc())
    )
    out: dict[str, list[TiResult]] = defaultdict(list)
    for row in rows:
        out[row.ioc_key].append(row)
    return out


def _ioc_key(outcome: Normalized | Skip) -> str | None:
    if isinstance(outcome, Normalized):
        return outcome.ioc_key
    if outcome.ioc_type is not None and outcome.value_norm is not None:
        # Special-use names keep their normalized form (the dev/test `mock` may hold results).
        return compute_ioc_key(outcome.ioc_type, outcome.value_norm)
    return None


async def _excluded(session: AsyncSession, org_id: uuid.UUID) -> tuple[str, ...]:
    row = await session.get(TiOrgSettings, org_id)
    if row is None:
        return ()
    return tuple(s for s in row.excluded_suffixes if isinstance(s, str) and s)


async def enrich_iocs(
    session: AsyncSession, org_id: uuid.UUID, rows: Sequence[Any]
) -> list[dict[str, Any]]:
    """`include=enrichment` for one page of `iocs` rows: each row's fields plus
    `enrichment` (latest per provider) and, for ineligible rows, `enrichment_skip`."""
    excluded = await _excluded(session, org_id)
    keyed: list[tuple[Any, str | None, str | None]] = []
    for row in rows:
        outcome = normalize(row.type, row.value)
        skip: str | None = outcome.reason.value if isinstance(outcome, Skip) else None
        if isinstance(outcome, Normalized) and is_excluded(outcome.host, excluded):
            skip = SkipReason.EXCLUDED_SUFFIX.value
        keyed.append((row, _ioc_key(outcome), skip))
    latest = await latest_by_key(session, org_id, (k for _, k, _ in keyed if k))
    now = datetime.now(UTC)
    out: list[dict[str, Any]] = []
    for row, key, skip in keyed:
        found = latest.get(key, []) if key else []
        out.append(
            {
                "id": row.id,
                "type": row.type,
                "value": row.value,
                "first_seen": row.first_seen,
                "last_seen": row.last_seen,
                "count": row.count,
                "source": row.source,
                "enrichment": [_enrichment_out(r, now) for r in found],
                # A provider that may receive special-use names (the dev/test mock) can have
                # answered a value the public providers skip: answers win over the skip note.
                "enrichment_skip": None if found else skip,
            }
        )
    return out


async def history(
    ctx: OrgContext,
    page: PageParams,
    *,
    value: str,
    type_: LookupType | None,
    provider: ProviderName | None,
) -> HistoryOut:
    outcome = normalize(type_.value if type_ is not None else None, value)
    if isinstance(outcome, Skip) and (outcome.reason in UNPARSEABLE and outcome.value_norm is None):
        raise InvalidIoc()
    key = _ioc_key(outcome)
    skipped = outcome.reason.value if isinstance(outcome, Skip) else None
    ioc_type = outcome.ioc_type
    value_norm = outcome.value_norm
    notes = [n.value for n in outcome.notes]
    if key is None:
        return HistoryOut(
            items=[],
            total=0,
            ioc_type=ioc_type,
            value_norm=value_norm,
            ioc_key=None,
            notes=notes,
            skipped=skipped,
        )
    where = [TiResult.organization_id == ctx.org_id, TiResult.ioc_key == key]
    if provider is not None:
        where.append(TiResult.provider == provider.value)
    total = await ctx.session.scalar(select(func.count(TiResult.id)).where(*where))
    rows = await ctx.session.scalars(
        select(TiResult)
        .where(*where)
        .order_by(TiResult.fetched_at.desc(), TiResult.id)
        .limit(page.limit)
        .offset(page.offset)
    )
    now = datetime.now(UTC)
    return HistoryOut(
        items=[result_out(r, now) for r in rows],
        total=int(total or 0),
        ioc_type=ioc_type,
        value_norm=value_norm,
        ioc_key=key,
        notes=notes,
        skipped=skipped,
    )


async def get_result(ctx: OrgContext, result_id: uuid.UUID) -> ResultOut:
    row = await ctx.session.scalar(
        select(TiResult).where(TiResult.id == result_id, TiResult.organization_id == ctx.org_id)
    )
    if row is None:
        raise NotFound()
    return result_out(row)
