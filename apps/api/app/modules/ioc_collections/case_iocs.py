"""The case-wide IOC read (frozen entry point of M6 phase 1; implemented by phase 2, RT11).

Aggregates `iocs` over the latest succeeded job per evidence of the case
(`investigations.timeline.latest_succeeded_jobs`, once per analyzer: every upload also gets
an automatic static job, which must not hide the pcap job's IOCs), deduplicated by (type,
value), with `count_jobs`, first / last seen, up to 5 source jobs, the collections holding
each IOC and its `ioc_key`. Both the phase-2 route (`GET /investigations/{inv}/iocs`) and
the phase-3 snapshot builder call it; the signature never changes.

One server-side GROUP BY over the per-job unique index `(job_id, type, md5(value))`, bounded
by the case's job count; ordered by `count_jobs` desc, then type and value, offset-paged
through an opaque cursor. `ioc_type` / `ioc_key` are the collection-normalized form
(`ioc_collections.normalize`), so a case IOC and a collection item of the same value share
the key; values that cannot be normalized keep their raw type and an opaque key.
"""

import uuid
from collections import defaultdict
from collections.abc import Sequence

from sqlalchemy import ColumnElement, func, select, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.analysis.models import Analyzer
from app.modules.investigations.repository import escape_like
from app.modules.investigations.timeline import latest_succeeded_jobs
from app.modules.ioc_collections.models import IocCollection, IocCollectionItem
from app.modules.ioc_collections.normalize import Item, normalize_item, opaque_key
from app.modules.ioc_collections.schemas import CaseIocOut, CaseIocPage
from app.modules.notes import paging
from app.modules.pcap_analysis.models import Ioc
from app.modules.threat_intel.normalize import IOC_TYPE_MAP

MAX_PAGE = 500
MAX_SOURCE_JOBS = 5


def raw_types(types: Sequence[str]) -> list[str]:
    """`iocs.type` values for a filter given in either vocabulary (`ipv4` -> `ip`, `ipv4`;
    `sha256` -> `file_sha256`, `sha256`)."""
    out: set[str] = set()
    for name in types:
        out.add(name)
        target = IOC_TYPE_MAP.get(name)
        for raw, mapped in IOC_TYPE_MAP.items():
            if mapped is not None and mapped is target:
                out.add(raw)
        if name in ("ipv4", "ipv6"):
            out.add("ip")
    return sorted(out)


def key_of(ioc_type: str, value: str) -> tuple[str, str]:
    """(normalized type, ioc_key) of one `iocs` row."""
    item = normalize_item(ioc_type, value)
    if isinstance(item, Item):
        return item.ioc_type, item.ioc_key
    return ioc_type, opaque_key(ioc_type, value)


async def case_iocs(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    *,
    types: Sequence[str] | None = None,
    q: str | None = None,
    limit: int,
    cursor: str | None = None,
) -> CaseIocPage:
    """One page of the case's deduplicated IOCs (the caller has checked the case exists)."""
    limit = max(1, min(limit, MAX_PAGE))
    offset = paging.decode_offset(cursor) if cursor else 0
    latest = union_all(
        *(
            select(sub.c.id)
            for sub in (
                latest_succeeded_jobs(org_id, investigation_id, analyzer) for analyzer in Analyzer
            )
        )
    ).subquery()
    where: list[ColumnElement[bool]] = [
        Ioc.organization_id == org_id,
        Ioc.job_id.in_(select(latest.c.id)),
    ]
    if types:
        where.append(Ioc.type.in_(raw_types(types)))
    if q:
        where.append(Ioc.value.ilike(f"%{escape_like(q.strip())}%", escape="\\"))
    count_jobs = func.count(func.distinct(Ioc.job_id))
    grouped = (
        select(
            Ioc.type,
            Ioc.value,
            count_jobs.label("count_jobs"),
            func.min(Ioc.first_seen).label("first_seen"),
            func.max(Ioc.last_seen).label("last_seen"),
            func.array_agg(func.distinct(Ioc.job_id)).label("job_ids"),
        )
        .where(*where)
        .group_by(Ioc.type, Ioc.value)
    )
    total = await session.scalar(select(func.count()).select_from(grouped.subquery()))
    rows = (
        await session.execute(
            grouped.order_by(count_jobs.desc(), Ioc.type, Ioc.value).limit(limit + 1).offset(offset)
        )
    ).all()
    page = rows[:limit]

    keyed = [(row, *key_of(row.type, row.value)) for row in page]
    holders = await _collections_by_key(
        session, org_id, investigation_id, {key for _, _, key in keyed}
    )
    items = [
        CaseIocOut(
            ioc_type=ioc_type,
            value=row.value,
            ioc_key=key,
            count_jobs=row.count_jobs,
            first_seen=row.first_seen,
            last_seen=row.last_seen,
            job_ids=list(dict.fromkeys(row.job_ids))[:MAX_SOURCE_JOBS],
            in_collections=holders.get(key, []),
        )
        for row, ioc_type, key in keyed
    ]
    next_cursor = paging.encode_offset(offset + limit) if len(rows) > limit else None
    return CaseIocPage(items=items, next_cursor=next_cursor, total=int(total or 0))


async def _collections_by_key(
    session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID, keys: set[str]
) -> dict[str, list[uuid.UUID]]:
    if not keys:
        return {}
    i, c = IocCollectionItem, IocCollection
    rows = await session.execute(
        select(i.ioc_key, i.collection_id)
        .join(c, (c.id == i.collection_id) & (c.organization_id == i.organization_id))
        .where(
            i.organization_id == org_id,
            c.investigation_id == investigation_id,
            i.removed_at.is_(None),
            i.ioc_key.in_(sorted(keys)),
        )
        .distinct()
        .order_by(i.ioc_key, i.collection_id)
    )
    out: dict[str, list[uuid.UUID]] = defaultdict(list)
    for key, collection_id in rows.all():
        out[key].append(collection_id)
    return out
