"""IOC collections of a case (M6).

- A collection is a named list per case (name unique per case, case-insensitive:
  `409 collection_exists`). Archiving (`archived_at`) makes it read-only
  (`409 collection_archived`) until it is unarchived; an archived case makes every
  collection read-only (`409 investigation_archived`).
- Items come from a job IOC of this case (`{ioc_id}`) or are typed in (`{type, value}`),
  normalized by `ioc_collections.normalize` (the M4 TI normalizer plus the documented
  fallbacks). One active item per `ioc_key`: a duplicate is answered `duplicate` (with the
  existing id), a removed one is re-added as a new row. Adds lock the collection row, so
  concurrent adds of one collection serialize.
- Item reads join the latest TI answer per provider by `ioc_key` (attributed, never a
  verdict) and carry the source job.
- Exports (`export.py`) are never redacted and are defanged unless `defang=false`.
"""

import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import ColumnElement, func, select, tuple_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import HTTPConnection

from app.core.errors import AppError, Conflict, NotFound
from app.core.rbac import OrgContext
from app.modules.analysis.models import AnalysisJob
from app.modules.audit import service as audit
from app.modules.evidence.models import Evidence
from app.modules.investigations.models import Investigation, InvestigationStatus
from app.modules.investigations.repository import escape_like
from app.modules.ioc_collections.models import IocCollection, IocCollectionItem
from app.modules.ioc_collections.normalize import Item, normalize_item, ti_eligible
from app.modules.ioc_collections.schemas import (
    IocCollectionCreate,
    IocCollectionDetail,
    IocCollectionItemOut,
    IocCollectionItemPage,
    IocCollectionOut,
    IocCollectionPage,
    IocCollectionUpdate,
    IocItemFromJob,
    IocItemResult,
    IocItemsAdd,
    IocItemsAddResult,
    TiSummaryOut,
)
from app.modules.notes import paging
from app.modules.pcap_analysis.models import Ioc
from app.modules.threat_intel.service_results import latest_by_key
from app.modules.users.models import User

PAGE_SIZE = 50
# Active items per collection (a report embeds at most 2 000 IOCs; exports stream).
MAX_ACTIVE_ITEMS = 10_000


class CollectionArchived(Conflict):
    code = "collection_archived"
    message = "The IOC collection is archived (read-only)"


class TooManyItems(AppError):
    status_code = 422
    code = "too_many_items"
    message = f"An IOC collection holds at most {MAX_ACTIVE_ITEMS} active items"


def _collection_exists() -> Conflict:
    return Conflict("An IOC collection with this name exists in the case", code="collection_exists")


@dataclass(frozen=True)
class CollectionRow:
    collection: IocCollection
    created_by_name: str
    item_count: int
    case: Investigation


def _active_count() -> ColumnElement[int]:
    i = IocCollectionItem
    return (
        select(func.count(i.id))
        .where(i.collection_id == IocCollection.id, i.removed_at.is_(None))
        .correlate(IocCollection)
        .scalar_subquery()
    )


def collection_out(row: CollectionRow) -> IocCollectionOut:
    c = row.collection
    return IocCollectionOut(
        id=c.id,
        investigation_id=c.investigation_id,
        name=c.name,
        description=c.description,
        archived=c.archived_at is not None,
        item_count=row.item_count,
        created_by=c.created_by,
        created_by_name=row.created_by_name,
        created_at=c.created_at,
        updated_at=c.updated_at,
    )


async def _case(
    session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID, *, lock: bool = False
) -> Investigation:
    stmt = select(Investigation).where(
        Investigation.id == investigation_id, Investigation.organization_id == org_id
    )
    if lock:
        stmt = stmt.with_for_update(read=True)  # a concurrent archive waits for this write
    case = await session.scalar(stmt)
    if case is None:
        raise NotFound()
    return case


def _case_writable(case: Investigation) -> None:
    if case.status == InvestigationStatus.ARCHIVED:
        raise Conflict("Archived investigations are read-only", code="investigation_archived")


async def get_row(
    session: AsyncSession, org_id: uuid.UUID, collection_id: uuid.UUID, *, lock: bool = False
) -> CollectionRow:
    """404 for an unknown or foreign collection. `lock` takes FOR NO KEY UPDATE on the
    collection (item inserts reference it with KEY SHARE and are not blocked by it) and FOR
    SHARE on its case."""
    stmt = select(IocCollection).where(
        IocCollection.id == collection_id, IocCollection.organization_id == org_id
    )
    if lock:
        stmt = stmt.with_for_update(key_share=True).execution_options(populate_existing=True)
    collection = await session.scalar(stmt)
    if collection is None:
        raise NotFound()
    case = await _case(session, org_id, collection.investigation_id, lock=lock)
    name, count = (
        await session.execute(
            select(User.display_name, _active_count())
            .select_from(IocCollection)
            .join(User, User.id == IocCollection.created_by)
            .where(IocCollection.id == collection.id)
        )
    ).one()
    return CollectionRow(collection, name, int(count), case)


def _audit(
    ctx: OrgContext,
    action: str,
    collection: IocCollection,
    request: HTTPConnection,
    **details: object,
) -> None:
    audit.record(
        ctx.session,
        action=action,
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="ioc_collection",
        target_id=collection.id,
        details={"investigation_id": str(collection.investigation_id), **details},
        request=request,
    )


async def _name_taken(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    name: str,
    *,
    except_id: uuid.UUID | None = None,
) -> bool:
    c = IocCollection
    stmt = select(c.id).where(
        c.organization_id == org_id,
        c.investigation_id == investigation_id,
        func.lower(c.name) == name.lower(),
    )
    if except_id is not None:
        stmt = stmt.where(c.id != except_id)
    return (await session.scalar(stmt)) is not None


async def _flush_unique(session: AsyncSession) -> None:
    """Flush; a lost race on the (case, lower(name)) unique index is `collection_exists`."""
    try:
        await session.flush()
    except IntegrityError as exc:
        if "ux_ioc_collections_investigation_id_lower_name" in str(exc.orig):
            raise _collection_exists() from None
        raise


# --- collections ------------------------------------------------------------------------------


async def list_collections(
    ctx: OrgContext, investigation_id: uuid.UUID, *, cursor: str | None
) -> IocCollectionPage:
    await _case(ctx.session, ctx.org_id, investigation_id)
    c = IocCollection
    stmt = (
        select(c, User.display_name, _active_count())
        .join(User, User.id == c.created_by)
        .where(c.organization_id == ctx.org_id, c.investigation_id == investigation_id)
    )
    if cursor:
        stmt = stmt.where(tuple_(c.created_at, c.id) < tuple_(*paging.decode(cursor)))
    rows = (
        await ctx.session.execute(
            stmt.order_by(c.created_at.desc(), c.id.desc()).limit(PAGE_SIZE + 1)
        )
    ).all()
    page = rows[:PAGE_SIZE]
    items = [
        IocCollectionOut(
            id=col.id,
            investigation_id=col.investigation_id,
            name=col.name,
            description=col.description,
            archived=col.archived_at is not None,
            item_count=int(count),
            created_by=col.created_by,
            created_by_name=name,
            created_at=col.created_at,
            updated_at=col.updated_at,
        )
        for col, name, count in page
    ]
    next_cursor = None
    if len(rows) > PAGE_SIZE:
        last = page[-1][0]
        next_cursor = paging.encode(last.created_at, last.id)
    return IocCollectionPage(items=items, next_cursor=next_cursor)


async def create_collection(
    ctx: OrgContext,
    investigation_id: uuid.UUID,
    data: IocCollectionCreate,
    request: HTTPConnection,
) -> IocCollectionOut:
    case = await _case(ctx.session, ctx.org_id, investigation_id, lock=True)
    _case_writable(case)
    if await _name_taken(ctx.session, ctx.org_id, investigation_id, data.name):
        raise _collection_exists()
    collection = IocCollection(
        organization_id=ctx.org_id,
        investigation_id=investigation_id,
        name=data.name,
        description=data.description,
        created_by=ctx.user.id,
    )
    ctx.session.add(collection)
    await _flush_unique(ctx.session)
    _audit(ctx, "ioc_collection.created", collection, request)
    out = collection_out(CollectionRow(collection, ctx.user.display_name, 0, case))
    await ctx.session.commit()
    return out


async def get_collection(ctx: OrgContext, collection_id: uuid.UUID) -> IocCollectionDetail:
    row = await get_row(ctx.session, ctx.org_id, collection_id)
    i = IocCollectionItem
    counts = await ctx.session.execute(
        select(i.ioc_type, func.count(i.id))
        .where(
            i.organization_id == ctx.org_id,
            i.collection_id == collection_id,
            i.removed_at.is_(None),
        )
        .group_by(i.ioc_type)
        .order_by(i.ioc_type)
    )
    return IocCollectionDetail(
        collection=collection_out(row),
        counts_by_type={ioc_type: int(n) for ioc_type, n in counts.all()},
    )


async def update_collection(
    ctx: OrgContext,
    collection_id: uuid.UUID,
    data: IocCollectionUpdate,
    request: HTTPConnection,
) -> IocCollectionOut:
    row = await get_row(ctx.session, ctx.org_id, collection_id, lock=True)
    collection = row.collection
    _case_writable(row.case)
    archived = collection.archived_at is not None
    # An archived collection is read-only unless this request unarchives it; a request that
    # archives may still rename / describe it (the edits apply before the archive).
    if (
        archived
        and data.archived is not False
        and (
            (data.name is not None and data.name != collection.name)
            or (data.description is not None and data.description != collection.description)
        )
    ):
        raise CollectionArchived()
    changed: list[str] = []
    if data.archived is not None and data.archived != archived:
        collection.archived_at = datetime.now(UTC) if data.archived else None
        changed.append("archived")
    if data.name is not None and data.name != collection.name:
        if await _name_taken(
            ctx.session, ctx.org_id, collection.investigation_id, data.name, except_id=collection.id
        ):
            raise _collection_exists()
        collection.name = data.name
        changed.append("name")
    if data.description is not None and data.description != collection.description:
        collection.description = data.description
        changed.append("description")
    if not changed:
        return collection_out(row)
    await _flush_unique(ctx.session)
    _audit(
        ctx,
        "ioc_collection.updated",
        collection,
        request,
        changed=sorted(changed),
        archived=collection.archived_at is not None,
    )
    out = collection_out(row)
    await ctx.session.commit()
    return out


# --- items ------------------------------------------------------------------------------------


def item_out(
    item: IocCollectionItem,
    added_by_name: str,
    ti: list[TiSummaryOut],
    *,
    value: str | None = None,
) -> IocCollectionItemOut:
    return IocCollectionItemOut(
        id=item.id,
        collection_id=item.collection_id,
        ioc_type=item.ioc_type,
        value=item.value_norm if value is None else value,
        ioc_key=item.ioc_key,
        source="job_ioc" if item.source == "job_ioc" else "manual",
        job_id=item.job_id,
        ioc_id=item.ioc_id,
        note=item.note,
        ti_eligible=ti_eligible(item.ioc_type, item.value_norm),
        ti=ti,
        added_by=item.added_by,
        added_by_name=added_by_name,
        added_at=item.added_at,
        removed_at=item.removed_at,
        removed_by=item.removed_by,
    )


async def ti_summaries(
    session: AsyncSession, org_id: uuid.UUID, keys: list[str]
) -> dict[str, list[TiSummaryOut]]:
    """ioc_key -> the latest answer of each provider (attributed, never a verdict)."""
    latest = await latest_by_key(session, org_id, keys)
    return {
        key: [
            TiSummaryOut(
                provider=r.provider,
                status=r.status,
                found=r.found,
                score=r.score,
                score_scale=r.score_scale,
                summary=r.summary,
                fetched_at=r.fetched_at,
            )
            for r in rows
        ]
        for key, rows in latest.items()
    }


async def item_rows(
    session: AsyncSession,
    org_id: uuid.UUID,
    collection_id: uuid.UUID,
    *,
    ioc_type: str | None = None,
    q: str | None = None,
    include_removed: bool = False,
    before: tuple[datetime, uuid.UUID] | None = None,
    limit: int | None = None,
) -> list[tuple[IocCollectionItem, str]]:
    """Items newest first, with the name of who added them."""
    i = IocCollectionItem
    stmt = (
        select(i, User.display_name)
        .join(User, User.id == i.added_by)
        .where(i.organization_id == org_id, i.collection_id == collection_id)
    )
    if not include_removed:
        stmt = stmt.where(i.removed_at.is_(None))
    if ioc_type:
        stmt = stmt.where(i.ioc_type == ioc_type)
    if q:
        stmt = stmt.where(i.value_norm.ilike(f"%{escape_like(q.strip())}%", escape="\\"))
    if before is not None:
        stmt = stmt.where(tuple_(i.added_at, i.id) < tuple_(*before))
    stmt = stmt.order_by(i.added_at.desc(), i.id.desc())
    if limit is not None:
        stmt = stmt.limit(limit)
    return [(item, name) for item, name in (await session.execute(stmt)).all()]


async def list_items(
    ctx: OrgContext,
    collection_id: uuid.UUID,
    *,
    ioc_type: str | None,
    q: str | None,
    include_removed: bool,
    cursor: str | None,
) -> IocCollectionItemPage:
    await get_row(ctx.session, ctx.org_id, collection_id)
    rows = await item_rows(
        ctx.session,
        ctx.org_id,
        collection_id,
        ioc_type=ioc_type,
        q=q,
        include_removed=include_removed,
        before=paging.decode(cursor) if cursor else None,
        limit=PAGE_SIZE + 1,
    )
    page = rows[:PAGE_SIZE]
    ti = await ti_summaries(ctx.session, ctx.org_id, [item.ioc_key for item, _ in page])
    next_cursor = None
    if len(rows) > PAGE_SIZE:
        last = page[-1][0]
        next_cursor = paging.encode(last.added_at, last.id)
    return IocCollectionItemPage(
        items=[item_out(item, name, ti.get(item.ioc_key, [])) for item, name in page],
        next_cursor=next_cursor,
    )


async def _job_iocs(
    session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID, ids: set[uuid.UUID]
) -> dict[uuid.UUID, Ioc]:
    """The requested job IOCs that belong to a job of this case (others are absent)."""
    if not ids:
        return {}
    rows = await session.scalars(
        select(Ioc)
        .join(
            AnalysisJob,
            (AnalysisJob.id == Ioc.job_id) & (AnalysisJob.organization_id == Ioc.organization_id),
        )
        .join(
            Evidence,
            (Evidence.id == AnalysisJob.evidence_id)
            & (Evidence.organization_id == AnalysisJob.organization_id),
        )
        .where(
            Ioc.organization_id == org_id,
            Ioc.id.in_(sorted(ids)),
            Evidence.investigation_id == investigation_id,
        )
    )
    return {ioc.id: ioc for ioc in rows}


async def add_items(
    ctx: OrgContext, collection_id: uuid.UUID, data: IocItemsAdd, request: HTTPConnection
) -> IocItemsAddResult:
    row = await get_row(ctx.session, ctx.org_id, collection_id, lock=True)
    collection = row.collection
    _case_writable(row.case)
    if collection.archived_at is not None:
        raise CollectionArchived()

    job_iocs = await _job_iocs(
        ctx.session,
        ctx.org_id,
        collection.investigation_id,
        {entry.ioc_id for entry in data.items if isinstance(entry, IocItemFromJob)},
    )
    active = dict(
        (
            await ctx.session.execute(
                select(IocCollectionItem.ioc_key, IocCollectionItem.id).where(
                    IocCollectionItem.organization_id == ctx.org_id,
                    IocCollectionItem.collection_id == collection_id,
                    IocCollectionItem.removed_at.is_(None),
                )
            )
        ).all()
    )
    results: list[IocItemResult] = []
    new: list[IocCollectionItem] = []
    for index, entry in enumerate(data.items):
        source_ioc: Ioc | None = None
        note: str | None = None
        if isinstance(entry, IocItemFromJob):
            source_ioc = job_iocs.get(entry.ioc_id)
            if source_ioc is None:
                results.append(
                    IocItemResult(
                        index=index, outcome="invalid", item_id=None, reason="ioc_out_of_scope"
                    )
                )
                continue
            normalized = normalize_item(source_ioc.type, source_ioc.value)
        else:
            normalized = normalize_item(entry.type, entry.value)
            note = entry.note or None
        if not isinstance(normalized, Item):
            results.append(
                IocItemResult(
                    index=index, outcome="invalid", item_id=None, reason=normalized.reason
                )
            )
            continue
        existing = active.get(normalized.ioc_key)
        if existing is not None:
            results.append(
                IocItemResult(index=index, outcome="duplicate", item_id=existing, reason=None)
            )
            continue
        item = IocCollectionItem(
            id=uuid.uuid4(),
            organization_id=ctx.org_id,
            collection_id=collection_id,
            ioc_type=normalized.ioc_type,
            value_norm=normalized.value_norm,
            ioc_key=normalized.ioc_key,
            source="job_ioc" if source_ioc is not None else "manual",
            job_id=source_ioc.job_id if source_ioc is not None else None,
            ioc_id=source_ioc.id if source_ioc is not None else None,
            note=note,
            added_by=ctx.user.id,
        )
        active[normalized.ioc_key] = item.id
        new.append(item)
        results.append(IocItemResult(index=index, outcome="added", item_id=item.id, reason=None))

    if row.item_count + len(new) > MAX_ACTIVE_ITEMS:
        raise TooManyItems()
    outcomes = Counter(r.outcome for r in results)
    if new:
        ctx.session.add_all(new)
        await ctx.session.flush()
        collection.updated_at = datetime.now(UTC)
        _audit(
            ctx,
            "ioc_collection.items_added",
            collection,
            request,
            added=outcomes["added"],
            duplicates=outcomes["duplicate"],
            invalid=outcomes["invalid"],
            from_jobs=sum(1 for item in new if item.source == "job_ioc"),
        )
        await ctx.session.commit()
    return IocItemsAddResult(
        results=results,
        added=outcomes["added"],
        duplicates=outcomes["duplicate"],
        invalid=outcomes["invalid"],
    )


async def remove_item(
    ctx: OrgContext, collection_id: uuid.UUID, item_id: uuid.UUID, request: HTTPConnection
) -> None:
    row = await get_row(ctx.session, ctx.org_id, collection_id, lock=True)
    collection = row.collection
    item = await ctx.session.scalar(
        select(IocCollectionItem)
        .where(
            IocCollectionItem.id == item_id,
            IocCollectionItem.organization_id == ctx.org_id,
            IocCollectionItem.collection_id == collection_id,
        )
        .with_for_update()
    )
    if item is None:
        raise NotFound()
    _case_writable(row.case)
    if collection.archived_at is not None:
        raise CollectionArchived()
    if item.removed_at is not None:
        return  # already removed: idempotent, the first removal stays recorded
    item.removed_at = datetime.now(UTC)
    item.removed_by = ctx.user.id
    collection.updated_at = datetime.now(UTC)
    _audit(
        ctx,
        "ioc_collection.item_removed",
        collection,
        request,
        item_id=str(item.id),
        ioc_type=item.ioc_type,
        ioc_key=item.ioc_key,
    )
    await ctx.session.commit()
