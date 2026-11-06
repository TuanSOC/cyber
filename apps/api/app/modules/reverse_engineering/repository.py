"""Read queries over one RE job's results (M10 phase 8); every query is bounded to (org, job)
on top of RLS.

Pages and capped totals work exactly like the other result reads
(`pcap_analysis.repository._page`: offset pages under the shared `MAX_OFFSET`, totals counted
up to `TOTAL_CAP`, `ref=<row id>` pages of one row or 404). The orderings and the filters'
EXISTS subqueries follow the 0018 indexes: (job, entry) unique on functions, (job,
priority_rank), (job, name); (job, callee_entry) on call edges; (job, function_entry) on the
reference and link tables. Page-level enrichments (capability counts, the functions behind
an import or a string) are one query per page, keyed by the page's rows.
"""

import uuid
from collections import defaultdict
from collections.abc import Iterable, Sequence
from decimal import Decimal
from typing import Any

from sqlalchemy import ColumnElement, and_, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFound
from app.core.pagination import PageParams
from app.modules.analysis.models import AnalysisJob, AnalysisStatus, Analyzer
from app.modules.investigations.repository import escape_like
from app.modules.pcap_analysis.models import AnalysisFinding, Ioc
from app.modules.pcap_analysis.repository import _contains, _page
from app.modules.reverse_engineering.models import (
    ReCallEdge,
    ReDecompilation,
    ReFunction,
    ReFunctionCapability,
    ReImport,
    ReImportRef,
    ReProgram,
    ReString,
    ReStringRef,
)
from app.modules.static_analysis.models import MalwareCapability
from app.modules.static_analysis.report import NOTABLE_FUNCTIONS

# Rows of one kind attached to a function detail (plan: <= 200 each).
DETAIL_CAP = 200
# Functions listed under one import / string of a page.
REF_FUNCTIONS_CAP = 20
# Functions listed per RE job on the capability-functions route.
CAPABILITY_FUNCTIONS_CAP = 50
CODE_STATUSES = ("ok", "truncated")
# The import names the `calls_suspicious_import` filter means (the static report's notable
# APIs, A / W variants included; listed, never scored).
SUSPICIOUS_IMPORTS = tuple(sorted(NOTABLE_FUNCTIONS))
# IOC kinds a referenced string can carry (the RE extractor's: URLs, domains, IPs, emails).
STRING_IOC_TYPES = ("url", "domain", "ip", "email")

FUNCTION_ORDER = (ReFunction.priority_rank.asc().nulls_last(), ReFunction.entry, ReFunction.id)


async def ensure_re_job(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID
) -> AnalysisJob:
    """404 unless the job belongs to the org AND is a reverse-engineering job."""
    job = await session.scalar(
        select(AnalysisJob).where(AnalysisJob.id == job_id, AnalysisJob.organization_id == org_id)
    )
    if job is None or job.analyzer != Analyzer.REVERSE:
        raise NotFound()
    return job


def _scope(model: Any, org_id: uuid.UUID, job_id: uuid.UUID) -> list[ColumnElement[bool]]:
    return [model.organization_id == org_id, model.job_id == job_id]


async def program(session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID) -> ReProgram | None:
    row: ReProgram | None = await session.scalar(
        select(ReProgram).where(ReProgram.organization_id == org_id, ReProgram.job_id == job_id)
    )
    return row


async def newer_job(session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob) -> uuid.UUID | None:
    """The newest later RE job of the same evidence that did not fail (RT10: the old job page
    links to it after "Decompile this function")."""
    j = AnalysisJob
    found: uuid.UUID | None = await session.scalar(
        select(j.id)
        .where(
            j.organization_id == org_id,
            j.evidence_id == job.evidence_id,
            j.analyzer == Analyzer.REVERSE,
            j.status != AnalysisStatus.FAILED,
            j.created_at > job.created_at,
        )
        .order_by(j.created_at.desc(), j.id.desc())
        .limit(1)
    )
    return found


# --- functions ---------------------------------------------------------------------------------


def _has_capability(org_id: uuid.UUID) -> ColumnElement[bool]:
    link = ReFunctionCapability
    return exists().where(
        link.organization_id == org_id,
        link.job_id == ReFunction.job_id,
        link.function_entry == ReFunction.entry,
    )


def _calls_suspicious_import(org_id: uuid.UUID) -> ColumnElement[bool]:
    ref, imp = ReImportRef, ReImport
    return exists().where(
        ref.organization_id == org_id,
        ref.job_id == ReFunction.job_id,
        ref.function_entry == ReFunction.entry,
        imp.id == ref.import_id,
        imp.organization_id == org_id,
        imp.name.in_(SUSPICIOUS_IMPORTS),
    )


def _references_ioc_string(org_id: uuid.UUID) -> ColumnElement[bool]:
    """A referenced string that contains one of the job's network IOC values (the RE IOC
    extractor reads them from code-referenced strings)."""
    ref, s, ioc = ReStringRef, ReString, Ioc
    return exists().where(
        ref.organization_id == org_id,
        ref.job_id == ReFunction.job_id,
        ref.function_entry == ReFunction.entry,
        s.id == ref.string_id,
        s.organization_id == org_id,
        ioc.organization_id == org_id,
        ioc.job_id == ReFunction.job_id,
        ioc.type.in_(STRING_IOC_TYPES),
        func.strpos(s.value, ioc.value) > 0,
    )


async def functions(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    q: str | None = None,
    decompiled: bool | None = None,
    has_capability: bool | None = None,
    calls_suspicious_import: bool | None = None,
    references_ioc_string: bool | None = None,
    include_library: bool = False,
    ref: uuid.UUID | None = None,
) -> tuple[Sequence[ReFunction], int]:
    """By priority rank (unranked last), then entry. `q`: a name substring."""
    m = ReFunction
    where = _scope(m, org_id, job_id)
    if q:
        where.append(_contains(m.name, q))
    if decompiled is not None:
        in_code = m.decompile_status.in_(CODE_STATUSES)
        where.append(in_code if decompiled else ~in_code)
    for flag, condition in (
        (has_capability, _has_capability(org_id)),
        (calls_suspicious_import, _calls_suspicious_import(org_id)),
        (references_ioc_string, _references_ioc_string(org_id)),
    ):
        if flag is not None:
            where.append(condition if flag else ~condition)
    if not include_library and ref is None:
        where.append(m.is_library.is_(False))
    return await _page(session, m, where, FUNCTION_ORDER, page, ref=ref)


async def function(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, entry: int
) -> ReFunction | None:
    row: ReFunction | None = await session.scalar(
        select(ReFunction).where(*_scope(ReFunction, org_id, job_id), ReFunction.entry == entry)
    )
    return row


async def capability_counts(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, entries: Iterable[Decimal]
) -> dict[int, int]:
    """Linked capabilities per function entry, for the entries of one page."""
    link = ReFunctionCapability
    wanted = list(entries)
    if not wanted:
        return {}
    rows = await session.execute(
        select(link.function_entry, func.count(link.capability_id.distinct()))
        .where(*_scope(link, org_id, job_id), link.function_entry.in_(wanted))
        .group_by(link.function_entry)
    )
    return {int(entry): int(n) for entry, n in rows}


async def entries_with(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    entries: Iterable[Decimal],
    condition: ColumnElement[bool],
) -> set[int]:
    """The page's entries for which a function-level condition holds (priority reasons)."""
    wanted = list(entries)
    if not wanted:
        return set()
    rows = await session.scalars(
        select(ReFunction.entry).where(
            *_scope(ReFunction, org_id, job_id), ReFunction.entry.in_(wanted), condition
        )
    )
    return {int(e) for e in rows}


async def callers(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, entry: int
) -> Sequence[Any]:
    """(entry, name) of at most DETAIL_CAP callers, by entry (the total is the function's
    `callers` count)."""
    e, f = ReCallEdge, ReFunction
    rows = await session.execute(
        select(f.entry, f.name)
        .join(e, and_(e.caller_entry == f.entry, e.job_id == f.job_id))
        .where(*_scope(e, org_id, job_id), *_scope(f, org_id, job_id), e.callee_entry == entry)
        .order_by(f.entry)
        .limit(DETAIL_CAP)
    )
    return rows.all()


async def callees(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, entry: int
) -> Sequence[Any]:
    e, f = ReCallEdge, ReFunction
    rows = await session.execute(
        select(f.entry, f.name)
        .join(e, and_(e.callee_entry == f.entry, e.job_id == f.job_id))
        .where(*_scope(e, org_id, job_id), *_scope(f, org_id, job_id), e.caller_entry == entry)
        .order_by(f.entry)
        .limit(DETAIL_CAP)
    )
    return rows.all()


async def imports_called(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, entry: int
) -> Sequence[ReImport]:
    imp, ref = ReImport, ReImportRef
    rows = await session.scalars(
        select(imp)
        .join(ref, ref.import_id == imp.id)
        .where(*_scope(ref, org_id, job_id), *_scope(imp, org_id, job_id))
        .where(ref.function_entry == entry)
        .order_by(imp.library, imp.name, imp.id)
        .limit(DETAIL_CAP)
    )
    return rows.all()


async def strings_referenced(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, entry: int
) -> Sequence[ReString]:
    s, ref = ReString, ReStringRef
    rows = await session.scalars(
        select(s)
        .join(ref, ref.string_id == s.id)
        .where(*_scope(ref, org_id, job_id), *_scope(s, org_id, job_id))
        .where(ref.function_entry == entry)
        .order_by(s.address, s.id)
        .limit(DETAIL_CAP)
    )
    return rows.all()


async def linked_capabilities(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, entry: int
) -> Sequence[Any]:
    """(link, capability) rows of the function, by capability name."""
    link, cap = ReFunctionCapability, MalwareCapability
    rows = await session.execute(
        select(link, cap)
        .join(cap, and_(cap.id == link.capability_id, cap.organization_id == link.organization_id))
        .where(*_scope(link, org_id, job_id), link.function_entry == entry)
        .order_by(cap.name, cap.id)
        .limit(DETAIL_CAP)
    )
    return rows.all()


async def finding_ids(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, entry: int
) -> list[uuid.UUID]:
    """Findings that cite the function (`attributes.function_entry`, `0x…` lowercase)."""
    f = AnalysisFinding
    rows = await session.scalars(
        select(f.id)
        .where(*_scope(f, org_id, job_id), f.attributes["function_entry"].astext == f"0x{entry:x}")
        .order_by(f.id)
        .limit(DETAIL_CAP)
    )
    return list(rows)


async def decompilation(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, entry: int
) -> ReDecompilation | None:
    row: ReDecompilation | None = await session.scalar(
        select(ReDecompilation).where(
            *_scope(ReDecompilation, org_id, job_id), ReDecompilation.function_entry == entry
        )
    )
    return row


# --- imports and strings -----------------------------------------------------------------------


async def imports(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    q: str | None = None,
    library: str | None = None,
    ref: uuid.UUID | None = None,
) -> tuple[Sequence[ReImport], int]:
    """`library`: case-insensitive exact name; `q`: substring of the name or the library."""
    m = ReImport
    where = _scope(m, org_id, job_id)
    if library:
        where.append(m.library.ilike(escape_like(library), escape="\\"))
    if q:
        where.append(or_(_contains(m.name, q), _contains(m.library, q)))
    return await _page(session, m, where, (m.library, m.name, m.id), page, ref=ref)


async def strings(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    q: str | None = None,
    referenced: bool | None = None,
    ref: uuid.UUID | None = None,
) -> tuple[Sequence[ReString], int]:
    m = ReString
    where = _scope(m, org_id, job_id)
    if q:
        where.append(_contains(m.value, q))
    if referenced is not None:
        refs = exists().where(
            ReStringRef.organization_id == org_id,
            ReStringRef.job_id == job_id,
            ReStringRef.string_id == m.id,
        )
        where.append(refs if referenced else ~refs)
    return await _page(session, m, where, (m.address, m.id), page, ref=ref)


async def _functions_of(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    ref_model: Any,
    key: Any,
    ids: list[uuid.UUID],
) -> tuple[dict[uuid.UUID, int], dict[uuid.UUID, list[tuple[Decimal, str]]]]:
    """Per row id of the page: how many functions reference it and the first
    REF_FUNCTIONS_CAP of them (entry, name), by entry."""
    if not ids:
        return {}, {}
    counted = await session.execute(
        select(key, func.count())
        .where(*_scope(ref_model, org_id, job_id), key.in_(ids))
        .group_by(key)
    )
    totals = {row_id: int(n) for row_id, n in counted}
    rank = func.row_number().over(partition_by=key, order_by=ref_model.function_entry)
    ranked = (
        select(key.label("row_id"), ref_model.function_entry.label("entry"), rank.label("n"))
        .where(*_scope(ref_model, org_id, job_id), key.in_(ids))
        .subquery()
    )
    f = ReFunction
    rows = await session.execute(
        select(ranked.c.row_id, f.entry, f.name)
        .join(f, f.entry == ranked.c.entry)
        .where(*_scope(f, org_id, job_id), ranked.c.n <= REF_FUNCTIONS_CAP)
        .order_by(ranked.c.row_id, f.entry)
    )
    listed: dict[uuid.UUID, list[tuple[Decimal, str]]] = defaultdict(list)
    for row_id, entry, name in rows:
        listed[row_id].append((entry, name))
    return totals, listed


async def import_functions(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, ids: list[uuid.UUID]
) -> tuple[dict[uuid.UUID, int], dict[uuid.UUID, list[tuple[Decimal, str]]]]:
    return await _functions_of(session, org_id, job_id, ReImportRef, ReImportRef.import_id, ids)


async def string_functions(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, ids: list[uuid.UUID]
) -> tuple[dict[uuid.UUID, int], dict[uuid.UUID, list[tuple[Decimal, str]]]]:
    return await _functions_of(session, org_id, job_id, ReStringRef, ReStringRef.string_id, ids)


# --- the static side (capability -> functions) ----------------------------------------------


async def newest_linked_job(
    session: AsyncSession, org_id: uuid.UUID, static_job_id: uuid.UUID
) -> uuid.UUID | None:
    """The newest succeeded RE job pinned to this static job (the links belong to it)."""
    j = AnalysisJob
    found: uuid.UUID | None = await session.scalar(
        select(j.id)
        .where(
            j.organization_id == org_id,
            j.analyzer == Analyzer.REVERSE,
            j.source_job_id == static_job_id,
            j.status == AnalysisStatus.SUCCEEDED,
        )
        .order_by(j.created_at.desc(), j.id.desc())
        .limit(1)
    )
    return found


async def capability_function_counts(
    session: AsyncSession, org_id: uuid.UUID, re_job_id: uuid.UUID, capability_ids: list[uuid.UUID]
) -> dict[uuid.UUID, int]:
    link = ReFunctionCapability
    if not capability_ids:
        return {}
    rows = await session.execute(
        select(link.capability_id, func.count(link.function_entry.distinct()))
        .where(*_scope(link, org_id, re_job_id), link.capability_id.in_(capability_ids))
        .group_by(link.capability_id)
    )
    return {cap_id: int(n) for cap_id, n in rows}


async def capability_functions(
    session: AsyncSession, org_id: uuid.UUID, re_job_id: uuid.UUID, capability_id: uuid.UUID
) -> Sequence[Any]:
    """(link, function) rows of one capability in one RE job, by entry (<= 50)."""
    link, f = ReFunctionCapability, ReFunction
    rows = await session.execute(
        select(link, f)
        .join(f, and_(f.entry == link.function_entry, f.job_id == link.job_id))
        .where(
            *_scope(link, org_id, re_job_id),
            *_scope(f, org_id, re_job_id),
            link.capability_id == capability_id,
        )
        .order_by(f.entry)
        .limit(CAPABILITY_FUNCTIONS_CAP)
    )
    return rows.all()
