"""Read queries over one static job's results; every query is bounded to (org, job).

Pages and capped totals work exactly like the pcap result reads (pcap_analysis.repository).
"""

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import Boolean, ColumnElement, cast, func, or_, select
from sqlalchemy.dialects.postgresql import JSONPATH
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFound
from app.core.pagination import PageParams
from app.modules.analysis.models import AnalysisJob, Analyzer
from app.modules.evidence.models import EvidenceHash
from app.modules.investigations.repository import escape_like
from app.modules.pcap_analysis.repository import _contains, _page
from app.modules.static_analysis.models import (
    MalwareCapability,
    MalwareExport,
    MalwareImport,
    MalwareResource,
    MalwareSample,
    MalwareSection,
    MalwareSignatureMatch,
    MalwareString,
)
from app.modules.static_analysis.schemas import SignatureEngine, StringEncoding


async def ensure_static_job(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID
) -> AnalysisJob:
    """404 unless the job belongs to the org AND is a static analysis."""
    job = await session.scalar(
        select(AnalysisJob).where(AnalysisJob.id == job_id, AnalysisJob.organization_id == org_id)
    )
    if job is None or job.analyzer != Analyzer.STATIC:
        raise NotFound()
    return job


async def sample(
    session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob
) -> tuple[MalwareSample, dict[str, str]] | None:
    """The job's sample row and the evidence record's hashes (algorithm -> value)."""
    row = await session.scalar(
        select(MalwareSample).where(
            MalwareSample.organization_id == org_id, MalwareSample.job_id == job.id
        )
    )
    if row is None:
        return None
    hashes = await session.execute(
        select(EvidenceHash.algorithm, EvidenceHash.value).where(
            EvidenceHash.organization_id == org_id, EvidenceHash.evidence_id == job.evidence_id
        )
    )
    return row, {algorithm.value: value for algorithm, value in hashes}


def _scope(model: Any, org_id: uuid.UUID, job_id: uuid.UUID) -> list[ColumnElement[bool]]:
    return [model.organization_id == org_id, model.job_id == job_id]


async def sections(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, page: PageParams
) -> tuple[Sequence[MalwareSection], int]:
    m = MalwareSection
    return await _page(session, m, _scope(m, org_id, job_id), (m.index, m.id), page)


async def imports(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    library: str | None,
    q: str | None,
) -> tuple[Sequence[MalwareImport], int]:
    m = MalwareImport
    where = _scope(m, org_id, job_id)
    if library:
        # DLL names differ in case between binaries: a case-insensitive exact match.
        where.append(m.library.ilike(escape_like(library), escape="\\"))
    if q:
        where.append(or_(_contains(m.function, q), _contains(m.library, q)))
    return await _page(session, m, where, (m.library, m.function, m.ordinal, m.id), page)


async def exports(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, page: PageParams, *, q: str | None
) -> tuple[Sequence[MalwareExport], int]:
    m = MalwareExport
    where = _scope(m, org_id, job_id)
    if q:
        where.append(_contains(m.name, q))
    return await _page(session, m, where, (m.ordinal, m.id), page)


async def resources(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, page: PageParams
) -> tuple[Sequence[MalwareResource], int]:
    m = MalwareResource
    return await _page(session, m, _scope(m, org_id, job_id), (m.type, m.name, m.id), page)


async def strings(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    encoding: StringEncoding | None,
    q: str | None,
) -> tuple[Sequence[MalwareString], int]:
    m = MalwareString
    where = _scope(m, org_id, job_id)
    if encoding is not None:
        where.append(m.encoding == encoding.value)
    if q:
        where.append(_contains(m.value, q))
    return await _page(session, m, where, (m.offset, m.id), page)


async def signatures(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    engine: SignatureEngine | None,
) -> tuple[Sequence[MalwareSignatureMatch], int]:
    m = MalwareSignatureMatch
    where = _scope(m, org_id, job_id)
    if engine is not None:
        where.append(m.engine == engine.value)
    return await _page(session, m, where, (m.engine, m.name, m.id), page)


def namespace_filter(column: Any, namespace: str) -> ColumnElement[bool]:
    """The namespace itself or anything below it (`host-interaction` matches
    `host-interaction/process/inject`)."""
    prefix = f"{escape_like(namespace)}/%"
    return or_(column == namespace, column.like(prefix, escape="\\"))


def attack_filter(column: Any, attack_id: str) -> ColumnElement[bool]:
    """A technique (`T1055`) also matches its sub-techniques (`T1055.012`): ids are exactly
    `T` + 4 digits (+ `.` + 3 digits), so a prefix cannot match another technique."""
    path = cast("$[*] ? (@ starts with $id)", JSONPATH)
    variables = func.jsonb_build_object("id", attack_id)
    return func.jsonb_path_exists(column, path, variables, type_=Boolean)


async def capabilities(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    page: PageParams,
    *,
    namespace: str | None,
    attack: str | None,
) -> tuple[Sequence[MalwareCapability], int]:
    m = MalwareCapability
    where = _scope(m, org_id, job_id)
    if namespace:
        where.append(namespace_filter(m.namespace, namespace))
    if attack:
        where.append(attack_filter(m.attack, attack))
    return await _page(session, m, where, (m.namespace, m.name, m.id), page)
