"""Correlation reads (M7 phase 4): "also seen in", key lookup and related cases.

`investigation.read`, RLS-bound and org-scoped: correlation never crosses an org. A key
carried by more than `CORRELATION_COMMON_KEY_JOBS` jobs of the org is flagged `common` and
left out of the related-case ranking. Deterministic: counts only, no scores, no AI.

Purged jobs keep their keys (RT9): a closed case whose bytes were purged still correlates.
"""

import base64
import binascii
import json
import uuid
from typing import Any

from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.errors import NotFound, SearchQueryInvalid
from app.core.rbac import OrgContext
from app.modules.analysis.models import AnalysisJob
from app.modules.correlation import repository as repo
from app.modules.correlation.models import CorrelationJobState, CorrelationKey
from app.modules.correlation.normalize import correlation_key
from app.modules.correlation.schemas import (
    CaseRefOut,
    CollectionRefOut,
    CorrelationKind,
    CorrelationLookupOut,
    JobCorrelationsOut,
    OccurrenceOut,
    RelatedCaseOut,
    RelatedCasesOut,
    SeenInOut,
    SharedKeyOut,
)
from app.modules.evidence.models import Evidence
from app.modules.investigations.models import Investigation
from app.modules.investigations.schemas import case_ref
from app.modules.notes.paging import InvalidCursor

# Response bounds (the frozen schemas document them).
JOB_ITEMS = 200
TOP_CASES = 5
LOOKUP_ITEMS = 100
LOOKUP_COLLECTIONS = 20
RELATED_ITEMS = 20
RELATED_SAMPLE_KEYS = 5
# The pivot's deepest page (a job holds at most CORRELATION_MAX_KEYS_PER_JOB keys).
MAX_PIVOT_OFFSET = 200_000
# Kinds threat intel looks up (the M4 `IocType`); JA3 / JA3S / certificate hashes are not.
TI_KINDS = frozenset({"ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256"})


def _common(jobs: int) -> bool:
    return jobs > get_settings().correlation_common_key_jobs


def encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset}).encode()).decode().rstrip("=")


def decode_cursor(token: str) -> int:
    """The pivot page offset (`400 invalid_cursor` otherwise)."""
    try:
        offset = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))["o"]
        if not isinstance(offset, int) or isinstance(offset, bool):
            raise ValueError("cursor")
        if not 0 < offset <= MAX_PIVOT_OFFSET:
            raise ValueError("cursor")
        return offset
    except (ValueError, TypeError, KeyError, binascii.Error):
        raise InvalidCursor() from None


async def job_correlations(
    ctx: OrgContext,
    job_id: uuid.UUID,
    *,
    kind: CorrelationKind | None = None,
    cursor: str | None = None,
    include_unique: bool = False,
) -> JobCorrelationsOut:
    offset = decode_cursor(cursor) if cursor is not None else 0
    session, org_id = ctx.session, ctx.org_id
    row = (
        await session.execute(
            select(AnalysisJob.id, Evidence.investigation_id)
            .join(
                Evidence,
                (Evidence.id == AnalysisJob.evidence_id)
                & (Evidence.organization_id == AnalysisJob.organization_id),
            )
            .where(AnalysisJob.id == job_id, AnalysisJob.organization_id == org_id)
        )
    ).one_or_none()
    if row is None:
        raise NotFound()
    inv_id = row[1]
    state = await session.get(CorrelationJobState, job_id)
    total = (
        await session.execute(
            select(func.count())
            .select_from(CorrelationKey)
            .where(CorrelationKey.organization_id == org_id, CorrelationKey.job_id == job_id)
        )
    ).scalar_one()
    rows = await repo.job_keys(
        session,
        org_id,
        job_id,
        inv_id,
        JOB_ITEMS + 1,
        kind=kind,
        include_unique=include_unique,
        offset=offset,
    )
    keys, more = rows[:JOB_ITEMS], len(rows) > JOB_ITEMS
    next_offset = offset + JOB_ITEMS
    cases = await repo.top_cases(
        session, org_id, inv_id, [(k["kind"], k["key"]) for k in keys], TOP_CASES
    )
    items = [
        SeenInOut(
            kind=k["kind"],
            value=k["value_norm"],
            key=k["key"],
            other_jobs=k["other_jobs"],
            other_cases=k["other_cases"],
            first_seen=k["first_seen"],
            last_seen=k["last_seen"],
            common=_common(k["jobs"]),
            top_cases=[
                CaseRefOut(
                    investigation_id=c["investigation_id"],
                    case_ref=case_ref(c["case_number"]),
                    title=c["title"],
                    jobs=c["jobs"],
                    last_seen=c["last_seen"],
                )
                for c in cases.get((k["kind"], k["key"]), [])
            ],
            source_ids=[k["ioc_id"]] if k["ioc_id"] else [],
        )
        for k in keys
    ]
    return JobCorrelationsOut(
        job_id=job_id,
        indexed=state is not None,
        truncated=bool(state and state.truncated),
        items=items,
        total_keys=total,
        next_cursor=(
            encode_cursor(next_offset) if more and next_offset <= MAX_PIVOT_OFFSET else None
        ),
    )


async def lookup(ctx: OrgContext, kind: CorrelationKind, value: str) -> CorrelationLookupOut:
    """`422 search_query_invalid` when the value does not normalize as `kind` (the error never
    echoes the value)."""
    normalized = correlation_key(kind, value)
    if normalized is None or normalized[0] != kind:
        raise SearchQueryInvalid()
    _, key, value_norm = normalized
    session, org_id = ctx.session, ctx.org_id
    stats = await repo.key_stats(session, org_id, kind, key)
    rows = await repo.occurrences(session, org_id, kind, key, LOOKUP_ITEMS)
    ti_results = (
        await repo.ti_result_count(session, org_id, kind, key) if kind in TI_KINDS else None
    )
    holders, holders_total = await repo.collections(session, org_id, kind, key, LOOKUP_COLLECTIONS)
    return CorrelationLookupOut(
        kind=kind,
        value_norm=value_norm,
        key=key,
        common=_common(stats["jobs"]),
        jobs=stats["jobs"],
        cases=stats["cases"],
        first_seen=stats["first_seen"],
        last_seen=stats["last_seen"],
        items=[
            OccurrenceOut(
                job_id=r["job_id"],
                analyzer=r["analyzer"],
                investigation_id=r["investigation_id"],
                case_ref=case_ref(r["case_number"]),
                title=r["title"],
                evidence_id=r["evidence_id"],
                evidence_filename=r["original_filename"],
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
            )
            for r in rows
        ],
        ti_results=ti_results,
        collections=[
            CollectionRefOut(
                collection_id=c["id"],
                investigation_id=c["investigation_id"],
                case_ref=case_ref(c["case_number"]),
                name=c["name"],
                archived=c["archived"],
            )
            for c in holders
        ],
        collections_total=holders_total,
    )


def _samples(raw: Any) -> list[SharedKeyOut]:
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = json.loads(raw)
    return [SharedKeyOut(kind=k["kind"], value=k["value"], key=k["key"]) for k in raw]


def _kinds(raw: Any) -> dict[str, int]:
    if raw is None:
        return {}
    if isinstance(raw, str):
        raw = json.loads(raw)
    return {str(k): int(v) for k, v in raw.items()}


async def related_cases(ctx: OrgContext, investigation_id: uuid.UUID) -> RelatedCasesOut:
    session, org_id = ctx.session, ctx.org_id
    found = (
        await session.execute(
            select(Investigation.id).where(
                Investigation.id == investigation_id, Investigation.organization_id == org_id
            )
        )
    ).scalar_one_or_none()
    if found is None:
        raise NotFound()
    common = get_settings().correlation_common_key_jobs
    rows, excluded = await repo.related(
        session, org_id, investigation_id, common, RELATED_ITEMS, RELATED_SAMPLE_KEYS
    )
    return RelatedCasesOut(
        investigation_id=investigation_id,
        items=[
            RelatedCaseOut(
                investigation_id=r["investigation_id"],
                case_ref=case_ref(r["case_number"]),
                title=r["title"],
                status=r["status"],
                shared_keys=r["shared_keys"],
                kinds=_kinds(r["kinds"]),
                last_seen=r["last_seen"],
                sample_keys=_samples(r["samples"]),
            )
            for r in rows
        ],
        common_keys_excluded=excluded,
    )
