"""Deterministic selectors, one per kind (M5 phase 4).

Every query runs in the caller's tenant session with explicit `organization_id` filters, is
bounded by a cap, and orders by the repository sort keys plus `id`, so the same DB state
always yields the same rows in the same order. Each selector returns a `Selection`
(candidates in priority order + the total rows of that kind in scope).

Default caps (plan): F 40, A 30 (grouped by sid, with counts), I 50, T latest per provider
for the chosen I only, S 50, C 60, E 100, N named by the chosen F refs + top 10 by bytes,
R records on those flows (+ top domains / hosts / SNI aggregated on the job item),
X ≤ 30 FLOSS-decoded strings, P / M / J / K summaries.
"""

import re
import uuid
from collections import OrderedDict
from collections.abc import Iterable, Sequence
from typing import Any

from sqlalchemy import Text, case, cast, func, or_, select, tuple_
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.ai.context import fields as F
from app.modules.ai.context.assemble import Selection
from app.modules.ai.context.fields import HostList, RawItem
from app.modules.ai.contracts import RefKind
from app.modules.analysis.models import AnalysisJob, AnalysisStatus
from app.modules.evidence.models import (
    CustodyAction,
    Evidence,
    EvidenceCustodyEvent,
    EvidenceHash,
    HashAlgorithm,
)
from app.modules.investigations import timeline as case_timeline
from app.modules.investigations.models import Investigation
from app.modules.investigations.schemas import case_ref
from app.modules.pcap_analysis.models import (
    AnalysisFinding,
    Ioc,
    NetworkAlert,
    NetworkFlow,
    NetworkRecord,
    TimelineEntry,
)
from app.modules.static_analysis.models import (
    MalwareCapability,
    MalwareSample,
    MalwareSignatureMatch,
    MalwareString,
)
from app.modules.threat_intel.models import TiResult
from app.modules.threat_intel.normalize import Normalized, normalize
from app.modules.threat_intel.providers.base import compute_ioc_key

CAP_FINDINGS = 40
CAP_ALERT_GROUPS = 30
CAP_IOCS = 50
CAP_SIGNATURES = 50
CAP_CAPABILITIES = 60
CAP_TIMELINE = 100
CAP_TOP_FLOWS = 10
CAP_NAMED_FLOWS = 40
CAP_RECORDS = 50
CAP_STRINGS = 30
CAP_EVIDENCE = 50
CAP_RELATED = 20
CAP_AGGREGATE = 10
# How many candidate rows a "mentions"/"related" filter scans (bounded work per request).
SCAN_LIMIT = 500

FLOSS_ENCODINGS = ("floss_decoded", "floss_stack", "floss_tight")
HOST_IOC_TYPES = frozenset({"domain"})

_SEVERITY_RANK = case(
    {"high": 4, "medium": 3, "low": 2, "info": 1}, value=AnalysisFinding.severity, else_=0
)

Jobs = Sequence[uuid.UUID]


def _job_scope(model: Any, org_id: uuid.UUID, job_ids: Jobs) -> list[Any]:
    return [model.organization_id == org_id, model.job_id.in_(list(job_ids))]


async def _count(session: AsyncSession, model: Any, where: Iterable[Any]) -> int:
    return int(await session.scalar(select(func.count()).select_from(model).where(*where)) or 0)


# --- job / sample ------------------------------------------------------------------------


async def get_job(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID
) -> AnalysisJob | None:
    return await session.scalar(
        select(AnalysisJob).where(AnalysisJob.id == job_id, AnalysisJob.organization_id == org_id)
    )


async def record_aggregates(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID
) -> dict[str, HostList]:
    """Top DNS names, HTTP hosts and TLS SNI of a pcap job (count desc, name)."""
    r = NetworkRecord
    out: dict[str, HostList] = {}
    for name, kind, key in (
        ("top.dns", "dns", "query"),
        ("top.http_host", "http", "host"),
        ("top.sni", "tls", "server_name"),
    ):
        value = r.details[key].astext
        n = func.count()
        rows = await session.execute(
            select(value, n)
            .where(
                r.organization_id == org_id,
                r.job_id == job_id,
                r.kind == kind,
                value.is_not(None),
                value != "",
            )
            .group_by(value)
            .order_by(n.desc(), value)
            .limit(CAP_AGGREGATE)
        )
        out[name] = HostList(tuple((str(v), int(c)) for v, c in rows))
    return out


async def job_items(
    session: AsyncSession, org_id: uuid.UUID, jobs: Sequence[AnalysisJob]
) -> Selection:
    items = []
    for job in jobs:
        aggregates = (
            await record_aggregates(session, org_id, job.id) if job.analyzer == "pcap" else None
        )
        items.append(
            RawItem(
                kind=RefKind.JOB,
                ref_table="analysis_jobs",
                ref_id=str(job.id),
                job_id=job.id,
                fields=F.job_fields(job, aggregates),
            )
        )
    return Selection(RefKind.JOB, items, len(items))


async def sample_items(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID
) -> tuple[Selection, Selection]:
    """`M` (sample facts) and `P` (PE summary) of a static job."""
    row = await session.scalar(
        select(MalwareSample).where(
            MalwareSample.organization_id == org_id, MalwareSample.job_id == job_id
        )
    )
    if row is None:
        return Selection(RefKind.SAMPLE, [], 0), Selection(RefKind.PE_SUMMARY, [], 0)
    sample = RawItem(RefKind.SAMPLE, "malware_samples", str(row.id), job_id, F.sample_fields(row))
    pe: list[RawItem] = []
    if isinstance(row.pe, dict):
        pe.append(
            RawItem(RefKind.PE_SUMMARY, "malware_samples", str(row.id), job_id, F.pe_fields(row.pe))
        )
    return Selection(RefKind.SAMPLE, [sample], 1), Selection(RefKind.PE_SUMMARY, pe, len(pe))


# --- findings / alerts ---------------------------------------------------------------------


def finding_item(row: AnalysisFinding) -> RawItem:
    fields, dropped, capped = F.finding_fields(row)
    hosts, urls = F.attribute_roles(fields)
    return RawItem(
        RefKind.FINDING,
        "analysis_findings",
        str(row.id),
        row.job_id,
        fields,
        host_fields=hosts,
        url_fields=urls,
        dropped_keys=dropped,
        capped=capped,
        extra={"row": row},
    )


async def finding_rows(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_ids: Jobs,
    *,
    limit: int,
    where: Iterable[Any] = (),
) -> list[AnalysisFinding]:
    m = AnalysisFinding
    stmt = (
        select(m)
        .where(*_job_scope(m, org_id, job_ids), *where)
        .order_by(_SEVERITY_RANK.desc(), m.ts, m.id)
        .limit(limit)
    )
    return list((await session.scalars(stmt)).all())


async def findings(
    session: AsyncSession, org_id: uuid.UUID, job_ids: Jobs, *, cap: int = CAP_FINDINGS
) -> Selection:
    rows = await finding_rows(session, org_id, job_ids, limit=cap)
    total = await _count(session, AnalysisFinding, _job_scope(AnalysisFinding, org_id, job_ids))
    return Selection(RefKind.FINDING, [finding_item(r) for r in rows], total)


def alert_item(
    row: NetworkAlert, *, count: int | None = None, first: Any = None, last: Any = None
) -> RawItem:
    return RawItem(
        RefKind.ALERT,
        "network_alerts",
        str(row.id),
        row.job_id,
        F.alert_fields(row, count=count, first=first, last=last),
        extra={"row": row},
    )


async def alert_groups(
    session: AsyncSession, org_id: uuid.UUID, job_ids: Jobs, *, cap: int = CAP_ALERT_GROUPS
) -> Selection:
    """One item per (job, sid): its most severe, earliest alert, plus count / first / last.
    Groups ordered by (severity, first ts, sid)."""
    a = NetworkAlert
    scope = _job_scope(a, org_id, job_ids)
    stats = (
        select(
            a.job_id,
            a.signature_id,
            func.count().label("n"),
            func.min(a.ts).label("first"),
            func.max(a.ts).label("last"),
            func.min(a.severity).label("sev"),
        )
        .where(*scope)
        .group_by(a.job_id, a.signature_id)
        .subquery()
    )
    total = int(await session.scalar(select(func.count()).select_from(stats)) or 0)
    groups = (
        await session.execute(
            select(stats)
            .order_by(stats.c.sev, stats.c.first, stats.c.signature_id, stats.c.job_id)
            .limit(cap)
        )
    ).all()
    if not groups:
        return Selection(RefKind.ALERT, [], total)
    keys = [(g.job_id, g.signature_id) for g in groups]
    reps = (
        await session.scalars(
            select(a)
            .where(*scope, tuple_(a.job_id, a.signature_id).in_(keys))
            .ext(distinct_on(a.job_id, a.signature_id))
            .order_by(a.job_id, a.signature_id, a.severity, a.ts, a.id)
        )
    ).all()
    by_key = {(r.job_id, r.signature_id): r for r in reps}
    items = [
        alert_item(by_key[(g.job_id, g.signature_id)], count=g.n, first=g.first, last=g.last)
        for g in groups
        if (g.job_id, g.signature_id) in by_key
    ]
    return Selection(RefKind.ALERT, items, total)


async def alert_rows(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_ids: Jobs,
    *,
    limit: int,
    where: Iterable[Any] = (),
) -> list[NetworkAlert]:
    a = NetworkAlert
    stmt = (
        select(a)
        .where(*_job_scope(a, org_id, job_ids), *where)
        .order_by(a.severity, a.ts, a.id)
        .limit(limit)
    )
    return list((await session.scalars(stmt)).all())


def _pair(model: Any, src: object, dst: object) -> Any:
    """Either direction of an endpoint pair."""
    return or_(
        (model.src_ip == src) & (model.dst_ip == dst), (model.src_ip == dst) & (model.dst_ip == src)
    )


def _related(model: Any, flow_refs: Sequence[str], src: object, dst: object) -> list[Any]:
    clauses = []
    if flow_refs:
        clauses.append(model.flow_ref.in_(list(flow_refs)))
    if src is not None and dst is not None:
        clauses.append(_pair(model, src, dst))
    return [or_(*clauses)] if clauses else []


async def related_alerts(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    *,
    flow_refs: Sequence[str],
    src: object,
    dst: object,
    exclude: uuid.UUID | None = None,
) -> Selection:
    where = _related(NetworkAlert, flow_refs, src, dst)
    if not where:
        return Selection(RefKind.ALERT, [], 0)
    if exclude is not None:
        where.append(NetworkAlert.id != exclude)
    rows = await alert_rows(session, org_id, [job_id], limit=CAP_RELATED, where=where)
    total = await _count(
        session, NetworkAlert, [*_job_scope(NetworkAlert, org_id, [job_id]), *where]
    )
    return Selection(RefKind.ALERT, [alert_item(r) for r in rows], total)


async def related_findings(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    *,
    flow_ref: str | None,
    src: object,
    dst: object,
) -> Selection:
    m = AnalysisFinding
    clauses = []
    if flow_ref:
        clauses.append(m.evidence_refs.contains([flow_ref]))
        clauses.append(m.flow_ref == flow_ref)
    if src is not None and dst is not None:
        clauses.append(_pair(m, src, dst))
    if not clauses:
        return Selection(RefKind.FINDING, [], 0)
    where = [or_(*clauses)]
    rows = await finding_rows(session, org_id, [job_id], limit=CAP_RELATED, where=where)
    total = await _count(session, m, [*_job_scope(m, org_id, [job_id]), *where])
    return Selection(RefKind.FINDING, [finding_item(r) for r in rows], total)


# --- flows / records -----------------------------------------------------------------------


def flow_item(row: NetworkFlow) -> RawItem:
    # N refs are (job_id, flow_ref), never the uid alone (RT16).
    return RawItem(
        RefKind.FLOW,
        "network_flows",
        str(row.flow_ref),
        row.job_id,
        F.flow_fields(row),
        extra={"row": row},
    )


async def flows(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    *,
    named: Sequence[str] = (),
    top: int = CAP_TOP_FLOWS,
    pair: tuple[object, object] | None = None,
) -> Selection:
    """Flows named by the chosen findings / alerts (in that order), then the endpoint pair's
    flows, then the top `top` by bytes; deduplicated by flow_ref (flows without one are
    never selected: they cannot be cited)."""
    m = NetworkFlow
    scope = [*_job_scope(m, org_id, [job_id]), m.flow_ref.is_not(None)]
    chosen: OrderedDict[str, NetworkFlow] = OrderedDict()
    wanted = list(dict.fromkeys(r for r in named if r))[:CAP_NAMED_FLOWS]
    if wanted:
        rows = (
            await session.scalars(
                select(m).where(*scope, m.flow_ref.in_(wanted)).order_by(m.flow_ref, m.ts, m.id)
            )
        ).all()
        first: dict[str, NetworkFlow] = {}
        for row in rows:
            first.setdefault(str(row.flow_ref), row)
        for ref in wanted:
            if ref in first:
                chosen[ref] = first[ref]
    extra = []
    if pair is not None and pair[0] is not None and pair[1] is not None:
        extra.append(_pair(m, *pair))
    if extra:
        rows = (
            await session.scalars(
                select(m)
                .where(*scope, *extra)
                .order_by(m.total_bytes.desc(), m.ts, m.id)
                .limit(top)
            )
        ).all()
        for row in rows:
            chosen.setdefault(str(row.flow_ref), row)
    if top:
        rows = (
            await session.scalars(
                select(m).where(*scope).order_by(m.total_bytes.desc(), m.ts, m.id).limit(top)
            )
        ).all()
        for row in rows:
            chosen.setdefault(str(row.flow_ref), row)
    total = await _count(session, m, scope)
    return Selection(RefKind.FLOW, [flow_item(r) for r in chosen.values()], total)


def record_item(row: NetworkRecord) -> RawItem:
    return RawItem(
        RefKind.RECORD,
        "network_records",
        str(row.id),
        row.job_id,
        F.record_fields(row),
        host_fields=F.HOST_FIELDS[RefKind.RECORD],
    )


async def records_on_flows(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    flow_refs: Sequence[str],
    *,
    cap: int = CAP_RECORDS,
) -> Selection:
    m = NetworkRecord
    scope = _job_scope(m, org_id, [job_id])
    total = await _count(session, m, scope)
    refs = [r for r in flow_refs if r]
    if not refs:
        return Selection(RefKind.RECORD, [], total)
    rows = (
        await session.scalars(
            select(m).where(*scope, m.flow_ref.in_(refs)).order_by(m.ts, m.id).limit(cap)
        )
    ).all()
    return Selection(RefKind.RECORD, [record_item(r) for r in rows], total)


# --- IOCs / TI -----------------------------------------------------------------------------


def ioc_item(row: Ioc) -> RawItem:
    return RawItem(
        RefKind.IOC,
        "iocs",
        str(row.id),
        row.job_id,
        F.ioc_fields(row),
        host_fields=frozenset({"value"}) if row.type in HOST_IOC_TYPES else frozenset(),
        extra={"row": row},
    )


async def ioc_rows(
    session: AsyncSession, org_id: uuid.UUID, job_ids: Jobs, *, limit: int
) -> list[Ioc]:
    m = Ioc
    stmt = (
        select(m)
        .where(*_job_scope(m, org_id, job_ids))
        .order_by(m.count.desc(), m.first_seen, m.id)
        .limit(limit)
    )
    return list((await session.scalars(stmt)).all())


async def iocs(
    session: AsyncSession, org_id: uuid.UUID, job_ids: Jobs, *, cap: int = CAP_IOCS
) -> Selection:
    rows = await ioc_rows(session, org_id, job_ids, limit=cap)
    total = await _count(session, Ioc, _job_scope(Ioc, org_id, job_ids))
    return Selection(RefKind.IOC, [ioc_item(r) for r in rows], total)


def mentions(value: str, haystack: str) -> bool:
    pattern = rf"(?<![\w.]){re.escape(value.lower())}(?![\w])"
    return re.search(pattern, haystack) is not None


async def iocs_mentioned(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_ids: Jobs,
    haystack: str,
    *,
    cap: int = CAP_RELATED,
) -> Selection:
    """IOCs of the job whose value appears in the given text (target row + its records)."""
    text = haystack.lower()
    rows = [
        r
        for r in await ioc_rows(session, org_id, job_ids, limit=SCAN_LIMIT)
        if mentions(r.value, text)
    ]
    return Selection(RefKind.IOC, [ioc_item(r) for r in rows[:cap]], len(rows))


def _ioc_key(row: Ioc) -> str | None:
    outcome = normalize(row.type, row.value)
    if isinstance(outcome, Normalized):
        return outcome.ioc_key
    if outcome.ioc_type is not None and outcome.value_norm is not None:
        return compute_ioc_key(outcome.ioc_type, outcome.value_norm)
    return None


async def ti_results(
    session: AsyncSession, org_id: uuid.UUID, ioc_rows_: Sequence[Ioc], ioc_labels: Sequence[str]
) -> Selection:
    """The latest TI answer per provider for each chosen IOC (answers before errors, newest
    first), in IOC order then provider. `ioc_labels[i]` is the `I` label of `ioc_rows_[i]`."""
    keyed = [(row, label, _ioc_key(row)) for row, label in zip(ioc_rows_, ioc_labels, strict=True)]
    keys = sorted({k for _, _, k in keyed if k})
    if not keys:
        return Selection(RefKind.TI_RESULT, [], 0)
    t = TiResult
    answered = case((t.status.in_(("ok", "not_found")), 0), else_=1)
    rows = (
        await session.scalars(
            select(t)
            .where(t.organization_id == org_id, t.ioc_key.in_(keys))
            .ext(distinct_on(t.ioc_key, t.provider))
            .order_by(t.ioc_key, t.provider, answered, t.fetched_at.desc(), t.id)
        )
    ).all()
    by_key: dict[str, list[TiResult]] = {}
    for row in rows:
        by_key.setdefault(row.ioc_key, []).append(row)
    items = []
    for ioc, label, key in keyed:
        for result in by_key.get(key or "", []):
            items.append(
                RawItem(
                    RefKind.TI_RESULT,
                    "ti_results",
                    str(result.id),
                    ioc.job_id,
                    F.ti_fields(result, label),
                )
            )
    return Selection(RefKind.TI_RESULT, items, len(items))


# --- static --------------------------------------------------------------------------------


async def signatures(
    session: AsyncSession, org_id: uuid.UUID, job_ids: Jobs, *, cap: int = CAP_SIGNATURES
) -> Selection:
    m = MalwareSignatureMatch
    scope = _job_scope(m, org_id, job_ids)
    rows = (
        await session.scalars(select(m).where(*scope).order_by(m.engine, m.name, m.id).limit(cap))
    ).all()
    items = [
        RawItem(
            RefKind.SIGNATURE,
            "malware_signature_matches",
            str(r.id),
            r.job_id,
            F.signature_fields(r),
        )
        for r in rows
    ]
    return Selection(RefKind.SIGNATURE, items, await _count(session, m, scope))


async def capabilities(
    session: AsyncSession, org_id: uuid.UUID, job_ids: Jobs, *, cap: int = CAP_CAPABILITIES
) -> Selection:
    m = MalwareCapability
    scope = _job_scope(m, org_id, job_ids)
    rows = (
        await session.scalars(
            select(m).where(*scope).order_by(m.namespace, m.name, m.id).limit(cap)
        )
    ).all()
    items = [
        RawItem(
            RefKind.CAPABILITY, "malware_capabilities", str(r.id), r.job_id, F.capability_fields(r)
        )
        for r in rows
    ]
    return Selection(RefKind.CAPABILITY, items, await _count(session, m, scope))


async def floss_strings(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, *, cap: int = CAP_STRINGS
) -> Selection:
    m = MalwareString
    scope = [*_job_scope(m, org_id, [job_id]), m.encoding.in_(FLOSS_ENCODINGS)]
    rows = (
        await session.scalars(
            select(m).where(*scope).order_by(m.offset.nulls_last(), m.id).limit(cap)
        )
    ).all()
    items = [
        RawItem(RefKind.STRING, "malware_strings", str(r.id), job_id, F.string_fields(r))
        for r in rows
    ]
    return Selection(RefKind.STRING, items, await _count(session, m, scope))


# --- timelines -----------------------------------------------------------------------------


async def job_timeline(
    session: AsyncSession, org_id: uuid.UUID, job_id: uuid.UUID, *, cap: int = CAP_TIMELINE
) -> Selection:
    m = TimelineEntry
    scope = _job_scope(m, org_id, [job_id])
    rows = (await session.scalars(select(m).where(*scope).order_by(m.ts, m.id).limit(cap))).all()
    items = [
        RawItem(RefKind.TIMELINE, "analysis_timeline", str(r.id), job_id, F.job_timeline_fields(r))
        for r in rows
    ]
    return Selection(RefKind.TIMELINE, items, await _count(session, m, scope))


async def case_timeline_items(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    *,
    cap: int = CAP_TIMELINE,
    exclude_evidence: frozenset[uuid.UUID] = frozenset(),
) -> Selection:
    """M6: only the M5 evidence-derived kinds (`EVIDENCE_KINDS`): analyst notes and status
    reasons never enter AI context. `exclude_evidence` (the share policy's AI-excluded
    evidence) drops their entries from the page; `total` then counts the remaining entries
    of the page as at least."""
    kinds = case_timeline.EVIDENCE_KINDS
    entries = await case_timeline.page(session, org_id, investigation_id, limit=cap, kinds=kinds)
    total = await case_timeline.count(session, org_id, investigation_id, kinds=kinds)
    if exclude_evidence:
        kept = [e for e in entries if e.evidence_id not in exclude_evidence]
        total = max(total - (len(entries) - len(kept)), len(kept))
        entries = kept
    items = [
        RawItem(
            RefKind.TIMELINE,
            e.ref_table,
            str(e.ref_id),
            e.job_id,
            F.merged_timeline_fields(e),
        )
        for e in entries
    ]
    return Selection(RefKind.TIMELINE, items, total)


# --- investigation -------------------------------------------------------------------------


async def get_investigation(
    session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID
) -> Investigation | None:
    return await session.scalar(
        select(Investigation).where(
            Investigation.id == investigation_id, Investigation.organization_id == org_id
        )
    )


def investigation_item(investigation: Investigation, *, include_text: bool) -> Selection:
    item = RawItem(
        RefKind.INVESTIGATION,
        "investigations",
        str(investigation.id),
        None,
        F.investigation_fields(
            investigation, case_ref(investigation.case_number), include_text=include_text
        ),
    )
    return Selection(RefKind.INVESTIGATION, [item], 1)


async def evidence_ids(
    session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID
) -> list[uuid.UUID]:
    rows = await session.scalars(
        select(Evidence.id)
        .where(Evidence.organization_id == org_id, Evidence.investigation_id == investigation_id)
        .order_by(Evidence.uploaded_at, Evidence.id)
    )
    return list(rows)


async def evidence_items(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    *,
    cap: int = CAP_EVIDENCE,
    exclude: frozenset[uuid.UUID] = frozenset(),
) -> Selection:
    """One `K` per evidence (upload order): file facts, its sha256 and a custody summary.
    M6: evidence in `exclude` (AI-excluded by the share policy) is left out entirely."""
    e = Evidence
    scope = [e.organization_id == org_id, e.investigation_id == investigation_id]
    if exclude:
        scope.append(e.id.not_in(list(exclude)))
    rows = (
        await session.scalars(select(e).where(*scope).order_by(e.uploaded_at, e.id).limit(cap))
    ).all()
    total = await _count(session, e, scope)
    if not rows:
        return Selection(RefKind.EVIDENCE, [], total)
    ids = [r.id for r in rows]
    hashes = dict(
        (
            await session.execute(
                select(EvidenceHash.evidence_id, EvidenceHash.value).where(
                    EvidenceHash.organization_id == org_id,
                    EvidenceHash.evidence_id.in_(ids),
                    EvidenceHash.algorithm == HashAlgorithm.SHA256,
                )
            )
        ).all()
    )
    c = EvidenceCustodyEvent
    custody: dict[uuid.UUID, dict[str, int]] = {}
    for evidence_id, action, n in (
        await session.execute(
            select(c.evidence_id, cast(c.action, Text), func.count())
            .where(c.organization_id == org_id, c.evidence_id.in_(ids))
            .group_by(c.evidence_id, c.action)
        )
    ).all():
        custody.setdefault(evidence_id, {})[str(action)] = int(n)
    verified = dict(
        (
            await session.execute(
                select(c.evidence_id, func.max(c.occurred_at))
                .where(
                    c.organization_id == org_id,
                    c.evidence_id.in_(ids),
                    c.action.in_([CustodyAction.VERIFIED_OK, CustodyAction.VERIFIED_MISMATCH]),
                )
                .group_by(c.evidence_id)
            )
        ).all()
    )
    items = [
        RawItem(
            RefKind.EVIDENCE,
            "evidence",
            str(r.id),
            None,
            F.evidence_fields(r, hashes.get(r.id), custody.get(r.id, {}), verified.get(r.id)),
        )
        for r in rows
    ]
    return Selection(RefKind.EVIDENCE, items, total)


async def latest_succeeded_jobs(
    session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID
) -> list[AnalysisJob]:
    """The newest succeeded job per evidence of the investigation, newest first."""
    latest = case_timeline.latest_succeeded_jobs(org_id, investigation_id)
    rows = await session.scalars(
        select(AnalysisJob)
        .where(
            AnalysisJob.organization_id == org_id,
            AnalysisJob.id.in_(select(latest.c.id)),
            AnalysisJob.status == AnalysisStatus.SUCCEEDED,
        )
        .order_by(AnalysisJob.created_at.desc(), AnalysisJob.id.desc())
    )
    return list(rows)


async def select_function_items(
    session: AsyncSession, org_id: uuid.UUID, job: AnalysisJob, target_id: uuid.UUID
) -> list[Selection]:
    """M10 phase 9 (`explain_function`; frozen entry point, stub until then): the target
    function's facts (G), its code (Q, capped at AI_MAX_CODE_CHARS), the job (J), the capa
    capabilities linked to it (C), the findings citing it (F), the IOCs from its strings (I)
    and <= 10 callee facts (G), in that order. The plan's `(session, run, target)` is spelled
    with the builder's own arguments (org, job, target id)."""
    raise NotImplementedError("M10 phase 9")
