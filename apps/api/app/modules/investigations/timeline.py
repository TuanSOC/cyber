"""Merged investigation timeline (M5 phase 4): one ordered, cursor-paged stream over

- evidence custody events (uploads included), `ts_source: recorded`;
- analysis job events: requested (`created_at`), succeeded / failed (`finished_at`);
- the `analysis_timeline` rows of the latest succeeded pcap job per evidence, and that job's
  alerts by ts (`ts_source: capture`, the capture's own clock);
- the findings of the latest succeeded static job per evidence, at the job's finish time
  (`ts_source: analysis_time`: static findings have no event time of their own).

Sorted by (ts, kind, ref_id); the cursor is the last entry's sort key. Everything is read in
the caller's tenant session with explicit org filters (RLS stays on).
"""

import base64
import binascii
import enum
import json
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import (
    ColumnElement,
    String,
    Subquery,
    Uuid,
    case,
    cast,
    func,
    literal,
    null,
    select,
    tuple_,
    union_all,
)
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError, NotFound
from app.modules.analysis.models import AnalysisJob, AnalysisStatus, Analyzer
from app.modules.evidence.models import Evidence, EvidenceCustodyEvent
from app.modules.investigations.models import Investigation
from app.modules.pcap_analysis.models import AnalysisFinding, NetworkAlert, TimelineEntry

MAX_PAGE = 500
DEFAULT_PAGE = 100


class TsSource(enum.StrEnum):
    RECORDED = "recorded"  # platform event time (custody, job lifecycle)
    CAPTURE = "capture"  # the capture's clock (pcap timeline rows, alerts)
    ANALYSIS_TIME = "analysis_time"  # the job's finish time (static findings)


class RefKindName(enum.StrEnum):
    CUSTODY = "custody"
    JOB = "job"
    TIMELINE = "timeline"
    ALERT = "alert"
    FINDING = "finding"
    # M6 (RT10): case events without evidence (`Entry.evidence_id` is None); phase 5 adds
    # their rows to the union.
    NOTE = "note"
    STATUS = "status"


# The `kinds` filter of `page()` (accepted from phase 1, applied from phase 5): ref kinds.
TimelineKind = RefKindName

REF_TABLES = {
    RefKindName.CUSTODY: "evidence_custody_events",
    RefKindName.JOB: "analysis_jobs",
    RefKindName.TIMELINE: "analysis_timeline",
    RefKindName.ALERT: "network_alerts",
    RefKindName.FINDING: "analysis_findings",
    RefKindName.NOTE: "analyst_notes",
    RefKindName.STATUS: "investigation_status_events",
}
_ANALYZER_TITLE = {"pcap": "PCAP analysis", "static": "Static analysis"}
_CUSTODY_TITLE = {
    "uploaded": "Evidence uploaded",
    "downloaded": "Evidence downloaded",
    "verified_ok": "Integrity verified",
    "verified_mismatch": "Integrity mismatch",
    "archived": "Evidence archived",
    "analysis_requested": "Analysis requested",
    "analyzed": "Evidence analyzed",
}


class InvalidCursor(AppError):
    status_code = 400
    code = "invalid_cursor"
    message = "The cursor is not valid for this timeline"


@dataclass(frozen=True)
class Entry:
    ts: datetime
    ts_source: str
    kind: str
    title: str
    severity: str | None
    # None for case events (notes, status changes; M6 RT10).
    evidence_id: uuid.UUID | None
    job_id: uuid.UUID | None
    ref_kind: str
    ref_id: uuid.UUID

    @property
    def ref_table(self) -> str:
        return REF_TABLES[RefKindName(self.ref_kind)]


@dataclass(frozen=True)
class Cursor:
    ts: datetime
    kind: str
    ref_id: uuid.UUID

    def encode(self) -> str:
        raw = json.dumps([self.ts.isoformat(), self.kind, str(self.ref_id)]).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    @classmethod
    def decode(cls, token: str) -> "Cursor":
        try:
            raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
            ts, kind, ref_id = json.loads(raw)
            parsed = datetime.fromisoformat(ts)
            if parsed.tzinfo is None or not isinstance(kind, str) or len(kind) > 64:
                raise ValueError("cursor")
            return cls(parsed, kind, uuid.UUID(ref_id))
        except (ValueError, TypeError, binascii.Error, json.JSONDecodeError):
            raise InvalidCursor() from None


async def ensure_investigation(
    session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID
) -> Investigation:
    """404 unless the investigation belongs to the org."""
    found = await session.scalar(
        select(Investigation).where(
            Investigation.id == investigation_id, Investigation.organization_id == org_id
        )
    )
    if found is None:
        raise NotFound()
    return found


def latest_succeeded_jobs(
    org_id: uuid.UUID, investigation_id: uuid.UUID, analyzer: Analyzer | None = None
) -> Subquery:
    """The newest succeeded job per evidence of the investigation (optionally one analyzer):
    columns `id`, `evidence_id`, `finished_at`, `created_at`, `analyzer`."""
    j = AnalysisJob
    where: list[ColumnElement[bool]] = [
        j.organization_id == org_id,
        j.status == AnalysisStatus.SUCCEEDED,
        Evidence.investigation_id == investigation_id,
        Evidence.organization_id == org_id,
    ]
    if analyzer is not None:
        where.append(j.analyzer == analyzer)
    return (
        select(j.id, j.evidence_id, j.finished_at, j.created_at, j.analyzer)
        .join(
            Evidence,
            (Evidence.id == j.evidence_id) & (Evidence.organization_id == j.organization_id),
        )
        .where(*where)
        .ext(distinct_on(j.evidence_id))
        .order_by(j.evidence_id, j.created_at.desc(), j.id.desc())
        .subquery()
    )


def _union(org_id: uuid.UUID, investigation_id: uuid.UUID) -> Subquery:
    ev, c, j = Evidence, EvidenceCustodyEvent, AnalysisJob
    in_case = (ev.investigation_id == investigation_id) & (ev.organization_id == org_id)
    no_text = cast(null(), String)
    no_uuid = cast(null(), Uuid)
    recorded = literal(TsSource.RECORDED.value, String)

    custody = (
        select(
            c.occurred_at.label("ts"),
            recorded.label("ts_source"),
            (literal("custody_", String) + cast(c.action, String)).label("kind"),
            ev.original_filename.label("detail"),
            no_text.label("severity"),
            c.evidence_id.label("evidence_id"),
            no_uuid.label("job_id"),
            literal(RefKindName.CUSTODY.value, String).label("ref_kind"),
            c.id.label("ref_id"),
        )
        .join(ev, (ev.id == c.evidence_id) & (ev.organization_id == c.organization_id))
        .where(c.organization_id == org_id, in_case)
    )
    jobs_base = (
        select(j)
        .join(ev, (ev.id == j.evidence_id) & (ev.organization_id == j.organization_id))
        .where(j.organization_id == org_id, in_case)
        .subquery()
    )
    requested = select(
        jobs_base.c.created_at,
        recorded,
        literal("analysis_requested", String),
        cast(jobs_base.c.analyzer, String),
        no_text,
        jobs_base.c.evidence_id,
        jobs_base.c.id,
        literal(RefKindName.JOB.value, String),
        jobs_base.c.id,
    )
    finished = select(
        jobs_base.c.finished_at,
        recorded,
        literal("analysis_", String) + cast(jobs_base.c.status, String),
        cast(jobs_base.c.analyzer, String),
        no_text,
        jobs_base.c.evidence_id,
        jobs_base.c.id,
        literal(RefKindName.JOB.value, String),
        jobs_base.c.id,
    ).where(
        jobs_base.c.finished_at.is_not(None),
        cast(jobs_base.c.status, String).in_(
            [AnalysisStatus.SUCCEEDED.value, AnalysisStatus.FAILED.value]
        ),
    )
    pcap = latest_succeeded_jobs(org_id, investigation_id, Analyzer.PCAP)
    capture = literal(TsSource.CAPTURE.value, String)
    t = TimelineEntry
    timeline_rows = (
        select(
            t.ts,
            capture,
            literal("capture_event", String),
            t.title,
            t.severity,
            pcap.c.evidence_id,
            t.job_id,
            literal(RefKindName.TIMELINE.value, String),
            t.id,
        )
        .join(pcap, pcap.c.id == t.job_id)
        .where(t.organization_id == org_id)
    )
    a = NetworkAlert
    alerts = (
        select(
            a.ts,
            capture,
            literal("alert", String),
            a.signature,
            case({1: "high", 2: "medium", 3: "low"}, value=a.severity, else_="info"),
            pcap.c.evidence_id,
            a.job_id,
            literal(RefKindName.ALERT.value, String),
            a.id,
        )
        .join(pcap, pcap.c.id == a.job_id)
        .where(a.organization_id == org_id)
    )
    static = latest_succeeded_jobs(org_id, investigation_id, Analyzer.STATIC)
    f = AnalysisFinding
    findings = (
        select(
            func.coalesce(static.c.finished_at, static.c.created_at),
            literal(TsSource.ANALYSIS_TIME.value, String),
            literal("finding", String),
            f.title,
            f.severity,
            static.c.evidence_id,
            f.job_id,
            literal(RefKindName.FINDING.value, String),
            f.id,
        )
        .join(static, static.c.id == f.job_id)
        .where(f.organization_id == org_id)
    )
    return union_all(custody, requested, finished, timeline_rows, alerts, findings).subquery("u")


def _title(kind: str, detail: str | None) -> str:
    detail = detail or ""
    if kind.startswith("custody_"):
        action = kind.removeprefix("custody_")
        return f"{_CUSTODY_TITLE.get(action, action)}: {detail}" if detail else action
    if kind.startswith("analysis_"):
        name = _ANALYZER_TITLE.get(detail, detail)
        return f"{name} {kind.removeprefix('analysis_')}"
    return detail


async def page(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    *,
    limit: int = DEFAULT_PAGE,
    after: Cursor | None = None,
    kinds: Sequence[TimelineKind] | None = None,
) -> list[Entry]:
    """Up to `limit` entries after the cursor (fetch `limit + 1` to know if more exist).

    `kinds` (M6, RT10) restricts the ref kinds; accepted and ignored until phase 5."""
    del kinds  # phase 5 applies it (the signature is frozen from phase 1)
    u = _union(org_id, investigation_id)
    stmt = select(u)
    if after is not None:
        stmt = stmt.where(
            tuple_(u.c.ts, u.c.kind, u.c.ref_id) > tuple_(after.ts, after.kind, after.ref_id)
        )
    stmt = stmt.order_by(u.c.ts, u.c.kind, u.c.ref_id).limit(limit)
    rows = (await session.execute(stmt)).all()
    return [
        Entry(
            ts=r.ts,
            ts_source=r.ts_source,
            kind=r.kind,
            title=_title(r.kind, r.detail),
            severity=r.severity,
            evidence_id=r.evidence_id,
            job_id=r.job_id,
            ref_kind=r.ref_kind,
            ref_id=r.ref_id,
        )
        for r in rows
    ]


async def count(session: AsyncSession, org_id: uuid.UUID, investigation_id: uuid.UUID) -> int:
    u = _union(org_id, investigation_id)
    return int(await session.scalar(select(func.count()).select_from(u)) or 0)


def next_cursor(entries: Sequence[Entry], limit: int) -> str | None:
    if len(entries) <= limit:
        return None
    last = entries[limit - 1]
    return Cursor(last.ts, last.kind, last.ref_id).encode()
