"""Merged investigation timeline (M5 phase 4): one ordered, cursor-paged stream over

- evidence custody events (uploads included), `ts_source: recorded`;
- analysis job events: requested (`created_at`), succeeded / failed (`finished_at`);
- the `analysis_timeline` rows of the latest succeeded pcap job per evidence, and that job's
  alerts by ts (`ts_source: capture`, the capture's own clock);
- the findings of the latest succeeded static job per evidence, at the job's finish time
  (`ts_source: analysis_time`: static findings have no event time of their own);
- M6: the case's status changes (`investigation_status_events`, kind `status_changed`) and
  its notes opted into reports (`include_in_reports`, not deleted; kind `note`) at the time
  of their first version (RT32: when the note was written), with the current text cut to
  280 characters. Both are case events: `evidence_id` and `job_id` are None.

`kinds` restricts the ref kinds (all of them when None or empty).
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
from datetime import UTC, datetime
from typing import Any

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
from sqlalchemy.orm import aliased
from sqlalchemy.sql import Select

from app.core.errors import AppError, NotFound
from app.modules.analysis.models import AnalysisJob, AnalysisStatus, Analyzer
from app.modules.evidence.models import Evidence, EvidenceCustodyEvent
from app.modules.investigations.models import Investigation, InvestigationStatusEvent
from app.modules.notes.models import AnalystNote, AnalystNoteVersion
from app.modules.pcap_analysis.models import AnalysisFinding, NetworkAlert, TimelineEntry

MAX_PAGE = 500
DEFAULT_PAGE = 100
# Case event titles: a note's text and a status reason are cut to this many characters.
CASE_TEXT_MAX = 280
NOTE_KIND = "note"
STATUS_KIND = "status_changed"


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
    # M6 (RT10): case events without evidence (`Entry.evidence_id` is None).
    NOTE = "note"
    STATUS = "status"


# The `kinds` filter of `page()` (M6): ref kinds.
TimelineKind = RefKindName

# The M5 evidence-derived kinds. AI context selects only these: analyst notes and status
# reasons are case-management text and never enter a model prompt (M6).
EVIDENCE_KINDS: tuple[TimelineKind, ...] = (
    RefKindName.CUSTODY,
    RefKindName.JOB,
    RefKindName.TIMELINE,
    RefKindName.ALERT,
    RefKindName.FINDING,
)

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


def _columns(
    ts: Any,
    ts_source: Any,
    kind: Any,
    detail: Any,
    severity: Any,
    evidence_id: Any,
    job_id: Any,
    ref_kind: RefKindName,
    ref_id: Any,
) -> list[ColumnElement[Any]]:
    """One union member's columns, labelled (any member may come first once filtered)."""
    return [
        ts.label("ts"),
        ts_source.label("ts_source"),
        kind.label("kind"),
        detail.label("detail"),
        severity.label("severity"),
        evidence_id.label("evidence_id"),
        job_id.label("job_id"),
        literal(ref_kind.value, String).label("ref_kind"),
        ref_id.label("ref_id"),
    ]


def _parts(
    org_id: uuid.UUID, investigation_id: uuid.UUID, kinds: frozenset[RefKindName]
) -> list[Select[Any]]:
    ev, c, j = Evidence, EvidenceCustodyEvent, AnalysisJob
    in_case = (ev.investigation_id == investigation_id) & (ev.organization_id == org_id)
    no_text = cast(null(), String)
    no_uuid = cast(null(), Uuid)
    recorded = literal(TsSource.RECORDED.value, String)
    parts: list[Select[Any]] = []

    if RefKindName.CUSTODY in kinds:
        parts.append(
            select(
                *_columns(
                    c.occurred_at,
                    recorded,
                    literal("custody_", String) + cast(c.action, String),
                    ev.original_filename,
                    no_text,
                    c.evidence_id,
                    no_uuid,
                    RefKindName.CUSTODY,
                    c.id,
                )
            )
            .join(ev, (ev.id == c.evidence_id) & (ev.organization_id == c.organization_id))
            .where(c.organization_id == org_id, in_case)
        )
    if RefKindName.JOB in kinds:
        jobs_base = (
            select(j)
            .join(ev, (ev.id == j.evidence_id) & (ev.organization_id == j.organization_id))
            .where(j.organization_id == org_id, in_case)
            .subquery()
        )
        parts.append(
            select(
                *_columns(
                    jobs_base.c.created_at,
                    recorded,
                    literal("analysis_requested", String),
                    cast(jobs_base.c.analyzer, String),
                    no_text,
                    jobs_base.c.evidence_id,
                    jobs_base.c.id,
                    RefKindName.JOB,
                    jobs_base.c.id,
                )
            )
        )
        parts.append(
            select(
                *_columns(
                    jobs_base.c.finished_at,
                    recorded,
                    literal("analysis_", String) + cast(jobs_base.c.status, String),
                    cast(jobs_base.c.analyzer, String),
                    no_text,
                    jobs_base.c.evidence_id,
                    jobs_base.c.id,
                    RefKindName.JOB,
                    jobs_base.c.id,
                )
            ).where(
                jobs_base.c.finished_at.is_not(None),
                cast(jobs_base.c.status, String).in_(
                    [AnalysisStatus.SUCCEEDED.value, AnalysisStatus.FAILED.value]
                ),
            )
        )
    capture = literal(TsSource.CAPTURE.value, String)
    if kinds & {RefKindName.TIMELINE, RefKindName.ALERT}:
        pcap = latest_succeeded_jobs(org_id, investigation_id, Analyzer.PCAP)
        if RefKindName.TIMELINE in kinds:
            t = TimelineEntry
            parts.append(
                select(
                    *_columns(
                        t.ts,
                        capture,
                        literal("capture_event", String),
                        t.title,
                        t.severity,
                        pcap.c.evidence_id,
                        t.job_id,
                        RefKindName.TIMELINE,
                        t.id,
                    )
                )
                .join(pcap, pcap.c.id == t.job_id)
                .where(t.organization_id == org_id)
            )
        if RefKindName.ALERT in kinds:
            a = NetworkAlert
            parts.append(
                select(
                    *_columns(
                        a.ts,
                        capture,
                        literal("alert", String),
                        a.signature,
                        case({1: "high", 2: "medium", 3: "low"}, value=a.severity, else_="info"),
                        pcap.c.evidence_id,
                        a.job_id,
                        RefKindName.ALERT,
                        a.id,
                    )
                )
                .join(pcap, pcap.c.id == a.job_id)
                .where(a.organization_id == org_id)
            )
    if RefKindName.FINDING in kinds:
        static = latest_succeeded_jobs(org_id, investigation_id, Analyzer.STATIC)
        f = AnalysisFinding
        parts.append(
            select(
                *_columns(
                    func.coalesce(static.c.finished_at, static.c.created_at),
                    literal(TsSource.ANALYSIS_TIME.value, String),
                    literal("finding", String),
                    f.title,
                    f.severity,
                    static.c.evidence_id,
                    f.job_id,
                    RefKindName.FINDING,
                    f.id,
                )
            )
            .join(static, static.c.id == f.job_id)
            .where(f.organization_id == org_id)
        )
    if RefKindName.STATUS in kinds:
        e = InvestigationStatusEvent
        # from|to|reason (statuses never hold "|"); the reason is cut in SQL first.
        detail = func.concat_ws(
            "|",
            func.coalesce(e.from_status, ""),
            e.to_status,
            func.coalesce(func.left(e.reason, CASE_TEXT_MAX + 1), ""),
        )
        parts.append(
            select(
                *_columns(
                    e.occurred_at,
                    recorded,
                    literal(STATUS_KIND, String),
                    detail,
                    no_text,
                    no_uuid,
                    no_uuid,
                    RefKindName.STATUS,
                    e.id,
                )
            ).where(e.organization_id == org_id, e.investigation_id == investigation_id)
        )
    if RefKindName.NOTE in kinds:
        n = AnalystNote
        first, current = aliased(AnalystNoteVersion), aliased(AnalystNoteVersion)
        parts.append(
            select(
                *_columns(
                    first.created_at,
                    recorded,
                    literal(NOTE_KIND, String),
                    func.left(current.body, CASE_TEXT_MAX + 1),
                    no_text,
                    no_uuid,
                    no_uuid,
                    RefKindName.NOTE,
                    n.id,
                )
            )
            .join(
                first,
                (first.note_id == n.id)
                & (first.organization_id == n.organization_id)
                & (first.version == 1),
            )
            .join(
                current,
                (current.note_id == n.id)
                & (current.organization_id == n.organization_id)
                & (current.version == n.current_version),
            )
            .where(
                n.organization_id == org_id,
                n.investigation_id == investigation_id,
                n.include_in_reports.is_(True),
                n.deleted_at.is_(None),
            )
        )
    return parts


def _kind_set(kinds: Sequence[TimelineKind] | None) -> frozenset[RefKindName]:
    if not kinds:
        return frozenset(RefKindName)
    return frozenset(RefKindName(k) for k in kinds)


def _union(
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    kinds: Sequence[TimelineKind] | None = None,
) -> Subquery:
    return union_all(*_parts(org_id, investigation_id, _kind_set(kinds))).subquery("u")


def _clip(text: str, limit: int = CASE_TEXT_MAX) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _status_title(detail: str) -> str:
    from_status, to_status, reason = ([*detail.split("|", 2), "", ""])[:3]
    to_text = to_status.replace("_", " ")
    title = (
        f"Status changed from {from_status.replace('_', ' ')} to {to_text}"
        if from_status
        else f"Status set to {to_text}"
    )
    return f"{title}: {_clip(reason)}" if reason else title


def _title(kind: str, detail: str | None) -> str:
    detail = detail or ""
    if kind == NOTE_KIND:
        return _clip(detail)
    if kind == STATUS_KIND:
        return _status_title(detail)
    if kind.startswith("custody_"):
        action = kind.removeprefix("custody_")
        return f"{_CUSTODY_TITLE.get(action, action)}: {detail}" if detail else action
    if kind.startswith("analysis_"):
        name = _ANALYZER_TITLE.get(detail, detail)
        return f"{name} {kind.removeprefix('analysis_')}"
    return detail


def as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


async def _entries(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    *,
    limit: int,
    after: Cursor | None = None,
    kinds: Sequence[TimelineKind] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[Entry]:
    u = _union(org_id, investigation_id, kinds)
    stmt = select(u)
    if after is not None:
        stmt = stmt.where(
            tuple_(u.c.ts, u.c.kind, u.c.ref_id) > tuple_(after.ts, after.kind, after.ref_id)
        )
    if since is not None:
        stmt = stmt.where(u.c.ts >= as_utc(since))
    if until is not None:
        stmt = stmt.where(u.c.ts <= as_utc(until))
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

    `kinds` (M6, RT10) restricts the ref kinds; None or empty means every kind."""
    return await _entries(session, org_id, investigation_id, limit=limit, after=after, kinds=kinds)


async def export_entries(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    *,
    limit: int,
    kinds: Sequence[TimelineKind] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[Entry]:
    """The first `limit` entries in timeline order with `since <= ts <= until` (the M6
    export; naive bounds are read as UTC)."""
    return await _entries(
        session, org_id, investigation_id, limit=limit, kinds=kinds, since=since, until=until
    )


async def count(
    session: AsyncSession,
    org_id: uuid.UUID,
    investigation_id: uuid.UUID,
    *,
    kinds: Sequence[TimelineKind] | None = None,
) -> int:
    u = _union(org_id, investigation_id, kinds)
    return int(await session.scalar(select(func.count()).select_from(u)) or 0)


def next_cursor(entries: Sequence[Entry], limit: int) -> str | None:
    if len(entries) <= limit:
        return None
    last = entries[limit - 1]
    return Cursor(last.ts, last.kind, last.ref_id).encode()
