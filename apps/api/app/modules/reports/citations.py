"""Citation resolution for the report snapshot (M6 phase 3).

Sources register the rows they cite (`Registry.add`): verified AI citations, the draft's
`cited_rows`, note refs and ATT&CK mapping sources. `resolve` then re-queries every row in
the requester's tenant session **and in the case scope** (a row of another case or org is
never resolved: it is dropped and counted, never shown). Each resolved row gets:

- a bounded copy of its fields, rendered with the same per-kind allow-list as the M5
  context (`ai/context/fields.py`), as strings, defanged once (RT24), each value cut at
  4 096 characters, at most `MAX_CITATION_FIELDS` fields;
- `fields_sha256` = sha256 of the canonical JSON of exactly that copy;
- the internal deep-link path, built from ids only (as `ai/service_outputs.deep_link`).

The `C1…Cn` numbers are assigned by the snapshot builder in first-use order.
"""

import hashlib
import re
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from cyberlab_jobs.report import MAX_CITATION_FIELDS, canonical_json, truncate_text
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.ai import postprocess
from app.modules.ai.context import fields as F
from app.modules.ai.contracts import RefKind
from app.modules.ai.models import AiCitation
from app.modules.ai.service_outputs import LinkContext, deep_link
from app.modules.analysis.models import AnalysisJob
from app.modules.evidence.models import Evidence, EvidenceCustodyEvent, EvidenceHash, HashAlgorithm
from app.modules.investigations.models import Investigation, InvestigationStatusEvent
from app.modules.investigations.schemas import case_ref
from app.modules.notes.models import AnalystNote
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

SOURCES = ("ai", "selection", "note", "attack")
_REF_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_IDENT = re.compile(r"^[A-Za-z0-9_.:+-]{1,64}$")
_KIND = re.compile(r"^[a-z_]{1,16}$")

# Report citation kind -> the tables a row of that kind may live in (first match wins).
KIND_TABLES: dict[str, tuple[str, ...]] = {
    "finding": ("analysis_findings",),
    "alert": ("network_alerts",),
    "ioc": ("iocs",),
    "flow": ("network_flows",),
    "record": ("network_records",),
    "job": ("analysis_jobs",),
    "evidence": ("evidence",),
    "custody": ("evidence_custody_events",),
    "capability": ("malware_capabilities",),
    "signature": ("malware_signature_matches",),
    "string": ("malware_strings",),
    "sample": ("malware_samples",),
    "pe_summary": ("malware_samples",),
    "ti_result": ("ti_results",),
    "note": ("analyst_notes",),
    "investigation": ("investigations",),
    # A merged case-timeline entry points at one of the timeline's source tables
    # (`investigations/timeline.REF_TABLES`); AI refs name it, a selection is looked up.
    "timeline": (
        "analysis_timeline",
        "evidence_custody_events",
        "analysis_jobs",
        "network_alerts",
        "analysis_findings",
        "investigation_status_events",
        "analyst_notes",
    ),
}
# Tables whose rows belong to an analysis job (scoped through the job's evidence).
_JOB_TABLES: dict[str, Any] = {
    "analysis_findings": AnalysisFinding,
    "network_alerts": NetworkAlert,
    "iocs": Ioc,
    "network_records": NetworkRecord,
    "analysis_timeline": TimelineEntry,
    "malware_capabilities": MalwareCapability,
    "malware_signature_matches": MalwareSignatureMatch,
    "malware_strings": MalwareString,
    "malware_samples": MalwareSample,
}
# Table -> (pcap tab, static tab) of the cited job's page; None: no link.
_TABS: dict[str, tuple[str | None, str | None]] = {
    "analysis_findings": ("findings", "findings"),
    "network_alerts": ("alerts", None),
    "network_flows": ("flows", None),
    "iocs": ("iocs", "iocs"),
    "analysis_timeline": ("timeline", None),
    "analysis_jobs": ("overview", "overview"),
    "malware_signature_matches": (None, "signatures"),
    "malware_capabilities": (None, "capabilities"),
    "malware_strings": (None, "strings"),
}
_RECORD_TABS = {"dns": "dns", "http": "http", "tls": "tls"}


def _defang(value: str) -> str:
    return postprocess.defang_all(value)


def field_text(value: object) -> str | None:
    """One field value as snapshot text (None: left out)."""
    if value is None or isinstance(value, F.HostList):
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        text = f"{value:.6f}".rstrip("0").rstrip(".")
        return text or "0"
    text = str(value)
    return truncate_text(_defang(text)) if text else None


def field_copy(raw: Mapping[str, object]) -> dict[str, str]:
    """The bounded, defanged string copy of a rendered field map (sorted, capped)."""
    out: dict[str, str] = {}
    for name in sorted(raw):
        if len(out) >= MAX_CITATION_FIELDS:
            break
        if not _IDENT.fullmatch(name):
            continue
        text = field_text(raw[name])
        if text is not None and text != "":
            out[name] = text
    return out


def fields_sha256(fields: Mapping[str, str]) -> str:
    return hashlib.sha256(canonical_json(dict(fields))).hexdigest()


# --- registry -------------------------------------------------------------------------------

CiteKey = tuple[str, str, uuid.UUID | None]


def cite_key(kind: str, ref_id: str, job_id: uuid.UUID | None) -> CiteKey:
    """Flows are keyed by (job, flow_ref) (RT16); every other row id is unique alone."""
    return (kind, ref_id, job_id if kind == "flow" else None)


@dataclass(frozen=True)
class CiteRequest:
    kind: str
    ref_id: str
    job_id: uuid.UUID | None
    source: str
    ai_citation_id: uuid.UUID | None = None
    ref_table: str | None = None  # the table an AI context ref named (a hint)


@dataclass
class Registry:
    """Requests in registration order; the first request of a key fixes its source."""

    requests: dict[CiteKey, CiteRequest] = field(default_factory=dict)
    invalid: int = 0

    def add(
        self,
        kind: str,
        ref_id: str | None,
        job_id: uuid.UUID | None,
        source: str,
        *,
        ai_citation_id: uuid.UUID | None = None,
        ref_table: str | None = None,
    ) -> CiteKey | None:
        if (
            not ref_id
            or kind not in KIND_TABLES
            or not _REF_ID.fullmatch(ref_id)
            or source not in SOURCES
        ):
            self.invalid += 1
            return None
        key = cite_key(kind, ref_id, job_id)
        if key not in self.requests:
            hint = ref_table if ref_table in KIND_TABLES[kind] else None
            self.requests[key] = CiteRequest(kind, ref_id, job_id, source, ai_citation_id, hint)
        return key


@dataclass(frozen=True)
class Resolved:
    kind: str
    ref_table: str
    ref_id: str
    job_id: uuid.UUID | None
    source: str
    ai_citation_id: uuid.UUID | None
    fields: dict[str, str]
    fields_sha256: str
    path: str | None


# --- scope ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class CaseScope:
    """The case's jobs (any status) with their analyzer, and its evidence ids."""

    org_id: uuid.UUID
    investigation: Investigation
    jobs: dict[uuid.UUID, str]
    evidence_ids: frozenset[uuid.UUID]

    @classmethod
    async def load(
        cls, session: AsyncSession, org_id: uuid.UUID, investigation: Investigation
    ) -> "CaseScope":
        evidence = await session.scalars(
            select(Evidence.id).where(
                Evidence.organization_id == org_id,
                Evidence.investigation_id == investigation.id,
            )
        )
        evidence_ids = frozenset(evidence)
        jobs: dict[uuid.UUID, str] = {}
        if evidence_ids:
            rows = await session.execute(
                select(AnalysisJob.id, AnalysisJob.analyzer).where(
                    AnalysisJob.organization_id == org_id,
                    AnalysisJob.evidence_id.in_(list(evidence_ids)),
                )
            )
            jobs = {jid: str(getattr(a, "value", a)) for jid, a in rows.all()}
        return cls(org_id, investigation, jobs, evidence_ids)


def _uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


# --- per-table lookup -------------------------------------------------------------------------


@dataclass(frozen=True)
class _Found:
    row: Any
    job_id: uuid.UUID | None
    raw: dict[str, object]
    evidence_id: uuid.UUID | None = None
    record_kind: str | None = None


async def _job_rows(
    session: AsyncSession, scope: CaseScope, table: str, ids: Sequence[uuid.UUID]
) -> dict[str, _Found]:
    model = _JOB_TABLES[table]
    if not ids or not scope.jobs:
        return {}
    rows = await session.scalars(
        select(model).where(
            model.organization_id == scope.org_id,
            model.id.in_(list(ids)),
            model.job_id.in_(list(scope.jobs)),
        )
    )
    out: dict[str, _Found] = {}
    for row in rows:
        out[str(row.id)] = _Found(
            row,
            row.job_id,
            _render_job_row(table, row),
            record_kind=row.kind if table == "network_records" else None,
        )
    return out


def _render_job_row(table: str, row: Any) -> dict[str, object]:
    if table == "analysis_findings":
        return dict(F.finding_fields(row)[0])
    if table == "network_alerts":
        return dict(F.alert_fields(row))
    if table == "iocs":
        return dict(F.ioc_fields(row))
    if table == "network_records":
        return dict(F.record_fields(row))
    if table == "analysis_timeline":
        return dict(F.job_timeline_fields(row))
    if table == "malware_capabilities":
        return dict(F.capability_fields(row))
    if table == "malware_signature_matches":
        return dict(F.signature_fields(row))
    if table == "malware_strings":
        return dict(F.string_fields(row))
    return dict(F.sample_fields(row))


async def _flows(
    session: AsyncSession, scope: CaseScope, pairs: Sequence[tuple[uuid.UUID, str]]
) -> dict[tuple[uuid.UUID, str], _Found]:
    wanted = {(job, ref) for job, ref in pairs if job in scope.jobs}
    if not wanted:
        return {}
    m = NetworkFlow
    rows = await session.scalars(
        select(m)
        .where(
            m.organization_id == scope.org_id,
            m.job_id.in_(sorted({j for j, _ in wanted})),
            m.flow_ref.in_(sorted({r for _, r in wanted})),
        )
        .order_by(m.job_id, m.flow_ref, m.ts, m.id)
    )
    out: dict[tuple[uuid.UUID, str], _Found] = {}
    for row in rows:
        key = (row.job_id, str(row.flow_ref))
        if key in out or key not in wanted:
            continue
        out[key] = _Found(row, row.job_id, dict(F.flow_fields(row)))
    return out


async def _jobs(
    session: AsyncSession, scope: CaseScope, ids: Sequence[uuid.UUID]
) -> dict[str, _Found]:
    wanted = [i for i in ids if i in scope.jobs]
    if not wanted:
        return {}
    rows = await session.scalars(
        select(AnalysisJob).where(
            AnalysisJob.organization_id == scope.org_id, AnalysisJob.id.in_(wanted)
        )
    )
    return {
        str(r.id): _Found(r, r.id, dict(F.job_fields(r)), evidence_id=r.evidence_id) for r in rows
    }


async def _evidence(
    session: AsyncSession, scope: CaseScope, ids: Sequence[uuid.UUID]
) -> dict[str, _Found]:
    wanted = [i for i in ids if i in scope.evidence_ids]
    if not wanted:
        return {}
    rows = list(
        await session.scalars(
            select(Evidence).where(
                Evidence.organization_id == scope.org_id, Evidence.id.in_(wanted)
            )
        )
    )
    hashes = dict(
        (
            await session.execute(
                select(EvidenceHash.evidence_id, EvidenceHash.value).where(
                    EvidenceHash.organization_id == scope.org_id,
                    EvidenceHash.evidence_id.in_(wanted),
                    EvidenceHash.algorithm == HashAlgorithm.SHA256,
                )
            )
        ).all()
    )
    return {
        str(r.id): _Found(
            r, None, dict(F.evidence_fields(r, hashes.get(r.id), {}, None)), evidence_id=r.id
        )
        for r in rows
    }


async def _custody(
    session: AsyncSession, scope: CaseScope, ids: Sequence[uuid.UUID]
) -> dict[str, _Found]:
    if not ids or not scope.evidence_ids:
        return {}
    c = EvidenceCustodyEvent
    rows = await session.scalars(
        select(c).where(
            c.organization_id == scope.org_id,
            c.id.in_(list(ids)),
            c.evidence_id.in_(list(scope.evidence_ids)),
        )
    )
    return {
        str(r.id): _Found(
            r,
            None,
            {
                "action": str(getattr(r.action, "value", r.action)),
                "occurred_at": F.ts(r.occurred_at),
                "evidence_id": str(r.evidence_id),
            },
            evidence_id=r.evidence_id,
        )
        for r in rows
    }


async def _ti(
    session: AsyncSession, scope: CaseScope, ids: Sequence[uuid.UUID]
) -> dict[str, _Found]:
    """A provider answer is in scope when its value is an IOC of one of the case's jobs."""
    if not ids or not scope.jobs:
        return {}
    in_case = (
        select(Ioc.id)
        .where(
            Ioc.organization_id == scope.org_id,
            Ioc.job_id.in_(list(scope.jobs)),
            func.lower(Ioc.value) == func.lower(TiResult.value_norm),
        )
        .exists()
    )
    rows = await session.scalars(
        select(TiResult).where(
            TiResult.organization_id == scope.org_id, TiResult.id.in_(list(ids)), in_case
        )
    )
    return {str(r.id): _Found(r, None, dict(F.ti_fields(r, r.value_norm))) for r in rows}


async def _notes(
    session: AsyncSession, scope: CaseScope, ids: Sequence[uuid.UUID]
) -> dict[str, _Found]:
    if not ids:
        return {}
    n = AnalystNote
    rows = await session.scalars(
        select(n).where(
            n.organization_id == scope.org_id,
            n.id.in_(list(ids)),
            n.investigation_id == scope.investigation.id,
            n.deleted_at.is_(None),
        )
    )
    return {
        str(r.id): _Found(r, None, {"version": r.current_version, "created_at": F.ts(r.created_at)})
        for r in rows
    }


async def _status_events(
    session: AsyncSession, scope: CaseScope, ids: Sequence[uuid.UUID]
) -> dict[str, _Found]:
    if not ids:
        return {}
    e = InvestigationStatusEvent
    rows = await session.scalars(
        select(e).where(
            e.organization_id == scope.org_id,
            e.id.in_(list(ids)),
            e.investigation_id == scope.investigation.id,
        )
    )
    return {
        str(r.id): _Found(
            r,
            None,
            {
                "from_status": r.from_status,
                "to_status": r.to_status,
                "occurred_at": F.ts(r.occurred_at),
            },
        )
        for r in rows
    }


def _investigation(scope: CaseScope, ids: Sequence[uuid.UUID]) -> dict[str, _Found]:
    inv = scope.investigation
    if inv.id not in ids:
        return {}
    raw = F.investigation_fields(inv, case_ref(inv.case_number), include_text=False)
    return {str(inv.id): _Found(inv, None, dict(raw))}


async def _lookup(
    session: AsyncSession, scope: CaseScope, table: str, ids: Sequence[uuid.UUID]
) -> dict[str, _Found]:
    if table in _JOB_TABLES:
        return await _job_rows(session, scope, table, ids)
    if table == "analysis_jobs":
        return await _jobs(session, scope, ids)
    if table == "evidence":
        return await _evidence(session, scope, ids)
    if table == "evidence_custody_events":
        return await _custody(session, scope, ids)
    if table == "ti_results":
        return await _ti(session, scope, ids)
    if table == "analyst_notes":
        return await _notes(session, scope, ids)
    if table == "investigation_status_events":
        return await _status_events(session, scope, ids)
    if table == "investigations":
        return _investigation(scope, ids)
    return {}


# --- deep links -------------------------------------------------------------------------------


def _job_path(org_id: uuid.UUID, route: str, job_id: uuid.UUID, tab: str, ref: str | None) -> str:
    params = []
    if tab != "overview":
        params.append(f"tab={tab}")
    if ref:
        params.append(f"ref={quote(ref, safe='')}")
    query = "?" + "&".join(params) if params else ""
    return f"/o/{org_id}/{route}/{job_id}{query}"


def _path(scope: CaseScope, kind: str, table: str, ref_id: str, found: _Found) -> str | None:
    """The internal deep link of a resolved row (ids and fixed tab names only)."""
    org = scope.org_id
    if table == "evidence":
        return f"/o/{org}/evidence/{ref_id}"
    if table == "evidence_custody_events":
        return f"/o/{org}/evidence/{found.evidence_id}" if found.evidence_id else None
    if table in ("investigations", "analyst_notes", "investigation_status_events"):
        return f"/o/{org}/investigations/{scope.investigation.id}"
    job_id = found.job_id
    if job_id is None:
        return None
    analyzer = scope.jobs.get(job_id)
    try:
        ref_kind = RefKind(kind)
    except ValueError:
        ref_kind = None
    # The M5 rule for the kinds it knows, on their own table.
    if ref_kind is not None and table == KIND_TABLES[kind][0] and kind != "timeline":
        row = AiCitation(status="verified", kind=kind, ref_id=ref_id, job_id=job_id)
        record_kinds = {ref_id: found.record_kind} if found.record_kind else {}
        link = deep_link(row, LinkContext({job_id: analyzer} if analyzer else {}, record_kinds))
        if link is None or link.job_id is None or link.tab is None:
            return None
        return _job_path(org, link.route, link.job_id, link.tab, link.ref)
    if table == "network_records":
        tab = _RECORD_TABS.get(found.record_kind or "")
        return _job_path(org, "pcap", job_id, tab, ref_id) if tab and analyzer == "pcap" else None
    tabs = _TABS.get(table)
    if tabs is None or analyzer not in ("pcap", "static"):
        return None
    tab = tabs[0] if analyzer == "pcap" else tabs[1]
    if tab is None:
        return None
    route = "pcap" if analyzer == "pcap" else "malware"
    return _job_path(org, route, job_id, tab, None if table == "analysis_jobs" else ref_id)


# --- resolve ----------------------------------------------------------------------------------


def _candidates(request: CiteRequest) -> tuple[str, ...]:
    if request.ref_table is not None:
        return (request.ref_table,)
    return KIND_TABLES[request.kind]


async def resolve(
    session: AsyncSession,
    scope: CaseScope,
    requests: Iterable[CiteRequest],
    *,
    with_paths: bool = True,
    drop_kinds: frozenset[str] = frozenset(),
) -> dict[CiteKey, Resolved]:
    """Every request whose row exists in the org **and** the case scope; the rest is left
    out (the caller counts it as dropped)."""
    pending = [r for r in requests if r.kind not in drop_kinds]
    out: dict[CiteKey, Resolved] = {}

    def done(request: CiteRequest, table: str, found: _Found) -> None:
        copy = field_copy(found.raw)
        out[cite_key(request.kind, request.ref_id, request.job_id)] = Resolved(
            kind=request.kind,
            ref_table=table,
            ref_id=request.ref_id,
            job_id=found.job_id,
            source=request.source,
            ai_citation_id=request.ai_citation_id,
            fields=copy,
            fields_sha256=fields_sha256(copy),
            path=_path(scope, request.kind, table, request.ref_id, found) if with_paths else None,
        )

    flows = [r for r in pending if r.kind == "flow"]
    if flows:
        found_flows = await _flows(
            session, scope, [(r.job_id, r.ref_id) for r in flows if r.job_id is not None]
        )
        for r in flows:
            hit = found_flows.get((r.job_id, r.ref_id)) if r.job_id is not None else None
            if hit is not None:
                done(r, "network_flows", hit)

    others = [r for r in pending if r.kind != "flow"]
    # Try each request's candidate tables in order, one batched query per table and round.
    remaining = [(r, list(_candidates(r))) for r in others]
    while remaining:
        by_table: dict[str, list[CiteRequest]] = {}
        for request, tables in remaining:
            by_table.setdefault(tables[0], []).append(request)
        hits: dict[tuple[str, str], _Found] = {}
        for table, batch in by_table.items():
            ids = sorted({u for u in (_uuid(r.ref_id) for r in batch) if u is not None})
            for ref, found in (await _lookup(session, scope, table, ids)).items():
                hits[(table, ref)] = found
        next_round = []
        for request, tables in remaining:
            row_id = _uuid(request.ref_id)
            hit = hits.get((tables[0], str(row_id))) if row_id is not None else None
            if hit is not None:
                done(request, tables[0], hit)
            elif len(tables) > 1:
                next_round.append((request, tables[1:]))
        remaining = next_round
    return out
