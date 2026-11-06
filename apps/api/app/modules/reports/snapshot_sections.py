"""The section builders of the report snapshot (M6 phase 3; called by `snapshot.py`).

Every builder re-reads its rows in the requester's tenant session (the one REPEATABLE READ
READ ONLY transaction of the build, RT14) with explicit org filters, trusts nothing of the
draft but its ids, flags and text, caps its items and keeps the uncapped `total`.

Builders return plain JSON-able dicts in the shape of `cyberlab_jobs.report`. A row that may
be cited carries a private `_cite` key (one `CiteKey`), a row that cites carries `_cites`
(a list); `snapshot.py` replaces both with the `C<n>` numbers once every citation is
resolved. Evidence-derived and AI text is defanged here, once (RT24); analyst text is not.

M8 (phase 8, RT10): every row derived from an analysis job of evidence whose memory
sensitivity is `restricted` (TLP:RED material by default) is left out of a report below
TLP:RED: its findings, alerts, timeline entries, IOCs seen only there (shared IOCs stay, with
the restricted jobs' sightings removed), job-scope AI runs, citations of its rows and the job
row's summary (tool versions). `memory_guard` finds those jobs once per build; every left-out
item is counted and `omissions()` gives the snapshot's additive `omissions` field (None when
nothing was left out, so a report without such evidence keeps byte-identical canonical JSON).

M9 (phase 9, RT23): the same guard covers restricted disk evidence (source `disk`) and files
exported from it (source `derived`). A disk job is withheld when **any** of its segments
(`analysis_job_segments`) is restricted; a static job on derived evidence follows its
evidence's state. Its findings, IOCs seen only there, timeline entries, citations, job-scope
AI runs and the job row's summary are left out below TLP:RED and counted in
`omissions.disk_restricted` (absent from the canonical bytes when 0, so M8 snapshots with
memory omissions keep their bytes). An item is counted once: as memory when the job's
restriction is a memory image (`omissions.memory_restricted`), else as disk.
"""

import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cyberlab_jobs.report import (
    ANALYST_TEXT_CHARS,
    CAPS,
    MAX_REFS_PER_ROW,
    MAX_TOOL_VERSIONS,
    SHORT_NOTE_CHARS,
    TITLE_CHARS,
    truncate_text,
)
from sqlalchemy import case as sql_case
from sqlalchemy import func, or_, select, union_all
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.core.config import get_settings
from app.modules.ai import postprocess
from app.modules.ai import repository as ai_repo
from app.modules.ai.context import fields as F
from app.modules.ai.contracts import AiRunStatus, ClaimStatus, OutputFlag
from app.modules.ai.models import AiCitation, AiContextRef, AiRun
from app.modules.ai.schemas import AiOutputOut
from app.modules.ai.service_outputs import LinkContext, build, has_canary_leak
from app.modules.analysis.models import AnalysisJob, AnalysisStatus, Analyzer
from app.modules.attack.index import label as attack_label
from app.modules.case_attack.models import CaseAttackMapping
from app.modules.disk_forensics.models import AnalysisJobSegment
from app.modules.evidence.models import (
    CustodyAction,
    Evidence,
    EvidenceCustodyEvent,
    EvidenceHash,
)
from app.modules.investigations import timeline as case_timeline
from app.modules.investigations.models import Investigation, InvestigationStatusEvent
from app.modules.investigations.schemas import case_ref
from app.modules.ioc_collections import case_iocs as case_iocs_mod
from app.modules.ioc_collections.models import IocCollection, IocCollectionItem
from app.modules.memory_analysis.models import (
    MemorySensitivity,
    SensitivitySource,
    SensitivityState,
)
from app.modules.notes.models import AnalystNote, AnalystNoteVersion
from app.modules.pcap_analysis.models import AnalysisFinding, Ioc, NetworkAlert
from app.modules.reports.citations import CaseScope, CiteKey, Registry, Resolved, cite_key
from app.modules.reports.models import Report, ReportVersion
from app.modules.reports.repository import user_names
from app.modules.reports.schemas import ReportDraft
from app.modules.threat_intel.service_results import latest_by_key

DISCLAIMER = "AI-generated interpretation: observations to verify before acting, not verdicts."
UNKNOWN = "unknown"
SEVERITY_RANK = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
# Suricata severity (1 = most severe) -> label; the M5 context rule.
ALERT_SEVERITY = F.SEVERITY_BY_SURICATA
TIMELINE_PAGE = 500
TIMELINE_SCAN = 20_000
AI_FINAL = (AiRunStatus.COMPLETED.value, AiRunStatus.PARTIAL.value)

_IDENT = re.compile(r"^[A-Za-z0-9_.:+-]{1,64}$")
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_MD5 = re.compile(r"^[0-9a-f]{32}$")
_FIXED = re.compile(r"^-?\d{1,12}(\.\d{1,6})?$")
_CLAIM_ID = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
_PATH = re.compile(r"^(observed|interpretation|hypotheses|next_steps)\[(\d+)\]\.")


# --- value helpers ----------------------------------------------------------------------


def defang(text: str | None) -> str:
    """Evidence-derived and AI text, defanged once (RT24) and bounded."""
    return truncate_text(postprocess.defang_all(text)) if text else ""


def ident(value: object) -> str | None:
    if value is None:
        return None
    text = str(getattr(value, "value", value))
    return text if _IDENT.fullmatch(text) else None


def ident_or(value: object, fallback: str = UNKNOWN) -> str:
    return ident(value) or fallback


def title(value: str | None, fallback: str = UNKNOWN) -> str:
    text = (value or "").strip()
    return text[:TITLE_CHARS] if text else fallback


def short(value: str | None) -> str | None:
    return value[:SHORT_NOTE_CHARS] if value else None


def analyst(value: str | None) -> str:
    # Analyst text is accepted at <= 20 000 characters; never cut below that (RT9).
    return (value or "")[:ANALYST_TEXT_CHARS]


def fixed(value: object) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        text = str(value)
    else:
        try:
            text = f"{float(str(value)):.6f}".rstrip("0").rstrip(".")
        except ValueError:
            return None
    return text if _FIXED.fullmatch(text) else None


def aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def iso(value: datetime | None) -> str | None:
    found = aware(value)
    return found.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ") if found else None


# --- the build context ----------------------------------------------------------------------


@dataclass
class Build:
    session: AsyncSession
    org_id: uuid.UUID
    user_id: uuid.UUID
    report: Report
    case: Investigation
    draft: ReportDraft
    now: datetime
    external: bool
    scope: CaseScope
    registry: Registry = field(default_factory=Registry)
    names: dict[uuid.UUID, str] = field(default_factory=dict)
    counts: dict[str, dict[str, int]] = field(default_factory=dict)
    # (pseudonym, original) of every reversed run map, in run order: the external profile
    # seeds its report-level map with them (`redact.seed_run_maps`, RT2).
    run_originals: list[tuple[str, str]] = field(default_factory=list)
    # M8: jobs of restricted evidence (empty at TLP:RED; `memory_guard`) and the number of
    # items left out because of them (`omissions.memory_restricted`).
    withheld_jobs: frozenset[uuid.UUID] = frozenset()
    withheld: int = 0
    # M9: the subset of `withheld_jobs` restricted as disk or derived evidence, and the items
    # left out because of them (`omissions.disk_restricted`).
    withheld_disk_jobs: frozenset[uuid.UUID] = frozenset()
    withheld_disk: int = 0

    async def name_of(self, user_ids: Sequence[uuid.UUID | None]) -> None:
        missing = [u for u in user_ids if u is not None and u not in self.names]
        self.names.update(await user_names(self.session, missing))

    def name(self, user_id: uuid.UUID | None) -> str:
        return title(self.names.get(user_id) if user_id else None)

    def count(self, section: str, **values: int) -> None:
        self.counts.setdefault(section, {}).update(values)

    def omit(self, job_id: uuid.UUID | None, n: int = 1) -> None:
        """Count `n` items of a withheld job into its omission (disk or memory)."""
        if job_id is not None and job_id in self.withheld_disk_jobs:
            self.withheld_disk += n
        else:
            self.withheld += n


# --- the memory sensitivity guard (M8 phase 8) ----------------------------------------------

# Citation tables that are not a job's results: a cited job row (shown in the jobs section),
# evidence and custody stay.
_WITHHELD_EXEMPT_TABLES = frozenset({"analysis_jobs", "evidence", "evidence_custody_events"})
# Timeline ref kinds that are a job's results (job lifecycle and custody entries stay).
_WITHHELD_TIMELINE_KINDS = frozenset({"timeline", "finding", "alert"})


async def memory_guard(b: Build) -> None:
    """Below TLP:RED, the jobs of the case's restricted evidence (any analyzer: every result
    of a memory or disk image is derived from it). M9: a disk job is withheld when any of its
    segments is restricted; disk jobs and jobs of `disk` / `derived` evidence count as disk."""
    if b.report.tlp == "red" or not b.scope.evidence_ids:
        return
    m = MemorySensitivity
    restricted: dict[uuid.UUID, str] = {
        evidence_id: str(source)
        for evidence_id, source in (
            await b.session.execute(
                select(m.evidence_id, m.source).where(
                    m.organization_id == b.org_id,
                    m.state == SensitivityState.RESTRICTED.value,
                    m.evidence_id.in_(list(b.scope.evidence_ids)),
                )
            )
        ).all()
    }
    if not restricted:
        return
    seg = AnalysisJobSegment
    via_segments = select(seg.job_id).where(
        seg.organization_id == b.org_id, seg.evidence_id.in_(list(restricted))
    )
    rows = (
        await b.session.execute(
            select(AnalysisJob.id, AnalysisJob.analyzer, AnalysisJob.evidence_id).where(
                AnalysisJob.organization_id == b.org_id,
                or_(
                    AnalysisJob.evidence_id.in_(list(restricted)),
                    AnalysisJob.id.in_(via_segments),
                ),
            )
        )
    ).all()
    memory = SensitivitySource.MEMORY.value
    b.withheld_jobs = frozenset(job_id for job_id, _, _ in rows)
    b.withheld_disk_jobs = frozenset(
        job_id
        for job_id, analyzer, evidence_id in rows
        if analyzer == Analyzer.DISK or restricted.get(evidence_id, memory) != memory
    )


def omissions(b: Build) -> dict[str, int] | None:
    """The snapshot's `omissions` (absent unless something was left out, RT10). M9:
    `disk_restricted` only when disk items were left out (RT23)."""
    if not (b.withheld or b.withheld_disk):
        return None
    out = {"memory_restricted": b.withheld}
    if b.withheld_disk:
        out["disk_restricted"] = b.withheld_disk
    return out


def withhold_citations(b: Build, resolved: dict[CiteKey, Resolved]) -> int:
    """Drop (in place) the resolved citations of the withheld jobs' result rows; returns how
    many (counted as omitted, not as out of scope)."""
    if not b.withheld_jobs:
        return 0
    gone = [
        key
        for key, r in resolved.items()
        if r.job_id in b.withheld_jobs and r.ref_table not in _WITHHELD_EXEMPT_TABLES
    ]
    for key in gone:
        b.omit(resolved[key].job_id)
        del resolved[key]
    return len(gone)


async def _withheld_count(b: Build, model: Any, where: Sequence[Any]) -> int:
    """Rows of the withheld jobs among `job_ids` matching a section's other filters."""
    found = await b.session.scalar(select(func.count(model.id)).where(*where))
    return int(found or 0)


async def _omit_rows(
    b: Build, model: Any, where: Sequence[Any], hidden: Sequence[uuid.UUID]
) -> None:
    """Count a section's rows of the withheld jobs `hidden` into their omission."""
    memory = [j for j in hidden if j not in b.withheld_disk_jobs]
    disk = [j for j in hidden if j in b.withheld_disk_jobs]
    if memory:
        b.withheld += await _withheld_count(b, model, [*where, model.job_id.in_(memory)])
    if disk:
        b.withheld_disk += await _withheld_count(b, model, [*where, model.job_id.in_(disk)])


async def _latest_job_ids(b: Build) -> set[uuid.UUID]:
    """The job set of `case_iocs` (the latest succeeded job per evidence and analyzer)."""
    latest = union_all(
        *(
            select(sub.c.id)
            for sub in (
                case_timeline.latest_succeeded_jobs(b.org_id, b.case.id, analyzer)
                for analyzer in Analyzer
            )
        )
    ).subquery()
    return set(await b.session.scalars(select(latest.c.id)))


@dataclass(frozen=True)
class _Sightings:
    count_jobs: int
    first_seen: datetime | None
    last_seen: datetime | None
    job_ids: list[uuid.UUID]


async def _open_sightings(
    b: Build, open_jobs: Sequence[uuid.UUID], values: Sequence[str]
) -> dict[str, _Sightings]:
    """`{ioc_key: sightings}` of the given values in the case-IOC jobs not withheld."""
    if not open_jobs or not values:
        return {}
    i = Ioc
    rows = await b.session.execute(
        select(
            i.type,
            i.value,
            func.count(func.distinct(i.job_id)),
            func.min(i.first_seen),
            func.max(i.last_seen),
            func.array_agg(func.distinct(i.job_id)),
        )
        .where(
            i.organization_id == b.org_id,
            i.job_id.in_(list(open_jobs)),
            i.value.in_(sorted(set(values))),
        )
        .group_by(i.type, i.value)
    )
    out: dict[str, _Sightings] = {}
    for ioc_type, value, n, first, last, job_ids in rows.all():
        _, key = case_iocs_mod.key_of(ioc_type, value)
        found = _Sightings(int(n), first, last, sorted(set(job_ids or [])))
        if key not in out or found.count_jobs > out[key].count_jobs:
            out[key] = found
    return out


async def _restricted_only_iocs(
    b: Build, latest: set[uuid.UUID], among: frozenset[uuid.UUID] | None = None
) -> int:
    """Distinct case IOCs (type, value) seen only in withheld jobs (`among`: only in those
    withheld jobs, e.g. the disk ones)."""
    among = b.withheld_jobs if among is None else among
    withheld = [j for j in latest if j in among]
    if not withheld:
        return 0
    open_jobs = [j for j in latest if j not in among]
    r = aliased(Ioc)
    where: list[Any] = [r.organization_id == b.org_id, r.job_id.in_(withheld)]
    if open_jobs:
        o = aliased(Ioc)
        where.append(
            ~select(o.id)
            .where(
                o.organization_id == b.org_id,
                o.job_id.in_(open_jobs),
                o.type == r.type,
                o.value == r.value,
            )
            .exists()
        )
    grouped = select(r.type, r.value).where(*where).group_by(r.type, r.value).subquery()
    return int(await b.session.scalar(select(func.count()).select_from(grouped)) or 0)


# --- report and case ----------------------------------------------------------------------


async def report_info(b: Build) -> dict[str, Any]:
    prior = await b.session.execute(
        select(
            ReportVersion.version,
            ReportVersion.finalized_at,
            ReportVersion.snapshot_sha256,
            ReportVersion.change_note,
        )
        .where(ReportVersion.organization_id == b.org_id, ReportVersion.report_id == b.report.id)
        .order_by(ReportVersion.version.desc())
        .limit(CAPS["document_control"])
    )
    document_control = [
        {
            "version": v,
            "finalized_at": iso(at),
            "snapshot_sha256_short": sha[:12],
            "change_note": short(note),
        }
        for v, at, sha, note in reversed(prior.all())
    ]
    await b.name_of([b.user_id])
    base_url = None if b.external else get_settings().public_base_url
    return {
        "report_id": str(b.report.id),
        "version": b.report.latest_version + 1,
        "title": title(b.report.title),
        "template": b.report.template,
        "tlp": b.report.tlp,
        "profile": b.report.profile,
        "distribution": short(b.report.distribution),
        "generated_by": b.name(b.user_id),
        "finalized_at": iso(b.now),
        "base_url": base_url,
        "change_note": None,
        "document_control": document_control,
    }


async def case_section(b: Build) -> dict[str, Any]:
    e = InvestigationStatusEvent
    where = [e.organization_id == b.org_id, e.investigation_id == b.case.id]
    total = int(await b.session.scalar(select(func.count(e.id)).where(*where)) or 0)
    events = list(
        await b.session.scalars(
            select(e).where(*where).order_by(e.occurred_at, e.id).limit(CAPS["status_history"])
        )
    )
    await b.name_of([ev.actor_id for ev in events])
    inv = b.case
    return {
        "investigation_id": str(inv.id),
        "case_ref": case_ref(inv.case_number),
        "title": title(inv.title),
        "description": analyst(inv.description),
        "status": ident_or(inv.status),
        "severity": ident_or(inv.severity),
        "tlp": inv.tlp,
        "created_at": iso(inv.created_at),
        "status_history": [
            {
                "from_status": ident(ev.from_status),
                "to_status": ident_or(ev.to_status),
                "reason": short(ev.reason),
                "actor": b.name(ev.actor_id),
                "occurred_at": iso(ev.occurred_at),
            }
            for ev in events
        ],
        "status_history_total": total,
    }


def analyst_sections(b: Build) -> dict[str, Any]:
    return {k: analyst(v) for k, v in b.draft.sections.model_dump().items()}


# --- evidence, custody and jobs ------------------------------------------------------------------


async def evidence(b: Build) -> dict[str, Any]:
    if not b.draft.include.evidence:
        return {"items": [], "total": 0}
    ev = Evidence
    where = [ev.organization_id == b.org_id, ev.investigation_id == b.case.id]
    total = int(await b.session.scalar(select(func.count(ev.id)).where(*where)) or 0)
    rows = list(
        await b.session.scalars(
            select(ev).where(*where).order_by(ev.uploaded_at, ev.id).limit(CAPS["evidence"])
        )
    )
    ids = [r.id for r in rows]
    hashes: dict[uuid.UUID, dict[str, str]] = {}
    if ids:
        for evidence_id, algorithm, value in (
            await b.session.execute(
                select(EvidenceHash.evidence_id, EvidenceHash.algorithm, EvidenceHash.value).where(
                    EvidenceHash.organization_id == b.org_id, EvidenceHash.evidence_id.in_(ids)
                )
            )
        ).all():
            hashes.setdefault(evidence_id, {})[str(getattr(algorithm, "value", algorithm))] = str(
                value
            ).lower()
    verified: dict[uuid.UUID, tuple[str, datetime]] = {}
    if ids:
        c = EvidenceCustodyEvent
        found = await b.session.execute(
            select(c.evidence_id, c.action, c.occurred_at)
            .where(
                c.organization_id == b.org_id,
                c.evidence_id.in_(ids),
                c.action.in_([CustodyAction.VERIFIED_OK, CustodyAction.VERIFIED_MISMATCH]),
            )
            .ext(distinct_on(c.evidence_id))
            .order_by(c.evidence_id, c.occurred_at.desc(), c.id.desc())
        )
        for evidence_id, verified_action, verified_at in found.all():
            verified[evidence_id] = (
                str(getattr(verified_action, "value", verified_action)),
                verified_at,
            )
    await b.name_of([r.uploaded_by for r in rows])
    items = []
    no_hash = 0
    for r in rows:
        h = hashes.get(r.id, {})
        sha256 = h.get("sha256", "")
        if not _SHA256.fullmatch(sha256):
            # Trusted hashes only: evidence without its upload-time sha256 is counted, not shown.
            no_hash += 1
            continue
        state = verified.get(r.id)
        action, at = state if state is not None else ("", None)
        items.append(
            {
                "evidence_id": str(r.id),
                "filename": truncate_text(r.original_filename),
                "size_bytes": int(r.size_bytes),
                "mime": truncate_text(r.detected_mime),
                "description": defang(r.description),
                "sha256": sha256,
                "sha1": h.get("sha1") if _SHA1.fullmatch(h.get("sha1", "")) else None,
                "md5": h.get("md5") if _MD5.fullmatch(h.get("md5", "")) else None,
                "uploaded_at": iso(r.uploaded_at),
                "uploaded_by": b.name(r.uploaded_by),
                "status": ident_or(r.status),
                "verification": {
                    "verified_ok": "ok",
                    "verified_mismatch": "mismatch",
                }.get(action, "unverified"),
                "last_verified_at": iso(at),
                "_cite": cite_key("evidence", str(r.id), None),
            }
        )
    if no_hash:
        b.count("evidence", without_hash=no_hash)
    return {"items": items, "total": max(total, len(items))}


async def custody(b: Build) -> dict[str, Any]:
    if not b.draft.include.custody or not b.scope.evidence_ids:
        return {"items": [], "total": 0}
    c = EvidenceCustodyEvent
    where = [c.organization_id == b.org_id, c.evidence_id.in_(list(b.scope.evidence_ids))]
    total = int(await b.session.scalar(select(func.count(c.id)).where(*where)) or 0)
    rows = list(
        await b.session.scalars(
            select(c).where(*where).order_by(c.occurred_at, c.id).limit(CAPS["custody"])
        )
    )
    await b.name_of([r.actor_id for r in rows])
    return {
        "items": [
            {
                "evidence_id": str(r.evidence_id),
                "action": ident_or(r.action),
                "actor": b.name(r.actor_id),
                "occurred_at": iso(r.occurred_at),
                "ip": None if b.external or r.ip is None else str(r.ip)[:45],
                "user_agent": None if b.external or not r.user_agent else defang(r.user_agent),
            }
            for r in rows
        ],
        "total": total,
    }


def _tool_versions(summary: object) -> dict[str, str]:
    raw = summary.get("tool_versions") if isinstance(summary, Mapping) else None
    out: dict[str, str] = {}
    if isinstance(raw, Mapping):
        for name in sorted(raw, key=str):
            value = raw[name]
            if len(out) >= MAX_TOOL_VERSIONS:
                break
            if ident(name) and isinstance(value, str | int | float) and not isinstance(value, bool):
                out[str(name)] = str(value)[:255]
    return out


async def jobs(b: Build) -> tuple[dict[str, Any], list[uuid.UUID]]:
    """The jobs section and the job ids every result section reads from."""
    selection = b.draft.include.jobs
    if selection == "latest":
        latest = case_timeline.latest_succeeded_jobs(b.org_id, b.case.id)
        rows = list(
            await b.session.scalars(
                select(AnalysisJob)
                .where(
                    AnalysisJob.organization_id == b.org_id,
                    AnalysisJob.id.in_(select(latest.c.id)),
                    AnalysisJob.status == AnalysisStatus.SUCCEEDED,
                )
                .order_by(AnalysisJob.created_at, AnalysisJob.id)
            )
        )
    else:
        wanted = [j for j in dict.fromkeys(selection) if j in b.scope.jobs]
        if len(wanted) != len(set(selection)):
            b.count("jobs", out_of_scope=len(set(selection)) - len(wanted))
        rows = (
            list(
                await b.session.scalars(
                    select(AnalysisJob)
                    .where(AnalysisJob.organization_id == b.org_id, AnalysisJob.id.in_(wanted))
                    .order_by(AnalysisJob.created_at, AnalysisJob.id)
                )
            )
            if wanted
            else []
        )
    kept = rows[: CAPS["jobs"]]
    items = []
    for j in kept:
        withheld = j.id in b.withheld_jobs
        if withheld:
            b.omit(j.id)  # the job row stays; its summary (tool versions) does not
        items.append(
            {
                "job_id": str(j.id),
                "evidence_id": str(j.evidence_id),
                "analyzer": ident_or(j.analyzer),
                "profile": ident(j.profile),
                "status": ident_or(j.status),
                "created_at": iso(j.created_at),
                "finished_at": iso(j.finished_at),
                "tool_versions": {} if withheld else _tool_versions(j.summary),
                "_cite": cite_key("job", str(j.id), None),
            }
        )
    return {"items": items, "total": len(rows)}, [j.id for j in kept]


# --- findings, alerts, IOCs and TI ---------------------------------------------------------------


def _attack_ids(attributes: object) -> list[str]:
    if not isinstance(attributes, Mapping):
        return []
    out: list[str] = []
    for key in ("attack_ids", "attack", "mitre_attack"):
        value = attributes.get(key)
        values = value if isinstance(value, list) else [value]
        # Analyzer attributes are scalars: a list arrives as "T1071.001, T1573".
        split = [p for v in values if isinstance(v, str) for p in re.split(r"[\s,;]+", v)]
        for v in split:
            if isinstance(v, str) and _TECHNIQUE.fullmatch(v) and v not in out:
                out.append(v)
    return out[:MAX_REFS_PER_ROW]


async def findings(b: Build, job_ids: Sequence[uuid.UUID]) -> dict[str, Any]:
    sel = b.draft.include.findings
    if not job_ids or sel.max == 0:
        return {"items": [], "total": 0}
    m = AnalysisFinding
    rank = sql_case(SEVERITY_RANK, value=m.severity, else_=0)
    where = [m.organization_id == b.org_id, rank >= SEVERITY_RANK[sel.min_severity]]
    hidden = [j for j in job_ids if j in b.withheld_jobs]
    if hidden:
        await _omit_rows(b, m, where, hidden)
    shown = [j for j in job_ids if j not in b.withheld_jobs]
    if not shown:
        return {"items": [], "total": 0}
    where.append(m.job_id.in_(shown))
    total = int(await b.session.scalar(select(func.count(m.id)).where(*where)) or 0)
    rows = await b.session.scalars(
        select(m)
        .where(*where)
        .order_by(rank.desc(), m.ts, m.id)
        .limit(min(sel.max, CAPS["findings"]))
    )
    items = [
        {
            "finding_id": str(r.id),
            "job_id": str(r.job_id),
            "severity": ident_or(r.severity),
            "category": ident(r.type),
            "title": defang(r.title),
            "description": defang(r.description),
            "attack_ids": _attack_ids(r.attributes),
            "score": fixed(r.confidence),
            "_cite": cite_key("finding", str(r.id), None),
        }
        for r in rows
    ]
    return {"items": items, "total": total}


async def alerts(b: Build, job_ids: Sequence[uuid.UUID]) -> dict[str, Any]:
    sel = b.draft.include.alerts
    if not job_ids or sel.max == 0:
        return {"items": [], "total": 0}
    m = NetworkAlert
    # Suricata 1 = high ... 4 = info: keep severities at least as severe as the minimum.
    allowed = [
        n
        for n, name in ALERT_SEVERITY.items()
        if SEVERITY_RANK[name] >= SEVERITY_RANK[sel.min_severity]
    ]
    where = [m.organization_id == b.org_id, m.severity.in_(allowed)]
    hidden = [j for j in job_ids if j in b.withheld_jobs]
    if hidden:
        await _omit_rows(b, m, where, hidden)
    shown = [j for j in job_ids if j not in b.withheld_jobs]
    if not shown:
        return {"items": [], "total": 0}
    where.append(m.job_id.in_(shown))
    total = int(await b.session.scalar(select(func.count(m.id)).where(*where)) or 0)
    rows = await b.session.scalars(
        select(m).where(*where).order_by(m.severity, m.ts, m.id).limit(min(sel.max, CAPS["alerts"]))
    )
    items = [
        {
            "alert_id": str(r.id),
            "job_id": str(r.job_id),
            "ts": iso(r.ts),
            "signature": defang(r.signature) or UNKNOWN,
            "signature_id": int(r.signature_id),
            "severity": ALERT_SEVERITY.get(r.severity, UNKNOWN),
            "src": defang(F.endpoint(r.src_ip, r.src_port)) or None,
            "dst": defang(F.endpoint(r.dst_ip, r.dst_port)) or None,
            "proto": ident(r.proto),
            "count": 1,
            "_cite": cite_key("alert", str(r.id), None),
        }
        for r in rows
    ]
    return {"items": items, "total": total}


async def iocs(b: Build) -> dict[str, Any]:
    sel = b.draft.include.iocs
    cap = min(sel.max, CAPS["iocs"])
    collections = {
        c.id: c.name
        for c in await b.session.scalars(
            select(IocCollection).where(
                IocCollection.organization_id == b.org_id,
                IocCollection.investigation_id == b.case.id,
            )
        )
    }
    by_key: dict[str, dict[str, Any]] = {}
    total = 0
    guarded = bool(b.withheld_jobs) and sel.case_iocs and cap > 0
    latest = await _latest_job_ids(b) if guarded else set()
    open_jobs = sorted(j for j in latest if j not in b.withheld_jobs)
    restricted_only = await _restricted_only_iocs(b, latest) if guarded else 0
    # M9: an IOC seen only in withheld jobs counts as disk when every such job is a disk one.
    disk_only = (
        await _restricted_only_iocs(b, latest, b.withheld_disk_jobs)
        if guarded and b.withheld_disk_jobs
        else 0
    )
    b.withheld += restricted_only - disk_only
    b.withheld_disk += disk_only
    if sel.case_iocs and cap > 0:
        cursor: str | None = None
        first = True
        while len(by_key) < cap:
            page = await case_iocs_mod.case_iocs(
                b.session,
                b.org_id,
                b.case.id,
                limit=min(case_iocs_mod.MAX_PAGE, cap - len(by_key)),
                cursor=cursor,
            )
            if first:
                total = page.total if page.total is not None else 0
                total = max(total - restricted_only, 0)
                first = False
            # M8: an IOC a withheld job may have contributed to (one of its listed jobs, or
            # more jobs than listed) is re-aggregated over the other jobs, or left out.
            touched = {
                item.ioc_key: item
                for item in page.items
                if guarded
                and (
                    not b.withheld_jobs.isdisjoint(item.job_ids)
                    or item.count_jobs > len(item.job_ids)
                )
            }
            sightings = await _open_sightings(b, open_jobs, [i.value for i in touched.values()])
            for item in page.items:
                if len(by_key) >= cap or not _SHA256.fullmatch(item.ioc_key):
                    continue
                count_jobs, first_seen, last_seen = item.count_jobs, item.first_seen, item.last_seen
                job_list = list(item.job_ids)
                if item.ioc_key in touched:
                    seen = sightings.get(item.ioc_key)
                    if seen is None:
                        continue  # seen only in withheld jobs (counted in `restricted_only`)
                    count_jobs, first_seen, last_seen = (
                        seen.count_jobs,
                        seen.first_seen,
                        seen.last_seen,
                    )
                    job_list = seen.job_ids
                by_key.setdefault(
                    item.ioc_key,
                    {
                        "ioc_type": ident_or(item.ioc_type),
                        "value": defang(item.value),
                        "ioc_key": item.ioc_key,
                        "count_jobs": max(int(count_jobs), 0),
                        "first_seen": iso(first_seen),
                        "last_seen": iso(last_seen),
                        "job_ids": [str(j) for j in job_list[:5]],
                        "collections": [
                            title(collections[c]) for c in item.in_collections if c in collections
                        ][:MAX_REFS_PER_ROW],
                    },
                )
            cursor = page.next_cursor
            if not cursor or not page.items:
                break
        total = max(total, len(by_key))
    selected = [c for c in dict.fromkeys(sel.collections) if c in collections]
    if len(selected) != len(set(sel.collections)):
        b.count("iocs", collections_out_of_scope=len(set(sel.collections)) - len(selected))
    if selected and cap > 0:
        i = IocCollectionItem
        rows = await b.session.scalars(
            select(i)
            .where(
                i.organization_id == b.org_id,
                i.collection_id.in_(selected),
                i.removed_at.is_(None),
            )
            .order_by(i.added_at, i.id)
        )
        extra = 0
        for row in rows:
            name = title(collections[row.collection_id])
            entry = by_key.get(row.ioc_key)
            if entry is not None:
                if (
                    name not in entry["collections"]
                    and len(entry["collections"]) < MAX_REFS_PER_ROW
                ):
                    entry["collections"].append(name)
                continue
            extra += 1
            if len(by_key) >= cap or not _SHA256.fullmatch(row.ioc_key):
                continue
            by_key[row.ioc_key] = {
                "ioc_type": ident_or(row.ioc_type),
                "value": defang(row.value_norm),
                "ioc_key": row.ioc_key,
                "count_jobs": 0,
                "first_seen": None,
                "last_seen": None,
                "job_ids": [],
                "collections": [name],
            }
        total += extra
    items = list(by_key.values())
    return {"items": items, "total": max(total, len(items))}


def _ti_summary(row: Any) -> str:
    parts = []
    for label, value in (
        ("tags", row.tags),
        ("families", row.families),
        ("ATT&CK", row.attack_ids),
    ):
        joined = F.joined(v for v in (value or []) if isinstance(v, str))
        if joined:
            parts.append(f"{label}: {joined}")
    head = "Reported by the provider" if row.found else "Not found by the provider"
    return defang(
        f"{head} (attributed to {row.provider})" + ("; " + "; ".join(parts) if parts else "")
    )


async def ti(b: Build, ioc_keys: Sequence[str]) -> dict[str, Any]:
    if not b.draft.include.ti or not ioc_keys:
        return {"items": [], "total": 0}
    latest = await latest_by_key(b.session, b.org_id, ioc_keys)
    items: list[dict[str, Any]] = []
    total = 0
    for key in ioc_keys:
        for row in latest.get(key, []):
            total += 1
            if len(items) >= CAPS["ti"] or not ident(row.provider) or not ident(row.status):
                continue
            items.append(
                {
                    "ioc_key": key,
                    "provider": ident_or(row.provider),
                    "status": ident_or(row.status),
                    "found": bool(row.found),
                    "score": fixed(row.score),
                    "score_scale": ident(row.score_scale),
                    "summary": _ti_summary(row),
                    "fetched_at": iso(row.fetched_at),
                    "_cite": cite_key("ti_result", str(row.id), None),
                }
            )
    return {"items": items, "total": total}


# --- ATT&CK, timeline and notes ------------------------------------------------------------------


async def attack(b: Build) -> dict[str, Any]:
    statuses = list(dict.fromkeys(b.draft.include.attack.statuses))
    if not statuses:
        return {"items": [], "total": 0}
    m = CaseAttackMapping
    where = [m.organization_id == b.org_id, m.investigation_id == b.case.id, m.status.in_(statuses)]
    total = int(await b.session.scalar(select(func.count(m.id)).where(*where)) or 0)
    rows = await b.session.scalars(
        select(m).where(*where).order_by(m.technique_id, m.id).limit(CAPS["attack"])
    )
    items = []
    for r in rows:
        if not _TECHNIQUE.fullmatch(r.technique_id):
            continue
        found = attack_label(r.technique_id)
        cites: list[CiteKey] = []
        for source in r.sources or []:
            if not isinstance(source, Mapping) or source.get("kind") not in (
                "capability",
                "finding",
            ):
                continue
            job = source.get("job_id")
            key = b.registry.add(
                str(source["kind"]),
                str(source.get("ref_id") or ""),
                _maybe_uuid(job),
                "attack",
            )
            if key is not None:
                cites.append(key)
        items.append(
            {
                "technique_id": r.technique_id,
                "name": truncate_text(found.name) if found else r.technique_id,
                "tactics": [t.shortname for t in found.tactics if ident(t.shortname)][:16]
                if found
                else [],
                "status": r.status,
                "revoked": bool(found.revoked) if found else False,
                "rationale": analyst(r.rationale),
                "_cites": cites,
            }
        )
    return {"items": items, "total": total}


def _maybe_uuid(value: object) -> uuid.UUID | None:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value)) if value else None
    except ValueError:
        return None


async def timeline(b: Build) -> dict[str, Any]:
    sel = b.draft.include.timeline
    if sel.max == 0:
        return {"items": [], "total": 0}
    kinds = [case_timeline.RefKindName(k) for k in sel.kinds] if sel.kinds else None
    wanted = {k.value for k in kinds} if kinds else None
    start = aware(sel.from_)
    end = aware(sel.to)
    after = case_timeline.Cursor(start, "", uuid.UUID(int=0)) if start else None
    items: list[dict[str, Any]] = []
    total = 0
    scanned = 0
    while scanned < TIMELINE_SCAN:
        entries = await case_timeline.page(
            b.session, b.org_id, b.case.id, limit=TIMELINE_PAGE, after=after, kinds=kinds
        )
        if not entries:
            break
        scanned += len(entries)
        stop = False
        for e in entries:
            ts = aware(e.ts)
            if end is not None and ts is not None and ts > end:
                stop = True
                break
            if wanted is not None and e.ref_kind not in wanted:
                continue
            if e.job_id in b.withheld_jobs and e.ref_kind in _WITHHELD_TIMELINE_KINDS:
                b.omit(e.job_id)
                continue
            total += 1
            if len(items) < min(sel.max, CAPS["timeline"]):
                items.append(
                    {
                        "ts": iso(e.ts),
                        "ts_source": ident_or(e.ts_source),
                        "kind": ident_or(e.kind),
                        "title": defang(e.title),
                        "severity": ident(e.severity),
                        "evidence_id": str(e.evidence_id) if e.evidence_id else None,
                        "job_id": str(e.job_id) if e.job_id else None,
                        "ref_kind": ident_or(e.ref_kind),
                        "ref_id": str(e.ref_id),
                        "_cite": cite_key("timeline", str(e.ref_id), None),
                    }
                )
        if stop or len(entries) < TIMELINE_PAGE:
            break
        last = entries[-1]
        after = case_timeline.Cursor(last.ts, last.kind, last.ref_id)
    if scanned >= TIMELINE_SCAN:
        b.count("timeline", scan_capped=1)
    return {"items": items, "total": total}


async def notes(b: Build) -> dict[str, Any]:
    selected = list(dict.fromkeys(b.draft.include.notes))
    if b.external or not selected:
        # The external profile never carries notes (RT8).
        return {"items": [], "total": 0}
    n, v = AnalystNote, AnalystNoteVersion
    rows = (
        await b.session.execute(
            select(n, v)
            .join(
                v,
                (v.note_id == n.id)
                & (v.version == n.current_version)
                & (v.organization_id == n.organization_id),
            )
            .where(
                n.organization_id == b.org_id,
                n.investigation_id == b.case.id,
                n.id.in_(selected),
                n.deleted_at.is_(None),
            )
            .order_by(n.created_at, n.id)
        )
    ).all()
    if len(rows) != len(selected):
        b.count("notes", out_of_scope=len(selected) - len(rows))
    await b.name_of([ver.author_id for _, ver in rows])
    items = []
    for note, ver in rows[: CAPS["notes"]]:
        cites: list[CiteKey] = []
        for ref in ver.refs or []:
            if not isinstance(ref, Mapping):
                continue
            key = b.registry.add(
                str(ref.get("kind") or ""),
                str(ref.get("ref_id") or ""),
                _maybe_uuid(ref.get("job_id")),
                "note",
            )
            if key is not None:
                cites.append(key)
        items.append(
            {
                "note_id": str(note.id),
                "version": int(ver.version),
                "author": b.name(ver.author_id),
                "created_at": iso(note.created_at),
                "updated_at": iso(ver.created_at),
                "body": analyst(ver.body),
                "_cites": cites,
            }
        )
    return {"items": items, "total": len(rows)}


# --- AI runs ----------------------------------------------------------------------


def run_in_scope(run: AiRun, b: Build) -> bool:
    if run.scope == "investigation":
        return run.investigation_id == b.case.id
    return run.job_id is not None and run.job_id in b.scope.jobs


def _pseudonym_order(item: tuple[str, str]) -> tuple[str, int, str]:
    prefix, _, number = item[0].rpartition("_")
    return (prefix, int(number) if number.isdigit() else 0, item[0])


async def _tree_map(b: Build, run: AiRun) -> dict[str, str]:
    """The run tree's own pseudonym map (the M5 rule): reversed in both profiles (RT2)."""
    tree = await ai_repo.tree_run_ids(b.session, b.org_id, run)
    merged: dict[str, str] = {}
    for item in await ai_repo.inputs_of(b.session, b.org_id, tree):
        for key, value in (item.pseudonym_map or {}).items():
            if isinstance(key, str) and isinstance(value, str):
                merged.setdefault(key, value)
    return merged


def _claim_flags(section: str, text: str) -> list[str]:
    flags = []
    if postprocess.has_verdict_language(text):
        flags.append(OutputFlag.VERDICT_LANGUAGE.value)
    if postprocess.find_urls(text):
        flags.append(OutputFlag.EXTERNAL_URL.value)
    if section == "next_steps" and postprocess.is_command_like(text):
        flags.append(OutputFlag.COMMAND_LIKE.value)
    return flags


async def ai_runs(b: Build) -> dict[str, Any]:
    selected = list(dict.fromkeys(b.draft.include.ai_runs))[: CAPS["ai_runs"]]
    items: list[dict[str, Any]] = []
    dropped = 0
    for run_id in selected:
        run = await b.session.scalar(
            select(AiRun).where(AiRun.organization_id == b.org_id, AiRun.id == run_id)
        )
        if (
            run is None
            or not run_in_scope(run, b)
            or run.status not in AI_FINAL
            or run.error_code == "canary_leak"
        ):
            dropped += 1
            continue
        if run.job_id is not None and run.job_id in b.withheld_jobs:
            b.omit(run.job_id)  # a job-scope run over restricted memory or disk evidence
            continue
        output = await ai_repo.output_of(b.session, b.org_id, run.id)
        if output is None or has_canary_leak(output):
            dropped += 1
            continue
        rows = await ai_repo.citations_of(b.session, b.org_id, output.id)
        links = await LinkContext.load(b.session, b.org_id, rows)
        mapping = await _tree_map(b, run)
        body = build(output, rows, links, mapping, keep_pseudonyms=False)
        if body is None:
            dropped += 1
            continue
        section = await _ai_section(b, run, rows, body)
        items.append(section)
        b.run_originals.extend(sorted(mapping.items(), key=_pseudonym_order))
    if dropped:
        b.count("ai", dropped=dropped)
    return {"items": items, "total": len(items)}


async def _ai_section(
    b: Build, run: AiRun, rows: Sequence[AiCitation], body: AiOutputOut
) -> dict[str, Any]:
    tables = dict(
        (
            await b.session.execute(
                select(AiContextRef.label, AiContextRef.ref_table).where(
                    AiContextRef.organization_id == b.org_id, AiContextRef.run_id == run.id
                )
            )
        ).all()
    )
    by_claim: dict[tuple[str, int], list[AiCitation]] = {}
    for row in rows:
        match = _PATH.match(row.claim_path)
        if match is None or row.status != "verified" or not row.kind or not row.ref_id:
            continue
        by_claim.setdefault((match.group(1), int(match.group(2))), []).append(row)

    claims: list[dict[str, Any]] = []
    omitted_unsupported = 0
    omitted_flagged = 0

    def add(
        section: str, n: int, claim_id: str | None, text: str, status: str, confidence: object
    ) -> None:
        nonlocal omitted_flagged
        clean = defang(text)
        flags = _claim_flags(section, clean)
        if b.external and (
            OutputFlag.VERDICT_LANGUAGE.value in flags or OutputFlag.EXTERNAL_URL.value in flags
        ):
            omitted_flagged += 1  # RT15: never in an external report
            return
        if len(claims) >= CAPS["ai_claims"]:
            return
        cites: list[CiteKey] = []
        for row in by_claim.get((section, n), []):
            key = b.registry.add(
                str(row.kind),
                row.ref_id,
                row.job_id,
                "ai",
                ai_citation_id=row.id,
                ref_table=tables.get(row.label),
            )
            if key is not None and key not in cites:
                cites.append(key)
        cid = claim_id if claim_id and _CLAIM_ID.fullmatch(claim_id) else f"{section}.{n}"
        claims.append(
            {
                "claim_id": cid[:32],
                "section": section,
                "status": status,
                "text": clean,
                "confidence": ident(confidence),
                "flags": flags,
                "_cites": cites,
            }
        )

    for section in ("observed", "interpretation"):
        for n, claim in enumerate(getattr(body, section)):
            if claim.status != ClaimStatus.SUPPORTED:
                omitted_unsupported += 1
                continue
            add(section, n, claim.id, claim.text, "supported", claim.confidence)
    for n, hyp in enumerate(body.hypotheses):
        if hyp.status == ClaimStatus.UNSUPPORTED:
            omitted_unsupported += 1
            continue
        add("hypotheses", n, hyp.id, hyp.text, "hypothesis", hyp.confidence)
    for n, step in enumerate(body.next_steps):
        text = step.text if not step.rationale else f"{step.text} ({step.rationale})"
        add("next_steps", n, None, text, "hypothesis", None)
    for n, limitation in enumerate(body.limitations):
        add("limitations", n, None, limitation, "hypothesis", None)

    return {
        "run_id": str(run.id),
        "task": ident_or(run.task),
        "provider": ident_or(run.provider),
        "model": ident_or(run.served_model or run.model),
        "prompt_version": ident_or(run.prompt_version),
        "context_sha256": run.context_sha256,
        "finished_at": iso(run.finished_at),
        "overall_confidence": ident(body.overall_confidence.level),
        "claims": claims,
        "omitted_unsupported": omitted_unsupported,
        "omitted_flagged": omitted_flagged,
        "disclaimer": DISCLAIMER,
    }
