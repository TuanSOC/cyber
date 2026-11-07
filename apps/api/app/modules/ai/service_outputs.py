"""The output read model of a run (M5 phase 7).

Built from the stored, sanitized body (`ai_outputs.body`), the claim verdicts
(`ai_outputs.verification.claims`) and the checked citations (`ai_citations`):
- every claim carries its status (`supported` / `unsupported` / `hypothesis`) and reason;
  a claim without a stored verdict is shown as unsupported (never as backed by evidence);
- every citation carries its status and reason; a citation without a stored row is shown
  unverified. Only **verified** citations get a deep-link descriptor, built here from the
  stored kind / ref id / job (never from model text), to an internal route and tab;
- display text has its pseudonyms reversed with the run tree's own map (unless kept);
- a timeline entry's time comes from the row of its first verified citation (the
  verifier's rule), never from model text (`TimelineEntry` has no time field).

A canary-leak output is never returned (the caller withholds it before calling `build`).
"""

import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Any

from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.ai.contracts import (
    CitationReason,
    CitationStatus,
    ClaimStatus,
    ClaimVerdict,
    OutputFlag,
    OutputVerification,
    RefKind,
)
from app.modules.ai.models import AiCitation, AiContextRef, AiOutput
from app.modules.ai.output_schema import AnalysisOutput, Citation
from app.modules.ai.schemas import (
    AiAttackOut,
    AiCitationOut,
    AiClaimOut,
    AiDeepLink,
    AiHypothesisOut,
    AiNextStepOut,
    AiOutputOut,
    AiOverallConfidenceOut,
    AiTimelineOut,
    AiVerificationOut,
    DeepLinkRoute,
    DeepLinkTab,
    PseudonymMode,
)
from app.modules.analysis.models import AnalysisJob
from app.modules.pcap_analysis.models import NetworkRecord
from app.modules.reverse_engineering.models import ReDecompilation, ReFunction

# Kind -> result tab of the cited job's page; kinds absent here get no link.
_PCAP_TABS: dict[RefKind, DeepLinkTab] = {
    RefKind.JOB: "overview",
    RefKind.FINDING: "findings",
    RefKind.ALERT: "alerts",
    RefKind.FLOW: "flows",
    RefKind.IOC: "iocs",
    RefKind.TIMELINE: "timeline",
}
_STATIC_TABS: dict[RefKind, DeepLinkTab] = {
    RefKind.JOB: "overview",
    RefKind.SAMPLE: "overview",
    RefKind.PE_SUMMARY: "sections",
    RefKind.FINDING: "findings",
    RefKind.SIGNATURE: "signatures",
    RefKind.CAPABILITY: "capabilities",
    RefKind.STRING: "strings",
    RefKind.IOC: "iocs",
}
# M8: a memory job's page has the shared findings / IOCs / timeline tabs.
_MEMORY_TABS: dict[RefKind, DeepLinkTab] = {
    RefKind.JOB: "overview",
    RefKind.FINDING: "findings",
    RefKind.IOC: "iocs",
    RefKind.TIMELINE: "timeline",
}
# M9: a disk job's page (`/forensics/{job}`) has the same shared tabs.
_DISK_TABS: dict[RefKind, DeepLinkTab] = dict(_MEMORY_TABS)
# M10: an RE job's page (`/reverse-engineering/{job}`): overview, findings and IOCs (no
# timeline), and one function (`?fn=<entry>&tab=facts|code`): a `G` / `Q` link's `ref` is the
# function's `0x…` entry, looked up from the cited row (never from model text).
_RE_TABS: dict[RefKind, DeepLinkTab] = {
    RefKind.JOB: "overview",
    RefKind.FINDING: "findings",
    RefKind.IOC: "iocs",
    RefKind.FUNCTION: "facts",
    RefKind.CODE: "code",
}
_ENTRY_KINDS = frozenset({RefKind.FUNCTION, RefKind.CODE})
# Analyzer -> (route, tabs): every analyzer (RT1: no "else" mislabels a memory job).
ANALYZER_LINKS: dict[str, tuple[DeepLinkRoute, dict[RefKind, DeepLinkTab]]] = {
    "pcap": ("pcap", _PCAP_TABS),
    "static": ("malware", _STATIC_TABS),
    "memory": ("memory", _MEMORY_TABS),
    "disk": ("forensics", _DISK_TABS),
    "reverse": ("reverse-engineering", _RE_TABS),
}
_RECORD_TABS: dict[str, DeepLinkTab] = {"dns": "dns", "http": "http", "tls": "tls"}
# A job overview / sample / PE summary link carries no row ref.
_NO_REF = frozenset({RefKind.JOB, RefKind.SAMPLE, RefKind.PE_SUMMARY})
_PSEUDONYM_EDGE = r"(?<![A-Za-z0-9_])({})(?![A-Za-z0-9_])"
_TIMELINE_PATH = re.compile(r"^timeline\[(\d+)\]\.citations\[(\d+)\]$")
# Ref table -> SQL expression (alias `t`) of the row's time: the verifier's rule. Table
# names and expressions come only from here, never from a stored value.
_ROW_TIME: dict[str, str] = {
    "analysis_jobs": "coalesce(t.finished_at, t.created_at)",
    "analysis_findings": "t.ts",
    "network_alerts": "t.ts",
    "network_records": "t.ts",
    "iocs": "t.first_seen",
    "analysis_timeline": "t.ts",
    "evidence": "t.uploaded_at",
    "evidence_custody_events": "t.occurred_at",
    "investigations": "t.created_at",
    "ti_results": "t.fetched_at",
}
# Static rows have no time of their own: the analysis time of their job.
_JOB_TIME_TABLES = frozenset(
    {
        "malware_samples",
        "malware_sections",
        "malware_imports",
        "malware_exports",
        "malware_resources",
        "malware_strings",
        "malware_signature_matches",
        "malware_capabilities",
        "re_functions",
        "re_decompilations",
    }
)
# When a citation's label has no stored ref (not expected), its kind names the table.
_KIND_TABLE: dict[RefKind, str] = {
    RefKind.JOB: "analysis_jobs",
    RefKind.FINDING: "analysis_findings",
    RefKind.ALERT: "network_alerts",
    RefKind.FLOW: "network_flows",
    RefKind.RECORD: "network_records",
    RefKind.IOC: "iocs",
    RefKind.TI_RESULT: "ti_results",
    RefKind.SAMPLE: "malware_samples",
    RefKind.PE_SUMMARY: "malware_samples",
    RefKind.SIGNATURE: "malware_signature_matches",
    RefKind.CAPABILITY: "malware_capabilities",
    RefKind.STRING: "malware_strings",
    RefKind.TIMELINE: "analysis_timeline",
    RefKind.INVESTIGATION: "investigations",
    RefKind.FUNCTION: "re_functions",
    RefKind.CODE: "re_decompilations",
}


def reverser(pseudonym_map: Mapping[str, str]) -> Callable[[str], str]:
    """Replace whole pseudonym tokens (`INT_IP_1`, never inside `INT_IP_12`) by their
    originals. Planted pseudonym-shaped text was neutralized by the builder (RT15)."""
    keys = sorted((k for k in pseudonym_map if k), key=len, reverse=True)
    if not keys:
        return lambda text: text
    pattern = re.compile(_PSEUDONYM_EDGE.format("|".join(re.escape(k) for k in keys)))
    return lambda text: pattern.sub(lambda m: pseudonym_map[m.group(1)], text)


class LinkContext:
    """What deep links need besides the citation row: each cited job's analyzer, the kind
    (dns / http / tls) of each cited network record and (M10) the `0x…` entry of each cited
    function (`G`) or code (`Q`) row."""

    def __init__(
        self,
        analyzers: dict[uuid.UUID, str],
        record_kinds: dict[str, str],
        entries: dict[str, str] | None = None,
    ) -> None:
        self.analyzers = analyzers
        self.record_kinds = record_kinds
        self.entries = entries or {}

    @classmethod
    async def load(
        cls, session: AsyncSession, org_id: uuid.UUID, rows: Sequence[AiCitation]
    ) -> "LinkContext":
        verified = [r for r in rows if r.status == CitationStatus.VERIFIED.value]
        job_ids = {r.job_id for r in verified if r.job_id is not None}
        analyzers: dict[uuid.UUID, str] = {}
        if job_ids:
            found = await session.execute(
                select(AnalysisJob.id, AnalysisJob.analyzer).where(
                    AnalysisJob.organization_id == org_id, AnalysisJob.id.in_(job_ids)
                )
            )
            analyzers = {job: getattr(a, "value", str(a)) for job, a in found}
        record_ids: set[uuid.UUID] = set()
        for r in verified:
            if r.kind == RefKind.RECORD.value and r.ref_id:
                try:
                    record_ids.add(uuid.UUID(r.ref_id))
                except ValueError:
                    continue
        kinds: dict[str, str] = {}
        if record_ids:
            found_kinds = await session.execute(
                select(NetworkRecord.id, NetworkRecord.kind).where(
                    NetworkRecord.organization_id == org_id, NetworkRecord.id.in_(record_ids)
                )
            )
            kinds = {str(rid): getattr(k, "value", str(k)) for rid, k in found_kinds}
        return cls(analyzers, kinds, await _entries(session, org_id, verified))


async def _entries(
    session: AsyncSession, org_id: uuid.UUID, verified: Sequence[AiCitation]
) -> dict[str, str]:
    """M10: row id -> `0x…` entry of the cited `re_functions` / `re_decompilations` rows."""
    wanted: dict[str, list[uuid.UUID]] = {"function": [], "code": []}
    for r in verified:
        if r.kind in wanted and r.ref_id:
            try:
                wanted[r.kind].append(uuid.UUID(r.ref_id))
            except ValueError:
                continue
    out: dict[str, str] = {}
    for model, column, ids in (
        (ReFunction, ReFunction.entry, wanted["function"]),
        (ReDecompilation, ReDecompilation.function_entry, wanted["code"]),
    ):
        if not ids:
            continue
        rows = await session.execute(
            select(model.id, column).where(model.organization_id == org_id, model.id.in_(ids))
        )
        out.update({str(rid): f"0x{int(entry):x}" for rid, entry in rows if entry is not None})
    return out


def _first_verified_timeline(rows: Sequence[AiCitation]) -> dict[int, AiCitation]:
    """Timeline entry index -> its first verified citation row."""
    firsts: dict[int, tuple[int, AiCitation]] = {}
    for row in rows:
        match = _TIMELINE_PATH.match(row.claim_path)
        if match is None or row.status != CitationStatus.VERIFIED.value or not row.ref_id:
            continue
        entry, position = int(match.group(1)), int(match.group(2))
        if entry not in firsts or position < firsts[entry][0]:
            firsts[entry] = (position, row)
    return {entry: row for entry, (_, row) in firsts.items()}


def _uuids(values: Sequence[str]) -> list[uuid.UUID]:
    out = []
    for value in values:
        try:
            out.append(uuid.UUID(value))
        except ValueError:
            continue
    return out


def _table_of(row: AiCitation, tables: Mapping[str, str]) -> str | None:
    table = tables.get(row.label)
    if table is None and row.kind:
        try:
            table = _KIND_TABLE.get(RefKind(row.kind))
        except ValueError:
            table = None
    return table


async def timeline_times(
    session: AsyncSession, org_id: uuid.UUID, run_id: uuid.UUID, rows: Sequence[AiCitation]
) -> dict[int, datetime]:
    """Timeline entry index -> the time of the row its first verified citation names."""
    firsts = _first_verified_timeline(rows)
    if not firsts:
        return {}
    labels = {row.label for row in firsts.values()}
    refs = await session.execute(
        select(AiContextRef.label, AiContextRef.ref_table).where(
            AiContextRef.organization_id == org_id,
            AiContextRef.run_id == run_id,
            AiContextRef.label.in_(labels),
        )
    )
    tables = {label: table for label, table in refs}
    by_table: dict[str, list[AiCitation]] = {}
    for row in firsts.values():
        table = _table_of(row, tables)
        if table is not None:
            by_table.setdefault(table, []).append(row)

    times: dict[tuple[str, str], datetime] = {}  # (table, row key) -> time
    for table, cited in by_table.items():
        if table in _JOB_TIME_TABLES:
            ids = list({r.job_id for r in cited if r.job_id is not None})
            sql = (
                "SELECT t.id::text AS id, coalesce(t.finished_at, t.created_at) AS ts "
                "FROM analysis_jobs t WHERE t.organization_id = :org AND t.id = ANY(:ids)"
            )
            params: dict[str, Any] = {"org": org_id, "ids": ids}
        elif table in _ROW_TIME:
            ids = _uuids([r.ref_id for r in cited if r.ref_id])
            sql = (
                f"SELECT t.id::text AS id, ({_ROW_TIME[table]}) AS ts FROM {table} t "  # noqa: S608
                "WHERE t.organization_id = :org AND t.id = ANY(:ids)"
            )
            params = {"org": org_id, "ids": ids}
        elif table == "network_flows":
            ids = list({r.job_id for r in cited if r.job_id is not None})
            sql = (
                "SELECT t.job_id::text || '|' || t.flow_ref AS id, min(t.ts) AS ts "
                "FROM network_flows t WHERE t.organization_id = :org "
                "AND t.job_id = ANY(:ids) AND t.flow_ref = ANY(:refs) "
                "GROUP BY t.job_id, t.flow_ref"
            )
            params = {"org": org_id, "ids": ids, "refs": [r.ref_id for r in cited if r.ref_id]}
        else:
            continue
        if not ids:
            continue
        for found in await session.execute(text(sql), params):
            if found.ts is not None:
                times[(table, found.id)] = found.ts

    out: dict[int, datetime] = {}
    for entry, row in firsts.items():
        table = _table_of(row, tables) or ""
        if table in _JOB_TIME_TABLES:
            key = str(row.job_id)
        elif table == "network_flows":
            key = f"{row.job_id}|{row.ref_id}"
        else:
            key = row.ref_id or ""
        ts = times.get((table, key))
        if ts is not None:
            out[entry] = ts
    return out


def deep_link(row: AiCitation | None, links: LinkContext) -> AiDeepLink | None:
    """The internal link of a verified citation, or None (unverified, invalid, unknown
    kind or job). Built only from stored ids and the kind, never from model text."""
    if row is None or row.status != CitationStatus.VERIFIED.value or not row.kind:
        return None
    try:
        kind = RefKind(row.kind)
    except ValueError:
        return None
    if kind is RefKind.DIGEST_CLAIM or not row.ref_id:
        return None
    if kind is RefKind.EVIDENCE:
        return AiDeepLink(route="evidence", job_id=None, tab=None, ref=row.ref_id)
    if kind is RefKind.INVESTIGATION:
        return AiDeepLink(route="investigation", job_id=None, tab=None, ref=row.ref_id)
    if row.job_id is None:
        return None
    analyzer = links.analyzers.get(row.job_id)
    found = ANALYZER_LINKS.get(analyzer or "")
    if found is None:
        return None
    route, tabs = found
    tab: DeepLinkTab | None
    if analyzer == "pcap" and kind is RefKind.RECORD:
        tab = _RECORD_TABS.get(links.record_kinds.get(row.ref_id, ""))
    else:
        tab = tabs.get(kind)
    if tab is None:
        return None
    if kind in _ENTRY_KINDS:
        entry = links.entries.get(row.ref_id)
        if entry is None:
            return None
        return AiDeepLink(route=route, job_id=row.job_id, tab=tab, ref=entry)
    ref = None if kind in _NO_REF else row.ref_id
    return AiDeepLink(route=route, job_id=row.job_id, tab=tab, ref=ref)


def _verdict(
    claims: Mapping[str, ClaimVerdict], key: str, default: ClaimStatus
) -> tuple[ClaimStatus, CitationReason | None]:
    verdict = claims.get(key)
    if verdict is None:
        reason = CitationReason.NO_VERIFIED_CITATION if default is ClaimStatus.UNSUPPORTED else None
        return default, reason
    return verdict.status, verdict.reason


def _verification(raw: dict[str, Any]) -> OutputVerification:
    try:
        return OutputVerification.model_validate(raw or {})
    except ValidationError:
        return OutputVerification()


def _flags(raw: Sequence[Any]) -> list[OutputFlag]:
    out = []
    for value in raw or ():
        try:
            out.append(OutputFlag(value))
        except ValueError:
            continue
    return out


def has_canary_leak(output: AiOutput) -> bool:
    return OutputFlag.CANARY_LEAK.value in (output.flags or [])


class _Builder:
    def __init__(
        self,
        rows: Sequence[AiCitation],
        links: LinkContext,
        text: Callable[[str], str],
    ) -> None:
        self.by_path = {row.claim_path: row for row in rows}
        self.links = links
        self.text = text

    def citation(
        self, path: str, label: str, field: str | None, quote: str | None
    ) -> AiCitationOut:
        row = self.by_path.get(path)
        if row is None:
            return AiCitationOut(
                label=label,
                kind=None,
                status=CitationStatus.UNVERIFIED,
                reason=None,
                field=field,
                quote=self.text(quote) if quote else quote,
                ref_id=None,
                job_id=None,
                stale=False,
                link=None,
            )
        kind = None
        if row.kind:
            try:
                kind = RefKind(row.kind)
            except ValueError:
                kind = None
        reason = None
        if row.reason:
            try:
                reason = CitationReason(row.reason)
            except ValueError:
                reason = None
        return AiCitationOut(
            label=row.label,
            kind=kind,
            status=CitationStatus(row.status),
            reason=reason,
            field=row.field,
            quote=self.text(row.quote) if row.quote else row.quote,
            ref_id=row.ref_id,
            job_id=row.job_id,
            stale=row.stale,
            link=deep_link(row, self.links),
        )

    def citations(self, prefix: str, items: Sequence[Citation]) -> list[AiCitationOut]:
        return [
            self.citation(f"{prefix}[{m}]", c.ref, c.field, c.quote) for m, c in enumerate(items)
        ]


def build(
    output: AiOutput,
    rows: Sequence[AiCitation],
    links: LinkContext,
    pseudonym_map: Mapping[str, str],
    *,
    keep_pseudonyms: bool,
    times: Mapping[int, datetime] | None = None,
) -> AiOutputOut | None:
    """The display model, or None when the stored body no longer validates (never shown
    half-parsed)."""
    if has_canary_leak(output):
        return None
    try:
        body = AnalysisOutput.model_validate(output.body)
    except ValidationError:
        return None
    verification = _verification(output.verification)
    claims = verification.claims
    text = (lambda t: t) if keep_pseudonyms else reverser(pseudonym_map)
    b = _Builder(rows, links, text)
    mode: PseudonymMode = "kept" if keep_pseudonyms else "reversed"

    def claim_out(section: str, n: int, claim: Any) -> AiClaimOut:
        status, reason = _verdict(claims, claim.id, ClaimStatus.UNSUPPORTED)
        return AiClaimOut(
            id=claim.id,
            text=text(claim.text),
            confidence=claim.confidence,
            status=status,
            reason=reason,
            citations=b.citations(f"{section}[{n}].citations", claim.citations),
        )

    hypotheses = []
    for n, h in enumerate(body.hypotheses):
        status, reason = _verdict(claims, h.id, ClaimStatus.HYPOTHESIS)
        hypotheses.append(
            AiHypothesisOut(
                id=h.id,
                text=text(h.text),
                confidence=h.confidence,
                status=status,
                reason=reason,
                supporting=b.citations(f"hypotheses[{n}].supporting", h.supporting),
                contradicting=b.citations(f"hypotheses[{n}].contradicting", h.contradicting),
            )
        )
    attacks = []
    for n, a in enumerate(body.attack_techniques):
        status, reason = _verdict(claims, f"attack:{a.technique_id}", ClaimStatus.UNSUPPORTED)
        attacks.append(
            AiAttackOut(
                technique_id=a.technique_id,
                rationale=text(a.rationale),
                status=status,
                reason=reason,
                citations=b.citations(f"attack_techniques[{n}].citations", a.citations),
            )
        )
    timeline = []
    for n, e in enumerate(body.timeline):
        status, reason = _verdict(claims, f"timeline:{n}", ClaimStatus.UNSUPPORTED)
        timeline.append(
            AiTimelineOut(
                ts=(times or {}).get(n),
                text=text(e.text),
                status=status,
                reason=reason,
                citations=b.citations(f"timeline[{n}].citations", e.citations),
            )
        )
    next_steps = [
        AiNextStepOut(
            text=text(s.text),
            rationale=text(s.rationale),
            refs=[
                b.citation(f"next_steps[{n}].refs[{m}]", ref, None, None)
                for m, ref in enumerate(s.refs)
            ],
        )
        for n, s in enumerate(body.next_steps)
    ]
    return AiOutputOut(
        observed=[claim_out("observed", n, c) for n, c in enumerate(body.observed)],
        interpretation=[
            claim_out("interpretation", n, c) for n, c in enumerate(body.interpretation)
        ],
        hypotheses=hypotheses,
        overall_confidence=AiOverallConfidenceOut(
            level=body.overall_confidence.level,
            rationale=text(body.overall_confidence.rationale),
        ),
        next_steps=next_steps,
        limitations=[text(item) for item in body.limitations],
        attack_techniques=attacks,
        timeline=timeline,
        flags=_flags(output.flags),
        verification=AiVerificationOut(
            citations=dict(verification.citations),
            dropped_refs=verification.dropped_refs,
            invalid_attack=verification.invalid_attack,
            truncation=dict(verification.truncation),
            reused_from_run_id=verification.reused_from_run_id,
        ),
        pseudonyms=mode,
        created_at=output.created_at,
    )
