"""The report snapshot builder (frozen entry point of M6 phase 1; implemented by phase 3).

`build_snapshot` runs in the requester's tenant session opened with
`tenant_session(..., snapshot_read=True)` (one REPEATABLE READ READ ONLY transaction, RT14),
re-reads every selected row, defangs evidence-derived and AI text once (RT24), resolves the
citations and returns the unredacted snapshot plus the `report_citations` rows to write.
Redaction (`redact.py`), the size and render-budget checks, hashing, storage and signing
happen after it (phase 3). The signature never changes.

Citation numbers `C1…Cn` follow the first use in document order (evidence, jobs, findings,
alerts, TI, ATT&CK, timeline, notes, AI claims), then the rows only the analyst selected, in
draft order; the same draft over the same data always numbers the same way.
"""

import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from cyberlab_jobs.report import CAPS, MAX_REFS_PER_ROW, ReportSnapshot, section_counts
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFound
from app.modules.reports import citations as cites
from app.modules.reports import repository as repo
from app.modules.reports import snapshot_sections as sections
from app.modules.reports.citations import CaseScope, CiteKey
from app.modules.reports.models import Report
from app.modules.reports.schemas import ReportDraft


@dataclass(frozen=True)
class CitationRow:
    """One `report_citations` row of the version being finalized."""

    cite_no: int
    kind: str
    ref_table: str
    ref_id: str
    job_id: uuid.UUID | None
    fields_sha256: str
    source: str  # ai | selection | note | attack
    ai_citation_id: uuid.UUID | None = None


@dataclass(frozen=True)
class BuiltSnapshot:
    snapshot: ReportSnapshot
    citations: list[CitationRow]
    # {section: {"included": n, "total": m}} plus build counters (dropped out-of-scope
    # citations, omitted AI claims, ...): ids and counts only.
    counts: dict[str, dict[str, int]] = field(default_factory=dict)
    # (pseudonym, original) of the AI run maps reversed into the claims (never stored, RT29).
    run_originals: tuple[tuple[str, str], ...] = ()


# Sections whose items carry a single `_cite`, then those carrying `_cites`, in document order.
_SINGLE = ("evidence", "jobs", "findings", "alerts", "ti")
_MULTI_BEFORE_TIMELINE = ("attack",)
_MULTI_AFTER_TIMELINE = ("notes",)


def _document_keys(data: dict[str, Any]) -> Iterator[CiteKey]:
    for name in _SINGLE:
        for item in data[name]["items"]:
            if item.get("_cite") is not None:
                yield item["_cite"]
    for name in _MULTI_BEFORE_TIMELINE:
        for item in data[name]["items"]:
            yield from item.get("_cites", [])
    for item in data["timeline"]["items"]:
        if item.get("_cite") is not None:
            yield item["_cite"]
    for name in _MULTI_AFTER_TIMELINE:
        for item in data[name]["items"]:
            yield from item.get("_cites", [])
    for run in data["ai"]["items"]:
        for claim in run["claims"]:
            yield from claim.get("_cites", [])


def _number(
    data: dict[str, Any], resolved: dict[CiteKey, cites.Resolved], order: list[CiteKey]
) -> dict[CiteKey, int]:
    numbers: dict[CiteKey, int] = {}
    for key in [*_document_keys(data), *order]:
        if key in resolved and key not in numbers and len(numbers) < CAPS["citations"]:
            numbers[key] = len(numbers) + 1
    return numbers


def _apply_numbers(data: dict[str, Any], numbers: dict[CiteKey, int]) -> None:
    def single(item: dict[str, Any]) -> None:
        key = item.pop("_cite", None)
        item["cite_no"] = numbers.get(key) if key is not None else None

    def multi(item: dict[str, Any]) -> None:
        keys = item.pop("_cites", [])
        nos = list(dict.fromkeys(numbers[k] for k in keys if k in numbers))
        item["cite_nos"] = nos[:MAX_REFS_PER_ROW]

    for name in (*_SINGLE, "timeline"):
        for item in data[name]["items"]:
            single(item)
    for name in (*_MULTI_BEFORE_TIMELINE, *_MULTI_AFTER_TIMELINE):
        for item in data[name]["items"]:
            multi(item)
    for run in data["ai"]["items"]:
        for claim in run["claims"]:
            multi(claim)


async def build_snapshot(
    session: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    report: Report,
    *,
    now: datetime,
) -> BuiltSnapshot:
    """The unredacted snapshot of `report` as version `latest_version + 1` at `now` (the
    finalize time). Ids and text are all that is taken from the draft."""
    case = await repo.get_case(session, org_id, report.investigation_id)
    if case is None:
        raise NotFound()
    draft = ReportDraft.model_validate(report.draft or {})
    scope = await CaseScope.load(session, org_id, case)
    b = sections.Build(
        session=session,
        org_id=org_id,
        user_id=user_id,
        report=report,
        case=case,
        draft=draft,
        now=now,
        external=report.profile == "external",
        scope=scope,
    )
    data: dict[str, Any] = {"schema_version": "cyberlab.report.v1"}
    data["report"] = await sections.report_info(b)
    data["case"] = await sections.case_section(b)
    data["sections"] = sections.analyst_sections(b)
    data["evidence"] = await sections.evidence(b)
    data["custody"] = await sections.custody(b)
    data["jobs"], job_ids = await sections.jobs(b)
    data["findings"] = await sections.findings(b, job_ids)
    data["alerts"] = await sections.alerts(b, job_ids)
    data["iocs"] = await sections.iocs(b)
    data["ti"] = await sections.ti(b, [i["ioc_key"] for i in data["iocs"]["items"]])
    # Sources that cite, registered in document order (the selection last).
    data["attack"] = await sections.attack(b)
    data["timeline"] = await sections.timeline(b)
    data["notes"] = await sections.notes(b)
    data["ai"] = await sections.ai_runs(b)
    selection: list[CiteKey] = []
    for ref in draft.include.cited_rows:
        key = b.registry.add(ref.kind, ref.ref_id, ref.job_id, "selection")
        if key is not None:
            selection.append(key)

    # Notes are never cited in an external report (they are not in it, RT8): neither as a
    # `note` citation nor as a `timeline` entry that resolves to an `analyst_notes` row.
    drop_kinds = frozenset({"note"}) if b.external else frozenset()
    drop_tables = frozenset({"analyst_notes"}) if b.external else frozenset()
    requests = list(b.registry.requests.values())
    resolved = await cites.resolve(
        session,
        scope,
        requests,
        with_paths=not b.external,
        drop_kinds=drop_kinds,
        drop_tables=drop_tables,
    )
    numbers = _number(data, resolved, list(b.registry.requests))
    _apply_numbers(data, numbers)
    considered = sum(1 for r in requests if r.kind not in drop_kinds)
    dropped = b.registry.invalid + (considered - len(resolved))
    by_number = sorted(numbers.items(), key=lambda kv: kv[1])
    data["citations"] = {
        "items": [
            {
                "cite_no": no,
                "kind": resolved[key].kind,
                "ref_table": resolved[key].ref_table,
                "ref_id": resolved[key].ref_id,
                "job_id": str(resolved[key].job_id) if resolved[key].job_id else None,
                "source": resolved[key].source,
                "fields": resolved[key].fields,
                "fields_sha256": resolved[key].fields_sha256,
                "path": resolved[key].path,
            }
            for key, no in by_number
        ],
        "total": len(resolved),
        "dropped_out_of_scope": dropped,
    }
    snapshot = ReportSnapshot.model_validate(data)
    rows = [
        CitationRow(
            cite_no=no,
            kind=resolved[key].kind,
            ref_table=resolved[key].ref_table,
            ref_id=resolved[key].ref_id,
            job_id=resolved[key].job_id,
            fields_sha256=resolved[key].fields_sha256,
            source=resolved[key].source,
            ai_citation_id=resolved[key].ai_citation_id,
        )
        for key, no in by_number
    ]
    counts: dict[str, dict[str, int]] = section_counts(snapshot)
    for name, extra in b.counts.items():
        counts.setdefault(name, {}).update(extra)
    counts["citations"]["dropped_out_of_scope"] = dropped
    ai_omitted = {
        "omitted_unsupported": sum(r.omitted_unsupported for r in snapshot.ai.items),
        "omitted_flagged": sum(r.omitted_flagged for r in snapshot.ai.items),
    }
    counts["ai"].update(ai_omitted)
    return BuiltSnapshot(
        snapshot=snapshot,
        citations=rows,
        counts=counts,
        run_originals=tuple(b.run_originals),
    )
