"""The report snapshot builder (frozen entry point of M6 phase 1; implemented by phase 3).

`build_snapshot` runs in the requester's tenant session opened with
`tenant_session(..., snapshot_read=True)` (one REPEATABLE READ READ ONLY transaction, RT14),
re-reads every selected row, defangs evidence-derived and AI text once (RT24), resolves the
citations and returns the unredacted snapshot plus the `report_citations` rows to write.
Redaction (`redact.py`), the size and render-budget checks, hashing, storage and signing
happen after it (phase 3). The signature never changes.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from cyberlab_jobs.report import ReportSnapshot
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.reports.models import Report


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


async def build_snapshot(
    session: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    report: Report,
    *,
    now: datetime,
) -> BuiltSnapshot:
    """Phase 3."""
    raise NotImplementedError("reports.snapshot.build_snapshot lands in M6 phase 3")
