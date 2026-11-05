"""Correlation read schemas (M7 phase 1, FROZEN; phase 4 implements the routes).

Deterministic and org-scoped: counts only, no scores. A key seen in more than
`CORRELATION_COMMON_KEY_JOBS` jobs is flagged `common` and left out of the related-case
ranking.
"""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.modules.analysis.models import Analyzer
from app.modules.investigations.models import InvestigationStatus

CorrelationKind = Literal[
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "email",
    "md5",
    "sha1",
    "sha256",
    "ja3",
    "ja3s",
    "cert_sha256",
]


class CaseRefOut(BaseModel):
    investigation_id: uuid.UUID
    case_ref: str
    title: str
    jobs: int
    last_seen: datetime | None


class SeenInOut(BaseModel):
    """One key of a job and where else the org saw it ("also seen in")."""

    kind: CorrelationKind
    value: str
    key: str
    other_jobs: int
    other_cases: int
    first_seen: datetime | None
    last_seen: datetime | None
    common: bool
    # At most 5 other cases, most recent first.
    top_cases: list[CaseRefOut]


class JobCorrelationsOut(BaseModel):
    job_id: uuid.UUID
    # False until the indexer processed the job (`correlation_job_state`).
    indexed: bool
    truncated: bool
    # Only keys seen in at least one other job, at most 200.
    items: list[SeenInOut]
    total_keys: int


class OccurrenceOut(BaseModel):
    job_id: uuid.UUID
    analyzer: Analyzer
    investigation_id: uuid.UUID
    case_ref: str
    title: str
    evidence_id: uuid.UUID
    evidence_filename: str
    first_seen: datetime | None
    last_seen: datetime | None


class CorrelationLookupOut(BaseModel):
    """`GET /correlations?kind=&value=`: the server normalizes the value (M6
    `normalize_item`, RT8). `key` is null when the value does not normalize."""

    kind: CorrelationKind
    value_norm: str | None
    key: str | None
    common: bool
    jobs: int
    cases: int
    first_seen: datetime | None
    last_seen: datetime | None
    # At most 100 occurrences, most recent first.
    items: list[OccurrenceOut]


class RelatedCaseOut(BaseModel):
    investigation_id: uuid.UUID
    case_ref: str
    title: str
    status: InvestigationStatus
    shared_keys: int
    kinds: dict[CorrelationKind, int]
    last_seen: datetime | None


class RelatedCasesOut(BaseModel):
    investigation_id: uuid.UUID
    # Ranked by shared keys (common keys excluded), at most 20.
    items: list[RelatedCaseOut]
    common_keys_excluded: int
