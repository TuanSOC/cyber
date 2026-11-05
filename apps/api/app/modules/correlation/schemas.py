"""Correlation read schemas (M7 phase 1, FROZEN; phase 4 implements the routes).

Deterministic and org-scoped: counts only, no scores. A key seen in more than
`CORRELATION_COMMON_KEY_JOBS` jobs is flagged `common` and left out of the related-case
ranking.
"""

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

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


class CorrelationLookupIn(BaseModel):
    """`POST /correlations/lookup`: the observable travels in the JSON body only, never in a
    URL (an IOC value in a query string lands in the uvicorn and gateway access logs and the
    browser history, like a search query, RT13). It is never logged or audited."""

    model_config = ConfigDict(extra="forbid")

    kind: CorrelationKind
    value: Annotated[str, StringConstraints(min_length=1, max_length=2048)]


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
    # Additive (M7 follow-up): the ids of this job's `iocs` rows carrying the key, so the IOC
    # tab joins its rows by id (RT8: never by re-normalizing values in the browser). The
    # indexer keeps one row per (job, kind, key), the first source row; a hash taken from the
    # sample or the evidence hashes (not an `iocs` row) has none.
    source_ids: list[str] = Field(default_factory=list)


class JobCorrelationsOut(BaseModel):
    job_id: uuid.UUID
    # False until the indexer processed the job (`correlation_job_state`).
    indexed: bool
    truncated: bool
    # Keys seen in at least one other job (every key with `include_unique=true`), optionally
    # of one `kind`; at most 200 per page, sorted by other cases desc, then kind and value.
    items: list[SeenInOut]
    # Every key of the job (whatever the filters).
    total_keys: int
    # Additive (M7 follow-up): the next page of `items` (`?cursor=`), null on the last page.
    next_cursor: str | None = None


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


class CollectionRefOut(BaseModel):
    """An IOC collection of the org holding the key (an item not removed)."""

    collection_id: uuid.UUID
    investigation_id: uuid.UUID
    case_ref: str
    name: str
    archived: bool


class CorrelationLookupOut(BaseModel):
    """`POST /correlations/lookup` (`{kind, value}` in the body): the server normalizes the
    value (M6 `normalize_item`, RT8). A value that does not normalize as `kind` answers
    `422 search_query_invalid` (the error never echoes the value), so `value_norm` and `key`
    are always set in a 200; they stay nullable for older clients only."""

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
    # Additive (M7 follow-up). Stored threat intel answers for the key in this org (a count
    # of `ti_results` joined on `ioc_key`); null for kinds threat intel never looks up (JA3,
    # JA3S, certificate hashes).
    ti_results: int | None = None
    # The org's IOC collections holding the key (at most 20, most recently updated first),
    # and how many there are in all.
    collections: list[CollectionRefOut] = Field(default_factory=list)
    collections_total: int = 0


class SharedKeyOut(BaseModel):
    kind: CorrelationKind
    value: str
    key: str


class RelatedCaseOut(BaseModel):
    investigation_id: uuid.UUID
    case_ref: str
    title: str
    status: InvestigationStatus
    shared_keys: int
    kinds: dict[CorrelationKind, int]
    last_seen: datetime | None
    # Additive (M7 follow-up): at most 5 of the shared (non-common) keys, most recently
    # seen first.
    sample_keys: list[SharedKeyOut] = Field(default_factory=list)


class RelatedCasesOut(BaseModel):
    investigation_id: uuid.UUID
    # Ranked by shared keys (common keys excluded), at most 20.
    items: list[RelatedCaseOut]
    common_keys_excluded: int
