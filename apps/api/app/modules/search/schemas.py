"""Org-wide search schemas (M7 phase 1, FROZEN; phase 4 implements the route).

`POST /orgs/{org}/search` with a JSON body (RT13): a query string in a URL would land in the
uvicorn access log, the Next.js request log and the browser history. The query text is never
logged and never audited (recorded decision, RT34). Postgres FTS (`simple`) and trigram only;
OpenSearch is deferred with criteria (ARCHITECTURE).
"""

import uuid
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

SearchType = Literal["observable", "case", "evidence", "finding", "alert", "note"]
SEARCH_TYPES: tuple[SearchType, ...] = (
    "observable",
    "case",
    "evidence",
    "finding",
    "alert",
    "note",
)
MatchKind = Literal["exact", "fts", "trigram"]
# The schema bounds the raw text; the service applies SEARCH_MIN/MAX_QUERY_CHARS to the
# stripped query and answers `422 search_query_invalid`.
RawQuery = Annotated[str, StringConstraints(min_length=1, max_length=1024, pattern=r"^[^\x00]*$")]
Cursor = Annotated[
    str, StringConstraints(min_length=1, max_length=512, pattern=r"^[A-Za-z0-9_-]+$")
]


class SearchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    q: RawQuery
    # Omitted: every type.
    types: Annotated[list[SearchType], Field(min_length=1, max_length=6)] | None = None
    # Opaque continuation of one type's hits (from `SearchGroup.next_cursor`).
    cursor: Cursor | None = None


class SearchHit(BaseModel):
    type: SearchType
    id: str
    title: str
    # Plain text around the match (never HTML), at most 240 characters.
    snippet: str | None
    match: MatchKind
    investigation_id: uuid.UUID | None
    case_ref: str | None
    job_id: uuid.UUID | None
    evidence_id: uuid.UUID | None
    # Observable hits: the correlation kind.
    kind: str | None
    # The app path of the deep link (relative, under /o/{org}).
    href: str


class SearchGroup(BaseModel):
    type: SearchType
    hits: list[SearchHit]
    next_cursor: str | None


class SearchOut(BaseModel):
    groups: list[SearchGroup]
    # True when a type hit the statement timeout and returned partial results.
    partial: bool
