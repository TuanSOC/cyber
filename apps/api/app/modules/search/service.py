"""Org-wide search (M7 phase 4): `POST /orgs/{org}/search` with a JSON body (RT13).

- Input: `q` stripped, `SEARCH_MIN..MAX_QUERY_CHARS` characters, no control characters
  (`422 search_query_invalid`); `types` default all; a `cursor` continues one type.
- Rate limit `SEARCH_PER_USER_PER_MIN` per user (`429`).
- One transaction (the request's tenant session) with `SET LOCAL statement_timeout`; the
  types run sequentially, each in its own SAVEPOINT, so a type that times out answers an
  empty group with `error: "timeout"` (and marks the response `partial`), and the others
  still answer.
- At most `SEARCH_HITS_PER_TYPE` hits per type; plain-text titles and snippets (never HTML),
  the case TLP, and the query matches in the snippet as UTF-16 ranges (`snippet_ranges`).
- **The query is never logged or audited** (recorded decision): it travels only in the body,
  no log line here carries it, and errors never echo it (a database error is logged by type
  and SQLSTATE only, then answered as a generic 500).
"""

import base64
import binascii
import json
import logging
import re
import uuid
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from sqlalchemy import RowMapping, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import rate_limit
from app.core.config import get_settings
from app.core.errors import AppError, SearchQueryInvalid
from app.core.rbac import OrgContext
from app.modules.correlation.normalize import candidate_keys
from app.modules.investigations.repository import escape_like
from app.modules.investigations.schemas import case_ref
from app.modules.notes.paging import InvalidCursor
from app.modules.search import queries
from app.modules.search.schemas import (
    SEARCH_TYPES,
    SearchGroup,
    SearchHit,
    SearchIn,
    SearchOut,
    SearchType,
    TextRange,
)

log = logging.getLogger(__name__)

TITLE_MAX = 200
SNIPPET_MAX = 200
SNIPPET_LEAD = 60
# Trigram needs three characters to use the index (and to mean anything).
TRIGRAM_MIN_CHARS = 3
MAX_OFFSET = 200
MAX_RANGES = 20
RANGE_MIN_CHARS = 2
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_WORDS = re.compile(r"\w+", re.UNICODE)
_CASE_NUMBER = re.compile(r"(?:case[-\s#]*)?0*(\d{1,9})", re.IGNORECASE)
_QUERY_CANCELED = "57014"


class SearchFailed(AppError):
    status_code = 500
    code = "search_failed"
    message = "The search could not be completed"


Page = tuple[list[SearchHit], bool]
Runner = Callable[[AsyncSession, uuid.UUID, str, int, int], Awaitable[Page]]


# --- text helpers ----------------------------------------------------------------------------


def _plain(value: str | None, limit: int) -> str:
    """One line of plain text, control characters removed, at most `limit` characters."""
    flat = " ".join(_CONTROL.sub(" ", value or "").split())
    return flat if len(flat) <= limit else flat[: limit - 1].rstrip() + "…"


def _snippet(body: str | None, q: str) -> str | None:
    """Plain text around the first query word found (case-insensitive), at most
    SNIPPET_MAX characters; the start of the text when no word is found."""
    flat = " ".join(_CONTROL.sub(" ", body or "").split())
    if not flat:
        return None
    lowered = flat.lower()
    positions = [p for w in _WORDS.findall(q.lower()) if (p := lowered.find(w)) >= 0]
    start = max(0, min(positions) - SNIPPET_LEAD) if positions else 0
    window = flat[start : start + SNIPPET_MAX]
    if start > 0:
        window = "…" + window[1:]
    if start + SNIPPET_MAX < len(flat):
        window = window[:-1] + "…"
    return window


def _utf16(text: str, index: int) -> int:
    """The UTF-16 code unit offset of code point `index` (the JavaScript string index)."""
    return len(text[:index].encode("utf-16-le")) // 2


def snippet_ranges(snippet: str | None, q: str) -> list[TextRange]:
    """Case-insensitive occurrences of each query word (>= 2 characters) in `snippet`, merged
    and sorted, as UTF-16 `[start, end)` ranges; at most MAX_RANGES."""
    if not snippet:
        return []
    words = {w for w in _WORDS.findall(q) if len(w) >= RANGE_MIN_CHARS}
    spans: list[tuple[int, int]] = []
    for word in sorted(words):
        spans.extend(m.span() for m in re.finditer(re.escape(word), snippet, re.IGNORECASE))
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [
        TextRange(start=_utf16(snippet, s), end=_utf16(snippet, e)) for s, e in merged[:MAX_RANGES]
    ]


def _text_snippet(body: str | None, q: str) -> tuple[str | None, list[TextRange]]:
    snippet = _snippet(body, q)
    return snippet, snippet_ranges(snippet, q)


def _like(q: str) -> str:
    return f"%{escape_like(q)}%"


def _job_href(analyzer: str, job_id: uuid.UUID, tab: str) -> str:
    route = "pcap" if analyzer == "pcap" else "malware"
    return f"/{route}/{job_id}?tab={tab}"


# --- cursors ---------------------------------------------------------------------------------


def encode_cursor(search_type: SearchType, offset: int) -> str:
    raw = json.dumps({"t": search_type, "o": offset}).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(token: str) -> tuple[SearchType, int]:
    try:
        raw = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
        search_type, offset = raw["t"], raw["o"]
        if search_type not in SEARCH_TYPES:
            raise ValueError("cursor")
        if not isinstance(offset, int) or isinstance(offset, bool):
            raise ValueError("cursor")
        if not 0 < offset <= MAX_OFFSET:
            raise ValueError("cursor")
        return search_type, offset
    except (ValueError, TypeError, KeyError, binascii.Error):
        raise InvalidCursor() from None


# --- per-type runners --------------------------------------------------------------------------


def _page(rows: Sequence[RowMapping], limit: int) -> tuple[Sequence[RowMapping], bool]:
    return rows[:limit], len(rows) > limit


async def _observables(
    session: AsyncSession, org_id: uuid.UUID, q: str, offset: int, limit: int
) -> Page:
    selected: list[tuple[str, str]] = []
    exact: set[tuple[str, str]] = set()
    candidates = [(kind, key) for kind, key, _ in candidate_keys(q)]
    if candidates:
        params = {"org": org_id, **queries.keys_params(candidates)}
        found = {(r[0], r[1]) for r in await session.execute(queries.OBSERVABLE_EXACT, params)}
        exact = {k for k in candidates if k in found}
        selected = [k for k in candidates if k in exact]
    if len(q) >= TRIGRAM_MIN_CHARS:
        params = {"org": org_id, "q": q, "like": _like(q), "limit": offset + limit + 1}
        for row in await session.execute(queries.OBSERVABLE_TRIGRAM, params):
            if (row[0], row[1]) not in exact:
                selected.append((row[0], row[1]))
    page, more = selected[offset : offset + limit], len(selected) > offset + limit
    if not page:
        return [], False
    params = {"org": org_id, **queries.keys_params(page)}
    details = {
        (r["kind"], r["key"]): r
        for r in (await session.execute(queries.OBSERVABLE_DETAILS, params)).mappings()
    }
    hits = []
    for kind_key in page:
        r = details.get(kind_key)
        if r is None:
            continue
        jobs = int(r["jobs"])
        hits.append(
            SearchHit(
                type="observable",
                id=r["key"],
                title=_plain(r["value_norm"], TITLE_MAX),
                snippet=f"{r['kind']}, seen in {jobs} job{'s' if jobs != 1 else ''}",
                match="exact" if kind_key in exact else "trigram",
                investigation_id=r["investigation_id"],
                case_ref=case_ref(r["case_number"]),
                job_id=r["job_id"],
                evidence_id=r["evidence_id"],
                kind=r["kind"],
                href=_job_href(r["analyzer"], r["job_id"], "iocs"),
                tlp=r["tlp"],
            )
        )
    return hits, more


def _case_number(q: str) -> int | None:
    match = _CASE_NUMBER.fullmatch(q.strip())
    return int(match.group(1)) if match else None


async def _cases(session: AsyncSession, org_id: uuid.UUID, q: str, offset: int, limit: int) -> Page:
    number = _case_number(q)
    digits = q if q.isdigit() and len(q) >= TRIGRAM_MIN_CHARS else None
    plan = queries.CaseQuery(fts=True, number=number is not None, number_like=digits is not None)
    params: dict[str, Any] = {"org": org_id, "q": q, "limit": limit + 1, "offset": offset}
    if number is not None:
        params["number"] = number
    if digits is not None:
        params["number_like"] = f"%{digits}%"
    rows, more = _page(
        (await session.execute(queries.case_query(plan), params)).mappings().all(), limit
    )
    hits = []
    for r in rows:
        snippet, ranges = _text_snippet(r["description"], q)
        hits.append(
            SearchHit(
                type="case",
                id=str(r["id"]),
                title=_plain(r["title"], TITLE_MAX),
                snippet=snippet,
                snippet_ranges=ranges,
                match="exact" if r["exact"] else "fts",
                investigation_id=r["id"],
                case_ref=case_ref(r["case_number"]),
                job_id=None,
                evidence_id=None,
                kind=None,
                href=f"/investigations/{r['id']}",
                tlp=r["tlp"],
            )
        )
    return hits, more


async def _evidence(
    session: AsyncSession, org_id: uuid.UUID, q: str, offset: int, limit: int
) -> Page:
    if len(q) < TRIGRAM_MIN_CHARS:
        return [], False
    params = {"org": org_id, "q": q, "like": _like(q), "limit": limit + 1, "offset": offset}
    rows, more = _page((await session.execute(queries.EVIDENCE, params)).mappings().all(), limit)
    hits = [
        SearchHit(
            type="evidence",
            id=str(r["id"]),
            title=_plain(r["original_filename"], TITLE_MAX),
            snippet=None,
            match="trigram",
            investigation_id=r["investigation_id"],
            case_ref=case_ref(r["case_number"]),
            job_id=None,
            evidence_id=r["id"],
            kind=None,
            href=f"/evidence/{r['id']}",
            tlp=r["tlp"],
        )
        for r in rows
    ]
    return hits, more


async def _findings(
    session: AsyncSession, org_id: uuid.UUID, q: str, offset: int, limit: int
) -> Page:
    params = {"org": org_id, "q": q, "limit": limit + 1, "offset": offset}
    rows, more = _page((await session.execute(queries.FINDING, params)).mappings().all(), limit)
    hits = []
    for r in rows:
        snippet, ranges = _text_snippet(r["description"], q)
        hits.append(
            SearchHit(
                type="finding",
                id=str(r["id"]),
                title=_plain(r["title"], TITLE_MAX),
                snippet=snippet,
                snippet_ranges=ranges,
                match="fts",
                investigation_id=r["investigation_id"],
                case_ref=case_ref(r["case_number"]),
                job_id=r["job_id"],
                evidence_id=r["evidence_id"],
                kind=None,
                href=_job_href(r["analyzer"], r["job_id"], "findings"),
                tlp=r["tlp"],
            )
        )
    return hits, more


async def _alerts(
    session: AsyncSession, org_id: uuid.UUID, q: str, offset: int, limit: int
) -> Page:
    params = {"org": org_id, "q": q, "limit": limit + 1, "offset": offset}
    rows, more = _page((await session.execute(queries.ALERT, params)).mappings().all(), limit)
    hits = []
    for r in rows:
        snippet = _plain(r["category"], SNIPPET_MAX) if r["category"] else None
        hits.append(
            SearchHit(
                type="alert",
                id=str(r["id"]),
                title=_plain(r["signature"], TITLE_MAX),
                snippet=snippet,
                snippet_ranges=snippet_ranges(snippet, q),
                match="fts",
                investigation_id=r["investigation_id"],
                case_ref=case_ref(r["case_number"]),
                job_id=r["job_id"],
                evidence_id=r["evidence_id"],
                kind=None,
                href=_job_href(r["analyzer"], r["job_id"], "alerts"),
                tlp=r["tlp"],
            )
        )
    return hits, more


async def _notes(session: AsyncSession, org_id: uuid.UUID, q: str, offset: int, limit: int) -> Page:
    params = {"org": org_id, "q": q, "limit": limit + 1, "offset": offset}
    rows, more = _page((await session.execute(queries.NOTE, params)).mappings().all(), limit)
    hits = []
    for r in rows:
        snippet, ranges = _text_snippet(r["body"], q)
        hits.append(
            SearchHit(
                type="note",
                id=str(r["id"]),
                title=f"Note on {case_ref(r['case_number'])}",
                snippet=snippet,
                snippet_ranges=ranges,
                match="fts",
                investigation_id=r["investigation_id"],
                case_ref=case_ref(r["case_number"]),
                job_id=None,
                evidence_id=None,
                kind=None,
                href=f"/investigations/{r['investigation_id']}?tab=notes",
                tlp=r["tlp"],
            )
        )
    return hits, more


RUNNERS: dict[SearchType, Runner] = {
    "observable": _observables,
    "case": _cases,
    "evidence": _evidence,
    "finding": _findings,
    "alert": _alerts,
    "note": _notes,
}


# --- the route body --------------------------------------------------------------------------


def _valid_query(raw: str) -> str:
    settings = get_settings()
    q = raw.strip()
    if not settings.search_min_query_chars <= len(q) <= settings.search_max_query_chars:
        raise SearchQueryInvalid()
    if _CONTROL.search(q):
        raise SearchQueryInvalid()
    return q


def _sqlstate(exc: DBAPIError) -> str | None:
    seen: BaseException | None = exc.orig
    for _ in range(4):  # DBAPIError -> adapted driver error -> asyncpg error
        if seen is None:
            break
        state = getattr(seen, "sqlstate", None)
        if isinstance(state, str):
            return state
        seen = seen.__cause__
    return None


async def search(ctx: OrgContext, body: SearchIn) -> SearchOut:
    settings = get_settings()
    await rate_limit.hit(f"search:{ctx.user.id}", settings.search_per_user_per_min, 60)
    q = _valid_query(body.q)
    requested = set(body.types or SEARCH_TYPES)
    offset = 0
    if body.cursor is not None:
        cursor_type, offset = decode_cursor(body.cursor)
        requested = {cursor_type}
    types = [t for t in SEARCH_TYPES if t in requested]
    limit = settings.search_hits_per_type

    session = ctx.session
    timeout_ms = settings.search_statement_timeout_s * 1000
    await session.execute(text(f"SET LOCAL statement_timeout = {int(timeout_ms)}"))
    groups: list[SearchGroup] = []
    partial = False
    for search_type in types:
        try:
            async with session.begin_nested():
                hits, more = await RUNNERS[search_type](session, ctx.org_id, q, offset, limit)
        except DBAPIError as exc:
            state = _sqlstate(exc)
            if state != _QUERY_CANCELED:
                log.warning("search: the %s query failed (sqlstate %s)", search_type, state)
                raise SearchFailed() from None
            log.info("search: the %s query timed out", search_type)
            partial = True
            groups.append(SearchGroup(type=search_type, hits=[], next_cursor=None, error="timeout"))
            continue
        next_offset = offset + limit
        next_cursor = (
            encode_cursor(search_type, next_offset) if more and next_offset <= MAX_OFFSET else None
        )
        groups.append(SearchGroup(type=search_type, hits=hits, next_cursor=next_cursor))
    await session.execute(text("SET LOCAL statement_timeout TO DEFAULT"))
    return SearchOut(groups=groups, partial=partial)
