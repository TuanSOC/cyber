"""Output verification (signature FROZEN in phase 1; phase 5 fills the body).

`coerce_caps` + full `AnalysisOutput` validation (failure: `ValidationFailed(errors)`), the
canary check, every citation re-checked against the frozen context AND re-queried from the DB
inside `run_scope` (batched per table, in the org's tenant `session`), claim support with the
anchor rule (RT1), ATT&CK ids against the v20 index, post-processing and metrics.

Citation rules (in this order; the first failing rule decides):
- `invalid / digest_not_evidence`: a `D` label (an earlier AI summary, never evidence);
- `invalid / unknown_label`: the label is not an item of the context or has no stored ref;
- `invalid / field_not_allowed`: `field` is not a key of the item's sent fields;
- `invalid / row_missing`: the row is not visible in the org's tenant session (deleted, or
  another org's row behind a forged ref) or the ref id is malformed;
- `invalid / out_of_scope`: the row exists but outside this run's scope (another job, an
  evidence item of another investigation, a ref whose job differs from the row's, an
  unknown ref table); flows are matched by (`job_id`, `flow_ref`), never `flow_ref` alone;
- `unverified / quote_required`: an `observed` citation without a quote;
- `unverified / quote_mismatch`: the normalized quote is not a substring of the normalized
  sent value of `field` (or of any sent field when `field` is absent);
- `unverified / quote_too_short` (RT1): the quote is shorter than `min(8, len(value))` or
  has no letter or digit, unless it is exactly one whole structured token of the value (an
  IP, a hash, a domain or an ATT&CK id), which identifies the record on its own;
- otherwise `verified` (`stale=true` when the sent fields no longer hash to the stored
  `fields_sha256`).
Normalization (quotes, values, claims): `text.sanitize`, NFC, whitespace collapsed, URLs and
domains refanged, IPs canonical, hex hashes lowercase; otherwise case-sensitive.

M10 (`explain_function`): `G` / `Q` items are re-queried in `re_functions` /
`re_decompilations` of the run's job, like every job row; a quote of `Q.code` follows the
rules above (whitespace collapsing lets a quote span reformatted lines; an identifier of ≥ 4
characters anchors as a word). Only the target function's code is ever sent, so a citation
of another function's code is an unknown label. No new flag.

Claim rules (`OutputVerification.claims`, keyed by the body's claim ids, `attack:<tid>` and
`timeline:<i>`):
- `observed`: supported iff ≥ 1 verified citation with a quote AND the claim contains a
  salient token of that quote (an IP, domain, hash, ATT&CK id, number of ≥ 2 digits or a
  non-stop word of ≥ 4 characters; words compared case-insensitively), else
  `unsupported / weak_anchor` (verified quotes exist but none anchors) or
  `unsupported / no_verified_citation`;
- `interpretation`: supported iff ≥ 1 verified citation, else `no_verified_citation`;
- `hypotheses`: always `hypothesis`; invalid `supporting` / `contradicting` entries are
  dropped from the body and counted in `dropped_refs` (RT21);
- `next_steps.refs`: label + scope checks; invalid refs are dropped and counted (RT21);
- `attack_techniques`: a malformed id, an id missing from the v20 index, or a revoked or
  deprecated one is dropped (`invalid_attack`); duplicates are dropped; invalid citations
  are dropped and counted; supported iff ≥ 1 verified citation, else `no_verified_citation`;
- `timeline`: supported iff the first verified citation's row has a time (the read model
  takes the timestamp from that row), else `no_timestamp` / `no_verified_citation`.

Claim ids in the stored body are rewritten to `O{n}` / `I{n}` / `H{n}` (unique, never
model text). Citation rows (`citations`) cover the citations kept in the stored body, with
paths into it; the counts and metrics cover every citation the model produced, including
the dropped ones.
"""

import hashlib
import json
import re
import uuid
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.ai import postprocess
from app.modules.ai import text as ai_text
from app.modules.ai.contracts import (
    CitationReason,
    CitationResult,
    CitationStatus,
    ClaimStatus,
    ClaimVerdict,
    ContextItem,
    ContextRef,
    FieldValue,
    FrozenContext,
    OutputFlag,
    OutputVerification,
    RefKind,
    RunMetrics,
    RunScope,
    Section,
    ValidationFailed,
    VerifiedOutput,
)
from app.modules.ai.labels import parse_label
from app.modules.ai.output_schema import (
    BODY_MAX_BYTES,
    MAX_FIELD,
    MAX_LABEL,
    MAX_QUOTE,
    MAX_TECHNIQUE,
    MAX_TEXT,
    AnalysisOutput,
    Citation,
    body_size,
    coerce_caps,
)
from app.modules.attack.index import get_index

MIN_QUOTE_CHARS = 8
TECHNIQUE_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")
# Citation field names kept verbatim in the stored body (no markup, scheme or space chars).
FIELD_NAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,64}")
# Whole-entry trimming when post-processing grew the body (defang adds characters); same
# order as `output_schema.coerce_caps`.
_TRIM_ORDER: tuple[str, ...] = (
    "timeline",
    "attack_techniques",
    "hypotheses",
    "interpretation",
    "limitations",
    "next_steps",
    "observed",
)
_BODY_TARGET = BODY_MAX_BYTES - 2 * 1024

# --- validation errors (paths and error types only, never values) ----------------------------

_SCHEMA_KEYS = frozenset(
    {
        "observed",
        "interpretation",
        "hypotheses",
        "overall_confidence",
        "next_steps",
        "limitations",
        "attack_techniques",
        "timeline",
        "id",
        "text",
        "confidence",
        "citations",
        "supporting",
        "contradicting",
        "level",
        "rationale",
        "refs",
        "technique_id",
        "ref",
        "field",
        "quote",
    }
)


def _error_path(loc: Sequence[int | str]) -> str:
    parts = [
        str(p) if isinstance(p, int) or p in _SCHEMA_KEYS else "?"
        for p in loc
        if p not in ("function-after", "function-before")
    ]
    return ".".join(parts) or "(root)"


def _errors(exc: ValidationError) -> list[str]:
    seen: list[str] = []
    for error in exc.errors(include_url=False, include_input=False):
        entry = f"{_error_path(error['loc'])}: {error['type']}"
        if entry not in seen:
            seen.append(entry)
    return seen


# --- normalization ---------------------------------------------------------------------------

_IPV4 = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?!\w|\.\d)")
# Candidates only (timestamps match too); `canonical_ip` decides. The tail may be an
# embedded IPv4 address (`::ffff:203.0.113.9`).
_IPV6 = re.compile(
    r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4})"
    r"(?:%\w+)?(?![\w:]|\.\d)"
)
_HASH = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{32,128}(?![0-9A-Za-z])")
_DOMAIN = re.compile(
    r"(?<![\w.-])(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+"
    r"[A-Za-z][A-Za-z0-9-]{1,62}(?![\w-])"
)
_ATTACK = re.compile(r"(?<![\w.])T\d{4}(?:\.\d{3})?(?!\w|\.\d)")
_WORD = re.compile(r"\w+")
_ALNUM = re.compile(r"[^\W_]")

_STOP_WORDS = frozenset(
    """
    about above after again against also although among another any anything because been
    before being below between both but could does doing done down during each either else
    even every from further have having here hers herself himself however into itself just
    least less like made make many might more most much must near neither never none nothing
    often once only other otherwise ours ourselves over perhaps rather same seem seemed seems
    shall should since some something such than that their theirs them themselves then there
    therefore these they this those though through thus together under until upon very want
    were what whatever when whenever where whereas whether which while whom whose will with
    within without would your yours yourself
    evidence observed observes shows show shown indicates indicate indicated appears appear
    possible possibly likely suggests suggest record records item items field value values
    """.split()
)


def _canonical_hash(match: re.Match[str]) -> str:
    return ai_text.canonical_hash(match.group(0)) or match.group(0)


def _canonical_ip(match: re.Match[str]) -> str:
    return ai_text.canonical_ip(match.group(0)) or match.group(0)


def normalize(value: str) -> str:
    """The matching form of a quote, a sent value or a claim (see the module docstring)."""
    clean = postprocess.sanitized(value)[0]
    clean = ai_text.refang(ai_text.collapse_ws(clean))
    clean = _HASH.sub(_canonical_hash, clean)
    clean = _IPV6.sub(_canonical_ip, clean)
    return _IPV4.sub(_canonical_ip, clean)


def _value_text(value: FieldValue) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value)


def _structured(value: str) -> set[str]:
    """IPs, hashes, domains and ATT&CK ids of a normalized text, in canonical form."""
    tokens: set[str] = set()
    for match in _IPV4.finditer(value):
        ip = ai_text.canonical_ip(match.group(0))
        if ip:
            tokens.add(ip)
    for match in _IPV6.finditer(value):
        ip = ai_text.canonical_ip(match.group(0))
        if ip and ip != "::":
            tokens.add(ip)
    tokens.update(
        m.group(0).lower() for m in _HASH.finditer(value) if len(m.group(0)) in {32, 40, 64, 128}
    )
    tokens.update(m.group(0).lower() for m in _DOMAIN.finditer(value))
    tokens.update(m.group(0) for m in _ATTACK.finditer(value))
    return tokens


def _salient(quote: str) -> set[str]:
    tokens = _structured(quote)
    for word in _WORD.findall(quote):
        folded = word.casefold()
        if word.isdigit():
            if len(word) >= 2:
                tokens.add(folded)
        elif len(word) >= 4 and folded not in _STOP_WORDS:
            tokens.add(folded)
    return tokens


def _claim_tokens(claim: str) -> set[str]:
    return _structured(claim) | {w.casefold() for w in _WORD.findall(claim)}


# Low-cardinality fields (enums, booleans, counts): their values are vocabulary ("high",
# "true", "beacon", "47") that any claim can contain, so a quote of one never anchors
# through its words or numbers, only through a structured token (IP, hash, domain,
# ATT&CK id). Identifier-like fields (detection_method, signature, sid, hashes, ...) anchor
# normally. Names apply to every kind; `count.*` / `*count` / `*_count` too.
ENUM_FIELDS = frozenset(
    {
        "severity",
        "status",
        "found",
        "confidence",
        "level",
        "type",
        "kind",
        "event",
        "engine",
        "encoding",
        "proto",
        "protocol",
        "qtype",
        "rcode",
        "method",
        "tls_version",
        "source",
        "ts_source",
        "file_format",
        "analyzer",
        "provider",
        "score_scale",
        "is_dll",
        "bits",
        "machine",
        "subsystem",
        "matches",
        "rev",
        # M10: function / code enums and counts.
        "name_source",
        "flags",
        "decompile_status",
        "code_kind",
        "lines",
        "truncated",
    }
)


def is_enum_field(name: str, value: FieldValue) -> bool:
    if isinstance(value, bool) or (isinstance(value, str) and value in ("true", "false")):
        return True
    counter = name == "count" or name.startswith("count.") or name.endswith("_count")
    return name in ENUM_FIELDS or counter


def anchored(claim_text: str, quote: str, *, enum_only: bool = False) -> bool:
    """RT1: the claim contains at least one salient token of the quote. A quote that only
    matched low-cardinality fields (`ENUM_FIELDS`, booleans, counts) anchors only through
    a structured token (IP, hash, domain, ATT&CK id)."""
    quote_norm = normalize(quote)
    salient = _structured(quote_norm) if enum_only else _salient(quote_norm)
    return bool(salient & _claim_tokens(normalize(claim_text)))


def _whole_token(quote: str, value: str) -> bool:
    """The quote is exactly one structured token that also stands alone in the value."""
    tokens = _structured(quote)
    if len(tokens) != 1:
        return False
    token = next(iter(tokens))
    if quote.lower() != token.lower():
        return False
    return token in _structured(value)


def is_trivial_quote(quote: str, value: str) -> bool:
    """RT1 on normalized strings: no letter / digit, or shorter than 8 characters unless it
    is exactly one whole structured token of the value. A short field's whole value
    (`severity="high"`, `found="true"`) is NOT enough: it would verify any claim."""
    if not _ALNUM.search(quote):
        return True
    if len(quote) >= MIN_QUOTE_CHARS:
        return False
    return not _whole_token(quote, value)


def fields_sha256(fields: dict[str, FieldValue]) -> str:
    """sha256 of the sent fields (sorted keys, compact, non-ASCII kept, NFC), as stored in
    `ai_context_refs.fields_sha256` (same bytes as phase 4's `context.encode.fields_sha256`;
    kept local so the verifier does not import the builder)."""
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(ai_text.nfc(canonical).encode()).hexdigest()


# --- DB re-query -----------------------------------------------------------------------------

_ScopeRule = Literal["job", "flow", "self_job", "evidence", "custody", "investigation", "org"]
_JOB_TIME = (
    "(SELECT coalesce(j.finished_at, j.created_at) FROM analysis_jobs j WHERE j.id = t.job_id)"
)


@dataclass(frozen=True)
class _Table:
    rule: _ScopeRule
    ts: str  # SQL expression over alias `t` for the record time


# Every ref table a context may point at. Table names come only from here (never from the
# stored ref) and an unknown table is out of scope.
_TABLES: dict[str, _Table] = {
    "analysis_jobs": _Table("self_job", "coalesce(t.finished_at, t.created_at)"),
    "analysis_findings": _Table("job", "t.ts"),
    "network_alerts": _Table("job", "t.ts"),
    "network_records": _Table("job", "t.ts"),
    "network_flows": _Table("flow", "t.ts"),
    "iocs": _Table("job", "t.first_seen"),
    "analysis_timeline": _Table("job", "t.ts"),
    "malware_samples": _Table("job", _JOB_TIME),
    "malware_sections": _Table("job", _JOB_TIME),
    "malware_imports": _Table("job", _JOB_TIME),
    "malware_exports": _Table("job", _JOB_TIME),
    "malware_resources": _Table("job", _JOB_TIME),
    "malware_strings": _Table("job", _JOB_TIME),
    "malware_signature_matches": _Table("job", _JOB_TIME),
    "malware_capabilities": _Table("job", _JOB_TIME),
    "evidence": _Table("evidence", "t.uploaded_at"),
    "evidence_custody_events": _Table("custody", "t.occurred_at"),
    "investigations": _Table("investigation", "t.created_at"),
    # The TI cache is org-wide (a run reuses another run's rows): org-level scope only.
    "ti_results": _Table("org", "t.fetched_at"),
    # M10: one function's facts (G) and code (Q) of the run's reverse-engineering job.
    "re_functions": _Table("job", _JOB_TIME),
    "re_decompilations": _Table("job", _JOB_TIME),
}

RowState = Literal["ok", "missing", "out_of_scope"]


@dataclass(frozen=True)
class RowCheck:
    state: RowState
    has_ts: bool = False


def _as_uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


async def lookup_rows(
    session: AsyncSession, org_id: uuid.UUID, run_scope: RunScope, refs: Sequence[ContextRef]
) -> dict[str, RowCheck]:
    """Re-query every ref (one query per table) in the org's tenant session; label ->
    state. RLS hides other orgs' rows, and every query also filters on `org_id`."""
    jobs = list(run_scope.job_ids)
    result: dict[str, RowCheck] = {}
    by_table: dict[str, list[ContextRef]] = {}
    for ref in refs:
        if ref.ref_table not in _TABLES:
            result[ref.label] = RowCheck("out_of_scope")
        else:
            by_table.setdefault(ref.ref_table, []).append(ref)

    for table, table_refs in by_table.items():
        spec = _TABLES[table]
        if spec.rule == "flow":
            await _lookup_flows(session, org_id, jobs, table_refs, result)
            continue
        ids: dict[str, uuid.UUID] = {}
        for ref in table_refs:
            parsed = _as_uuid(ref.ref_id)
            if parsed is None:
                result[ref.label] = RowCheck("missing")
            else:
                ids[ref.label] = parsed
        if not ids:
            continue
        rows = await _fetch(session, table, spec, org_id, jobs, sorted(set(ids.values()), key=str))
        for ref in table_refs:
            if ref.label not in ids:
                continue
            row = rows.get(str(ids[ref.label]))
            if row is None:
                result[ref.label] = RowCheck("missing")
                continue
            in_scope = _in_scope(spec.rule, row, ref, run_scope)
            result[ref.label] = RowCheck("ok" if in_scope else "out_of_scope", bool(row["has_ts"]))
    return result


async def _fetch(
    session: AsyncSession,
    table: str,
    spec: _Table,
    org_id: uuid.UUID,
    jobs: list[uuid.UUID],
    ids: list[uuid.UUID],
) -> dict[str, dict[str, Any]]:
    via_job = (
        "EXISTS (SELECT 1 FROM analysis_jobs j WHERE j.organization_id = :org "
        "AND j.evidence_id = {ev} AND j.id = ANY(:jobs))"
    )
    if spec.rule == "job":
        select = "t.job_id::text AS job_id, NULL AS investigation_id, false AS via_job"
        source = f"{table} t"
    elif spec.rule == "self_job":
        select = "t.id::text AS job_id, NULL AS investigation_id, false AS via_job"
        source = f"{table} t"
    elif spec.rule == "evidence":
        select = (
            "NULL AS job_id, t.investigation_id::text AS investigation_id, "
            f"{via_job.format(ev='t.id')} AS via_job, t.id::text AS evidence_id"
        )
        source = f"{table} t"
    elif spec.rule == "custody":
        select = (
            "NULL AS job_id, e.investigation_id::text AS investigation_id, "
            f"{via_job.format(ev='t.evidence_id')} AS via_job, t.evidence_id::text AS evidence_id"
        )
        source = (
            f"{table} t JOIN evidence e ON e.id = t.evidence_id "
            "AND e.organization_id = t.organization_id"
        )
    elif spec.rule == "investigation":
        select = "NULL AS job_id, t.id::text AS investigation_id, false AS via_job"
        source = f"{table} t"
    else:  # org
        select = "NULL AS job_id, NULL AS investigation_id, false AS via_job"
        source = f"{table} t"
    # Table names and SQL expressions come only from `_TABLES` and the literals above (never
    # from a stored ref); every value is a bound parameter.
    sql = (
        f"SELECT t.id::text AS id, {select}, ({spec.ts}) IS NOT NULL AS has_ts "  # noqa: S608
        f"FROM {source} WHERE t.organization_id = :org AND t.id = ANY(:ids)"
    )
    params: dict[str, Any] = {"org": org_id, "ids": ids}
    if ":jobs" in sql:
        params["jobs"] = jobs
    rows = (await session.execute(text(sql), params)).mappings().all()
    return {row["id"]: dict(row) for row in rows}


async def _lookup_flows(
    session: AsyncSession,
    org_id: uuid.UUID,
    jobs: list[uuid.UUID],
    refs: list[ContextRef],
    result: dict[str, RowCheck],
) -> None:
    """Flows by (`job_id`, `flow_ref`) (RT16): a ref without a job, or whose job is not in
    the run's scope, is out of scope without a query."""
    wanted: list[ContextRef] = []
    for ref in refs:
        if ref.job_id is None or ref.job_id not in jobs:
            result[ref.label] = RowCheck("out_of_scope")
        else:
            wanted.append(ref)
    if not wanted:
        return
    sql = text(
        "SELECT t.job_id::text AS job_id, t.flow_ref AS flow_ref, "
        "bool_or(t.ts IS NOT NULL) AS has_ts FROM network_flows t "
        "WHERE t.organization_id = :org AND t.job_id = ANY(:jobs) "
        "AND t.flow_ref = ANY(:refs) GROUP BY t.job_id, t.flow_ref"
    )
    params = {
        "org": org_id,
        "jobs": sorted({ref.job_id for ref in wanted if ref.job_id is not None}, key=str),
        "refs": sorted({ref.ref_id for ref in wanted}),
    }
    found = {
        (row["job_id"], row["flow_ref"]): bool(row["has_ts"])
        for row in (await session.execute(sql, params)).mappings().all()
    }
    for ref in wanted:
        key = (str(ref.job_id), ref.ref_id)
        result[ref.label] = RowCheck("ok", found[key]) if key in found else RowCheck("missing")


def _in_scope(rule: _ScopeRule, row: dict[str, Any], ref: ContextRef, scope: RunScope) -> bool:
    """Row columns arrive as text (no driver-specific uuid types in the comparisons)."""
    investigation = str(scope.investigation_id) if scope.investigation_id else None
    if rule in ("job", "self_job"):
        job = row["job_id"]
        own_job = ref.job_id is None or str(ref.job_id) == job
        return own_job and job in {str(j) for j in scope.job_ids}
    if rule in ("evidence", "custody"):
        return bool(
            (investigation is not None and row["investigation_id"] == investigation)
            or row["evidence_id"] in {str(e) for e in scope.evidence_ids}
            or row["via_job"]
        )
    if rule == "investigation":
        return investigation is not None and row["investigation_id"] == investigation
    return True  # org: RLS and the org filter already scoped it


# --- citation checks -------------------------------------------------------------------------


@dataclass(frozen=True)
class _Outcome:
    status: CitationStatus
    reason: CitationReason | None = None
    ref: ContextRef | None = None
    stale: bool = False
    row: RowCheck | None = None
    # The quote matched only low-cardinality fields (it anchors only via structured tokens).
    enum_only: bool = False

    @property
    def verified(self) -> bool:
        return self.status is CitationStatus.VERIFIED


@dataclass
class _Checker:
    items: dict[str, ContextItem]
    refs: dict[str, ContextRef]
    rows: dict[str, RowCheck]
    outcomes: list[_Outcome] = field(default_factory=list)
    _norm_cache: dict[str, str] = field(default_factory=dict)

    def _norm(self, value: str) -> str:
        cached = self._norm_cache.get(value)
        if cached is None:
            cached = self._norm_cache[value] = normalize(value)
        return cached

    def check(
        self, label: str, field_name: str | None, quote: str | None, *, quote_required: bool
    ) -> _Outcome:
        outcome = self._check(label, field_name, quote, quote_required=quote_required)
        self.outcomes.append(outcome)
        return outcome

    def _check(
        self, label: str, field_name: str | None, quote: str | None, *, quote_required: bool
    ) -> _Outcome:
        parsed = parse_label(label)
        item = self.items.get(label)
        if (parsed is not None and parsed.kind is RefKind.DIGEST_CLAIM) or (
            item is not None and item.kind is RefKind.DIGEST_CLAIM
        ):
            return _Outcome(CitationStatus.INVALID, CitationReason.DIGEST_NOT_EVIDENCE)
        ref = self.refs.get(label)
        if parsed is None or item is None or ref is None or ref.kind is not item.kind:
            return _Outcome(CitationStatus.INVALID, CitationReason.UNKNOWN_LABEL)
        if field_name is not None and field_name not in item.fields:
            return _Outcome(CitationStatus.INVALID, CitationReason.FIELD_NOT_ALLOWED, ref)
        row = self.rows.get(label, RowCheck("missing"))
        if row.state == "missing":
            return _Outcome(CitationStatus.INVALID, CitationReason.ROW_MISSING, ref)
        if row.state == "out_of_scope":
            return _Outcome(CitationStatus.INVALID, CitationReason.OUT_OF_SCOPE, ref)
        stale = fields_sha256(item.fields) != ref.fields_sha256
        unverified = CitationStatus.UNVERIFIED
        if quote is None or not quote.strip():
            if quote_required:
                return _Outcome(unverified, CitationReason.QUOTE_REQUIRED, ref, stale, row)
            return _Outcome(CitationStatus.VERIFIED, None, ref, stale, row)
        needle = self._norm(quote)
        names = [field_name] if field_name is not None else sorted(item.fields)
        matched = [
            (name, value)
            for name, value in ((n, self._norm(_value_text(item.fields[n]))) for n in names)
            if needle and needle in value
        ]
        if not matched:
            return _Outcome(unverified, CitationReason.QUOTE_MISMATCH, ref, stale, row)
        quotable = [name for name, value in matched if not is_trivial_quote(needle, value)]
        if not quotable:
            return _Outcome(unverified, CitationReason.QUOTE_TOO_SHORT, ref, stale, row)
        enum_only = all(is_enum_field(name, item.fields[name]) for name in quotable)
        return _Outcome(CitationStatus.VERIFIED, None, ref, stale, row, enum_only)


# --- canary ----------------------------------------------------------------------------------

_SPACE = re.compile(r"\s+")


def _strings(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield str(key)
            yield from _strings(value)
    elif isinstance(node, list | tuple):
        for value in node:
            yield from _strings(value)


def canary_leaked(parsed: Any, canary: str) -> bool:
    """The canary anywhere in the output: case-insensitive, also after removing invisible
    characters and all whitespace (a canary split across adjacent strings counts)."""
    target = _SPACE.sub("", canary).casefold()
    if not target:
        return False
    joined = "\n".join(_strings(parsed))
    if target in joined.casefold():
        return True
    clean = postprocess.sanitized(joined)[0]
    return (
        target in _SPACE.sub("", clean).casefold()
        or target in _SPACE.sub("", ai_text.refang(clean)).casefold()
    )


def _redact(value: str, canary: str) -> str:
    if not canary:
        return value
    return re.sub(re.escape(canary), "[redacted]", value, flags=re.IGNORECASE)


# --- the verifier ----------------------------------------------------------------------------


def _attack_valid(tid: str) -> bool:
    if not TECHNIQUE_PATTERN.fullmatch(tid):
        return False
    entry = get_index().techniques.get(tid)
    return entry is not None and entry.revoked_by is None and not entry.deprecated


def _cited_labels(body: AnalysisOutput) -> set[str]:
    labels: set[str] = set()
    for claim in (*body.observed, *body.interpretation):
        labels.update(c.ref for c in claim.citations)
    for hypothesis in body.hypotheses:
        labels.update(c.ref for c in (*hypothesis.supporting, *hypothesis.contradicting))
    for step in body.next_steps:
        labels.update(step.refs)
    for technique in body.attack_techniques:
        labels.update(c.ref for c in technique.citations)
    for entry in body.timeline:
        labels.update(c.ref for c in entry.citations)
    return labels


def _trim_body(body: AnalysisOutput, canary: str, leaked: bool) -> tuple[AnalysisOutput, int]:
    """Drop whole entries (`_TRIM_ORDER`) until the post-processed body fits."""
    trimmed = 0
    while True:
        cleaned = _clean_body(body, canary if leaked else "", postprocess.CleanStats())
        if body_size(cleaned) <= _BODY_TARGET:
            return body, trimmed
        for section in _TRIM_ORDER:
            entries = getattr(body, section)
            if entries:
                entries.pop()
                trimmed += 1
                break
        else:
            return body, trimmed


def _clean_body(body: AnalysisOutput, canary: str, stats: postprocess.CleanStats) -> dict[str, Any]:
    """A post-processed copy of `body` (every free-text string), same structure."""

    def clean(value: str, limit: int) -> str:
        # Redacted before and after cleaning: sanitizing can join a split canary.
        return _redact(postprocess.clean_text(_redact(value, canary), limit, stats), canary)

    def label(value: str) -> str:
        return value if parse_label(value) is not None else clean(value, MAX_LABEL)

    def technique_id(value: str) -> str:
        return value if TECHNIQUE_PATTERN.fullmatch(value) else clean(value, MAX_TECHNIQUE)

    def field_name(value: str) -> str:
        # Structural: a field key (`attributes.domain`) is kept verbatim, never defanged, so
        # the stored citation still names the sent field. Only a name outside the key
        # grammar (it can never match a sent field) is cleaned like free text.
        if FIELD_NAME_PATTERN.fullmatch(value):
            return _redact(value, canary)
        return clean(value, MAX_FIELD)

    def citation(c: Citation) -> dict[str, Any]:
        return {
            "ref": label(c.ref),
            "field": field_name(c.field) if c.field is not None else None,
            "quote": clean(c.quote, MAX_QUOTE) if c.quote is not None else None,
        }

    return {
        "observed": [
            {
                "id": f"O{n}",
                "text": clean(c.text, MAX_TEXT),
                "confidence": c.confidence,
                "citations": [citation(x) for x in c.citations],
            }
            for n, c in enumerate(body.observed, start=1)
        ],
        "interpretation": [
            {
                "id": f"I{n}",
                "text": clean(c.text, MAX_TEXT),
                "confidence": c.confidence,
                "citations": [citation(x) for x in c.citations],
            }
            for n, c in enumerate(body.interpretation, start=1)
        ],
        "hypotheses": [
            {
                "id": f"H{n}",
                "text": clean(h.text, MAX_TEXT),
                "confidence": h.confidence,
                "supporting": [citation(x) for x in h.supporting],
                "contradicting": [citation(x) for x in h.contradicting],
            }
            for n, h in enumerate(body.hypotheses, start=1)
        ],
        "overall_confidence": {
            "level": body.overall_confidence.level,
            "rationale": clean(body.overall_confidence.rationale, MAX_TEXT),
        },
        "next_steps": [
            {
                "text": clean(s.text, MAX_TEXT),
                "rationale": clean(s.rationale, MAX_TEXT),
                "refs": [label(r) for r in s.refs],
            }
            for s in body.next_steps
        ],
        "limitations": [clean(x, MAX_TEXT) for x in body.limitations],
        "attack_techniques": [
            {
                "technique_id": technique_id(t.technique_id),
                "rationale": clean(t.rationale, MAX_TEXT),
                "citations": [citation(x) for x in t.citations],
            }
            for t in body.attack_techniques
        ],
        "timeline": [
            {"text": clean(e.text, MAX_TEXT), "citations": [citation(x) for x in e.citations]}
            for e in body.timeline
        ],
    }


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


async def verify_output(
    session: AsyncSession,
    org_id: uuid.UUID,
    run_scope: RunScope,
    ctx: FrozenContext,
    refs: Sequence[ContextRef],
    parsed: dict[str, Any],
    canary: str,
) -> VerifiedOutput:
    # 1. Caps (truncate, never repair; RT19), then the full model.
    coerced, truncation = coerce_caps(parsed)
    try:
        body = AnalysisOutput.model_validate(coerced)
    except ValidationError as exc:
        raise ValidationFailed(_errors(exc)) from None
    truncation = dict(truncation)

    # 2. Canary over everything the model sent (also what the caps cut away).
    flags: set[OutputFlag] = set()
    leaked = canary_leaked(parsed, canary)
    if leaked:
        flags.add(OutputFlag.CANARY_LEAK)

    body, trimmed = _trim_body(body, canary, leaked)
    if trimmed:
        truncation["size_trimmed"] = truncation.get("size_trimmed", 0) + trimmed

    # 3. Rows of every cited label, one query per table.
    items = {item.label: item for item in ctx.items}
    ref_map = {ref.label: ref for ref in refs}
    cited = _cited_labels(body)
    to_query = [
        ref_map[label]
        for label in sorted(cited)
        if label in ref_map
        and label in items
        and ref_map[label].kind is not RefKind.DIGEST_CLAIM
        and items[label].kind is ref_map[label].kind
    ]
    rows = await lookup_rows(session, org_id, run_scope, to_query)
    checker = _Checker(items=items, refs=ref_map, rows=rows)

    stats = postprocess.CleanStats()
    cleaned = _clean_body(body, canary if leaked else "", stats)
    claims: dict[str, ClaimVerdict] = {}
    results: list[CitationResult] = []
    dropped = 0
    weak_anchor = 0
    unsupported = 0

    def row(
        section: Section,
        path: str,
        claim_id: str | None,
        outcome: _Outcome,
        label: str,
        field_name: str | None,
        quote: str | None,
    ) -> None:
        ref = outcome.ref
        results.append(
            CitationResult(
                claim_path=path,
                section=section,
                claim_id=claim_id,
                label=label,
                kind=ref.kind if ref else None,
                ref_id=ref.ref_id if ref else None,
                job_id=ref.job_id if ref else None,
                field=field_name,
                quote=quote,
                status=outcome.status,
                reason=outcome.reason,
                stale=outcome.stale,
            )
        )

    # 4. observed / interpretation claims (invalid citations stay visible, grey).
    for section in ("observed", "interpretation"):
        sec: Section = "observed" if section == "observed" else "interpretation"
        for n, claim in enumerate(getattr(body, section)):
            out = cleaned[section][n]
            verified_quotes: list[tuple[str, bool]] = []
            any_verified = False
            for m, cit in enumerate(claim.citations):
                outcome = checker.check(
                    cit.ref, cit.field, cit.quote, quote_required=section == "observed"
                )
                shown = out["citations"][m]
                row(
                    sec,
                    f"{section}[{n}].citations[{m}]",
                    out["id"],
                    outcome,
                    shown["ref"],
                    shown["field"],
                    shown["quote"],
                )
                if outcome.verified:
                    any_verified = True
                    if cit.quote is not None and cit.quote.strip():
                        verified_quotes.append((cit.quote, outcome.enum_only))
            if section == "observed":
                if any(anchored(claim.text, q, enum_only=s) for q, s in verified_quotes):
                    verdict = ClaimVerdict(status=ClaimStatus.SUPPORTED)
                elif verified_quotes:
                    weak_anchor += 1
                    verdict = ClaimVerdict(
                        status=ClaimStatus.UNSUPPORTED, reason=CitationReason.WEAK_ANCHOR
                    )
                else:
                    verdict = ClaimVerdict(
                        status=ClaimStatus.UNSUPPORTED, reason=CitationReason.NO_VERIFIED_CITATION
                    )
            elif any_verified:
                verdict = ClaimVerdict(status=ClaimStatus.SUPPORTED)
            else:
                verdict = ClaimVerdict(
                    status=ClaimStatus.UNSUPPORTED, reason=CitationReason.NO_VERIFIED_CITATION
                )
            if verdict.status is ClaimStatus.UNSUPPORTED:
                unsupported += 1
            claims[out["id"]] = verdict

    # 5. hypotheses: invalid supporting / contradicting entries are dropped (RT21).
    for n, hypothesis in enumerate(body.hypotheses):
        out = cleaned["hypotheses"][n]
        for side in ("supporting", "contradicting"):
            kept: list[dict[str, Any]] = []
            for m, cit in enumerate(getattr(hypothesis, side)):
                outcome = checker.check(cit.ref, cit.field, cit.quote, quote_required=False)
                if outcome.status is CitationStatus.INVALID:
                    dropped += 1
                    continue
                shown = out[side][m]
                row(
                    "hypotheses",
                    f"hypotheses[{n}].{side}[{len(kept)}]",
                    out["id"],
                    outcome,
                    shown["ref"],
                    shown["field"],
                    shown["quote"],
                )
                kept.append(shown)
            out[side] = kept
        claims[out["id"]] = ClaimVerdict(status=ClaimStatus.HYPOTHESIS)

    # 6. next steps: refs checked like citations; invalid ones dropped (RT21).
    for n, step in enumerate(body.next_steps):
        out = cleaned["next_steps"][n]
        kept_refs: list[str] = []
        for ref_label in step.refs:
            outcome = checker.check(ref_label, None, None, quote_required=False)
            if outcome.status is CitationStatus.INVALID:
                dropped += 1
                continue
            row(
                "next_steps",
                f"next_steps[{n}].refs[{len(kept_refs)}]",
                None,
                outcome,
                ref_label,
                None,
                None,
            )
            kept_refs.append(ref_label)
        out["refs"] = kept_refs

    # 7. ATT&CK: v20 index, not revoked / deprecated; shown only with a verified citation.
    invalid_attack = 0
    techniques: list[dict[str, Any]] = []
    seen_tids: set[str] = set()
    for n, technique in enumerate(body.attack_techniques):
        tid = technique.technique_id
        if not _attack_valid(tid):
            invalid_attack += 1
            continue
        if tid in seen_tids:
            continue
        seen_tids.add(tid)
        out = cleaned["attack_techniques"][n]
        index = len(techniques)
        kept_cits: list[dict[str, Any]] = []
        any_verified = False
        for m, cit in enumerate(technique.citations):
            outcome = checker.check(cit.ref, cit.field, cit.quote, quote_required=False)
            if outcome.status is CitationStatus.INVALID:
                dropped += 1
                continue
            shown = out["citations"][m]
            row(
                "attack_techniques",
                f"attack_techniques[{index}].citations[{len(kept_cits)}]",
                f"attack:{tid}",
                outcome,
                shown["ref"],
                shown["field"],
                shown["quote"],
            )
            kept_cits.append(shown)
            any_verified = any_verified or outcome.verified
        out["citations"] = kept_cits
        techniques.append(out)
        claims[f"attack:{tid}"] = (
            ClaimVerdict(status=ClaimStatus.SUPPORTED)
            if any_verified
            else ClaimVerdict(
                status=ClaimStatus.UNSUPPORTED, reason=CitationReason.NO_VERIFIED_CITATION
            )
        )
    cleaned["attack_techniques"] = techniques

    # 8. timeline: the time comes from the first verified citation's row.
    for n, entry in enumerate(body.timeline):
        out = cleaned["timeline"][n]
        first: _Outcome | None = None
        for m, cit in enumerate(entry.citations):
            outcome = checker.check(cit.ref, cit.field, cit.quote, quote_required=False)
            shown = out["citations"][m]
            row(
                "timeline",
                f"timeline[{n}].citations[{m}]",
                f"timeline:{n}",
                outcome,
                shown["ref"],
                shown["field"],
                shown["quote"],
            )
            if first is None and outcome.verified:
                first = outcome
        if first is None:
            verdict = ClaimVerdict(
                status=ClaimStatus.UNSUPPORTED, reason=CitationReason.NO_VERIFIED_CITATION
            )
        elif first.row is None or not first.row.has_ts:
            verdict = ClaimVerdict(
                status=ClaimStatus.UNSUPPORTED, reason=CitationReason.NO_TIMESTAMP
            )
        else:
            verdict = ClaimVerdict(status=ClaimStatus.SUPPORTED)
        claims[f"timeline:{n}"] = verdict

    # 9. Flags over the model's text (sanitized, before markup stripping).
    claim_texts = [c.text for c in (*body.observed, *body.interpretation)]
    claim_texts += [h.text for h in body.hypotheses]
    claim_texts.append(body.overall_confidence.rationale)
    if any(postprocess.has_verdict_language(t) for t in claim_texts):
        flags.add(OutputFlag.VERDICT_LANGUAGE)
    if any(
        postprocess.is_command_like(s.text) or postprocess.is_command_like(s.rationale)
        for s in body.next_steps
    ):
        flags.add(OutputFlag.COMMAND_LIKE)
    if _external_url(body, items, ref_map, checker):
        flags.add(OutputFlag.EXTERNAL_URL)

    # 10. Metrics over every checked citation (including the dropped ones).
    by_status = Counter(o.status for o in checker.outcomes)
    by_reason = Counter(o.reason for o in checker.outcomes if o.reason is not None)
    total = len(checker.outcomes)
    verified = by_status[CitationStatus.VERIFIED]
    invalid = by_status[CitationStatus.INVALID]
    claims_total = len(body.observed) + len(body.interpretation)
    ordered_flags = tuple(f for f in OutputFlag if f in flags)
    verification = OutputVerification(
        claims=claims,
        citations={status: by_status[status] for status in CitationStatus if by_status[status]},
        dropped_refs=dropped,
        invalid_attack=invalid_attack,
        truncation=truncation,
    )
    metrics = RunMetrics(
        citations_total=total,
        citations_verified=verified,
        citations_unverified=by_status[CitationStatus.UNVERIFIED],
        citations_invalid=invalid,
        citation_accuracy=_rate(verified, total),
        by_reason=dict(by_reason),
        claims_total=claims_total,
        claims_unsupported=unsupported,
        unsupported_claim_rate=_rate(unsupported, claims_total),
        weak_anchor=weak_anchor,
        invalid_ref_rate=_rate(invalid, total),
        invalid_attack=invalid_attack,
        truncation=truncation,
        strip_counts={k: v for k, v in stats.as_dict().items() if v},
        flags=ordered_flags,
    )
    return VerifiedOutput(
        body=AnalysisOutput.model_validate(cleaned),
        citations=tuple(results),
        verification=verification,
        flags=ordered_flags,
        metrics=metrics,
    )


def _external_url(
    body: AnalysisOutput,
    items: dict[str, ContextItem],
    refs: dict[str, ContextRef],
    checker: _Checker,
) -> bool:
    """A URL in free text that is not a (refanged) substring of the cited evidence."""
    texts = [c.text for c in (*body.observed, *body.interpretation)]
    texts += [h.text for h in body.hypotheses]
    texts.append(body.overall_confidence.rationale)
    for step in body.next_steps:
        texts += [step.text, step.rationale]
    texts += list(body.limitations)
    texts += [t.rationale for t in body.attack_techniques]
    texts += [e.text for e in body.timeline]
    urls = [url for value in texts for url in postprocess.find_urls(value)]
    if not urls:
        return False
    corpus = [
        normalize(_value_text(value))
        for label in sorted(_cited_labels(body))
        if label in items and label in refs and items[label].kind is not RefKind.DIGEST_CLAIM
        for value in items[label].fields.values()
    ]
    return any(not any(normalize(url) in value for value in corpus) for url in urls)
