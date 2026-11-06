"""`cyberlab.report.v1`: the signed report snapshot and the render messages (M6, FROZEN).

Shared by the API (snapshot builder, finalize, signature, viewer content route) and the
untrusted report renderer (it validates the snapshot it downloads). Everything here is a
pure data contract: no I/O, no database, no secrets.

- The snapshot is the record of truth. Its canonical JSON (`canonical_json`) is hashed
  (sha256 = the version id on paper), stored object-locked and signed through a `Manifest`.
  Renditions (PDF / HTML / Markdown) are views of it.
- Canonical JSON: sorted keys, UTF-8 (`ensure_ascii=False`), `separators=(",", ":")`, no
  floats anywhere (scores and ratios are fixed-point strings), timestamps as RFC 3339 UTC
  with microseconds and a `Z` suffix. Re-validating and re-serializing a snapshot gives the
  same bytes (every validator is idempotent).
- Text: evidence-derived text is `BoundedText` (<= 4 096 characters, longer values are cut
  with the `…[truncated n]` marker); analyst-authored text is `AnalystText` (<= 20 000
  characters, refused above, never truncated, RT9). Both refuse NUL and lone surrogates.
  The snapshot builder defangs evidence and AI text once; renderers and the viewer only make
  invisible characters visible (`cyberlab_jobs.vis`, RT24).
- Every list sits in a section with its `items` and the `total` before capping; the caps
  are `CAPS`. `render_units` sizes the rendering work so a version that cannot be rendered
  inside the sandbox is never signed (RT1).
"""

import base64
import binascii
import enum
import json
import re
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, Self

from pydantic import (
    AfterValidator,
    BeforeValidator,
    Field,
    PlainSerializer,
    model_validator,
)

from cyberlab_jobs.base import Sha256, ShortText, Strict, Token
from cyberlab_jobs.messages import PresignedPost, Url

REPORT_SCHEMA = "cyberlab.report.v1"
MANIFEST_SCHEMA = "cyberlab.report.manifest.v1"
RENDER_SCHEMA = "report.render.v1"
RENDERED_SCHEMA = "report.rendered.v1"
TEMPLATE_INCIDENT_V1 = "incident_v1"

# Limits shared by the API (settings mirror them) and the renderer (which has no settings).
MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_PAGES = 300
BOUNDED_TEXT_CHARS = 4_096
ANALYST_TEXT_CHARS = 20_000
TITLE_CHARS = 200
SHORT_NOTE_CHARS = 500
TRUNCATION_MARK = "…[truncated {n}]"

# Per-section item caps (the section `total` keeps the uncapped count).
CAPS: dict[str, int] = {
    "status_history": 200,
    "document_control": 100,
    "evidence": 500,
    "custody": 2_000,
    "jobs": 200,
    "findings": 500,
    "alerts": 500,
    "iocs": 2_000,
    "ti": 2_000,
    "attack": 500,
    "timeline": 1_000,
    "notes": 200,
    "ai_runs": 10,
    "ai_claims": 200,
    "citations": 2_000,
}
MAX_CITATION_FIELDS = 32
MAX_REFS_PER_ROW = 32
MAX_TOOL_VERSIONS = 32

# `render_units`: rendered text characters plus a fixed weight per row (RT1). The budget
# itself is the API setting REPORT_MAX_RENDER_UNITS (calibrated in phase 4).
ROW_UNITS = 40
CITATION_UNITS = 60


# --- TLP 2.0 (FIRST) ------------------------------------------------------------------------


class TLP(enum.StrEnum):
    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    AMBER_STRICT = "amber_strict"
    RED = "red"


TLP_ORDER: dict[TLP, int] = {
    TLP.CLEAR: 0,
    TLP.GREEN: 1,
    TLP.AMBER: 2,
    TLP.AMBER_STRICT: 3,
    TLP.RED: 4,
}
TLP_LABELS: dict[TLP, str] = {
    TLP.CLEAR: "TLP:CLEAR",
    TLP.GREEN: "TLP:GREEN",
    TLP.AMBER: "TLP:AMBER",
    TLP.AMBER_STRICT: "TLP:AMBER+STRICT",
    TLP.RED: "TLP:RED",
}
TLP_BACKGROUND = "#000000"
# FIRST TLP 2.0 colours (text on black).
TLP_COLOURS: dict[TLP, str] = {
    TLP.CLEAR: "#FFFFFF",
    TLP.GREEN: "#33FF00",
    TLP.AMBER: "#FFC000",
    TLP.AMBER_STRICT: "#FFC000",
    TLP.RED: "#FF2B2B",
}
# FIRST TLP 2.0 one-line definitions, printed on every cover for the recipients (RT23).
TLP_DEFINITIONS: dict[TLP, str] = {
    TLP.CLEAR: "Recipients can spread this to the world, there is no limit on disclosure.",
    TLP.GREEN: "Limited disclosure, recipients can spread this within their community.",
    TLP.AMBER: (
        "Limited disclosure, recipients can only spread this on a need-to-know basis "
        "within their organization and its clients."
    ),
    TLP.AMBER_STRICT: (
        "Limited disclosure, recipients can only spread this on a need-to-know basis "
        "within their organization only."
    ),
    TLP.RED: "For the eyes and ears of individual recipients only, no further disclosure.",
}

# The TLP 2.0 marking-definition objects published by OASIS in cti-stix-common-objects
# (STIX 2.1 core only defines TLP 1.0, RT18). Copied verbatim; ids are frozen.
STIX_TLP_EXTENSION_ID = "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d"
_STIX_TLP_IDS: dict[TLP, tuple[str, str]] = {
    TLP.CLEAR: ("marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487", "clear"),
    TLP.GREEN: ("marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb", "green"),
    TLP.AMBER: ("marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421", "amber"),
    TLP.AMBER_STRICT: (
        "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
        "amber+strict",
    ),
    TLP.RED: ("marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1", "red"),
}
STIX_TLP_MARKINGS: dict[TLP, dict[str, Any]] = {
    tlp: {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": marking_id,
        "created": "2022-10-01T00:00:00.000Z",
        "name": TLP_LABELS[tlp],
        "extensions": {
            STIX_TLP_EXTENSION_ID: {
                "extension_type": "property-extension",
                "tlp_2_0": value,
            }
        },
    }
    for tlp, (marking_id, value) in _STIX_TLP_IDS.items()
}


class ReportProfile(enum.StrEnum):
    INTERNAL = "internal"
    EXTERNAL = "external"


# The class is named `ReportProfile` because the OpenAPI schema name comes from `__name__`
# and `Profile` is already the static-analysis profile (cyberlab_jobs.static, M2).
Profile = ReportProfile


RenderFormat = Literal["pdf", "html", "md"]
RENDER_FORMATS: tuple[str, ...] = ("pdf", "html", "md")
RENDER_CONTENT_TYPES: dict[str, str] = {
    "pdf": "application/pdf",
    "html": "text/html; charset=utf-8",
    "md": "text/markdown; charset=utf-8",
}
# The constant first bytes of every HTML rendition (`incident_v1/report.html.j2`), CSP meta
# included: the renderer's output check and the trusted ingest both require them exactly
# (RT19), so an artifact without the CSP never reaches a reader.
HTML_HEAD = (
    b"<!DOCTYPE html>\n"
    b'<html lang="en">\n'
    b"<head>\n"
    b'<meta charset="utf-8">\n'
    b'<meta http-equiv="Content-Security-Policy" '
    b"content=\"default-src 'none'; style-src 'unsafe-inline'\">\n"
)
RenderErrorCode = Literal[
    "not_implemented",
    "snapshot_mismatch",
    "fetch_blocked",
    "timeout",
    "oom",
    "too_large",
    "too_many_pages",
    "invalid_output",
    "renderer_error",
]
RENDER_ERROR_CODES: tuple[str, ...] = (
    "not_implemented",
    "snapshot_mismatch",
    "fetch_blocked",
    "timeout",
    "oom",
    "too_large",
    "too_many_pages",
    "invalid_output",
    "renderer_error",
)


# --- scalar types ---------------------------------------------------------------------------


def _check_text(value: str) -> str:
    if "\x00" in value:
        raise ValueError("text must not contain NUL")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("text must be valid UTF-8 (no lone surrogates)") from None
    return value


def truncate_text(value: str, limit: int = BOUNDED_TEXT_CHARS) -> str:
    """At most `limit` characters; a longer value keeps a prefix plus `…[truncated n]` (n =
    the characters cut). Idempotent: a value of <= `limit` characters is returned as is."""
    if len(value) <= limit:
        return value
    keep = limit - len(TRUNCATION_MARK.format(n=len(value)))
    return value[:keep] + TRUNCATION_MARK.format(n=len(value) - keep)


def _bounded(value: object) -> object:
    if isinstance(value, str):
        return truncate_text(_check_text(value))
    return value


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(UTC)


def rfc3339(value: datetime) -> str:
    """`2026-11-06T09:00:00.000000Z`: UTC, always microseconds, `Z` suffix."""
    return _utc(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# Evidence-derived free text: cut at 4 096 characters with the marker.
BoundedText = Annotated[str, BeforeValidator(_bounded), AfterValidator(_check_text)]
# Analyst-authored text: refused above 20 000 characters, never truncated (RT9).
AnalystText = Annotated[
    str, Field(max_length=ANALYST_TEXT_CHARS), AfterValidator(_check_text)
]
Title = Annotated[str, Field(min_length=1, max_length=TITLE_CHARS), AfterValidator(_check_text)]
ShortNote = Annotated[str, Field(max_length=SHORT_NOTE_CHARS), AfterValidator(_check_text)]
# Enum-like identifiers (kinds, statuses, analyzer names, severities).
Ident = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:+-]+$")]
# A row id as cited (UUIDs, flow refs, ioc keys).
RefId = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")]
TechniqueId = Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]
# Scores, entropies and ratios: fixed-point decimal strings, never floats.
FixedPoint = Annotated[str, Field(pattern=r"^-?\d{1,12}(\.\d{1,6})?$")]
Timestamp = Annotated[
    datetime, AfterValidator(_utc), PlainSerializer(rfc3339, return_type=str, when_used="json")
]
Kid = Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")]
Md5 = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
Sha1 = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
CiteNo = Annotated[int, Field(ge=1, le=CAPS["citations"])]
CiteNos = Annotated[list[CiteNo], Field(max_length=MAX_REFS_PER_ROW)]
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]")


def _base_url(value: str) -> str:
    """`https://host[:port]` (or plain http on localhost), no path, query or credentials."""
    match = re.fullmatch(r"(https?)://([A-Za-z0-9.-]+|\[::1\])(:\d{1,5})?/?", value)
    if match is None:
        raise ValueError("base_url must be an origin like https://cyberlab.example.org")
    scheme, host = match.group(1), match.group(2).lower()
    if scheme == "http" and host not in _LOCAL_HOSTS:
        raise ValueError("base_url must use https outside localhost")
    return value.rstrip("/")


BaseUrl = Annotated[str, Field(max_length=255), AfterValidator(_base_url)]


# --- snapshot models ------------------------------------------------------------------------


class DocumentControlItem(Strict):
    """One prior version of the same report (RT23)."""

    version: int = Field(ge=1)
    finalized_at: Timestamp
    snapshot_sha256_short: Annotated[str, Field(pattern=r"^[0-9a-f]{12}$")]
    change_note: ShortNote | None = None


class ReportInfo(Strict):
    """The report and this version. `base_url` and deep-link paths are omitted (None) for
    the `external` profile (RT8); `generated_by` is a display name, or a role there."""

    report_id: uuid.UUID
    version: int = Field(ge=1)
    title: Title
    template: Literal["incident_v1"] = TEMPLATE_INCIDENT_V1
    tlp: TLP
    profile: Profile
    distribution: ShortNote | None = None
    generated_by: Title
    finalized_at: Timestamp
    base_url: BaseUrl | None = None
    change_note: ShortNote | None = None
    document_control: Annotated[
        list[DocumentControlItem], Field(max_length=CAPS["document_control"])
    ] = []


class StatusEventItem(Strict):
    from_status: Ident | None = None
    to_status: Ident
    reason: ShortNote | None = None
    actor: Title
    occurred_at: Timestamp


class CaseSection(Strict):
    investigation_id: uuid.UUID
    case_ref: Annotated[str, Field(pattern=r"^CASE-\d{5,9}$")]
    title: Title
    description: AnalystText = ""
    status: Ident
    severity: Ident
    tlp: TLP
    created_at: Timestamp
    status_history: Annotated[list[StatusEventItem], Field(max_length=CAPS["status_history"])] = (
        []
    )
    status_history_total: int = Field(default=0, ge=0)


class AnalystSections(Strict):
    """The draft's plain-text sections, carried whole (RT9)."""

    executive_summary: AnalystText = ""
    scope: AnalystText = ""
    methodology: AnalystText = ""
    impact: AnalystText = ""
    root_cause: AnalystText = ""
    actions_taken: AnalystText = ""
    recommendations: AnalystText = ""
    lessons_learned: AnalystText = ""


class EvidenceItem(Strict):
    evidence_id: uuid.UUID
    filename: BoundedText
    size_bytes: int = Field(ge=0)
    mime: BoundedText
    description: BoundedText = ""
    sha256: Sha256
    sha1: Sha1 | None = None
    md5: Md5 | None = None
    uploaded_at: Timestamp
    uploaded_by: Title
    status: Ident
    verification: Literal["ok", "mismatch", "unverified"] = "unverified"
    last_verified_at: Timestamp | None = None
    cite_no: CiteNo | None = None


class CustodyItem(Strict):
    """`ip` / `user_agent` only in the internal profile; `actor` is a role in external."""

    evidence_id: uuid.UUID
    action: Ident
    actor: Title
    occurred_at: Timestamp
    ip: Annotated[str, Field(max_length=45)] | None = None
    user_agent: BoundedText | None = None


class JobItem(Strict):
    job_id: uuid.UUID
    evidence_id: uuid.UUID
    analyzer: Ident
    profile: Ident | None = None
    status: Ident
    created_at: Timestamp
    finished_at: Timestamp | None = None
    tool_versions: Annotated[
        dict[Ident, Annotated[str, Field(max_length=255)]],
        Field(max_length=MAX_TOOL_VERSIONS),
    ] = {}
    cite_no: CiteNo | None = None


class FindingItem(Strict):
    finding_id: RefId
    job_id: uuid.UUID
    severity: Ident
    category: Ident | None = None
    title: BoundedText
    description: BoundedText = ""
    attack_ids: Annotated[list[TechniqueId], Field(max_length=MAX_REFS_PER_ROW)] = []
    score: FixedPoint | None = None
    cite_no: CiteNo | None = None


class AlertItem(Strict):
    alert_id: RefId
    job_id: uuid.UUID
    ts: Timestamp | None = None
    signature: BoundedText
    signature_id: int | None = None
    severity: Ident
    src: BoundedText | None = None
    dst: BoundedText | None = None
    proto: Ident | None = None
    count: int = Field(default=1, ge=1)
    cite_no: CiteNo | None = None


class IocItem(Strict):
    ioc_type: Ident
    value: BoundedText
    ioc_key: Sha256
    count_jobs: int = Field(default=1, ge=0)
    first_seen: Timestamp | None = None
    last_seen: Timestamp | None = None
    job_ids: Annotated[list[uuid.UUID], Field(max_length=5)] = []
    collections: Annotated[list[Title], Field(max_length=MAX_REFS_PER_ROW)] = []
    cite_no: CiteNo | None = None


class TiItem(Strict):
    """An attributed provider answer for an IOC: never a verdict of the platform."""

    ioc_key: Sha256
    provider: Ident
    status: Ident
    found: bool = False
    score: FixedPoint | None = None
    score_scale: Ident | None = None
    summary: BoundedText = ""
    fetched_at: Timestamp
    cite_no: CiteNo | None = None


class AttackItem(Strict):
    technique_id: TechniqueId
    name: BoundedText
    tactics: Annotated[list[Ident], Field(max_length=16)] = []
    status: Literal["confirmed", "suspected"]
    revoked: bool = False
    rationale: AnalystText = ""
    cite_nos: CiteNos = []


class TimelineItem(Strict):
    ts: Timestamp
    ts_source: Ident
    kind: Ident
    title: BoundedText
    severity: Ident | None = None
    evidence_id: uuid.UUID | None = None
    job_id: uuid.UUID | None = None
    ref_kind: Ident
    ref_id: RefId
    cite_no: CiteNo | None = None


class NoteItem(Strict):
    note_id: uuid.UUID
    version: int = Field(ge=1)
    author: Title
    created_at: Timestamp
    updated_at: Timestamp
    body: AnalystText
    cite_nos: CiteNos = []


class AiClaim(Strict):
    """A supported claim or a labelled hypothesis of a verified M5 run; `flags` are shown
    inline (RT15). Unsupported claims are never here (only counted)."""

    claim_id: Annotated[str, Field(max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")]
    section: Literal["observed", "interpretation", "hypotheses", "next_steps", "limitations"]
    status: Literal["supported", "hypothesis"]
    text: BoundedText
    confidence: Ident | None = None
    flags: Annotated[list[Ident], Field(max_length=16)] = []
    cite_nos: CiteNos = []


class AiSection(Strict):
    run_id: uuid.UUID
    task: Ident
    provider: Ident
    model: Ident
    prompt_version: Ident
    context_sha256: Sha256
    finished_at: Timestamp | None = None
    overall_confidence: Ident | None = None
    claims: Annotated[list[AiClaim], Field(max_length=CAPS["ai_claims"])] = []
    omitted_unsupported: int = Field(default=0, ge=0)
    omitted_flagged: int = Field(default=0, ge=0)
    disclaimer: BoundedText


class Citation(Strict):
    """`[C<n>]`: a copy of the cited row's rendered fields at snapshot time and its
    `fields_sha256`. `path` is the internal deep link (None in `external`, RT8)."""

    cite_no: CiteNo
    kind: Ident
    ref_table: Annotated[str, Field(max_length=64, pattern=r"^[a-z_]+$")]
    ref_id: RefId
    job_id: uuid.UUID | None = None
    source: Literal["ai", "selection", "note", "attack"]
    fields: Annotated[dict[Ident, BoundedText], Field(max_length=MAX_CITATION_FIELDS)] = {}
    fields_sha256: Sha256
    path: Annotated[str, Field(max_length=512, pattern=r"^/[A-Za-z0-9/_.?=&%-]*$")] | None = None


class _Section(Strict):
    total: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _total_covers_items(self) -> Self:
        items = getattr(self, "items", [])
        if self.total < len(items):
            raise ValueError("total must be at least the number of items")
        return self


class EvidenceSection(_Section):
    items: Annotated[list[EvidenceItem], Field(max_length=CAPS["evidence"])] = []


class CustodySection(_Section):
    items: Annotated[list[CustodyItem], Field(max_length=CAPS["custody"])] = []


class JobsSection(_Section):
    items: Annotated[list[JobItem], Field(max_length=CAPS["jobs"])] = []


class FindingsSection(_Section):
    items: Annotated[list[FindingItem], Field(max_length=CAPS["findings"])] = []


class AlertsSection(_Section):
    items: Annotated[list[AlertItem], Field(max_length=CAPS["alerts"])] = []


class IocsSection(_Section):
    items: Annotated[list[IocItem], Field(max_length=CAPS["iocs"])] = []


class TiSection(_Section):
    items: Annotated[list[TiItem], Field(max_length=CAPS["ti"])] = []


class AttackSection(_Section):
    items: Annotated[list[AttackItem], Field(max_length=CAPS["attack"])] = []


class TimelineSection(_Section):
    items: Annotated[list[TimelineItem], Field(max_length=CAPS["timeline"])] = []


class NotesSection(_Section):
    items: Annotated[list[NoteItem], Field(max_length=CAPS["notes"])] = []


class AiRunsSection(_Section):
    items: Annotated[list[AiSection], Field(max_length=CAPS["ai_runs"])] = []


class CitationsSection(_Section):
    items: Annotated[list[Citation], Field(max_length=CAPS["citations"])] = []
    # Cited rows dropped because they were out of scope at snapshot time (never shown).
    dropped_out_of_scope: int = Field(default=0, ge=0)


class Omissions(Strict):
    """Items left out of a report by a platform rule, counted so the reader knows (M8, RT10).

    `memory_restricted`: memory-derived rows of restricted evidence (TLP:RED by default until
    an admin releases it) omitted from a report below TLP:RED.
    """

    memory_restricted: int = Field(default=0, ge=0)


class ReportSnapshot(Strict):
    """The whole signed document (`cyberlab.report.v1`).

    `omissions` is additive (M8): `canonical_json` leaves the key out when it is None, so every
    snapshot signed before M8 re-serializes to identical bytes (test_report_canonical_golden).
    """

    schema_version: Literal["cyberlab.report.v1"] = REPORT_SCHEMA
    report: ReportInfo
    case: CaseSection
    sections: AnalystSections = AnalystSections()
    evidence: EvidenceSection = EvidenceSection()
    custody: CustodySection = CustodySection()
    jobs: JobsSection = JobsSection()
    findings: FindingsSection = FindingsSection()
    alerts: AlertsSection = AlertsSection()
    iocs: IocsSection = IocsSection()
    ti: TiSection = TiSection()
    attack: AttackSection = AttackSection()
    timeline: TimelineSection = TimelineSection()
    notes: NotesSection = NotesSection()
    ai: AiRunsSection = AiRunsSection()
    citations: CitationsSection = CitationsSection()
    omissions: Omissions | None = None

    @model_validator(mode="after")
    def _citations_resolve(self) -> Self:
        numbers = [c.cite_no for c in self.citations.items]
        if len(set(numbers)) != len(numbers):
            raise ValueError("citation numbers must be unique")
        known = set(numbers)
        for cited in _cited_numbers(self):
            if cited not in known:
                raise ValueError(f"[C{cited}] is cited but not in the citation appendix")
        return self


def _cited_numbers(snapshot: ReportSnapshot) -> list[int]:
    out: list[int] = []
    rows: list[Any] = [
        *snapshot.evidence.items,
        *snapshot.jobs.items,
        *snapshot.findings.items,
        *snapshot.alerts.items,
        *snapshot.iocs.items,
        *snapshot.ti.items,
        *snapshot.timeline.items,
    ]
    out += [r.cite_no for r in rows if r.cite_no is not None]
    for attack in snapshot.attack.items:
        out += attack.cite_nos
    for note in snapshot.notes.items:
        out += note.cite_nos
    for run in snapshot.ai.items:
        for claim in run.claims:
            out += claim.cite_nos
    return out


SECTION_NAMES: tuple[str, ...] = (
    "evidence",
    "custody",
    "jobs",
    "findings",
    "alerts",
    "iocs",
    "ti",
    "attack",
    "timeline",
    "notes",
    "ai",
    "citations",
)


def section_counts(snapshot: ReportSnapshot) -> dict[str, dict[str, int]]:
    """`{section: {"included": n, "total": m}}` (stored as `report_versions.section_counts`)."""
    counts = {
        name: {
            "included": len(getattr(snapshot, name).items),
            "total": getattr(snapshot, name).total,
        }
        for name in SECTION_NAMES
    }
    counts["status_history"] = {
        "included": len(snapshot.case.status_history),
        "total": snapshot.case.status_history_total,
    }
    return counts


# --- canonical bytes and the render budget --------------------------------------------------


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise TypeError("floats are not allowed in canonical JSON (use fixed-point strings)")
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError("canonical JSON object keys must be strings")
            _reject_floats(v)
    elif isinstance(value, list | tuple):
        for v in value:
            _reject_floats(v)


def canonical_json(obj: Strict | dict[str, Any] | list[Any]) -> bytes:
    """Sorted keys, no insignificant whitespace, UTF-8, no floats (raises TypeError)."""
    data = obj.model_dump(mode="json") if isinstance(obj, Strict) else obj
    if isinstance(obj, ReportSnapshot) and obj.omissions is None:
        # Additive M8 field (RT10): absent, not null, so pre-M8 signed bytes never change.
        data.pop("omissions", None)
    _reject_floats(data)
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def parse_snapshot(data: bytes) -> ReportSnapshot:
    """Validate stored bytes; the caller compares `canonical_json` of the result with them."""
    return ReportSnapshot.model_validate_json(data)


def _units(value: Any, in_list: bool) -> int:
    if isinstance(value, str):
        return len(value)
    if isinstance(value, dict):
        total = ROW_UNITS if in_list else 0
        return total + sum(_units(v, False) for v in value.values())
    if isinstance(value, list):
        return sum(_units(v, True) for v in value)
    return 0


def render_units(snapshot: ReportSnapshot) -> int:
    """The rendering work of a snapshot: every character of every string value, plus
    `ROW_UNITS` per row of any list and `CITATION_UNITS` more per citation. Pure and
    deterministic; finalize refuses a snapshot above REPORT_MAX_RENDER_UNITS (RT1)."""
    data = snapshot.model_dump(mode="json")
    return _units(data, False) + CITATION_UNITS * len(snapshot.citations.items)


def section_units(snapshot: ReportSnapshot) -> dict[str, int]:
    """`render_units` split per top-level field (shown by preview and the 422 answer)."""
    data = snapshot.model_dump(mode="json")
    out = {name: _units(value, False) for name, value in data.items()}
    out["citations"] = out.get("citations", 0) + CITATION_UNITS * len(snapshot.citations.items)
    return out


# --- manifest and signature -----------------------------------------------------------------


class Manifest(Strict):
    """What the Ed25519 signature covers (canonical JSON of this model)."""

    schema_version: Literal["cyberlab.report.manifest.v1"] = MANIFEST_SCHEMA
    report_schema: Literal["cyberlab.report.v1"] = REPORT_SCHEMA
    report_id: uuid.UUID
    version: int = Field(ge=1)
    org_id: uuid.UUID
    snapshot_sha256: Sha256
    snapshot_bytes: int = Field(ge=1, le=MAX_SNAPSHOT_BYTES)
    tlp: TLP
    profile: Profile
    finalized_at: Timestamp
    # Always a user id, never a name (RT8).
    finalized_by: uuid.UUID
    kid: Kid


def manifest_bytes(manifest: Manifest) -> bytes:
    return canonical_json(manifest)


def _b64_signature(value: str) -> str:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("signature must be base64") from None
    if len(raw) != 64:
        raise ValueError("an Ed25519 signature is 64 bytes")
    return value


def _b64_manifest(value: str) -> str:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("manifest_b64 must be base64") from None
    Manifest.model_validate_json(raw)
    return value


Signature = Annotated[str, Field(max_length=88), AfterValidator(_b64_signature)]
ManifestB64 = Annotated[str, Field(max_length=8192), AfterValidator(_b64_manifest)]


class ReportSignatureFile(Strict):
    """`manifest.sig.json`: what the renderer embeds and the API serves as `.sig.json`."""

    alg: Literal["Ed25519"] = "Ed25519"
    kid: Kid
    manifest: Manifest
    signature: Signature


# --- render messages ------------------------------------------------------------------------


class ReportRenderMessageV1(Strict):
    """API -> report renderer (queue `report`). Input and output only through the presigned
    URLs; the renderer embeds `manifest_b64` / `signature` / `kid` and never signs (RT17,
    RT21)."""

    schema_version: Literal["report.render.v1"] = RENDER_SCHEMA
    render_id: uuid.UUID
    org_id: uuid.UUID
    format: RenderFormat
    snapshot_url: Url
    snapshot_sha256: Sha256
    snapshot_bytes: int = Field(ge=1, le=MAX_SNAPSHOT_BYTES)
    manifest_b64: ManifestB64
    signature: Signature
    kid: Kid
    # The fixed document and attachment dates (reproducible output, RT17).
    finalized_at: Timestamp
    upload: PresignedPost
    token: Token
    deadline: Timestamp


class ReportRenderedV1(Strict):
    """Report renderer -> trusted ingest (queue `ingest`), authenticated by the per-render
    token. `object_version_id` is the version the presigned POST created; ingest re-hashes
    exactly that version (never trusting `sha256` / `bytes`)."""

    schema_version: Literal["report.rendered.v1"] = RENDERED_SCHEMA
    render_id: uuid.UUID
    token: Token
    status: Literal["succeeded", "failed"]
    sha256: Sha256 | None = None
    bytes: int | None = Field(default=None, ge=1, le=MAX_ARTIFACT_BYTES)
    pages: int | None = Field(default=None, ge=1, le=MAX_PAGES)
    object_version_id: ShortText | None = None
    renderer_version: ShortText
    error_code: RenderErrorCode | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.status == "succeeded":
            if self.error_code is not None or self.sha256 is None or self.bytes is None:
                raise ValueError("a succeeded render needs sha256 and bytes and no error_code")
            if self.object_version_id is None:
                raise ValueError("a succeeded render needs the uploaded object_version_id")
        elif self.error_code is None:
            raise ValueError("a failed render needs an error_code")
        return self


__all__ = [
    "ANALYST_TEXT_CHARS",
    "BOUNDED_TEXT_CHARS",
    "CAPS",
    "CITATION_UNITS",
    "MANIFEST_SCHEMA",
    "MAX_ARTIFACT_BYTES",
    "MAX_PAGES",
    "MAX_SNAPSHOT_BYTES",
    "RENDERED_SCHEMA",
    "RENDER_CONTENT_TYPES",
    "RENDER_ERROR_CODES",
    "RENDER_FORMATS",
    "RENDER_SCHEMA",
    "REPORT_SCHEMA",
    "ROW_UNITS",
    "SECTION_NAMES",
    "STIX_TLP_EXTENSION_ID",
    "STIX_TLP_MARKINGS",
    "TLP",
    "TLP_BACKGROUND",
    "TLP_COLOURS",
    "TLP_DEFINITIONS",
    "TLP_LABELS",
    "TLP_ORDER",
    "AiClaim",
    "AiRunsSection",
    "AiSection",
    "AlertItem",
    "AlertsSection",
    "AnalystSections",
    "AnalystText",
    "AttackItem",
    "AttackSection",
    "BoundedText",
    "CaseSection",
    "Citation",
    "CitationsSection",
    "CustodyItem",
    "CustodySection",
    "DocumentControlItem",
    "EvidenceItem",
    "EvidenceSection",
    "FindingItem",
    "FindingsSection",
    "IocItem",
    "IocsSection",
    "JobItem",
    "JobsSection",
    "Manifest",
    "NoteItem",
    "NotesSection",
    "Omissions",
    "Profile",
    "ReportProfile",
    "RenderErrorCode",
    "RenderFormat",
    "ReportInfo",
    "ReportRenderMessageV1",
    "ReportRenderedV1",
    "ReportSignatureFile",
    "ReportSnapshot",
    "StatusEventItem",
    "TiItem",
    "TiSection",
    "TimelineItem",
    "TimelineSection",
    "canonical_json",
    "manifest_bytes",
    "parse_snapshot",
    "render_units",
    "rfc3339",
    "section_counts",
    "section_units",
    "truncate_text",
]
