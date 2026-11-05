"""Reports (migration 0012, M6 phase 1, FROZEN).

- `reports`: the mutable **draft** (title, TLP, profile, sections and selections in
  `draft`, distribution) with an optimistic `revision` (+1 per UPDATE, `report_guard`),
  a monotonic `latest_version`, and `discarded` only while no version exists (final).
- `report_versions`: each finalize, append-only: the canonical snapshot's sha256 and size,
  its exact object version in the object-locked `reports` bucket, the signed manifest and
  its detached Ed25519 signature (`kid`), section counts and the change note (RT23).
- `report_citations`: the `[C<n>]` rows of a version (append-only), indexed by
  (org, kind, ref_id) next to the M5 `ai_citations` index ("which versions cite this row").
- `report_renders`: one rendition (pdf / html / md, DOCX deferred RT12) with a transition
  trigger (`queued -> running | failed`, `running -> succeeded | failed`, finals immutable)
  and a per-render token hash.
- `report_render_index`: the system lookup for the trusted ingest worker and the reaper
  (the `analysis_job_index` / `ti_run_index` pattern): ids and scheduling only.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, UUIDPk
from app.modules.investigations.models import TLP_VALUES

TEMPLATES = ("incident_v1",)
PROFILES = ("internal", "external")
REPORT_STATUSES = ("draft", "discarded")
RENDER_FORMATS = ("pdf", "html", "md")
RENDER_STATUSES = ("queued", "running", "succeeded", "failed")
CITATION_SOURCES = ("ai", "selection", "note", "attack")
DRAFT_MAX_BYTES = 1024 * 1024  # RT9: 8 sections x 20 000 non-ASCII characters fit
MANIFEST_MAX_BYTES = 4 * 1024
SECTION_COUNTS_MAX_BYTES = 4 * 1024
CHANGE_NOTE_MAX_CHARS = 500
DISTRIBUTION_MAX_CHARS = 500
TITLE_MAX_CHARS = 200
SHA256_PATTERN = "^[0-9a-f]{64}$"
KID_PATTERN = "^[A-Za-z0-9._-]{1,64}$"
# A base64 Ed25519 signature: 64 bytes -> 86 characters + "==".
SIGNATURE_PATTERN = "^[A-Za-z0-9+/]{86}==$"


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class Report(UUIDPk, Base):
    __tablename__ = "reports"
    __table_args__ = (
        ForeignKeyConstraint(
            ["investigation_id", "organization_id"],
            ["investigations.id", "investigations.organization_id"],
        ),
        UniqueConstraint("id", "organization_id"),
        Index(None, "organization_id", "updated_at"),
        Index(None, "investigation_id", "created_at"),
        CheckConstraint(_in("template", TEMPLATES), name="template"),
        CheckConstraint(_in("tlp", TLP_VALUES), name="tlp"),
        CheckConstraint(_in("profile", PROFILES), name="profile"),
        CheckConstraint(_in("status", REPORT_STATUSES), name="status"),
        CheckConstraint(
            f"char_length(title) BETWEEN 1 AND {TITLE_MAX_CHARS}", name="title_length"
        ),
        CheckConstraint(
            f"distribution IS NULL OR char_length(distribution) <= {DISTRIBUTION_MAX_CHARS}",
            name="distribution_length",
        ),
        CheckConstraint(
            f"jsonb_typeof(draft) = 'object' AND octet_length(draft::text) <= {DRAFT_MAX_BYTES}",
            name="draft",
        ),
        CheckConstraint("revision >= 1", name="revision_positive"),
        CheckConstraint("latest_version >= 0", name="latest_version_non_negative"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    investigation_id: Mapped[uuid.UUID]
    title: Mapped[str] = mapped_column(String(TITLE_MAX_CHARS))
    template: Mapped[str] = mapped_column(
        String(32), server_default="incident_v1", default="incident_v1"
    )
    tlp: Mapped[str] = mapped_column(String(16))
    profile: Mapped[str] = mapped_column(String(16), server_default="internal", default="internal")
    # `reports.schemas.ReportDraft` (sections + selections), validated by the API.
    draft: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)
    distribution: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), server_default="draft", default="draft")
    revision: Mapped[int] = mapped_column(Integer, server_default="1", default=1)
    latest_version: Mapped[int] = mapped_column(Integer, server_default="0", default=0)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())

    __mapper_args__ = {"eager_defaults": True}


class ReportVersion(UUIDPk, Base):
    __tablename__ = "report_versions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["report_id", "organization_id"], ["reports.id", "reports.organization_id"]
        ),
        UniqueConstraint("id", "organization_id"),
        UniqueConstraint("report_id", "version"),
        Index(None, "organization_id", "finalized_at"),
        CheckConstraint("version >= 1", name="version_positive"),
        CheckConstraint(_in("tlp", TLP_VALUES), name="tlp"),
        CheckConstraint(_in("profile", PROFILES), name="profile"),
        CheckConstraint("schema_version = 'cyberlab.report.v1'", name="schema_version"),
        CheckConstraint(f"snapshot_sha256 ~ '{SHA256_PATTERN}'", name="snapshot_sha256"),
        CheckConstraint("snapshot_bytes > 0", name="snapshot_bytes_positive"),
        CheckConstraint(
            f"jsonb_typeof(manifest) = 'object' AND octet_length(manifest::text) <= "
            f"{MANIFEST_MAX_BYTES}",
            name="manifest",
        ),
        CheckConstraint(f"signature ~ '{SIGNATURE_PATTERN}'", name="signature"),
        CheckConstraint(f"kid ~ '{KID_PATTERN}'", name="kid"),
        CheckConstraint(
            f"jsonb_typeof(section_counts) = 'object' AND octet_length(section_counts::text) "
            f"<= {SECTION_COUNTS_MAX_BYTES}",
            name="section_counts",
        ),
        CheckConstraint(
            f"change_note IS NULL OR char_length(change_note) <= {CHANGE_NOTE_MAX_CHARS}",
            name="change_note_length",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    report_id: Mapped[uuid.UUID]
    version: Mapped[int] = mapped_column(Integer)
    schema_version: Mapped[str] = mapped_column(String(32))
    tlp: Mapped[str] = mapped_column(String(16))
    profile: Mapped[str] = mapped_column(String(16))
    snapshot_sha256: Mapped[str] = mapped_column(String(64))
    snapshot_bytes: Mapped[int] = mapped_column(BigInteger)
    object_key: Mapped[str] = mapped_column(String(512))
    object_version_id: Mapped[str] = mapped_column(String(255))
    manifest: Mapped[dict[str, Any]]
    signature: Mapped[str] = mapped_column(String(88))
    kid: Mapped[str] = mapped_column(String(64))
    section_counts: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)
    change_note: Mapped[str | None] = mapped_column(Text)
    finalized_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    finalized_at: Mapped[datetime] = mapped_column(server_default=func.now())


class ReportCitation(UUIDPk, Base):
    __tablename__ = "report_citations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["version_id", "organization_id"],
            ["report_versions.id", "report_versions.organization_id"],
        ),
        ForeignKeyConstraint(
            ["job_id", "organization_id"],
            ["analysis_jobs.id", "analysis_jobs.organization_id"],
        ),
        UniqueConstraint("version_id", "cite_no"),
        Index(None, "organization_id", "kind", "ref_id"),
        CheckConstraint("cite_no > 0", name="cite_no_positive"),
        CheckConstraint("char_length(ref_id) BETWEEN 1 AND 64", name="ref_id_length"),
        CheckConstraint("kind ~ '^[a-z_]{1,16}$'", name="kind"),
        CheckConstraint("ref_table ~ '^[a-z_]{1,64}$'", name="ref_table"),
        CheckConstraint(f"fields_sha256 ~ '{SHA256_PATTERN}'", name="fields_sha256"),
        CheckConstraint(_in("source", CITATION_SOURCES), name="source"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    version_id: Mapped[uuid.UUID]
    cite_no: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(16))
    ref_table: Mapped[str] = mapped_column(String(64))
    ref_id: Mapped[str] = mapped_column(String(64))
    job_id: Mapped[uuid.UUID | None]
    fields_sha256: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(16))
    ai_citation_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("ai_citations.id"))


class ReportRender(UUIDPk, Base):
    __tablename__ = "report_renders"
    __table_args__ = (
        ForeignKeyConstraint(
            ["version_id", "organization_id"],
            ["report_versions.id", "report_versions.organization_id"],
        ),
        UniqueConstraint("id", "organization_id"),
        # Dedupe: one non-failed render per (version, format, renderer version).
        Index(
            "ux_report_renders_version_id_format_renderer",
            "version_id",
            "format",
            text("coalesce(renderer_version, '')"),
            unique=True,
            postgresql_where=text("status <> 'failed'"),
        ),
        Index(None, "organization_id", "created_at"),
        CheckConstraint(_in("format", RENDER_FORMATS), name="format"),
        CheckConstraint(_in("status", RENDER_STATUSES), name="status"),
        CheckConstraint(f"token_sha256 ~ '{SHA256_PATTERN}'", name="token_sha256"),
        CheckConstraint(f"sha256 IS NULL OR sha256 ~ '{SHA256_PATTERN}'", name="sha256"),
        CheckConstraint("bytes IS NULL OR bytes > 0", name="bytes_positive"),
        CheckConstraint("pages IS NULL OR pages > 0", name="pages_positive"),
        CheckConstraint(
            "error_code IS NULL OR error_code ~ '^[a-z][a-z_]{0,31}$'", name="error_code"
        ),
        CheckConstraint(
            "status <> 'succeeded' OR (sha256 IS NOT NULL AND bytes IS NOT NULL AND "
            "object_version_id IS NOT NULL)",
            name="succeeded_has_artifact",
        ),
        CheckConstraint("status <> 'failed' OR error_code IS NOT NULL", name="failed_has_code"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    version_id: Mapped[uuid.UUID]
    format: Mapped[str] = mapped_column(String(8))
    status: Mapped[str] = mapped_column(String(16), server_default="queued", default="queued")
    error_code: Mapped[str | None] = mapped_column(String(32))
    token_sha256: Mapped[str] = mapped_column(String(64))
    sha256: Mapped[str | None] = mapped_column(String(64))
    bytes: Mapped[int | None] = mapped_column(BigInteger)
    pages: Mapped[int | None] = mapped_column(Integer)
    object_version_id: Mapped[str | None] = mapped_column(String(255))
    renderer_version: Mapped[str | None] = mapped_column(String(255))
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]


class ReportRenderIndex(Base):
    """System lookup: the trusted ingest worker and the reaper find a render's org here
    (system session), never from the message alone. No tenant data."""

    __tablename__ = "report_render_index"
    __table_args__ = (
        ForeignKeyConstraint(
            ["render_id", "organization_id"],
            ["report_renders.id", "report_renders.organization_id"],
            ondelete="CASCADE",
        ),
        Index(None, "status", "deadline_at"),
        CheckConstraint(_in("status", RENDER_STATUSES), name="status"),
        CheckConstraint("attempts >= 0", name="attempts_non_negative"),
    )

    render_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id"))
    status: Mapped[str] = mapped_column(String(16))
    dispatched_at: Mapped[datetime | None]
    deadline_at: Mapped[datetime]
    attempts: Mapped[int] = mapped_column(Integer, server_default="0", default=0)
