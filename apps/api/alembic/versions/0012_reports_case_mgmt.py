"""reports and case management: case TLP + share-policy flags, status history, evidence
share policies, analyst notes (versioned), IOC collections, ATT&CK case mappings, report
drafts, versions, citations, renders and the render index

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-06 09:00:00

Frozen in M6 phase 1 (later schema needs go into 0013, assigned by the parent). The M4/M5
conventions:
- Every tenant table has FORCE RLS on `organization_id = app_org_id()`.
  `report_render_index` is the system lookup with the `ai_run_index` pattern: a system
  session sees every row, a tenant session only its own org's.
- Composite (id, organization_id) FKs pin every child row to its parent of the same org.
- No DELETE grant anywhere. UPDATE is granted per column, only where the API or a trusted
  worker legitimately writes. `investigations` keeps its table-wide UPDATE (M1).
- Append-only (`forbid_mutation`, also for the owner): status events, note versions,
  report versions, report citations.
- Guard triggers: `analyst_note_guard`, `ioc_collection_item_guard`, `report_guard`,
  `report_render_transition`.
- `ti_run_items.reason` gains `policy_blocked` (the TI run error code of the share policy);
  `ai_runs.error_code` has no CHECK, so `policy_blocked` needs no change there.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "cyberlab_app"
TENANT_TABLES = (
    "investigation_status_events",
    "evidence_share_policies",
    "analyst_notes",
    "analyst_note_versions",
    "ioc_collections",
    "ioc_collection_items",
    "case_attack_mappings",
    "reports",
    "report_versions",
    "report_citations",
    "report_renders",
)
APPEND_ONLY = (
    "investigation_status_events",
    "analyst_note_versions",
    "report_versions",
    "report_citations",
)
GRANTS = {table: "SELECT, INSERT" for table in (*TENANT_TABLES, "report_render_index")}
UPDATE_COLUMNS = {
    "evidence_share_policies": "ai_excluded, ti_excluded, updated_by, updated_at",
    "analyst_notes": (
        "current_version, pinned, include_in_reports, deleted_at, deleted_by, updated_at"
    ),
    "ioc_collections": "name, description, archived_at, updated_at",
    "ioc_collection_items": "removed_at, removed_by, note",
    "case_attack_mappings": "status, rationale, sources, updated_by, updated_at",
    "reports": (
        "title, tlp, profile, draft, distribution, status, revision, latest_version, updated_at"
    ),
    "report_renders": (
        "status, error_code, sha256, bytes, pages, object_version_id, renderer_version, "
        "started_at, finished_at"
    ),
    "report_render_index": "status, dispatched_at, deadline_at, attempts",
}
TLP = "('clear', 'green', 'amber', 'amber_strict', 'red')"
STATUSES = "('open', 'in_progress', 'closed', 'archived')"
OLD_TI_REASONS = "('rate_limited', 'quota_exhausted', 'deadline', 'auth_failed')"
NEW_TI_REASONS = "('rate_limited', 'quota_exhausted', 'deadline', 'auth_failed', 'policy_blocked')"
SHA256 = "'^[0-9a-f]{64}$'"

NOTE_GUARD = """CREATE FUNCTION analyst_note_guard() RETURNS trigger LANGUAGE plpgsql
  SET search_path = pg_catalog AS $$
BEGIN
  IF NEW.current_version < OLD.current_version THEN
    RAISE EXCEPTION 'note current_version may not decrease'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.deleted_at IS NOT NULL
     AND (NEW.deleted_at, NEW.deleted_by) IS DISTINCT FROM (OLD.deleted_at, OLD.deleted_by) THEN
    RAISE EXCEPTION 'note delete fields are set once'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.id, NEW.organization_id, NEW.investigation_id, NEW.created_by, NEW.created_at)
     IS DISTINCT FROM
     (OLD.id, OLD.organization_id, OLD.investigation_id, OLD.created_by, OLD.created_at) THEN
    RAISE EXCEPTION 'note identity columns are immutable'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$"""

ITEM_GUARD = """CREATE FUNCTION ioc_collection_item_guard() RETURNS trigger LANGUAGE plpgsql
  SET search_path = pg_catalog AS $$
BEGIN
  IF OLD.removed_at IS NOT NULL
     AND (NEW.removed_at, NEW.removed_by) IS DISTINCT FROM (OLD.removed_at, OLD.removed_by) THEN
    RAISE EXCEPTION 'collection item removal is set once'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.id, NEW.organization_id, NEW.collection_id, NEW.ioc_type, NEW.value_norm,
      NEW.ioc_key, NEW.source, NEW.job_id, NEW.ioc_id, NEW.added_by, NEW.added_at)
     IS DISTINCT FROM
     (OLD.id, OLD.organization_id, OLD.collection_id, OLD.ioc_type, OLD.value_norm,
      OLD.ioc_key, OLD.source, OLD.job_id, OLD.ioc_id, OLD.added_by, OLD.added_at) THEN
    RAISE EXCEPTION 'collection item identity columns are immutable'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$"""

REPORT_GUARD = """CREATE FUNCTION report_guard() RETURNS trigger LANGUAGE plpgsql
  SET search_path = pg_catalog AS $$
BEGIN
  IF OLD.status = 'discarded' THEN
    RAISE EXCEPTION 'report % is discarded (final)', OLD.id
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.revision <> OLD.revision + 1 THEN
    RAISE EXCEPTION 'report revision must increase by one per update'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.latest_version < OLD.latest_version THEN
    RAISE EXCEPTION 'report latest_version may not decrease'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.status = 'discarded' AND (OLD.latest_version <> 0 OR NEW.latest_version <> 0) THEN
    RAISE EXCEPTION 'a report with versions cannot be discarded'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.id, NEW.organization_id, NEW.investigation_id, NEW.template, NEW.created_by,
      NEW.created_at)
     IS DISTINCT FROM
     (OLD.id, OLD.organization_id, OLD.investigation_id, OLD.template, OLD.created_by,
      OLD.created_at) THEN
    RAISE EXCEPTION 'report identity columns are immutable'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$"""

# queued -> running | failed; running -> succeeded | failed. Final states never change.
RENDER_TRANSITION = """CREATE FUNCTION report_render_transition() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF OLD.status IN ('succeeded', 'failed') THEN
    RAISE EXCEPTION 'report render % is final (%)', OLD.id, OLD.status
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
       (OLD.status = 'queued' AND NEW.status IN ('running', 'failed'))
    OR (OLD.status = 'running' AND NEW.status IN ('succeeded', 'failed'))
  ) THEN
    RAISE EXCEPTION 'illegal report render transition % -> %', OLD.status, NEW.status
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.id, NEW.organization_id, NEW.version_id, NEW.format, NEW.token_sha256,
      NEW.requested_by, NEW.created_at)
     IS DISTINCT FROM
     (OLD.id, OLD.organization_id, OLD.version_id, OLD.format, OLD.token_sha256,
      OLD.requested_by, OLD.created_at) THEN
    RAISE EXCEPTION 'report render identity columns are immutable'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$"""

FUNCTIONS = (
    "analyst_note_guard",
    "ioc_collection_item_guard",
    "report_guard",
    "report_render_transition",
)
GUARDED = {
    "analyst_notes": "analyst_note_guard",
    "ioc_collection_items": "ioc_collection_item_guard",
    "reports": "report_guard",
    "report_renders": "report_render_transition",
}


def _ts(name: str, *, nullable: bool = False, default: bool = True) -> sa.Column[object]:
    return sa.Column(
        name,
        sa.DateTime(timezone=True),
        server_default=sa.text("now()") if default and not nullable else None,
        nullable=nullable,
    )


def _org_fk(table: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["organization_id"],
        ["organizations.id"],
        name=op.f(f"fk_{table}_organization_id_organizations"),
    )


def _user_fk(table: str, column: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint([column], ["users.id"], name=op.f(f"fk_{table}_{column}_users"))


def _parent_fk(
    table: str, column: str, parent: str, *, ondelete: str | None = None
) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        [column, "organization_id"],
        [f"{parent}.id", f"{parent}.organization_id"],
        name=op.f(f"fk_{table}_{column}_organization_id_{parent}"),
        ondelete=ondelete,
    )


def _jsonb(name: str, default: str) -> sa.Column[object]:
    return sa.Column(
        name, postgresql.JSONB(astext_type=sa.Text()), server_default=default, nullable=False
    )


def _ck(table: str, name: str, sql: str) -> sa.CheckConstraint:
    return sa.CheckConstraint(sql, name=op.f(f"ck_{table}_{name}"))


def _uuid_pk() -> sa.Column[object]:
    return sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False)


def upgrade() -> None:
    _alter_existing()
    _create_tables()
    _create_security()


def _alter_existing() -> None:
    # Existing cases are backfilled by the defaults: TLP:AMBER, nothing excluded.
    op.add_column(
        "investigations",
        sa.Column("tlp", sa.String(length=16), server_default="amber", nullable=False),
    )
    op.add_column(
        "investigations",
        sa.Column("ai_excluded", sa.Boolean(), server_default="false", nullable=False),
    )
    op.add_column(
        "investigations",
        sa.Column("ti_excluded", sa.Boolean(), server_default="false", nullable=False),
    )
    op.create_check_constraint(op.f("ck_investigations_tlp"), "investigations", f"tlp IN {TLP}")
    op.drop_constraint(op.f("ck_ti_run_items_reason"), "ti_run_items", type_="check")
    op.create_check_constraint(
        op.f("ck_ti_run_items_reason"),
        "ti_run_items",
        f"reason IS NULL OR reason IN {NEW_TI_REASONS}",
    )


def _create_tables() -> None:
    t = "investigation_status_events"
    op.create_table(
        t,
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("from_status", sa.String(length=16), nullable=True),
        sa.Column("to_status", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("actor_id", sa.Uuid(), nullable=False),
        _ts("occurred_at"),
        _uuid_pk(),
        _ck(t, "from_status", f"from_status IS NULL OR from_status IN {STATUSES}"),
        _ck(t, "to_status", f"to_status IN {STATUSES}"),
        _ck(t, "reason_length", "reason IS NULL OR char_length(reason) BETWEEN 1 AND 500"),
        _parent_fk(t, "investigation_id", "investigations"),
        _org_fk(t),
        _user_fk(t, "actor_id"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
    )
    op.create_index(
        op.f(f"ix_{t}_investigation_id_occurred_at"), t, ["investigation_id", "occurred_at"]
    )

    t = "evidence_share_policies"
    op.create_table(
        t,
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("ai_excluded", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("ti_excluded", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("updated_by", sa.Uuid(), nullable=False),
        _ts("updated_at"),
        _parent_fk(t, "evidence_id", "evidence"),
        _org_fk(t),
        _user_fk(t, "updated_by"),
        sa.PrimaryKeyConstraint("evidence_id", name=op.f(f"pk_{t}")),
    )
    op.create_index(op.f(f"ix_{t}_organization_id"), t, ["organization_id"])

    t = "analyst_notes"
    op.create_table(
        t,
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("current_version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("pinned", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("include_in_reports", sa.Boolean(), server_default="false", nullable=False),
        _ts("deleted_at", nullable=True),
        sa.Column("deleted_by", sa.Uuid(), nullable=True),
        _ts("created_at"),
        _ts("updated_at"),
        _uuid_pk(),
        _ck(t, "current_version_positive", "current_version >= 1"),
        _ck(t, "deleted_pair", "(deleted_at IS NULL) = (deleted_by IS NULL)"),
        _parent_fk(t, "investigation_id", "investigations"),
        _org_fk(t),
        _user_fk(t, "created_by"),
        _user_fk(t, "deleted_by"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("id", "organization_id", name=op.f(f"uq_{t}_id_organization_id")),
    )
    op.create_index(
        op.f(f"ix_{t}_investigation_id_created_at"), t, ["investigation_id", "created_at"]
    )

    t = "analyst_note_versions"
    op.create_table(
        t,
        sa.Column("note_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        _jsonb("refs", "[]"),
        sa.Column("author_id", sa.Uuid(), nullable=False),
        _ts("created_at"),
        _ck(t, "version_positive", "version >= 1"),
        _ck(t, "body_length", "char_length(body) BETWEEN 1 AND 20000"),
        _ck(
            t,
            "refs",
            "jsonb_typeof(refs) = 'array' AND jsonb_array_length(refs) <= 20 "
            "AND octet_length(refs::text) <= 16384",
        ),
        _parent_fk(t, "note_id", "analyst_notes"),
        _org_fk(t),
        _user_fk(t, "author_id"),
        sa.PrimaryKeyConstraint("note_id", "version", name=op.f(f"pk_{t}")),
    )
    op.create_index(op.f(f"ix_{t}_organization_id"), t, ["organization_id"])

    t = "ioc_collections"
    op.create_table(
        t,
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        _ts("archived_at", nullable=True),
        _ts("created_at"),
        _ts("updated_at"),
        _uuid_pk(),
        _ck(t, "name_length", "char_length(name) BETWEEN 1 AND 120"),
        _ck(t, "description_length", "char_length(description) <= 2000"),
        _parent_fk(t, "investigation_id", "investigations"),
        _org_fk(t),
        _user_fk(t, "created_by"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("id", "organization_id", name=op.f(f"uq_{t}_id_organization_id")),
    )
    op.create_index(
        "ux_ioc_collections_investigation_id_lower_name",
        t,
        ["investigation_id", sa.text("lower(name)")],
        unique=True,
    )

    t = "ioc_collection_items"
    op.create_table(
        t,
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("collection_id", sa.Uuid(), nullable=False),
        sa.Column("ioc_type", sa.String(length=32), nullable=False),
        sa.Column("value_norm", sa.String(length=2048), nullable=False),
        sa.Column("ioc_key", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=True),
        sa.Column("ioc_id", sa.Uuid(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("added_by", sa.Uuid(), nullable=False),
        _ts("added_at"),
        _ts("removed_at", nullable=True),
        sa.Column("removed_by", sa.Uuid(), nullable=True),
        _uuid_pk(),
        _ck(t, "ioc_key", f"ioc_key ~ {SHA256}"),
        _ck(t, "value_length", "char_length(value_norm) BETWEEN 1 AND 2048"),
        _ck(t, "ioc_type", "ioc_type ~ '^[a-z][a-z0-9_]{0,31}$'"),
        _ck(t, "source", "source IN ('job_ioc', 'manual')"),
        _ck(t, "job_ioc_pair", "(job_id IS NULL) = (ioc_id IS NULL)"),
        _ck(t, "source_matches", "(source = 'job_ioc') = (ioc_id IS NOT NULL)"),
        _ck(t, "note_length", "note IS NULL OR char_length(note) <= 500"),
        _ck(t, "removed_pair", "(removed_at IS NULL) = (removed_by IS NULL)"),
        _parent_fk(t, "collection_id", "ioc_collections"),
        _parent_fk(t, "job_id", "analysis_jobs"),
        sa.ForeignKeyConstraint(["ioc_id"], ["iocs.id"], name=op.f(f"fk_{t}_ioc_id_iocs")),
        _org_fk(t),
        _user_fk(t, "added_by"),
        _user_fk(t, "removed_by"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
    )
    op.create_index(
        "ux_ioc_collection_items_collection_id_ioc_key",
        t,
        ["collection_id", "ioc_key"],
        unique=True,
        postgresql_where=sa.text("removed_at IS NULL"),
    )
    op.create_index(op.f(f"ix_{t}_organization_id_ioc_key"), t, ["organization_id", "ioc_key"])

    t = "case_attack_mappings"
    op.create_table(
        t,
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("technique_id", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("rationale", sa.Text(), server_default="", nullable=False),
        _jsonb("sources", "[]"),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("updated_by", sa.Uuid(), nullable=False),
        _ts("created_at"),
        _ts("updated_at"),
        _uuid_pk(),
        _ck(t, "technique_id", "technique_id ~ '^T\\d{4}(\\.\\d{3})?$'"),
        _ck(t, "status", "status IN ('confirmed', 'suspected', 'rejected')"),
        _ck(t, "rationale_length", "char_length(rationale) <= 2000"),
        _ck(
            t,
            "sources",
            "jsonb_typeof(sources) = 'array' AND jsonb_array_length(sources) <= 32 "
            "AND octet_length(sources::text) <= 16384",
        ),
        _parent_fk(t, "investigation_id", "investigations"),
        _org_fk(t),
        _user_fk(t, "created_by"),
        _user_fk(t, "updated_by"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("id", "organization_id", name=op.f(f"uq_{t}_id_organization_id")),
        sa.UniqueConstraint(
            "investigation_id", "technique_id", name=op.f(f"uq_{t}_investigation_id_technique_id")
        ),
    )
    op.create_index(op.f(f"ix_{t}_organization_id"), t, ["organization_id"])

    t = "reports"
    op.create_table(
        t,
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("template", sa.String(length=32), server_default="incident_v1", nullable=False),
        sa.Column("tlp", sa.String(length=16), nullable=False),
        sa.Column("profile", sa.String(length=16), server_default="internal", nullable=False),
        _jsonb("draft", "{}"),
        sa.Column("distribution", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=16), server_default="draft", nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column("latest_version", sa.Integer(), server_default="0", nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        _ts("created_at"),
        _ts("updated_at"),
        _uuid_pk(),
        _ck(t, "template", "template IN ('incident_v1')"),
        _ck(t, "tlp", f"tlp IN {TLP}"),
        _ck(t, "profile", "profile IN ('internal', 'external')"),
        _ck(t, "status", "status IN ('draft', 'discarded')"),
        _ck(t, "title_length", "char_length(title) BETWEEN 1 AND 200"),
        _ck(
            t,
            "distribution_length",
            "distribution IS NULL OR char_length(distribution) <= 500",
        ),
        _ck(
            t,
            "draft",
            "jsonb_typeof(draft) = 'object' AND octet_length(draft::text) <= 1048576",
        ),
        _ck(t, "revision_positive", "revision >= 1"),
        _ck(t, "latest_version_non_negative", "latest_version >= 0"),
        _parent_fk(t, "investigation_id", "investigations"),
        _org_fk(t),
        _user_fk(t, "created_by"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("id", "organization_id", name=op.f(f"uq_{t}_id_organization_id")),
    )
    op.create_index(
        op.f(f"ix_{t}_organization_id_updated_at"), t, ["organization_id", "updated_at"]
    )
    op.create_index(
        op.f(f"ix_{t}_investigation_id_created_at"), t, ["investigation_id", "created_at"]
    )

    t = "report_versions"
    op.create_table(
        t,
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("report_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.String(length=32), nullable=False),
        sa.Column("tlp", sa.String(length=16), nullable=False),
        sa.Column("profile", sa.String(length=16), nullable=False),
        sa.Column("snapshot_sha256", sa.String(length=64), nullable=False),
        sa.Column("snapshot_bytes", sa.BigInteger(), nullable=False),
        sa.Column("object_key", sa.String(length=512), nullable=False),
        sa.Column("object_version_id", sa.String(length=255), nullable=False),
        sa.Column("manifest", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("signature", sa.String(length=88), nullable=False),
        sa.Column("kid", sa.String(length=64), nullable=False),
        _jsonb("section_counts", "{}"),
        sa.Column("change_note", sa.Text(), nullable=True),
        sa.Column("finalized_by", sa.Uuid(), nullable=False),
        _ts("finalized_at"),
        _uuid_pk(),
        _ck(t, "version_positive", "version >= 1"),
        _ck(t, "tlp", f"tlp IN {TLP}"),
        _ck(t, "profile", "profile IN ('internal', 'external')"),
        _ck(t, "schema_version", "schema_version = 'cyberlab.report.v1'"),
        _ck(t, "snapshot_sha256", f"snapshot_sha256 ~ {SHA256}"),
        _ck(t, "snapshot_bytes_positive", "snapshot_bytes > 0"),
        _ck(
            t,
            "manifest",
            "jsonb_typeof(manifest) = 'object' AND octet_length(manifest::text) <= 4096",
        ),
        _ck(t, "signature", "signature ~ '^[A-Za-z0-9+/]{86}==$'"),
        _ck(t, "kid", "kid ~ '^[A-Za-z0-9._-]{1,64}$'"),
        _ck(
            t,
            "section_counts",
            "jsonb_typeof(section_counts) = 'object' AND octet_length(section_counts::text) "
            "<= 4096",
        ),
        _ck(t, "change_note_length", "change_note IS NULL OR char_length(change_note) <= 500"),
        _parent_fk(t, "report_id", "reports"),
        _org_fk(t),
        _user_fk(t, "finalized_by"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("id", "organization_id", name=op.f(f"uq_{t}_id_organization_id")),
        sa.UniqueConstraint("report_id", "version", name=op.f(f"uq_{t}_report_id_version")),
    )
    op.create_index(
        op.f(f"ix_{t}_organization_id_finalized_at"), t, ["organization_id", "finalized_at"]
    )

    t = "report_citations"
    op.create_table(
        t,
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("version_id", sa.Uuid(), nullable=False),
        sa.Column("cite_no", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("ref_table", sa.String(length=64), nullable=False),
        sa.Column("ref_id", sa.String(length=64), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=True),
        sa.Column("fields_sha256", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("ai_citation_id", sa.Uuid(), nullable=True),
        _uuid_pk(),
        _ck(t, "cite_no_positive", "cite_no > 0"),
        _ck(t, "ref_id_length", "char_length(ref_id) BETWEEN 1 AND 64"),
        _ck(t, "kind", "kind ~ '^[a-z_]{1,16}$'"),
        _ck(t, "ref_table", "ref_table ~ '^[a-z_]{1,64}$'"),
        _ck(t, "fields_sha256", f"fields_sha256 ~ {SHA256}"),
        _ck(t, "source", "source IN ('ai', 'selection', 'note', 'attack')"),
        _parent_fk(t, "version_id", "report_versions"),
        _parent_fk(t, "job_id", "analysis_jobs"),
        sa.ForeignKeyConstraint(
            ["ai_citation_id"],
            ["ai_citations.id"],
            name=op.f(f"fk_{t}_ai_citation_id_ai_citations"),
        ),
        _org_fk(t),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("version_id", "cite_no", name=op.f(f"uq_{t}_version_id_cite_no")),
    )
    op.create_index(
        op.f(f"ix_{t}_organization_id_kind_ref_id"), t, ["organization_id", "kind", "ref_id"]
    )

    t = "report_renders"
    op.create_table(
        t,
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("version_id", sa.Uuid(), nullable=False),
        sa.Column("format", sa.String(length=8), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="queued", nullable=False),
        sa.Column("error_code", sa.String(length=32), nullable=True),
        sa.Column("token_sha256", sa.String(length=64), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("bytes", sa.BigInteger(), nullable=True),
        sa.Column("pages", sa.Integer(), nullable=True),
        sa.Column("object_version_id", sa.String(length=255), nullable=True),
        sa.Column("renderer_version", sa.String(length=255), nullable=True),
        sa.Column("requested_by", sa.Uuid(), nullable=False),
        _ts("created_at"),
        _ts("started_at", nullable=True),
        _ts("finished_at", nullable=True),
        _uuid_pk(),
        _ck(t, "format", "format IN ('pdf', 'html', 'md')"),
        _ck(t, "status", "status IN ('queued', 'running', 'succeeded', 'failed')"),
        _ck(t, "token_sha256", f"token_sha256 ~ {SHA256}"),
        _ck(t, "sha256", f"sha256 IS NULL OR sha256 ~ {SHA256}"),
        _ck(t, "bytes_positive", "bytes IS NULL OR bytes > 0"),
        _ck(t, "pages_positive", "pages IS NULL OR pages > 0"),
        _ck(t, "error_code", "error_code IS NULL OR error_code ~ '^[a-z][a-z_]{0,31}$'"),
        _ck(
            t,
            "succeeded_has_artifact",
            "status <> 'succeeded' OR (sha256 IS NOT NULL AND bytes IS NOT NULL AND "
            "object_version_id IS NOT NULL)",
        ),
        _ck(t, "failed_has_code", "status <> 'failed' OR error_code IS NOT NULL"),
        _parent_fk(t, "version_id", "report_versions"),
        _org_fk(t),
        _user_fk(t, "requested_by"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("id", "organization_id", name=op.f(f"uq_{t}_id_organization_id")),
    )
    op.create_index(
        "ux_report_renders_version_id_format_renderer",
        t,
        ["version_id", "format", sa.text("coalesce(renderer_version, '')")],
        unique=True,
        postgresql_where=sa.text("status <> 'failed'"),
    )
    op.create_index(
        op.f(f"ix_{t}_organization_id_created_at"), t, ["organization_id", "created_at"]
    )

    t = "report_render_index"
    op.create_table(
        t,
        sa.Column("render_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        _ts("dispatched_at", nullable=True),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        _ck(t, "status", "status IN ('queued', 'running', 'succeeded', 'failed')"),
        _ck(t, "attempts_non_negative", "attempts >= 0"),
        _parent_fk(t, "render_id", "report_renders", ondelete="CASCADE"),
        _org_fk(t),
        sa.PrimaryKeyConstraint("render_id", name=op.f(f"pk_{t}")),
    )
    op.create_index(op.f(f"ix_{t}_status_deadline_at"), t, ["status", "deadline_at"])


def _create_security() -> None:
    for table in (*TENANT_TABLES, "report_render_index"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    for table in TENANT_TABLES:
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            "USING (organization_id = app_org_id()) "
            "WITH CHECK (organization_id = app_org_id())"
        )
    # Written by the API in the render-creating transaction (tenant session), read and
    # updated by the trusted ingest worker and the reaper in a system session.
    op.execute(
        "CREATE POLICY render_index_scope ON report_render_index "
        "USING (app_org_id() IS NULL OR organization_id = app_org_id()) "
        "WITH CHECK (app_org_id() IS NULL OR organization_id = app_org_id())"
    )

    for sql in (NOTE_GUARD, ITEM_GUARD, REPORT_GUARD, RENDER_TRANSITION):
        op.execute(sql)
    for table, function in GUARDED.items():
        op.execute(
            f"CREATE TRIGGER {function} BEFORE UPDATE ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION {function}()"
        )
    for table in APPEND_ONLY:
        op.execute(
            f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION forbid_mutation()"
        )

    for table, privileges in GRANTS.items():
        op.execute(f"GRANT {privileges} ON {table} TO {APP_ROLE}")
    for table, columns in UPDATE_COLUMNS.items():
        op.execute(f"GRANT UPDATE ({columns}) ON {table} TO {APP_ROLE}")


def downgrade() -> None:
    for table in (
        "report_render_index",
        "report_renders",
        "report_citations",
        "report_versions",
        "reports",
        "case_attack_mappings",
        "ioc_collection_items",
        "ioc_collections",
        "analyst_note_versions",
        "analyst_notes",
        "evidence_share_policies",
        "investigation_status_events",
    ):
        op.drop_table(table)  # indexes, triggers and policies go with the table
    for function in FUNCTIONS:
        op.execute(f"DROP FUNCTION IF EXISTS {function}()")
    # Items abandoned with `policy_blocked` may exist (and FORCE RLS hides them from the
    # owner here): the restored M4 check is NOT VALID, so it binds new rows only.
    op.drop_constraint(op.f("ck_ti_run_items_reason"), "ti_run_items", type_="check")
    op.execute(
        "ALTER TABLE ti_run_items ADD CONSTRAINT ck_ti_run_items_reason "
        f"CHECK (reason IS NULL OR reason IN {OLD_TI_REASONS}) NOT VALID"
    )
    op.drop_constraint(op.f("ck_investigations_tlp"), "investigations", type_="check")
    op.drop_column("investigations", "ti_excluded")
    op.drop_column("investigations", "ai_excluded")
    op.drop_column("investigations", "tlp")
