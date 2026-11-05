"""platform operations: retention policies, legal holds, retention runs and tombstones,
correlation keys, job outcomes (runtime metrics), the retention append-only exception, the
retention system user, evidence type columns, purged renders and the search indexes

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-06 18:00:00

Frozen in M7 phase 1 (later schema needs go into 0015, assigned by the parent). The M4-M6
conventions:
- Every tenant table has FORCE RLS on `organization_id = app_org_id()`.
  `retention_policy_index` is the system lookup with the `analysis_job_index` pattern (a system
  session sees every row, a tenant session only its own org's): the retention sweep's org
  list (RT3). `job_outcomes` is a system table with no org id and no tenant data.
- Composite (id, organization_id) FKs pin every child row to its parent of the same org.
- No DELETE grant to the app role. The new role `cyberlab_retention` (created by
  `infra/postgres/bootstrap.sh` / `02-m7-roles.sh`, never here) gets SELECT on what the
  retention selector reads, DELETE on the purgeable tables only (never `correlation_*`, RT9),
  INSERT on runs, run items, tombstones, custody and audit, and a few column UPDATEs.
- Append-only (`forbid_mutation`, also for the owner): retention run items, evidence purges.
  `ti_results` and the four append-only `ai_*` tables switch to
  `forbid_mutation_except_retention()`: DELETE only as `cyberlab_retention`, UPDATE never.
  Referential actions run as the table owner, so no cascade can delete from them (RT10).
- `custody_action` gains `purged` and `sent_to_sandbox` (RT12) in an autocommit block (0006's
  rule: one alembic run is one transaction, which may not use a value it added). The
  downgrade cannot drop enum values and leaves them.
- `report_renders.status` gains `purged` (`succeeded -> purged`, retention role only), and
  the dedupe index skips purged rows so a purged rendition can be re-rendered (RT11).
- Search indexes are plain `CREATE INDEX` inside the transaction (RT20).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "cyberlab_app"
RETENTION_ROLE = "cyberlab_retention"
# app.core.config.RETENTION_SYSTEM_USER_ID / _EMAIL (fixed: the migration is frozen).
SYSTEM_USER_ID = "00000000-0000-4000-8000-00000000a7e0"
SYSTEM_USER_EMAIL = "retention@system.invalid"
# Not an argon2 string: `verify_password` fails on it (InvalidHashError), so nobody logs in.
UNUSABLE_HASH = "!unusable:retention-system-user"
FLOOR_DAYS = 30
MAX_DAYS = 36500
SHA256 = "'^[0-9a-f]{64}$'"

TENANT_TABLES = (
    "org_retention_policies",
    "legal_holds",
    "retention_runs",
    "retention_run_items",
    "evidence_purges",
    "correlation_keys",
    "correlation_job_state",
)
_M7_TABLES = frozenset({*TENANT_TABLES, "retention_policy_index", "job_outcomes"})
APPEND_ONLY = ("retention_run_items", "evidence_purges")
EXCEPTION_TABLES = ("ti_results", "ai_run_inputs", "ai_context_refs", "ai_outputs", "ai_citations")
CORRELATION_KINDS = (
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
)
RUN_ITEM_OUTCOMES = (
    "purged",
    "skipped_hold",
    "skipped_locked",
    "object_delete_failed",
    "kept_cited",
)
OLD_RENDER_STATUSES = "('queued', 'running', 'succeeded', 'failed')"
NEW_RENDER_STATUSES = "('queued', 'running', 'succeeded', 'failed', 'purged')"

APP_GRANTS = {
    "org_retention_policies": "SELECT, INSERT",
    "retention_policy_index": "SELECT, INSERT",
    "legal_holds": "SELECT, INSERT",
    "retention_runs": "SELECT, INSERT",
    "retention_run_items": "SELECT",
    "evidence_purges": "SELECT",
    "correlation_keys": "SELECT, INSERT",
    "correlation_job_state": "SELECT, INSERT",
    "job_outcomes": "SELECT",
}
APP_UPDATE_COLUMNS = {
    "org_retention_policies": (
        "ti_results_days, ai_runs_days, closed_case_days, pending_ti_results_days, "
        "pending_ai_runs_days, pending_closed_case_days, effective_at, enforce, "
        "pending_enforce, enforce_effective_at, updated_by, updated_at"
    ),
    "retention_policy_index": "updated_at",
    "legal_holds": "released_by, released_at, release_reason",
}
# What the retention selector and the purge read (RLS-bound, per-org tenant sessions).
RETENTION_SELECT = (
    "org_retention_policies",
    "retention_policy_index",
    "legal_holds",
    "retention_runs",
    "retention_run_items",
    "evidence_purges",
    "investigations",
    "investigation_status_events",
    "evidence",
    "evidence_hashes",
    "evidence_custody_events",
    "audit_logs",
    "analysis_jobs",
    "analysis_job_index",
    "network_flows",
    "network_records",
    "analysis_timeline",
    "malware_strings",
    "malware_sections",
    "malware_imports",
    "malware_exports",
    "malware_resources",
    "ti_enrichment_runs",
    "ti_run_items",
    "ti_results",
    "ai_runs",
    "ai_run_index",
    "ai_run_inputs",
    "ai_context_refs",
    "ai_outputs",
    "ai_citations",
    "reports",
    "report_versions",
    "report_citations",
    "report_renders",
    "job_outcomes",
)
# Purgeable tables only (plan.md data model); never correlation_* (RT9), never metadata.
RETENTION_DELETE = (
    "network_flows",
    "network_records",
    "analysis_timeline",
    "malware_strings",
    "malware_sections",
    "malware_imports",
    "malware_exports",
    "malware_resources",
    "ti_results",
    "ti_run_items",
    "ai_runs",
    "ai_run_index",
    "ai_run_inputs",
    "ai_context_refs",
    "ai_outputs",
    "ai_citations",
    "job_outcomes",
)
RETENTION_INSERT = (
    "retention_runs",
    "retention_run_items",
    "evidence_purges",
    "evidence_custody_events",
    "audit_logs",
)
RETENTION_UPDATE_COLUMNS = {
    "retention_runs": "status, counts, sample, started_at, finished_at, error",
    "report_renders": "status",
    "legal_holds": "s3_synced_at",
}

ROLE_GUARD = f"""DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{RETENTION_ROLE}') THEN
    RAISE EXCEPTION 'role {RETENTION_ROLE} does not exist: run db-bootstrap first '
      '(docker compose run --rm db-bootstrap; infra/postgres/bootstrap.sh)';
  END IF;
END $$"""

EXCEPT_RETENTION = f"""CREATE FUNCTION forbid_mutation_except_retention() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  -- Retention (M7) may DELETE rows of its purgeable append-only tables; nobody may UPDATE.
  -- Not SECURITY DEFINER: current_user is the role running the statement. Referential
  -- actions run as the table owner, so a cascade from another table is refused here.
  IF TG_OP = 'DELETE' AND current_user = '{RETENTION_ROLE}' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION '% on % is not allowed: table is append-only', TG_OP, TG_TABLE_NAME
    USING ERRCODE = 'insufficient_privilege';
END $$"""

_EVIDENCE_IMMUTABLE = """CREATE OR REPLACE FUNCTION evidence_immutable() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  -- Only status and description may change.
  IF (NEW.id, NEW.organization_id, NEW.investigation_id, NEW.original_filename,
      NEW.detected_mime, NEW.detected_description, NEW.size_bytes, NEW.storage_bucket,
      NEW.storage_key, NEW.storage_version_id, NEW.uploaded_by, NEW.uploaded_at)
     IS DISTINCT FROM
     (OLD.id, OLD.organization_id, OLD.investigation_id, OLD.original_filename,
      OLD.detected_mime, OLD.detected_description, OLD.size_bytes, OLD.storage_bucket,
      OLD.storage_key, OLD.storage_version_id, OLD.uploaded_by, OLD.uploaded_at) THEN
    RAISE EXCEPTION 'evidence identity and storage columns are immutable'
      USING ERRCODE = 'insufficient_privilege';
  END IF;{type_check}
  RETURN NEW;
END $$"""
# M7: `declared_type` / `type_mismatch` are write-once. A NULL may become a value only in the
# transaction that inserted the row (OLD.xmin is the current transaction id), so in practice
# both are set at INSERT; once set they never change, and an older row stays NULL.
_TYPE_CHECK = """
  IF (NEW.declared_type, NEW.type_mismatch) IS DISTINCT FROM
     (OLD.declared_type, OLD.type_mismatch)
     AND NOT (OLD.declared_type IS NULL AND OLD.type_mismatch IS NULL
              AND OLD.xmin::text::bigint = (pg_catalog.txid_current() % 4294967296)) THEN
    RAISE EXCEPTION 'evidence declared_type and type_mismatch are write-once'
      USING ERRCODE = 'insufficient_privilege';
  END IF;"""
EVIDENCE_IMMUTABLE_M7 = _EVIDENCE_IMMUTABLE.format(type_check=_TYPE_CHECK)
EVIDENCE_IMMUTABLE_M1 = _EVIDENCE_IMMUTABLE.format(type_check="")

_RENDER_TRANSITION = """CREATE OR REPLACE FUNCTION report_render_transition() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN{purged_edge}
  IF OLD.status IN ({final}) THEN
    RAISE EXCEPTION 'report render % is final (%)', OLD.id, OLD.status
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
       (OLD.status = 'queued' AND NEW.status IN ('running', 'failed'))
    OR (OLD.status = 'running' AND NEW.status IN ('succeeded', 'failed'))
  ) THEN
    RAISE EXCEPTION 'illegal report render transition % -> %', OLD.status, NEW.status
      USING ERRCODE = 'insufficient_privilege';
  END IF;{identity}
  RETURN NEW;
END $$"""
_RENDER_IDENTITY = """
  IF (NEW.id, NEW.organization_id, NEW.version_id, NEW.format, NEW.token_sha256,
      NEW.requested_by, NEW.created_at)
     IS DISTINCT FROM
     (OLD.id, OLD.organization_id, OLD.version_id, OLD.format, OLD.token_sha256,
      OLD.requested_by, OLD.created_at) THEN
    RAISE EXCEPTION 'report render identity columns are immutable'
      USING ERRCODE = 'insufficient_privilege';
  END IF;"""
# M7 (RT11): retention marks a succeeded rendition `purged` once its object version is gone
# (the row, hash and size stay); only `cyberlab_retention` may, and only the status changes.
_PURGED_EDGE = f"""
  IF OLD.status = 'succeeded' AND NEW.status = 'purged' THEN
    IF current_user <> '{RETENTION_ROLE}' THEN
      RAISE EXCEPTION 'only the retention worker may purge a report render'
        USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF (NEW.error_code, NEW.sha256, NEW.bytes, NEW.pages, NEW.object_version_id,
        NEW.renderer_version, NEW.started_at, NEW.finished_at)
       IS DISTINCT FROM
       (OLD.error_code, OLD.sha256, OLD.bytes, OLD.pages, OLD.object_version_id,
        OLD.renderer_version, OLD.started_at, OLD.finished_at) THEN
      RAISE EXCEPTION 'a render purge changes the status only'
        USING ERRCODE = 'insufficient_privilege';
    END IF;{_RENDER_IDENTITY.replace(chr(10), chr(10) + "  ")}
    RETURN NEW;
  END IF;"""
RENDER_TRANSITION_M7 = _RENDER_TRANSITION.format(
    purged_edge=_PURGED_EDGE, final="'succeeded', 'failed', 'purged'", identity=_RENDER_IDENTITY
)
RENDER_TRANSITION_M6 = _RENDER_TRANSITION.format(
    purged_edge="", final="'succeeded', 'failed'", identity=_RENDER_IDENTITY
)

POLICY_TOUCH = """CREATE FUNCTION org_retention_policy_touch() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF (NEW.organization_id, NEW.created_at) IS DISTINCT FROM
     (OLD.organization_id, OLD.created_at) THEN
    RAISE EXCEPTION 'retention policy identity columns are immutable'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  NEW.updated_at := pg_catalog.now();
  RETURN NEW;
END $$"""

HOLD_GUARD = """CREATE FUNCTION legal_hold_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF OLD.released_at IS NOT NULL
     AND (NEW.released_at, NEW.released_by, NEW.release_reason)
         IS DISTINCT FROM (OLD.released_at, OLD.released_by, OLD.release_reason) THEN
    RAISE EXCEPTION 'legal hold % is already released', OLD.id
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.id, NEW.organization_id, NEW.scope, NEW.investigation_id, NEW.reason,
      NEW.placed_by, NEW.placed_at)
     IS DISTINCT FROM
     (OLD.id, OLD.organization_id, OLD.scope, OLD.investigation_id, OLD.reason,
      OLD.placed_by, OLD.placed_at) THEN
    RAISE EXCEPTION 'legal hold identity columns are immutable'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$"""

RUN_GUARD = """CREATE FUNCTION retention_run_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF OLD.status IN ('completed', 'partial', 'failed') THEN
    RAISE EXCEPTION 'retention run % is final (%)', OLD.id, OLD.status
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.id, NEW.organization_id, NEW.mode, NEW.trigger, NEW.requested_by, NEW.policy,
      NEW.created_at)
     IS DISTINCT FROM
     (OLD.id, OLD.organization_id, OLD.mode, OLD.trigger, OLD.requested_by, OLD.policy,
      OLD.created_at) THEN
    RAISE EXCEPTION 'retention run identity columns are immutable'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$"""

# Runtime metrics (M7 phase 5 owns the full test): one row per terminal transition of a job,
# TI run, AI run or report render. SECURITY DEFINER (owner) so the app and the workers need no
# INSERT on job_outcomes. It copies codes and durations only: never an org id, a user, a value
# or free text (codes are sanitized so a bad value can never fail the status change), and any
# error is turned into a WARNING instead of failing the transition it observes.
OUTCOME_FUNCTION = """CREATE FUNCTION record_job_outcome() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_kind text;
  v_subkind text;
  v_error text;
  v_created timestamptz;
  v_started timestamptz;
  v_finished timestamptz;
BEGIN
  BEGIN
    IF TG_TABLE_NAME = 'analysis_jobs' THEN
      v_kind := NEW.analyzer::text;
      v_subkind := NEW.profile::text;
      v_error := NEW.error_code;
    ELSIF TG_TABLE_NAME = 'ti_enrichment_runs' THEN
      v_kind := 'ti';
      v_subkind := CASE WHEN jsonb_typeof(NEW.providers) = 'array'
                         AND jsonb_array_length(NEW.providers) = 1
                        THEN NEW.providers ->> 0 ELSE 'multi' END;
      v_error := NULL;
    ELSIF TG_TABLE_NAME = 'ai_runs' THEN
      v_kind := 'ai';
      v_subkind := NEW.provider;
      v_error := NEW.error_code;
    ELSE
      v_kind := 'report';
      v_subkind := NEW.format;
      v_error := NEW.error_code;
    END IF;
    v_created := NEW.created_at;
    v_started := NEW.started_at;
    v_finished := coalesce(NEW.finished_at, now());
    IF v_subkind IS NOT NULL AND v_subkind !~ '^[a-z0-9][a-z0-9_.-]{0,31}$' THEN
      v_subkind := 'other';
    END IF;
    IF v_error IS NOT NULL AND v_error !~ '^[a-z][a-z0-9_]{0,63}$' THEN
      v_error := 'other';
    END IF;
    INSERT INTO job_outcomes (kind, subkind, status, error_code, queue_ms, run_ms, finished_at)
    VALUES (
      v_kind,
      v_subkind,
      NEW.status::text,
      v_error,
      CASE WHEN v_started IS NULL THEN NULL
           ELSE greatest(0, (extract(epoch FROM (v_started - v_created)) * 1000)::bigint) END,
      CASE WHEN v_started IS NULL THEN NULL
           ELSE greatest(0, (extract(epoch FROM (v_finished - v_started)) * 1000)::bigint) END,
      v_finished
    );
  EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'job_outcomes: % (%)', SQLERRM, TG_TABLE_NAME;
  END;
  RETURN NULL;
END $$"""
# (table, terminal statuses): an AFTER UPDATE OF status trigger fires when a row enters one.
OUTCOME_TABLES = {
    "analysis_jobs": "('succeeded', 'failed')",
    "ti_enrichment_runs": "('completed', 'partial', 'failed')",
    "ai_runs": "('completed', 'partial', 'failed', 'refused')",
    "report_renders": "('succeeded', 'failed')",
}

# Search (phase 4 uses these exact expressions; `simple` config, coalesce on every column).
SEARCH_INDEXES = (
    (
        "ix_investigations_search_fts",
        "investigations USING gin (to_tsvector('simple'::regconfig, "
        "coalesce(title, '') || ' ' || coalesce(description, '')))",
    ),
    (
        "ix_investigations_case_number_trgm",
        "investigations USING gin ((case_number::text) gin_trgm_ops)",
    ),
    (
        "ix_analysis_findings_search_fts",
        "analysis_findings USING gin (to_tsvector('simple'::regconfig, "
        "coalesce(title, '') || ' ' || coalesce(description, '')))",
    ),
    (
        "ix_network_alerts_search_fts",
        "network_alerts USING gin (to_tsvector('simple'::regconfig, coalesce(signature, '')))",
    ),
    (
        "ix_analyst_note_versions_search_fts",
        "analyst_note_versions USING gin (to_tsvector('simple'::regconfig, coalesce(body, '')))",
    ),
    ("ix_evidence_original_filename_trgm", "evidence USING gin (original_filename gin_trgm_ops)"),
    ("ix_correlation_keys_value_norm_trgm", "correlation_keys USING gin (value_norm gin_trgm_ops)"),
)


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


def _parent_fk(table: str, column: str, parent: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        [column, "organization_id"],
        [f"{parent}.id", f"{parent}.organization_id"],
        name=op.f(f"fk_{table}_{column}_organization_id_{parent}"),
    )


def _jsonb(name: str, default: str) -> sa.Column[object]:
    return sa.Column(
        name, postgresql.JSONB(astext_type=sa.Text()), server_default=default, nullable=False
    )


def _ck(table: str, name: str, sql: str) -> sa.CheckConstraint:
    return sa.CheckConstraint(sql, name=op.f(f"ck_{table}_{name}"))


def _uuid_pk() -> sa.Column[object]:
    return sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False)


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _days(column: str) -> str:
    return f"{column} IS NULL OR {column} BETWEEN {FLOOR_DAYS} AND {MAX_DAYS}"


def upgrade() -> None:
    op.execute(ROLE_GUARD)
    # Enum values first, committed on their own (0006's rule); nothing below uses them.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE custody_action ADD VALUE IF NOT EXISTS 'purged'")
        op.execute("ALTER TYPE custody_action ADD VALUE IF NOT EXISTS 'sent_to_sandbox'")
    op.execute(ROLE_GUARD)  # the autocommit block ended the guarded transaction
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    _alter_existing()
    _create_tables()
    _create_security()
    _create_outcome_triggers()
    _create_search_indexes()
    _seed_system_user()


def _alter_existing() -> None:
    op.add_column("evidence", sa.Column("declared_type", sa.String(length=32), nullable=True))
    op.add_column("evidence", sa.Column("type_mismatch", sa.Boolean(), nullable=True))
    op.create_check_constraint(
        op.f("ck_evidence_declared_type_length"),
        "evidence",
        "declared_type IS NULL OR char_length(declared_type) BETWEEN 1 AND 32",
    )
    op.execute(EVIDENCE_IMMUTABLE_M7)

    op.drop_constraint(op.f("ck_report_renders_status"), "report_renders", type_="check")
    op.create_check_constraint(
        op.f("ck_report_renders_status"), "report_renders", f"status IN {NEW_RENDER_STATUSES}"
    )
    op.drop_index("ux_report_renders_version_id_format_renderer", table_name="report_renders")
    op.create_index(
        "ux_report_renders_version_id_format_renderer",
        "report_renders",
        ["version_id", "format", sa.text("coalesce(renderer_version, '')")],
        unique=True,
        postgresql_where=sa.text("status NOT IN ('failed', 'purged')"),
    )
    op.execute(RENDER_TRANSITION_M7)

    op.execute(EXCEPT_RETENTION)
    for table in EXCEPTION_TABLES:
        op.execute(f"DROP TRIGGER {table}_append_only ON {table}")
        op.execute(
            f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION forbid_mutation_except_retention()"
        )


def _create_tables() -> None:
    t = "org_retention_policies"
    op.create_table(
        t,
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("ti_results_days", sa.Integer(), nullable=True),
        sa.Column("ai_runs_days", sa.Integer(), nullable=True),
        sa.Column("closed_case_days", sa.Integer(), nullable=True),
        sa.Column("pending_ti_results_days", sa.Integer(), nullable=True),
        sa.Column("pending_ai_runs_days", sa.Integer(), nullable=True),
        sa.Column("pending_closed_case_days", sa.Integer(), nullable=True),
        _ts("effective_at", nullable=True),
        sa.Column("enforce", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("pending_enforce", sa.Boolean(), server_default="false", nullable=False),
        _ts("enforce_effective_at", nullable=True),
        sa.Column("updated_by", sa.Uuid(), nullable=False),
        _ts("created_at"),
        _ts("updated_at"),
        _ck(t, "ti_results_days", _days("ti_results_days")),
        _ck(t, "ai_runs_days", _days("ai_runs_days")),
        _ck(t, "closed_case_days", _days("closed_case_days")),
        _ck(t, "pending_ti_results_days", _days("pending_ti_results_days")),
        _ck(t, "pending_ai_runs_days", _days("pending_ai_runs_days")),
        _ck(t, "pending_closed_case_days", _days("pending_closed_case_days")),
        _ck(
            t,
            "pending_pair",
            "(effective_at IS NULL) = (pending_ti_results_days IS NULL AND "
            "pending_ai_runs_days IS NULL AND pending_closed_case_days IS NULL)",
        ),
        _ck(t, "enforce_pair", "pending_enforce = (enforce_effective_at IS NOT NULL)"),
        _ck(t, "enforce_pending_only_when_off", "NOT (enforce AND pending_enforce)"),
        _org_fk(t),
        _user_fk(t, "updated_by"),
        sa.PrimaryKeyConstraint("organization_id", name=op.f(f"pk_{t}")),
    )

    t = "retention_policy_index"
    op.create_table(
        t,
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        _ts("updated_at"),
        _org_fk(t),
        sa.PrimaryKeyConstraint("organization_id", name=op.f(f"pk_{t}")),
    )

    t = "legal_holds"
    op.create_table(
        t,
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("placed_by", sa.Uuid(), nullable=False),
        _ts("placed_at"),
        sa.Column("released_by", sa.Uuid(), nullable=True),
        _ts("released_at", nullable=True),
        sa.Column("release_reason", sa.Text(), nullable=True),
        _ts("s3_synced_at", nullable=True),
        _uuid_pk(),
        _ck(t, "scope", "scope IN ('org', 'investigation')"),
        _ck(t, "scope_target", "(scope = 'org') = (investigation_id IS NULL)"),
        _ck(t, "reason_length", "char_length(reason) BETWEEN 1 AND 500"),
        _ck(
            t,
            "release_reason_length",
            "release_reason IS NULL OR char_length(release_reason) BETWEEN 1 AND 500",
        ),
        _ck(t, "released_pair", "(released_at IS NULL) = (released_by IS NULL)"),
        _ck(t, "release_reason_when_released", "release_reason IS NULL OR released_at IS NOT NULL"),
        _parent_fk(t, "investigation_id", "investigations"),
        _org_fk(t),
        _user_fk(t, "placed_by"),
        _user_fk(t, "released_by"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("id", "organization_id", name=op.f(f"uq_{t}_id_organization_id")),
    )
    # Holds that still protect: active, or released less than RETENTION_POLICY_DELAY_DAYS ago
    # (RT1). The delay is configuration, so the index covers (org, released_at) and the query
    # bounds released_at; the investigation index serves the case badge.
    op.create_index(
        op.f(f"ix_{t}_organization_id_released_at"), t, ["organization_id", "released_at"]
    )
    op.create_index(op.f(f"ix_{t}_investigation_id"), t, ["investigation_id"])

    t = "retention_runs"
    op.create_table(
        t,
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("mode", sa.String(length=16), nullable=False),
        sa.Column("trigger", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="queued", nullable=False),
        sa.Column("requested_by", sa.Uuid(), nullable=True),
        _jsonb("policy", "{}"),
        _jsonb("counts", "{}"),
        _jsonb("sample", "[]"),
        sa.Column("error", sa.String(length=64), nullable=True),
        _ts("created_at"),
        _ts("started_at", nullable=True),
        _ts("finished_at", nullable=True),
        _uuid_pk(),
        _ck(t, "mode", "mode IN ('dry_run', 'enforce')"),
        _ck(t, "trigger", "trigger IN ('schedule', 'manual')"),
        _ck(t, "status", "status IN ('queued', 'running', 'completed', 'partial', 'failed')"),
        _ck(t, "manual_has_requester", "(trigger = 'manual') = (requested_by IS NOT NULL)"),
        _ck(t, "error", "error IS NULL OR error ~ '^[a-z][a-z0-9_]{0,63}$'"),
        _ck(t, "policy", "jsonb_typeof(policy) = 'object' AND octet_length(policy::text) <= 4096"),
        _ck(t, "counts", "jsonb_typeof(counts) = 'object' AND octet_length(counts::text) <= 8192"),
        _ck(t, "sample", "jsonb_typeof(sample) = 'array' AND octet_length(sample::text) <= 65536"),
        _org_fk(t),
        _user_fk(t, "requested_by"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("id", "organization_id", name=op.f(f"uq_{t}_id_organization_id")),
    )
    op.create_index(
        op.f(f"ix_{t}_organization_id_created_at"), t, ["organization_id", "created_at"]
    )

    t = "retention_run_items"
    op.create_table(
        t,
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("category", sa.String(length=16), nullable=False),
        sa.Column("ref_table", sa.String(length=64), nullable=False),
        sa.Column("ref_id", sa.String(length=64), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=True),
        sa.Column("rows", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("bytes", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("object_key", sa.String(length=1024), nullable=True),
        sa.Column("object_version_id", sa.String(length=255), nullable=True),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        _ts("created_at"),
        _uuid_pk(),
        _ck(t, "category", "category IN ('ti_results', 'ai_runs', 'closed_case')"),
        _ck(t, "ref_table", "ref_table ~ '^[a-z_]{1,64}$'"),
        _ck(t, "ref_id_length", "char_length(ref_id) BETWEEN 1 AND 64"),
        _ck(t, "rows_non_negative", "rows >= 0"),
        _ck(t, "bytes_non_negative", "bytes >= 0"),
        _ck(t, "outcome", _in("outcome", RUN_ITEM_OUTCOMES)),
        _ck(t, "object_pair", "(object_key IS NULL) = (object_version_id IS NULL)"),
        _parent_fk(t, "run_id", "retention_runs"),
        _parent_fk(t, "job_id", "analysis_jobs"),
        _org_fk(t),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
    )
    op.create_index(op.f(f"ix_{t}_run_id_created_at"), t, ["run_id", "created_at"])
    op.create_index(op.f(f"ix_{t}_organization_id"), t, ["organization_id"])

    t = "evidence_purges"
    op.create_table(
        t,
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("object_version_id", sa.String(length=255), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        _ts("purged_at"),
        _ck(t, "sha256", f"sha256 ~ {SHA256}"),
        _parent_fk(t, "evidence_id", "evidence"),
        _parent_fk(t, "run_id", "retention_runs"),
        _org_fk(t),
        sa.PrimaryKeyConstraint("evidence_id", name=op.f(f"pk_{t}")),
    )
    op.create_index(op.f(f"ix_{t}_organization_id_purged_at"), t, ["organization_id", "purged_at"])

    t = "correlation_keys"
    op.create_table(
        t,
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value_norm", sa.String(length=2048), nullable=False),
        sa.Column("source_table", sa.String(length=32), nullable=False),
        sa.Column("source_id", sa.String(length=64), nullable=False),
        _ts("first_seen", nullable=True),
        _ts("last_seen", nullable=True),
        _ts("created_at"),
        _uuid_pk(),
        _ck(t, "kind", _in("kind", CORRELATION_KINDS)),
        _ck(t, "key", f"key ~ {SHA256}"),
        _ck(t, "value_length", "char_length(value_norm) BETWEEN 1 AND 2048"),
        _ck(t, "source_table", "source_table IN ('iocs', 'malware_samples', 'evidence_hashes')"),
        _ck(t, "source_id_length", "char_length(source_id) BETWEEN 1 AND 64"),
        _parent_fk(t, "investigation_id", "investigations"),
        _parent_fk(t, "evidence_id", "evidence"),
        _parent_fk(t, "job_id", "analysis_jobs"),
        _org_fk(t),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
        sa.UniqueConstraint("job_id", "kind", "key", name=op.f(f"uq_{t}_job_id_kind_key")),
    )
    op.create_index(op.f(f"ix_{t}_organization_id_kind_key"), t, ["organization_id", "kind", "key"])
    op.create_index(op.f(f"ix_{t}_investigation_id"), t, ["investigation_id"])

    t = "correlation_job_state"
    op.create_table(
        t,
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        _ts("indexed_at"),
        sa.Column("keys", sa.Integer(), server_default="0", nullable=False),
        sa.Column("truncated", sa.Boolean(), server_default="false", nullable=False),
        _ck(t, "keys_non_negative", "keys >= 0"),
        _parent_fk(t, "job_id", "analysis_jobs"),
        _org_fk(t),
        sa.PrimaryKeyConstraint("job_id", name=op.f(f"pk_{t}")),
    )
    op.create_index(op.f(f"ix_{t}_organization_id"), t, ["organization_id"])

    t = "job_outcomes"
    op.create_table(
        t,
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("subkind", sa.String(length=32), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("queue_ms", sa.BigInteger(), nullable=True),
        sa.Column("run_ms", sa.BigInteger(), nullable=True),
        _ts("finished_at"),
        _uuid_pk(),
        _ck(t, "kind", "kind IN ('pcap', 'static', 'ti', 'ai', 'report')"),
        _ck(t, "queue_ms_non_negative", "queue_ms IS NULL OR queue_ms >= 0"),
        _ck(t, "run_ms_non_negative", "run_ms IS NULL OR run_ms >= 0"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{t}")),
    )
    op.create_index(op.f(f"ix_{t}_finished_at"), t, ["finished_at"])
    op.create_index(op.f(f"ix_{t}_kind_finished_at"), t, ["kind", "finished_at"])


def _create_security() -> None:
    for table in (*TENANT_TABLES, "retention_policy_index"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    for table in TENANT_TABLES:
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            "USING (organization_id = app_org_id()) "
            "WITH CHECK (organization_id = app_org_id())"
        )
    # Written by the API with every policy PUT (tenant session), read by the retention sweep
    # in a system session (RT3).
    op.execute(
        "CREATE POLICY retention_policy_index_scope ON retention_policy_index "
        "USING (app_org_id() IS NULL OR organization_id = app_org_id()) "
        "WITH CHECK (app_org_id() IS NULL OR organization_id = app_org_id())"
    )

    for sql in (POLICY_TOUCH, HOLD_GUARD, RUN_GUARD):
        op.execute(sql)
    op.execute(
        "CREATE TRIGGER org_retention_policy_touch BEFORE UPDATE ON org_retention_policies "
        "FOR EACH ROW EXECUTE FUNCTION org_retention_policy_touch()"
    )
    op.execute(
        "CREATE TRIGGER legal_hold_guard BEFORE UPDATE ON legal_holds "
        "FOR EACH ROW EXECUTE FUNCTION legal_hold_guard()"
    )
    op.execute(
        "CREATE TRIGGER retention_run_guard BEFORE UPDATE ON retention_runs "
        "FOR EACH ROW EXECUTE FUNCTION retention_run_guard()"
    )
    for table in APPEND_ONLY:
        op.execute(
            f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION forbid_mutation()"
        )

    for table, privileges in APP_GRANTS.items():
        op.execute(f"GRANT {privileges} ON {table} TO {APP_ROLE}")
    for table, columns in APP_UPDATE_COLUMNS.items():
        op.execute(f"GRANT UPDATE ({columns}) ON {table} TO {APP_ROLE}")

    op.execute(f"GRANT USAGE ON SCHEMA public TO {RETENTION_ROLE}")
    op.execute(f"GRANT EXECUTE ON FUNCTION app_org_id(), app_user_id() TO {RETENTION_ROLE}")
    op.execute(f"GRANT SELECT ON {', '.join(RETENTION_SELECT)} TO {RETENTION_ROLE}")
    op.execute(f"GRANT DELETE ON {', '.join(RETENTION_DELETE)} TO {RETENTION_ROLE}")
    op.execute(f"GRANT INSERT ON {', '.join(RETENTION_INSERT)} TO {RETENTION_ROLE}")
    for table, columns in RETENTION_UPDATE_COLUMNS.items():
        op.execute(f"GRANT UPDATE ({columns}) ON {table} TO {RETENTION_ROLE}")


def _create_outcome_triggers() -> None:
    op.execute(OUTCOME_FUNCTION)
    op.execute("REVOKE ALL ON FUNCTION record_job_outcome() FROM PUBLIC")
    for table, terminal in OUTCOME_TABLES.items():
        op.execute(
            f"CREATE TRIGGER {table}_job_outcome AFTER UPDATE OF status ON {table} "
            f"FOR EACH ROW WHEN (NEW.status::text IN {terminal} "
            f"AND OLD.status::text NOT IN {terminal}) "
            "EXECUTE FUNCTION record_job_outcome()"
        )


def _create_search_indexes() -> None:
    for name, definition in SEARCH_INDEXES:
        op.execute(f"CREATE INDEX {name} ON {definition}")


def _seed_system_user() -> None:
    op.execute(
        "INSERT INTO users (id, email, password_hash, display_name, is_active) VALUES "
        f"('{SYSTEM_USER_ID}', '{SYSTEM_USER_EMAIL}', '{UNUSABLE_HASH}', "
        "'Retention (system)', false) ON CONFLICT (id) DO NOTHING"
    )


def downgrade() -> None:
    # The system user stays (inactive, unusable hash), like the custody enum values: purge
    # custody events may reference it, and custody is append-only.
    for name, _ in SEARCH_INDEXES:
        if not name.startswith("ix_correlation_keys"):
            op.execute(f"DROP INDEX IF EXISTS {name}")
    for table in OUTCOME_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS {table}_job_outcome ON {table}")
    op.execute("DROP FUNCTION IF EXISTS record_job_outcome()")

    for table in (
        "job_outcomes",
        "correlation_job_state",
        "correlation_keys",
        "evidence_purges",
        "retention_run_items",
        "retention_runs",
        "legal_holds",
        "retention_policy_index",
        "org_retention_policies",
    ):
        op.drop_table(table)  # indexes, triggers and policies go with the table
    for function in ("org_retention_policy_touch", "legal_hold_guard", "retention_run_guard"):
        op.execute(f"DROP FUNCTION IF EXISTS {function}()")

    for table in EXCEPTION_TABLES:
        op.execute(f"DROP TRIGGER {table}_append_only ON {table}")
        op.execute(
            f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION forbid_mutation()"
        )
    op.execute("DROP FUNCTION IF EXISTS forbid_mutation_except_retention()")
    # Privileges of the retention role on the tables that stay (a table-level REVOKE also
    # revokes the column grants); the dropped tables took theirs with them.
    remaining = sorted({*RETENTION_SELECT, *RETENTION_DELETE, *RETENTION_INSERT} - _M7_TABLES)
    op.execute(f"REVOKE ALL ON {', '.join(remaining)} FROM {RETENTION_ROLE}")
    op.execute(f"REVOKE EXECUTE ON FUNCTION app_org_id(), app_user_id() FROM {RETENTION_ROLE}")
    op.execute(f"REVOKE USAGE ON SCHEMA public FROM {RETENTION_ROLE}")

    # Renders already marked `purged` (if any) keep that status: FORCE RLS hides them from the
    # owner here, so the restored M6 check is NOT VALID (it binds new rows only, like 0012's).
    op.execute(RENDER_TRANSITION_M6)
    op.drop_index("ux_report_renders_version_id_format_renderer", table_name="report_renders")
    op.create_index(
        "ux_report_renders_version_id_format_renderer",
        "report_renders",
        ["version_id", "format", sa.text("coalesce(renderer_version, '')")],
        unique=True,
        postgresql_where=sa.text("status <> 'failed'"),
    )
    op.drop_constraint(op.f("ck_report_renders_status"), "report_renders", type_="check")
    op.execute(
        "ALTER TABLE report_renders ADD CONSTRAINT ck_report_renders_status "
        f"CHECK (status IN {OLD_RENDER_STATUSES}) NOT VALID"
    )

    op.execute(EVIDENCE_IMMUTABLE_M1)
    op.drop_constraint(op.f("ck_evidence_declared_type_length"), "evidence", type_="check")
    op.drop_column("evidence", "type_mismatch")
    op.drop_column("evidence", "declared_type")
    # Other databases or extensions may use pg_trgm; 0014 created it if it was missing, and
    # nothing else in the schema uses it after the indexes above are gone.
    op.execute("DROP EXTENSION IF EXISTS pg_trgm")
    # Enum values cannot be removed from custody_action; they stay (unused) on downgrade.
