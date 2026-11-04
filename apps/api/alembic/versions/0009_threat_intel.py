"""threat intel: provider configs (sealed keys), org settings, runs, run items, run index,
results (append-only history and per-org cache)

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-05 16:00:00

Frozen in M4 phase 1 (0010 is reserved for read indexes if phase 5 needs them).

- Every tenant table has FORCE RLS on `organization_id = app_org_id()`. `ti_run_index` is the
  system lookup, with the `analysis_job_index` pattern (0002/0003): a system session (no
  org context) sees every row, a tenant session only its own org's (M4 RT25).
- The app role never UPDATEs `organization_id`, `provider` or `created_at`: UPDATE is granted
  per column, and only on the columns the API and the enrich worker legitimately write.
- `ti_results` is append-only (`forbid_mutation`), `ti_enrichment_runs` follows a status
  graph and `ti_provider_configs.key_version` is monotonic (DB triggers, RT18).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "cyberlab_app"
TENANT_TABLES = (
    "ti_provider_configs",
    "ti_org_settings",
    "ti_enrichment_runs",
    "ti_run_items",
    "ti_results",
)
# Table-level privileges, then the only columns the app role may UPDATE.
GRANTS = {
    "ti_provider_configs": "SELECT, INSERT, DELETE",
    "ti_org_settings": "SELECT, INSERT",
    "ti_enrichment_runs": "SELECT, INSERT",
    "ti_run_items": "SELECT, INSERT",
    "ti_run_index": "SELECT, INSERT",
    "ti_results": "SELECT, INSERT",
}
UPDATE_COLUMNS = {
    "ti_provider_configs": (
        "enabled, base_url, key_kid, key_version, key_epk, key_nonce, key_ct, key_last4, "
        "verify_status, verified_at, last_error_code, limits, terms_ack_at, terms_ack_by, "
        "updated_at"
    ),
    "ti_org_settings": "excluded_suffixes, updated_by, updated_at",
    "ti_enrichment_runs": "status, summary, deadline_at, started_at, finished_at",
    "ti_run_items": "state, result_id, reason",
    "ti_run_index": "status, resume_at, deadline_at, dispatched_at, lease_until, lease_owner",
}

# queued -> running <-> waiting -> completed / partial / failed, plus queued / waiting ->
# partial / failed (worker deadline, fallback reaper). Final states never change.
RUN_TRANSITION = """CREATE FUNCTION ti_run_transition() RETURNS trigger LANGUAGE plpgsql
  SET search_path = pg_catalog AS $$
BEGIN
  IF OLD.status IN ('completed', 'partial', 'failed') THEN
    RAISE EXCEPTION 'ti run % is final (%)', OLD.id, OLD.status
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
       (OLD.status = 'queued' AND NEW.status IN ('running', 'partial', 'failed'))
    OR (OLD.status = 'running' AND NEW.status IN ('waiting', 'completed', 'partial', 'failed'))
    OR (OLD.status = 'waiting' AND NEW.status IN ('running', 'partial', 'failed'))
  ) THEN
    RAISE EXCEPTION 'illegal ti run transition % -> %', OLD.status, NEW.status
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.id, NEW.organization_id, NEW.scope, NEW.job_id, NEW.requested_by, NEW.providers,
      NEW.created_at)
     IS DISTINCT FROM
     (OLD.id, OLD.organization_id, OLD.scope, OLD.job_id, OLD.requested_by, OLD.providers,
      OLD.created_at) THEN
    RAISE EXCEPTION 'ti run identity columns are immutable'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$"""

# RT18: a new sealed key needs a higher key_version (the version is in the seal AAD, so an
# old ciphertext can never be put back); a re-seal of the same key under another kid keeps
# the version. Clearing the key keeps it too, so the next key still needs a higher one.
KEY_VERSION_GUARD = """CREATE FUNCTION ti_key_version_guard() RETURNS trigger LANGUAGE plpgsql
  SET search_path = pg_catalog AS $$
BEGIN
  IF NEW.key_version < OLD.key_version THEN
    RAISE EXCEPTION 'key_version may not decrease'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.key_ct IS NOT NULL
     AND (NEW.key_kid, NEW.key_epk, NEW.key_nonce, NEW.key_ct, NEW.key_last4)
         IS DISTINCT FROM
         (OLD.key_kid, OLD.key_epk, OLD.key_nonce, OLD.key_ct, OLD.key_last4)
     AND NOT (
       NEW.key_version > OLD.key_version
       OR (NEW.key_version = OLD.key_version AND OLD.key_ct IS NOT NULL
           AND NEW.key_kid IS DISTINCT FROM OLD.key_kid
           AND NEW.key_last4 = OLD.key_last4)
     ) THEN
    RAISE EXCEPTION 'a new sealed key needs a higher key_version'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$"""

FUNCTIONS = ("ti_run_transition", "ti_key_version_guard")
PROVIDERS = "('virustotal', 'abuseipdb', 'urlhaus', 'malwarebazaar', 'otx', 'misp', 'mock')"
REASONS = "('rate_limited', 'quota_exhausted', 'deadline', 'auth_failed')"
SEALED = ("key_kid", "key_epk", "key_nonce", "key_ct", "key_last4")


def _create_security() -> None:
    for table in (*TENANT_TABLES, "ti_run_index"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    for table in TENANT_TABLES:
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            "USING (organization_id = app_org_id()) "
            "WITH CHECK (organization_id = app_org_id())"
        )
    # Written by the API in the run-creating transaction (tenant session), read and
    # scheduled by the trusted workers in a system session (no org context).
    op.execute(
        "CREATE POLICY run_index_scope ON ti_run_index "
        "USING (app_org_id() IS NULL OR organization_id = app_org_id()) "
        "WITH CHECK (app_org_id() IS NULL OR organization_id = app_org_id())"
    )

    op.execute(RUN_TRANSITION)
    op.execute(
        "CREATE TRIGGER ti_run_transition BEFORE UPDATE ON ti_enrichment_runs "
        "FOR EACH ROW EXECUTE FUNCTION ti_run_transition()"
    )
    op.execute(KEY_VERSION_GUARD)
    op.execute(
        "CREATE TRIGGER ti_key_version_guard BEFORE UPDATE ON ti_provider_configs "
        "FOR EACH ROW EXECUTE FUNCTION ti_key_version_guard()"
    )
    op.execute(
        "CREATE TRIGGER ti_results_append_only BEFORE UPDATE OR DELETE ON ti_results "
        "FOR EACH ROW EXECUTE FUNCTION forbid_mutation()"
    )

    for table, privileges in GRANTS.items():
        op.execute(f"GRANT {privileges} ON {table} TO {APP_ROLE}")
    for table, columns in UPDATE_COLUMNS.items():
        op.execute(f"GRANT UPDATE ({columns}) ON {table} TO {APP_ROLE}")


def upgrade() -> None:
    _create_tables()
    _create_security()


def _create_tables() -> None:
    op.create_table(
        "ti_org_settings",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column(
            "excluded_suffixes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="[]",
            nullable=False,
        ),
        sa.Column("updated_by", sa.Uuid(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "jsonb_typeof(excluded_suffixes) = 'array' "
            "AND jsonb_array_length(excluded_suffixes) <= 50",
            name=op.f("ck_ti_org_settings_excluded_suffixes"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_ti_org_settings_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["updated_by"], ["users.id"], name=op.f("fk_ti_org_settings_updated_by_users")
        ),
        sa.PrimaryKeyConstraint("organization_id", name=op.f("pk_ti_org_settings")),
    )
    op.create_table(
        "ti_provider_configs",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("base_url", sa.String(length=512), nullable=True),
        sa.Column("key_kid", sa.String(length=64), nullable=True),
        sa.Column("key_version", sa.Integer(), server_default="0", nullable=False),
        sa.Column("key_epk", sa.LargeBinary(), nullable=True),
        sa.Column("key_nonce", sa.LargeBinary(), nullable=True),
        sa.Column("key_ct", sa.LargeBinary(), nullable=True),
        sa.Column("key_last4", sa.String(length=4), nullable=True),
        sa.Column(
            "verify_status", sa.String(length=16), server_default="unverified", nullable=False
        ),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
        sa.Column(
            "limits", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False
        ),
        sa.Column("terms_ack_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("terms_ack_by", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.CheckConstraint(
            "(base_url IS NOT NULL) = (provider = 'misp')",
            name=op.f("ck_ti_provider_configs_base_url_iff_misp"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(limits) = 'object'", name=op.f("ck_ti_provider_configs_limits_object")
        ),
        sa.CheckConstraint(
            f"provider IN {PROVIDERS}",
            name=op.f("ck_ti_provider_configs_provider"),
        ),
        sa.CheckConstraint(
            "verify_status IN ('unverified', 'valid', 'invalid', 'error')",
            name=op.f("ck_ti_provider_configs_verify_status"),
        ),
        sa.CheckConstraint(
            "NOT enabled OR key_ct IS NOT NULL",
            name=op.f("ck_ti_provider_configs_enabled_needs_key"),
        ),
        sa.CheckConstraint(
            "NOT enabled OR terms_ack_at IS NOT NULL",
            name=op.f("ck_ti_provider_configs_enabled_needs_terms"),
        ),
        sa.CheckConstraint(
            "key_ct IS NULL OR key_version >= 1", name=op.f("ck_ti_provider_configs_sealed_version")
        ),
        sa.CheckConstraint(
            "key_epk IS NULL OR (octet_length(key_epk) = 32 AND octet_length(key_nonce) = 12)",
            name=op.f("ck_ti_provider_configs_sealed_sizes"),
        ),
        sa.CheckConstraint(
            " AND ".join(f"{c} IS NULL" for c in SEALED)
            + " OR "
            + " AND ".join(f"{c} IS NOT NULL" for c in SEALED),
            name=op.f("ck_ti_provider_configs_sealed_all_or_none"),
        ),
        sa.CheckConstraint(
            "key_last4 IS NULL OR char_length(key_last4) = 4",
            name=op.f("ck_ti_provider_configs_key_last4"),
        ),
        sa.CheckConstraint(
            "key_version >= 0", name=op.f("ck_ti_provider_configs_key_version_non_negative")
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_ti_provider_configs_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["terms_ack_by"], ["users.id"], name=op.f("fk_ti_provider_configs_terms_ack_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ti_provider_configs")),
        sa.UniqueConstraint(
            "organization_id",
            "provider",
            name=op.f("uq_ti_provider_configs_organization_id_provider"),
        ),
    )
    op.create_table(
        "ti_enrichment_runs",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("scope", sa.String(length=8), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=True),
        sa.Column("requested_by", sa.Uuid(), nullable=False),
        sa.Column("providers", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="queued", nullable=False),
        sa.Column(
            "summary", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False
        ),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.CheckConstraint(
            "(job_id IS NOT NULL) = (scope = 'job')",
            name=op.f("ck_ti_enrichment_runs_job_id_iff_job_scope"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(providers) = 'array'", name=op.f("ck_ti_enrichment_runs_providers_array")
        ),
        sa.CheckConstraint("scope IN ('manual', 'job')", name=op.f("ck_ti_enrichment_runs_scope")),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'waiting', 'completed', 'partial', 'failed')",
            name=op.f("ck_ti_enrichment_runs_status"),
        ),
        sa.CheckConstraint(
            "summary IS NULL OR octet_length(summary::text) <= 16384",
            name=op.f("ck_ti_enrichment_runs_summary_size"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "organization_id"],
            ["analysis_jobs.id", "analysis_jobs.organization_id"],
            name=op.f("fk_ti_enrichment_runs_job_id_organization_id_analysis_jobs"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_ti_enrichment_runs_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["requested_by"], ["users.id"], name=op.f("fk_ti_enrichment_runs_requested_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ti_enrichment_runs")),
        sa.UniqueConstraint(
            "id", "organization_id", name=op.f("uq_ti_enrichment_runs_id_organization_id")
        ),
    )
    op.create_index(
        op.f("ix_ti_enrichment_runs_job_id_created_at"),
        "ti_enrichment_runs",
        ["job_id", "created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_ti_enrichment_runs_organization_id_created_at"),
        "ti_enrichment_runs",
        ["organization_id", "created_at"],
        unique=False,
    )
    op.create_table(
        "ti_results",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("ioc_type", sa.String(length=8), nullable=False),
        sa.Column("value_norm", sa.String(length=2048), nullable=False),
        sa.Column("ioc_key", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("found", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("detections", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("score", sa.Double(), nullable=True),
        sa.Column("score_scale", sa.String(length=32), nullable=True),
        sa.Column(
            "tags", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False
        ),
        sa.Column(
            "families", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False
        ),
        sa.Column(
            "attack_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="[]",
            nullable=False,
        ),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("summary", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("permalink", sa.String(length=2048), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column(
            "fetched_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.CheckConstraint(
            "(expires_at IS NULL) = (status IN ('error', 'auth_failed'))",
            name=op.f("ck_ti_results_expires_iff_cacheable"),
        ),
        sa.CheckConstraint("NOT found OR status = 'ok'", name=op.f("ck_ti_results_found_only_ok")),
        sa.CheckConstraint(
            "ioc_type IN ('ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email')",
            name=op.f("ck_ti_results_ioc_type"),
        ),
        sa.CheckConstraint(
            "permalink IS NULL OR permalink LIKE 'https://%'",
            name=op.f("ck_ti_results_permalink_https"),
        ),
        sa.CheckConstraint(
            f"provider IN {PROVIDERS}",
            name=op.f("ck_ti_results_provider"),
        ),
        sa.CheckConstraint(
            "status IN ('ok', 'not_found', 'error', 'auth_failed')",
            name=op.f("ck_ti_results_status"),
        ),
        sa.CheckConstraint("char_length(ioc_key) = 64", name=op.f("ck_ti_results_ioc_key")),
        sa.CheckConstraint(
            "summary IS NULL OR octet_length(summary::text) <= 16384",
            name=op.f("ck_ti_results_summary_size"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_ti_results_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["ti_enrichment_runs.id", "ti_enrichment_runs.organization_id"],
            name=op.f("fk_ti_results_run_id_organization_id_ti_enrichment_runs"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ti_results")),
        sa.UniqueConstraint("id", "organization_id", name=op.f("uq_ti_results_id_organization_id")),
        sa.UniqueConstraint(
            "run_id", "provider", "ioc_key", name=op.f("uq_ti_results_run_id_provider_ioc_key")
        ),
    )
    op.create_index(
        "ix_ti_results_organization_id_ioc_key_provider_fetched_at",
        "ti_results",
        ["organization_id", "ioc_key", "provider", sa.literal_column("fetched_at DESC")],
        unique=False,
    )
    op.create_table(
        "ti_run_index",
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("resume_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_owner", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'waiting', 'completed', 'partial', 'failed')",
            name=op.f("ck_ti_run_index_status"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_ti_run_index_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["ti_enrichment_runs.id"],
            name=op.f("fk_ti_run_index_run_id_ti_enrichment_runs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("run_id", name=op.f("pk_ti_run_index")),
    )
    op.create_index(
        op.f("ix_ti_run_index_status_resume_at"),
        "ti_run_index",
        ["status", "resume_at"],
        unique=False,
    )
    op.create_table(
        "ti_run_items",
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("ioc_type", sa.String(length=8), nullable=False),
        sa.Column("value_norm", sa.String(length=2048), nullable=False),
        sa.Column("ioc_key", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=16), server_default="pending", nullable=False),
        sa.Column("result_id", sa.Uuid(), nullable=True),
        sa.Column("reason", sa.String(length=32), nullable=True),
        sa.CheckConstraint(
            "(reason IS NOT NULL) = (state = 'abandoned')",
            name=op.f("ck_ti_run_items_reason_iff_abandoned"),
        ),
        sa.CheckConstraint(
            "(result_id IS NOT NULL) = (state IN ('done', 'cached'))",
            name=op.f("ck_ti_run_items_result_iff_answered"),
        ),
        sa.CheckConstraint(
            "ioc_type IN ('ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email')",
            name=op.f("ck_ti_run_items_ioc_type"),
        ),
        sa.CheckConstraint(
            f"provider IN {PROVIDERS}",
            name=op.f("ck_ti_run_items_provider"),
        ),
        sa.CheckConstraint(
            f"reason IS NULL OR reason IN {REASONS}",
            name=op.f("ck_ti_run_items_reason"),
        ),
        sa.CheckConstraint(
            "state IN ('pending', 'done', 'cached', 'abandoned')",
            name=op.f("ck_ti_run_items_state"),
        ),
        sa.CheckConstraint("char_length(ioc_key) = 64", name=op.f("ck_ti_run_items_ioc_key")),
        sa.CheckConstraint("seq >= 0", name=op.f("ck_ti_run_items_seq_non_negative")),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_ti_run_items_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["result_id", "organization_id"],
            ["ti_results.id", "ti_results.organization_id"],
            name=op.f("fk_ti_run_items_result_id_organization_id_ti_results"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["ti_enrichment_runs.id", "ti_enrichment_runs.organization_id"],
            name=op.f("fk_ti_run_items_run_id_organization_id_ti_enrichment_runs"),
        ),
        sa.PrimaryKeyConstraint("run_id", "provider", "ioc_key", name=op.f("pk_ti_run_items")),
    )
    op.create_index(
        op.f("ix_ti_run_items_run_id_state_seq"),
        "ti_run_items",
        ["run_id", "state", "seq"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_ti_run_items_run_id_state_seq"), table_name="ti_run_items")
    op.drop_table("ti_run_items")
    op.drop_index(op.f("ix_ti_run_index_status_resume_at"), table_name="ti_run_index")
    op.drop_table("ti_run_index")
    op.drop_index(
        "ix_ti_results_organization_id_ioc_key_provider_fetched_at", table_name="ti_results"
    )
    op.drop_table("ti_results")
    op.drop_index(
        op.f("ix_ti_enrichment_runs_organization_id_created_at"), table_name="ti_enrichment_runs"
    )
    op.drop_index(op.f("ix_ti_enrichment_runs_job_id_created_at"), table_name="ti_enrichment_runs")
    op.drop_table("ti_enrichment_runs")
    op.drop_table("ti_provider_configs")
    op.drop_table("ti_org_settings")
    for function in FUNCTIONS:
        op.execute(f"DROP FUNCTION IF EXISTS {function}()")
