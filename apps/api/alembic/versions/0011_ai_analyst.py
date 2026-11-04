"""ai analyst: provider configs (sealed keys), org settings, runs, run index, frozen
inputs, context refs, outputs, citations

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-05 21:00:00

Frozen in M5 phase 1 (later schema needs go into 0012, assigned by the parent). M4
conventions:
- Every tenant table has FORCE RLS on `organization_id = app_org_id()`. `ai_run_index` is the
  system lookup with the `ti_run_index` pattern: a system session (no org context) sees every
  row, a tenant session only its own org's.
- Composite (id, organization_id) FKs pin every child row to its run / output / job /
  investigation of the same org.
- The app role never UPDATEs `organization_id`, `provider`, `task` or `created_at`: UPDATE is
  granted per column, only where the API or the analyst worker legitimately writes.
- `ai_provider_configs` has no DELETE grant and a monotonic `key_version` (the M4 0010
  lesson); removing a key is an UPDATE that clears the sealed columns.
- `ai_runs` follows a status graph (`ai_run_transition`, `refused` is final); the inputs,
  refs, outputs and citations are append-only (`forbid_mutation`, also for the owner).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "cyberlab_app"
TENANT_TABLES = (
    "ai_provider_configs",
    "ai_org_settings",
    "ai_runs",
    "ai_run_inputs",
    "ai_context_refs",
    "ai_outputs",
    "ai_citations",
)
APPEND_ONLY = ("ai_run_inputs", "ai_context_refs", "ai_outputs", "ai_citations")
# Table-level privileges (no DELETE anywhere), then the only columns the app role may UPDATE.
GRANTS = {
    "ai_provider_configs": "SELECT, INSERT",
    "ai_org_settings": "SELECT, INSERT",
    "ai_runs": "SELECT, INSERT",
    "ai_run_index": "SELECT, INSERT",
    "ai_run_inputs": "SELECT, INSERT",
    "ai_context_refs": "SELECT, INSERT",
    "ai_outputs": "SELECT, INSERT",
    "ai_citations": "SELECT, INSERT",
}
UPDATE_COLUMNS = {
    # The sealed columns too: the analyst's lazy re-seal under the active kid (RT18).
    "ai_provider_configs": (
        "enabled, model, key_kid, key_version, key_epk, key_nonce, key_ct, key_last4, "
        "verify_status, verified_at, last_error_code, limits, terms_ack_at, terms_ack_by, "
        "paid_tier_ack_at, paid_tier_ack_by, updated_at"
    ),
    "ai_org_settings": (
        "ai_enabled, privacy_ack_at, privacy_ack_by, default_provider, pseudonymize_internal, "
        "internal_cidrs, internal_suffixes, include_strings, include_ti, include_case_text, "
        "daily_token_budget, run_token_cap, incident_token_cap, updated_by, updated_at"
    ),
    "ai_runs": (
        "status, error_code, served_model, usage, cost_micros, price_version, metrics, "
        "started_at, finished_at"
    ),
    "ai_run_index": (
        "status, resume_at, deadline_at, dispatched_at, lease_until, lease_owner, attempts, calls"
    ),
}

# queued -> running <-> waiting -> completed / partial / failed / refused, plus queued /
# waiting -> failed (worker deadline, fallback reaper). Final states never change.
RUN_TRANSITION = """CREATE FUNCTION ai_run_transition() RETURNS trigger LANGUAGE plpgsql
  SET search_path = pg_catalog AS $$
BEGIN
  IF OLD.status IN ('completed', 'partial', 'failed', 'refused') THEN
    RAISE EXCEPTION 'ai run % is final (%)', OLD.id, OLD.status
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
       (OLD.status = 'queued' AND NEW.status IN ('running', 'failed'))
    OR (OLD.status = 'running'
        AND NEW.status IN ('waiting', 'completed', 'partial', 'failed', 'refused'))
    OR (OLD.status = 'waiting' AND NEW.status IN ('running', 'failed'))
  ) THEN
    RAISE EXCEPTION 'illegal ai run transition % -> %', OLD.status, NEW.status
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.id, NEW.organization_id, NEW.task, NEW.scope, NEW.job_id, NEW.investigation_id,
      NEW.target_kind, NEW.target_id, NEW.parent_run_id, NEW.provider, NEW.model,
      NEW.prompt_version, NEW.output_schema, NEW.context_sha256, NEW.context_stats,
      NEW.requested_by, NEW.supersedes_run_id, NEW.deadline_at, NEW.created_at)
     IS DISTINCT FROM
     (OLD.id, OLD.organization_id, OLD.task, OLD.scope, OLD.job_id, OLD.investigation_id,
      OLD.target_kind, OLD.target_id, OLD.parent_run_id, OLD.provider, OLD.model,
      OLD.prompt_version, OLD.output_schema, OLD.context_sha256, OLD.context_stats,
      OLD.requested_by, OLD.supersedes_run_id, OLD.deadline_at, OLD.created_at) THEN
    RAISE EXCEPTION 'ai run identity columns are immutable'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$"""

# Copied from 0009's ti_key_version_guard (RT18): a new sealed key needs a higher
# key_version (the version is in the seal AAD); a re-seal of the same key under another kid
# keeps it; clearing the key keeps it too, so the next key still needs a higher one.
KEY_VERSION_GUARD = """CREATE FUNCTION ai_key_version_guard() RETURNS trigger LANGUAGE plpgsql
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

FUNCTIONS = ("ai_run_transition", "ai_key_version_guard")


def _create_security() -> None:
    for table in (*TENANT_TABLES, "ai_run_index"):
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
        "CREATE POLICY run_index_scope ON ai_run_index "
        "USING (app_org_id() IS NULL OR organization_id = app_org_id()) "
        "WITH CHECK (app_org_id() IS NULL OR organization_id = app_org_id())"
    )

    op.execute(RUN_TRANSITION)
    op.execute(
        "CREATE TRIGGER ai_run_transition BEFORE UPDATE ON ai_runs "
        "FOR EACH ROW EXECUTE FUNCTION ai_run_transition()"
    )
    op.execute(KEY_VERSION_GUARD)
    op.execute(
        "CREATE TRIGGER ai_key_version_guard BEFORE UPDATE ON ai_provider_configs "
        "FOR EACH ROW EXECUTE FUNCTION ai_key_version_guard()"
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


def upgrade() -> None:
    _create_tables()
    _create_security()


def _create_tables() -> None:
    op.create_table(
        "ai_org_settings",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("ai_enabled", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("privacy_ack_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("privacy_ack_by", sa.Uuid(), nullable=True),
        sa.Column("default_provider", sa.String(length=16), nullable=True),
        sa.Column("pseudonymize_internal", sa.Boolean(), server_default="true", nullable=False),
        sa.Column(
            "internal_cidrs",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="[]",
            nullable=False,
        ),
        sa.Column(
            "internal_suffixes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="[]",
            nullable=False,
        ),
        sa.Column("include_strings", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("include_ti", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("include_case_text", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("daily_token_budget", sa.BigInteger(), server_default="1000000", nullable=False),
        sa.Column("run_token_cap", sa.BigInteger(), server_default="100000", nullable=False),
        sa.Column("incident_token_cap", sa.BigInteger(), server_default="600000", nullable=False),
        sa.Column("updated_by", sa.Uuid(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "default_provider IS NULL OR default_provider IN ('anthropic', 'gemini', 'mock')",
            name=op.f("ck_ai_org_settings_default_provider"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(internal_cidrs) = 'array' AND jsonb_array_length(internal_cidrs) <= 50",
            name=op.f("ck_ai_org_settings_internal_cidrs"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(internal_suffixes) = 'array' AND jsonb_array_length(internal_suffixes) "
            "<= 50",
            name=op.f("ck_ai_org_settings_internal_suffixes"),
        ),
        sa.CheckConstraint(
            "NOT ai_enabled OR privacy_ack_at IS NOT NULL",
            name=op.f("ck_ai_org_settings_enabled_needs_privacy"),
        ),
        sa.CheckConstraint(
            "daily_token_budget > 0 AND run_token_cap > 0 AND incident_token_cap > 0",
            name=op.f("ck_ai_org_settings_budgets_positive"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_ai_org_settings_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["privacy_ack_by"], ["users.id"], name=op.f("fk_ai_org_settings_privacy_ack_by_users")
        ),
        sa.ForeignKeyConstraint(
            ["updated_by"], ["users.id"], name=op.f("fk_ai_org_settings_updated_by_users")
        ),
        sa.PrimaryKeyConstraint("organization_id", name=op.f("pk_ai_org_settings")),
    )
    op.create_table(
        "ai_provider_configs",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=16), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("model", sa.String(length=64), nullable=True),
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
        sa.Column("paid_tier_ack_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("paid_tier_ack_by", sa.Uuid(), nullable=True),
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
            "NOT enabled OR provider <> 'gemini' OR paid_tier_ack_at IS NOT NULL",
            name=op.f("ck_ai_provider_configs_gemini_enabled_needs_paid_tier"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(limits) = 'object'", name=op.f("ck_ai_provider_configs_limits_object")
        ),
        sa.CheckConstraint(
            "model IS NULL OR model ~ '^[a-z0-9][a-z0-9._-]{0,63}$'",
            name=op.f("ck_ai_provider_configs_model_pattern"),
        ),
        sa.CheckConstraint(
            "provider IN ('anthropic', 'gemini', 'mock')",
            name=op.f("ck_ai_provider_configs_provider"),
        ),
        sa.CheckConstraint(
            "verify_status IN ('unverified', 'valid', 'invalid', 'error')",
            name=op.f("ck_ai_provider_configs_verify_status"),
        ),
        sa.CheckConstraint(
            "NOT enabled OR terms_ack_at IS NOT NULL",
            name=op.f("ck_ai_provider_configs_enabled_needs_terms"),
        ),
        sa.CheckConstraint(
            "key_ct IS NULL OR key_version >= 1", name=op.f("ck_ai_provider_configs_sealed_version")
        ),
        sa.CheckConstraint(
            "key_epk IS NULL OR (octet_length(key_epk) = 32 AND octet_length(key_nonce) = 12)",
            name=op.f("ck_ai_provider_configs_sealed_sizes"),
        ),
        sa.CheckConstraint(
            "key_kid IS NULL AND key_epk IS NULL AND key_nonce IS NULL AND key_ct IS NULL AND "
            "key_last4 IS NULL OR key_kid IS NOT NULL AND key_epk IS NOT NULL AND key_nonce IS "
            "NOT NULL AND key_ct IS NOT NULL AND key_last4 IS NOT NULL",
            name=op.f("ck_ai_provider_configs_sealed_all_or_none"),
        ),
        sa.CheckConstraint(
            "key_last4 IS NULL OR char_length(key_last4) = 4",
            name=op.f("ck_ai_provider_configs_key_last4"),
        ),
        sa.CheckConstraint(
            "key_version >= 0", name=op.f("ck_ai_provider_configs_key_version_non_negative")
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_ai_provider_configs_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["paid_tier_ack_by"],
            ["users.id"],
            name=op.f("fk_ai_provider_configs_paid_tier_ack_by_users"),
        ),
        sa.ForeignKeyConstraint(
            ["terms_ack_by"], ["users.id"], name=op.f("fk_ai_provider_configs_terms_ack_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ai_provider_configs")),
        sa.UniqueConstraint(
            "organization_id",
            "provider",
            name=op.f("uq_ai_provider_configs_organization_id_provider"),
        ),
    )
    op.create_table(
        "ai_runs",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("task", sa.String(length=32), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=True),
        sa.Column("investigation_id", sa.Uuid(), nullable=True),
        sa.Column("target_kind", sa.String(length=16), nullable=True),
        sa.Column("target_id", sa.Uuid(), nullable=True),
        sa.Column("parent_run_id", sa.Uuid(), nullable=True),
        sa.Column("provider", sa.String(length=16), nullable=False),
        sa.Column("model", sa.String(length=64), nullable=False),
        sa.Column("prompt_version", sa.String(length=32), nullable=False),
        sa.Column("output_schema", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="queued", nullable=False),
        sa.Column("error_code", sa.String(length=32), nullable=True),
        sa.Column("served_model", sa.String(length=64), nullable=True),
        sa.Column("context_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "context_stats",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column(
            "usage", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False
        ),
        sa.Column(
            "metrics", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False
        ),
        sa.Column("cost_micros", sa.BigInteger(), nullable=True),
        sa.Column("price_version", sa.String(length=32), nullable=True),
        sa.Column("requested_by", sa.Uuid(), nullable=False),
        sa.Column("supersedes_run_id", sa.Uuid(), nullable=True),
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
            "(investigation_id IS NOT NULL) = (scope = 'investigation')",
            name=op.f("ck_ai_runs_investigation_id_iff_investigation_scope"),
        ),
        sa.CheckConstraint(
            "(job_id IS NOT NULL) = (scope = 'job')", name=op.f("ck_ai_runs_job_id_iff_job_scope")
        ),
        sa.CheckConstraint(
            "(parent_run_id IS NOT NULL) = (task = 'job_digest')",
            name=op.f("ck_ai_runs_parent_iff_job_digest"),
        ),
        sa.CheckConstraint(
            "(target_id IS NULL) = (target_kind IS NULL) AND (target_kind IS NULL OR target_kind "
            "IN ('finding', 'alert'))",
            name=op.f("ck_ai_runs_target"),
        ),
        sa.CheckConstraint(
            "context_sha256 ~ '^[0-9a-f]{64}$'", name=op.f("ck_ai_runs_context_sha256")
        ),
        sa.CheckConstraint(
            "model ~ '^[a-z0-9][a-z0-9._-]{0,63}$'", name=op.f("ck_ai_runs_model_pattern")
        ),
        sa.CheckConstraint(
            "provider IN ('anthropic', 'gemini', 'mock')", name=op.f("ck_ai_runs_provider")
        ),
        sa.CheckConstraint("scope IN ('job', 'investigation')", name=op.f("ck_ai_runs_scope")),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'waiting', 'completed', 'partial', 'failed', "
            "'refused')",
            name=op.f("ck_ai_runs_status"),
        ),
        sa.CheckConstraint(
            "task IN ('explain_finding', 'explain_alert', 'summarize_pcap', 'explain_static', "
            "'ioc_correlation', 'attack_mapping', 'incident_summary', 'job_digest')",
            name=op.f("ck_ai_runs_task"),
        ),
        sa.CheckConstraint(
            "context_stats IS NULL OR octet_length(context_stats::text) <= 16384",
            name=op.f("ck_ai_runs_stats_size"),
        ),
        sa.CheckConstraint(
            "cost_micros IS NULL OR cost_micros >= 0", name=op.f("ck_ai_runs_cost_non_negative")
        ),
        sa.CheckConstraint(
            "metrics IS NULL OR octet_length(metrics::text) <= 4096",
            name=op.f("ck_ai_runs_metrics_size"),
        ),
        sa.CheckConstraint(
            "usage IS NULL OR octet_length(usage::text) <= 2048", name=op.f("ck_ai_runs_usage_size")
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id", "organization_id"],
            ["investigations.id", "investigations.organization_id"],
            name=op.f("fk_ai_runs_investigation_id_organization_id_investigations"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id", "organization_id"],
            ["analysis_jobs.id", "analysis_jobs.organization_id"],
            name=op.f("fk_ai_runs_job_id_organization_id_analysis_jobs"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_ai_runs_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["parent_run_id", "organization_id"],
            ["ai_runs.id", "ai_runs.organization_id"],
            name=op.f("fk_ai_runs_parent_run_id_organization_id_ai_runs"),
        ),
        sa.ForeignKeyConstraint(
            ["requested_by"], ["users.id"], name=op.f("fk_ai_runs_requested_by_users")
        ),
        sa.ForeignKeyConstraint(
            ["supersedes_run_id", "organization_id"],
            ["ai_runs.id", "ai_runs.organization_id"],
            name=op.f("fk_ai_runs_supersedes_run_id_organization_id_ai_runs"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ai_runs")),
        sa.UniqueConstraint("id", "organization_id", name=op.f("uq_ai_runs_id_organization_id")),
    )
    op.create_index(
        op.f("ix_ai_runs_investigation_id_created_at"),
        "ai_runs",
        ["investigation_id", "created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_ai_runs_job_id_created_at"), "ai_runs", ["job_id", "created_at"], unique=False
    )
    op.create_index(
        op.f("ix_ai_runs_organization_id_context_sha256"),
        "ai_runs",
        ["organization_id", "context_sha256"],
        unique=False,
    )
    op.create_index(
        op.f("ix_ai_runs_organization_id_created_at"),
        "ai_runs",
        ["organization_id", "created_at"],
        unique=False,
    )
    op.create_index(op.f("ix_ai_runs_parent_run_id"), "ai_runs", ["parent_run_id"], unique=False)
    op.create_table(
        "ai_context_refs",
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("label", sa.String(length=16), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("stage", sa.String(length=8), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("ref_table", sa.String(length=64), nullable=False),
        sa.Column("ref_id", sa.String(length=128), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=True),
        sa.Column("fields_sha256", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "fields_sha256 ~ '^[0-9a-f]{64}$'", name=op.f("ck_ai_context_refs_fields_sha256")
        ),
        sa.CheckConstraint(
            "kind IN ('job', 'finding', 'alert', 'flow', 'record', 'ioc', 'ti_result', 'sample', "
            "'signature', 'capability', 'pe_summary', 'string', 'timeline', 'evidence', "
            "'investigation', 'digest_claim')",
            name=op.f("ck_ai_context_refs_kind"),
        ),
        sa.CheckConstraint(
            "label ~ '^(J[0-9]{1,3}:)?[A-Z][0-9]{1,4}$'", name=op.f("ck_ai_context_refs_label")
        ),
        sa.CheckConstraint("stage IN ('base', 'reduce')", name=op.f("ck_ai_context_refs_stage")),
        sa.ForeignKeyConstraint(
            ["job_id", "organization_id"],
            ["analysis_jobs.id", "analysis_jobs.organization_id"],
            name=op.f("fk_ai_context_refs_job_id_organization_id_analysis_jobs"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_ai_context_refs_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["ai_runs.id", "ai_runs.organization_id"],
            name=op.f("fk_ai_context_refs_run_id_organization_id_ai_runs"),
        ),
        sa.PrimaryKeyConstraint("run_id", "label", name=op.f("pk_ai_context_refs")),
    )
    op.create_index(
        op.f("ix_ai_context_refs_organization_id_kind_ref_id"),
        "ai_context_refs",
        ["organization_id", "kind", "ref_id"],
        unique=False,
    )
    op.create_table(
        "ai_outputs",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("body", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "verification",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column(
            "flags", postgresql.JSONB(astext_type=sa.Text()), server_default="[]", nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.CheckConstraint("jsonb_typeof(flags) = 'array'", name=op.f("ck_ai_outputs_flags_array")),
        sa.CheckConstraint(
            "body IS NULL OR octet_length(body::text) <= 65536",
            name=op.f("ck_ai_outputs_body_size"),
        ),
        sa.CheckConstraint(
            "verification IS NULL OR octet_length(verification::text) <= 32768",
            name=op.f("ck_ai_outputs_verification_size"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_ai_outputs_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["ai_runs.id", "ai_runs.organization_id"],
            name=op.f("fk_ai_outputs_run_id_organization_id_ai_runs"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ai_outputs")),
        sa.UniqueConstraint("id", "organization_id", name=op.f("uq_ai_outputs_id_organization_id")),
        sa.UniqueConstraint("run_id", name=op.f("uq_ai_outputs_run_id")),
    )
    op.create_table(
        "ai_run_index",
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("resume_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_owner", sa.String(length=64), nullable=True),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("calls", sa.Integer(), server_default="0", nullable=False),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'waiting', 'completed', 'partial', 'failed', "
            "'refused')",
            name=op.f("ck_ai_run_index_status"),
        ),
        sa.CheckConstraint("attempts >= 0", name=op.f("ck_ai_run_index_attempts_non_negative")),
        sa.CheckConstraint("calls >= 0", name=op.f("ck_ai_run_index_calls_non_negative")),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_ai_run_index_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["ai_runs.id", "ai_runs.organization_id"],
            name=op.f("fk_ai_run_index_run_id_organization_id_ai_runs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("run_id", name=op.f("pk_ai_run_index")),
    )
    op.create_index(
        op.f("ix_ai_run_index_status_resume_at"),
        "ai_run_index",
        ["status", "resume_at"],
        unique=False,
    )
    op.create_table(
        "ai_run_inputs",
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("stage", sa.String(length=8), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("context", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("context_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "pseudonym_map",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "context_sha256 ~ '^[0-9a-f]{64}$'", name=op.f("ck_ai_run_inputs_context_sha256")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(pseudonym_map) = 'object' AND octet_length(pseudonym_map::text) <= 65536",
            name=op.f("ck_ai_run_inputs_pseudonym_map"),
        ),
        sa.CheckConstraint("stage IN ('base', 'reduce')", name=op.f("ck_ai_run_inputs_stage")),
        sa.CheckConstraint(
            "context IS NULL OR octet_length(context::text) <= 524288",
            name=op.f("ck_ai_run_inputs_context_size"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_ai_run_inputs_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["ai_runs.id", "ai_runs.organization_id"],
            name=op.f("fk_ai_run_inputs_run_id_organization_id_ai_runs"),
        ),
        sa.PrimaryKeyConstraint("run_id", "stage", name=op.f("pk_ai_run_inputs")),
    )
    op.create_table(
        "ai_citations",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("output_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("claim_path", sa.String(length=128), nullable=False),
        sa.Column("section", sa.String(length=32), nullable=False),
        sa.Column("claim_id", sa.String(length=32), nullable=True),
        sa.Column("claim_status", sa.String(length=16), nullable=True),
        sa.Column("label", sa.String(length=32), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=True),
        sa.Column("ref_id", sa.String(length=128), nullable=True),
        sa.Column("job_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.String(length=32), nullable=True),
        sa.Column("field", sa.String(length=64), nullable=True),
        sa.Column("quote", sa.String(length=256), nullable=True),
        sa.Column("stale", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.CheckConstraint(
            "claim_status IS NULL OR claim_status IN ('supported', 'unsupported', 'hypothesis')",
            name=op.f("ck_ai_citations_claim_status"),
        ),
        sa.CheckConstraint(
            "kind IS NULL OR kind IN ('job', 'finding', 'alert', 'flow', 'record', 'ioc', "
            "'ti_result', 'sample', 'signature', 'capability', 'pe_summary', 'string', "
            "'timeline', 'evidence', 'investigation', 'digest_claim')",
            name=op.f("ck_ai_citations_kind"),
        ),
        sa.CheckConstraint(
            "reason IS NULL OR reason IN ('unknown_label', 'digest_not_evidence', "
            "'field_not_allowed', 'out_of_scope', 'row_missing', 'quote_mismatch', "
            "'quote_too_short', 'quote_required', 'weak_anchor', 'no_verified_citation', "
            "'invalid_attack', 'no_timestamp')",
            name=op.f("ck_ai_citations_reason"),
        ),
        sa.CheckConstraint(
            "section IN ('observed', 'interpretation', 'hypotheses', 'next_steps', "
            "'attack_techniques', 'timeline')",
            name=op.f("ck_ai_citations_section"),
        ),
        sa.CheckConstraint(
            "status IN ('verified', 'unverified', 'invalid')", name=op.f("ck_ai_citations_status")
        ),
        sa.CheckConstraint(
            "quote IS NULL OR char_length(quote) <= 256", name=op.f("ck_ai_citations_quote_length")
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_ai_citations_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["output_id", "organization_id"],
            ["ai_outputs.id", "ai_outputs.organization_id"],
            name=op.f("fk_ai_citations_output_id_organization_id_ai_outputs"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["ai_runs.id", "ai_runs.organization_id"],
            name=op.f("fk_ai_citations_run_id_organization_id_ai_runs"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ai_citations")),
    )
    op.create_index(
        op.f("ix_ai_citations_organization_id_kind_ref_id"),
        "ai_citations",
        ["organization_id", "kind", "ref_id"],
        unique=False,
    )
    op.create_index(op.f("ix_ai_citations_output_id"), "ai_citations", ["output_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_ai_citations_output_id"), table_name="ai_citations")
    op.drop_index(op.f("ix_ai_citations_organization_id_kind_ref_id"), table_name="ai_citations")
    op.drop_table("ai_citations")
    op.drop_table("ai_run_inputs")
    op.drop_index(op.f("ix_ai_run_index_status_resume_at"), table_name="ai_run_index")
    op.drop_table("ai_run_index")
    op.drop_table("ai_outputs")
    op.drop_index(
        op.f("ix_ai_context_refs_organization_id_kind_ref_id"), table_name="ai_context_refs"
    )
    op.drop_table("ai_context_refs")
    op.drop_index(op.f("ix_ai_runs_parent_run_id"), table_name="ai_runs")
    op.drop_index(op.f("ix_ai_runs_organization_id_created_at"), table_name="ai_runs")
    op.drop_index(op.f("ix_ai_runs_organization_id_context_sha256"), table_name="ai_runs")
    op.drop_index(op.f("ix_ai_runs_job_id_created_at"), table_name="ai_runs")
    op.drop_index(op.f("ix_ai_runs_investigation_id_created_at"), table_name="ai_runs")
    op.drop_table("ai_runs")
    op.drop_table("ai_provider_configs")
    op.drop_table("ai_org_settings")
    for function in FUNCTIONS:
        op.execute(f"DROP FUNCTION IF EXISTS {function}()")
