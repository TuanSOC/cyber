"""analysis jobs

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-04 15:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

STATUS = postgresql.ENUM(
    "queued", "running", "succeeded", "failed", name="analysis_status", create_type=False
)
ANALYZER = postgresql.ENUM("pcap", name="analyzer", create_type=False)

TERMINAL_GUARD = """CREATE FUNCTION analysis_job_terminal() RETURNS trigger LANGUAGE plpgsql
  SET search_path = pg_catalog AS $$
BEGIN
  IF OLD.status IN ('succeeded', 'failed') THEN
    RAISE EXCEPTION 'analysis job % is final (%)', OLD.id, OLD.status
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.id, NEW.organization_id, NEW.evidence_id, NEW.analyzer, NEW.requested_by,
      NEW.auto, NEW.ingest_token_sha256, NEW.created_at)
     IS DISTINCT FROM
     (OLD.id, OLD.organization_id, OLD.evidence_id, OLD.analyzer, OLD.requested_by,
      OLD.auto, OLD.ingest_token_sha256, OLD.created_at) THEN
    RAISE EXCEPTION 'analysis job identity columns are immutable'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$"""


def upgrade() -> None:
    # New custody actions (not used in this transaction, so ADD VALUE is safe here).
    op.execute("ALTER TYPE custody_action ADD VALUE IF NOT EXISTS 'analysis_requested'")
    op.execute("ALTER TYPE custody_action ADD VALUE IF NOT EXISTS 'analyzed'")
    STATUS.create(op.get_bind())
    ANALYZER.create(op.get_bind())

    op.create_table(
        "analysis_jobs",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("analyzer", ANALYZER, nullable=False),
        sa.Column("status", STATUS, server_default="queued", nullable=False),
        sa.Column("error_code", sa.String(64)),
        sa.Column("requested_by", sa.Uuid(), nullable=False),
        sa.Column("auto", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("ingest_token_sha256", sa.String(64), nullable=False),
        sa.Column("worker_version", sa.String(255)),
        sa.Column("result_version_id", sa.String(255)),
        sa.Column(
            "summary",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["evidence.id", "evidence.organization_id"],
            name="fk_analysis_jobs_evidence_id_organization_id_evidence",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_analysis_jobs_organization_id_organizations",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by"], ["users.id"], name="fk_analysis_jobs_requested_by_users"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_analysis_jobs"),
        sa.UniqueConstraint("id", "organization_id", name="uq_analysis_jobs_id_organization_id"),
        sa.CheckConstraint(
            "(status IN ('queued', 'running', 'succeeded')) = (error_code IS NULL)",
            name="ck_analysis_jobs_error_code_iff_failed",
        ),
    )
    op.create_index(
        "ix_analysis_jobs_organization_id_created_at",
        "analysis_jobs",
        ["organization_id", "created_at"],
    )
    op.create_index(
        "ix_analysis_jobs_evidence_id_created_at", "analysis_jobs", ["evidence_id", "created_at"]
    )
    op.create_index(
        "uq_analysis_jobs_active",
        "analysis_jobs",
        ["evidence_id", "analyzer"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )

    op.create_table(
        "analysis_job_index",
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("status", STATUS, nullable=False),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["analysis_jobs.id"],
            ondelete="CASCADE",
            name="fk_analysis_job_index_job_id_analysis_jobs",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_analysis_job_index_organization_id_organizations",
        ),
        sa.PrimaryKeyConstraint("job_id", name="pk_analysis_job_index"),
    )
    op.create_index(
        "ix_analysis_job_index_status_deadline_at",
        "analysis_job_index",
        ["status", "deadline_at"],
    )

    op.execute("ALTER TABLE analysis_jobs ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE analysis_jobs FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON analysis_jobs "
        "USING (organization_id = app_org_id()) "
        "WITH CHECK (organization_id = app_org_id())"
    )
    op.execute(TERMINAL_GUARD)
    op.execute(
        "CREATE TRIGGER analysis_job_terminal BEFORE UPDATE ON analysis_jobs "
        "FOR EACH ROW EXECUTE FUNCTION analysis_job_terminal()"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE ON analysis_jobs TO cyberlab_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON analysis_job_index TO cyberlab_app")


def downgrade() -> None:
    op.drop_table("analysis_job_index")
    op.execute("DROP TRIGGER IF EXISTS analysis_job_terminal ON analysis_jobs")
    op.drop_table("analysis_jobs")
    op.execute("DROP FUNCTION IF EXISTS analysis_job_terminal()")
    ANALYZER.drop(op.get_bind())
    STATUS.drop(op.get_bind())
    # Enum values cannot be removed from custody_action; they stay (unused) on downgrade.
