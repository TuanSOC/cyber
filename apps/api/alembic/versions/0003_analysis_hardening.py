"""analysis hardening: job index RLS + column grants, transition graph in the DB

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-04 18:00:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TRANSITIONS = """CREATE OR REPLACE FUNCTION analysis_job_terminal() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF OLD.status IN ('succeeded', 'failed') THEN
    RAISE EXCEPTION 'analysis job % is final (%)', OLD.id, OLD.status
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
       (OLD.status = 'queued' AND NEW.status IN ('running', 'succeeded', 'failed'))
    OR (OLD.status = 'running' AND NEW.status IN ('succeeded', 'failed'))
  ) THEN
    RAISE EXCEPTION 'illegal analysis job transition % -> %', OLD.status, NEW.status
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

FINAL_ONLY = """CREATE OR REPLACE FUNCTION analysis_job_terminal() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF OLD.status IN ('succeeded', 'failed') THEN
    RAISE EXCEPTION 'analysis job % is final (%)', OLD.id, OLD.status
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$"""


def upgrade() -> None:
    # System sessions (no org context: ingest, reaper) see every row; a tenant session only
    # its own org's rows, so a tenant-context bug cannot list or rewrite other orgs' jobs.
    op.execute("ALTER TABLE analysis_job_index ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE analysis_job_index FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY job_index_scope ON analysis_job_index "
        "USING (app_org_id() IS NULL OR organization_id = app_org_id()) "
        "WITH CHECK (app_org_id() IS NULL OR organization_id = app_org_id())"
    )
    op.execute("REVOKE UPDATE ON analysis_job_index FROM cyberlab_app")
    op.execute("GRANT UPDATE (status, deadline_at) ON analysis_job_index TO cyberlab_app")
    op.execute(TRANSITIONS)


def downgrade() -> None:
    op.execute(FINAL_ONLY)
    op.execute("REVOKE UPDATE ON analysis_job_index FROM cyberlab_app")
    op.execute("GRANT UPDATE ON analysis_job_index TO cyberlab_app")
    op.execute("DROP POLICY IF EXISTS job_index_scope ON analysis_job_index")
    op.execute("ALTER TABLE analysis_job_index NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE analysis_job_index DISABLE ROW LEVEL SECURITY")
