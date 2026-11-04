"""static analyzer: `analyzer` enum value, job profile, analyzer on the job index

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-05 09:00:00

`env.py` runs every pending migration in ONE transaction, and Postgres refuses to use an
enum value added by `ALTER TYPE ... ADD VALUE` before that transaction commits. The value is
therefore added in an autocommit block (alembic commits the work so far, runs the ALTER on
its own, then opens a new transaction for the rest), and nothing here or in any later
migration parses the literal as an `analyzer` (comparisons go through `analyzer::text`).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ANALYZER = postgresql.ENUM(name="analyzer", create_type=False)

_GUARD = """CREATE OR REPLACE FUNCTION analysis_job_terminal() RETURNS trigger
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
      NEW.auto, NEW.ingest_token_sha256, NEW.created_at{new_extra})
     IS DISTINCT FROM
     (OLD.id, OLD.organization_id, OLD.evidence_id, OLD.analyzer, OLD.requested_by,
      OLD.auto, OLD.ingest_token_sha256, OLD.created_at{old_extra}) THEN
    RAISE EXCEPTION 'analysis job identity columns are immutable'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$"""
# The profile is part of a job's identity (what was asked for), like its analyzer.
GUARD_WITH_PROFILE = _GUARD.format(new_extra=", NEW.profile", old_extra=", OLD.profile")
GUARD_0003 = _GUARD.format(new_extra="", old_extra="")


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE analyzer ADD VALUE IF NOT EXISTS 'static'")

    # Static runs carry a profile (`full` = every engine, `av` = ClamAV + YARA); others none.
    op.add_column("analysis_jobs", sa.Column("profile", sa.String(16), nullable=True))
    op.create_check_constraint(
        op.f("ck_analysis_jobs_profile_valid"),
        "analysis_jobs",
        "profile IS NULL OR profile IN ('full', 'av')",
    )
    op.create_check_constraint(
        op.f("ck_analysis_jobs_profile_iff_static"),
        "analysis_jobs",
        "(profile IS NOT NULL) = (analyzer::text = 'static')",
    )
    op.execute(GUARD_WITH_PROFILE)

    # Global caps are per analyzer and counted by system code on the (RLS-free for system
    # sessions) job index. Before this revision 'pcap' was the only analyzer, so every
    # existing index row is a pcap job: the default backfills them, then it is dropped.
    op.add_column(
        "analysis_job_index",
        sa.Column("analyzer", ANALYZER, nullable=False, server_default="pcap"),
    )
    op.alter_column("analysis_job_index", "analyzer", server_default=None)
    op.create_index(
        op.f("ix_analysis_job_index_analyzer_status"), "analysis_job_index", ["analyzer", "status"]
    )
    # cyberlab_app keeps table-level INSERT/SELECT and UPDATE on (status, deadline_at) only,
    # so the analyzer of an index row cannot be changed after insert.


def downgrade() -> None:
    # Postgres cannot drop an enum value: 'static' stays in `analyzer` (unused by 0005 code).
    # Static jobs already recorded keep analyzer = 'static'; their profile is dropped.
    op.drop_index(op.f("ix_analysis_job_index_analyzer_status"), table_name="analysis_job_index")
    op.drop_column("analysis_job_index", "analyzer")
    op.execute(GUARD_0003)
    op.drop_constraint(op.f("ck_analysis_jobs_profile_iff_static"), "analysis_jobs", type_="check")
    op.drop_constraint(op.f("ck_analysis_jobs_profile_valid"), "analysis_jobs", type_="check")
    op.drop_column("analysis_jobs", "profile")
