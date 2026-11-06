"""M7 review M1/M2: resumable S3 legal-hold sync state on legal_holds

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-06 22:00:00

0014 stays frozen. The retention worker mirrors legal holds as S3 legal holds (RT5) in
bounded passes. 0014 kept one column, `s3_synced_at`, as both the last completed pass and
(below `placed_at`) the resume watermark of an incomplete org-hold pass, so a pass that could
not finish within the budget either restarted from the beginning (OFF passes) or stalled
(an ON pass with more uploads than the budget at one timestamp or since placement). This
revision separates them:
- `s3_synced_at`: set by a COMPLETED pass only (an ON pass stores its start time, the lower
  bound of the next incremental pass; an OFF pass or a stamp-only release its end time);
- `s3_full_synced_at`: when the first complete ON pass (from the beginning) finished, i.e.
  the hold reads `s3_sync: synced` while it protects;
- `s3_sync_cursor_at` / `s3_sync_cursor_id`: the keyset cursor (uploaded_at or finalized_at,
  id) of the pass in progress, and `s3_sync_pass_at`: when that pass started. All three are
  NULL together (no pass in progress).
The retention role gets UPDATE on the four new columns (the API never writes them). Existing
rows keep `s3_synced_at`; their `s3_full_synced_at` is NULL, so the worker redoes one full ON
pass for each protecting hold (idempotent). No data is migrated: FORCE RLS hides the rows
from the owner here.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

RETENTION_ROLE = "cyberlab_retention"
TABLE = "legal_holds"
TIMESTAMPS = ("s3_full_synced_at", "s3_sync_cursor_at", "s3_sync_pass_at")
COLUMNS = (*TIMESTAMPS, "s3_sync_cursor_id")
CURSOR_CHECK = "ck_legal_holds_s3_sync_cursor"


def upgrade() -> None:
    for name in TIMESTAMPS:
        op.add_column(TABLE, sa.Column(name, sa.DateTime(timezone=True), nullable=True))
    op.add_column(TABLE, sa.Column("s3_sync_cursor_id", sa.Uuid(), nullable=True))
    op.create_check_constraint(
        op.f(CURSOR_CHECK),
        TABLE,
        "(s3_sync_cursor_at IS NULL) = (s3_sync_cursor_id IS NULL) "
        "AND (s3_sync_cursor_at IS NULL) = (s3_sync_pass_at IS NULL)",
    )
    op.execute(f"GRANT UPDATE ({', '.join(COLUMNS)}) ON {TABLE} TO {RETENTION_ROLE}")


def downgrade() -> None:
    # Dropping a column drops its column privileges too.
    op.drop_constraint(op.f(CURSOR_CHECK), TABLE, type_="check")
    for name in reversed(COLUMNS):
        op.drop_column(TABLE, name)
