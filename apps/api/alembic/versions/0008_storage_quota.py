"""per-organization storage quota; column-level write grants on organizations

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-06 09:00:00

`storage_quota_bytes` NULL means the deployment default (`DEFAULT_STORAGE_QUOTA_BYTES`).
Only the database owner (an operator) sets it: the app role loses table-wide INSERT/UPDATE
on `organizations` and keeps them only on the columns the API legitimately writes, so a
compromised or buggy app session cannot raise its own quota (M3 RT8).
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "cyberlab_app"
# Register / org create insert these; rename (name), case numbering (next_case_number) and
# the onupdate timestamp (updated_at) update these. SELECT ... FOR UPDATE (the org lock)
# needs UPDATE on at least one column, which these grants keep.
INSERT_COLUMNS = "id, name, slug, next_case_number, created_by, created_at, updated_at"
UPDATE_COLUMNS = "name, next_case_number, updated_at"


def upgrade() -> None:
    op.add_column("organizations", sa.Column("storage_quota_bytes", sa.BigInteger()))
    op.create_check_constraint(
        op.f("ck_organizations_storage_quota_bytes_non_negative"),
        "organizations",
        "storage_quota_bytes IS NULL OR storage_quota_bytes >= 0",
    )
    op.execute(f"REVOKE INSERT, UPDATE ON organizations FROM {APP_ROLE}")
    op.execute(f"GRANT INSERT ({INSERT_COLUMNS}) ON organizations TO {APP_ROLE}")
    op.execute(f"GRANT UPDATE ({UPDATE_COLUMNS}) ON organizations TO {APP_ROLE}")


def downgrade() -> None:
    # Column-level grants are separate ACL entries: revoke them, then restore the table-wide
    # privileges of 0001.
    op.execute(f"REVOKE INSERT ({INSERT_COLUMNS}) ON organizations FROM {APP_ROLE}")
    op.execute(f"REVOKE UPDATE ({UPDATE_COLUMNS}) ON organizations FROM {APP_ROLE}")
    op.execute(f"GRANT INSERT, UPDATE ON organizations TO {APP_ROLE}")
    op.drop_constraint(
        op.f("ck_organizations_storage_quota_bytes_non_negative"), "organizations", type_="check"
    )
    op.drop_column("organizations", "storage_quota_bytes")
