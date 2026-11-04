"""threat intel hardening: no provider-config DELETE for the app role; composite run-index FK

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-05 20:00:00

Review of M4 phase 1 (0009 stays frozen):
- L7: the app role could DELETE a `ti_provider_configs` row, which reset the monotonic
  `key_version` floor of that provider (RT18 residual): an old sealed key could then be put
  back. DELETE is revoked; removing a key is an UPDATE that clears the sealed columns and sets
  `enabled = false` (the version floor stays).
- L8: `ti_run_index.run_id` referenced `ti_enrichment_runs(id)` alone, so an index row could
  name another org than its run. It now references `(id, organization_id)` (the unique
  constraint already exists), like `ti_run_items` and `ti_results`.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "cyberlab_app"
OLD_FK = "fk_ti_run_index_run_id_ti_enrichment_runs"
NEW_FK = "fk_ti_run_index_run_id_organization_id_ti_enrichment_runs"


def upgrade() -> None:
    op.execute(f"REVOKE DELETE ON ti_provider_configs FROM {APP_ROLE}")
    op.drop_constraint(OLD_FK, "ti_run_index", type_="foreignkey")
    op.create_foreign_key(
        NEW_FK,
        "ti_run_index",
        "ti_enrichment_runs",
        ["run_id", "organization_id"],
        ["id", "organization_id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint(NEW_FK, "ti_run_index", type_="foreignkey")
    op.create_foreign_key(
        OLD_FK, "ti_run_index", "ti_enrichment_runs", ["run_id"], ["id"], ondelete="CASCADE"
    )
    op.execute(f"GRANT DELETE ON ti_provider_configs TO {APP_ROLE}")
