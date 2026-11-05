"""M6 review L4: same-org composite FKs for IOC collection items and report citations

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-07 09:00:00

0012 stays frozen. Two of its references were plain `id` FKs because their parents had no
`(id, organization_id)` unique constraint:
- `ioc_collection_items.ioc_id -> iocs.id`;
- `report_citations.ai_citation_id -> ai_citations.id`.
RLS already keeps every app read and write inside one org, but the schema itself did not
forbid a row naming another org's IOC or AI citation. This revision adds the unique
constraints `uq_iocs_id_organization_id` and `uq_ai_citations_id_organization_id` (the
`id` is already the primary key, so they always hold) and replaces the two plain FKs with
composite `(column, organization_id)` FKs, like every other child of M6. Both columns are
nullable, so MATCH SIMPLE leaves rows without a reference unchecked. Creating the FKs
validates the existing rows: a cross-org row (only possible by writing past RLS) fails the
upgrade instead of being kept.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# (child table, column, parent table)
LINKS = (
    ("ioc_collection_items", "ioc_id", "iocs"),
    ("report_citations", "ai_citation_id", "ai_citations"),
)


def _unique(parent: str) -> str:
    return f"uq_{parent}_id_organization_id"


def _old_fk(table: str, column: str, parent: str) -> str:
    return f"fk_{table}_{column}_{parent}"


def _new_fk(table: str, column: str, parent: str) -> str:
    return f"fk_{table}_{column}_organization_id_{parent}"


def upgrade() -> None:
    for table, column, parent in LINKS:
        op.create_unique_constraint(_unique(parent), parent, ["id", "organization_id"])
        op.drop_constraint(_old_fk(table, column, parent), table, type_="foreignkey")
        op.create_foreign_key(
            _new_fk(table, column, parent),
            table,
            parent,
            [column, "organization_id"],
            ["id", "organization_id"],
        )


def downgrade() -> None:
    for table, column, parent in reversed(LINKS):
        op.drop_constraint(_new_fk(table, column, parent), table, type_="foreignkey")
        op.create_foreign_key(_old_fk(table, column, parent), table, parent, [column], ["id"])
        op.drop_constraint(_unique(parent), parent, type_="unique")
