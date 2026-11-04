"""static results: samples, sections, imports, exports, resources, strings, signatures,
capabilities

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-05 14:00:00

Findings and IOCs of static jobs go into the shared `analysis_findings` and `iocs`. Nothing
here references the `analyzer` enum (M3 RT7): which job a row belongs to is enforced by the
composite FK, which analyzer wrote it by the ingest dispatch.
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = (
    "malware_samples",
    "malware_sections",
    "malware_imports",
    "malware_exports",
    "malware_resources",
    "malware_strings",
    "malware_signature_matches",
    "malware_capabilities",
)
ENCODINGS = "('ascii', 'utf16le', 'floss_decoded', 'floss_stack', 'floss_tight')"


def _jsonb() -> postgresql.JSONB:
    return postgresql.JSONB(astext_type=sa.Text())


def _address(name: str) -> sa.Column[Any]:
    # Unsigned 64-bit RVAs / VAs: bigint cannot hold the upper half.
    return sa.Column(name, sa.Numeric(20, 0), nullable=False)


def fk_name(table: str) -> str:
    """The naming convention's FK name, shortened where it would exceed 63 characters."""
    name = f"fk_{table}_job_id_organization_id_analysis_jobs"
    return name if len(name) <= 63 else f"fk_{table}_job_id_analysis_jobs"


def _base(table: str) -> list[Any]:
    return [
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=f"pk_{table}"),
        # Rows only ever point at a job of their own organization; they go with the job.
        sa.ForeignKeyConstraint(
            ["job_id", "organization_id"],
            ["analysis_jobs.id", "analysis_jobs.organization_id"],
            ondelete="CASCADE",
            name=fk_name(table),
        ),
    ]


def upgrade() -> None:
    op.create_table(
        "malware_samples",
        *_base("malware_samples"),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("md5", sa.String(32), nullable=False),
        sa.Column("sha1", sa.String(40), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("ssdeep", sa.String(128)),
        sa.Column("file_type", sa.String(255)),
        sa.Column("mime", sa.String(128)),
        sa.Column("entropy", sa.Double(), nullable=False),
        sa.Column("file_format", sa.String(8), nullable=False),
        sa.Column("pe", _jsonb()),
        sa.Column("elf", _jsonb()),
        sa.UniqueConstraint("job_id", name="uq_malware_samples_job_id"),
        sa.CheckConstraint(
            "file_format IN ('pe', 'elf', 'other')", name="ck_malware_samples_file_format"
        ),
    )

    op.create_table(
        "malware_sections",
        *_base("malware_sections"),
        sa.Column("index", sa.BigInteger(), nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        _address("virtual_address"),
        sa.Column("virtual_size", sa.BigInteger(), nullable=False),
        sa.Column("raw_size", sa.BigInteger(), nullable=False),
        sa.Column("entropy", sa.Double(), nullable=False),
        sa.Column("flags", _jsonb(), nullable=False),
    )
    op.create_index("ix_malware_sections_job_id_index", "malware_sections", ["job_id", "index"])

    op.create_table(
        "malware_imports",
        *_base("malware_imports"),
        sa.Column("library", sa.String(255), nullable=False),
        sa.Column("function", sa.String(255)),
        sa.Column("ordinal", sa.Integer()),
    )
    op.create_index("ix_malware_imports_job_id_library", "malware_imports", ["job_id", "library"])

    op.create_table(
        "malware_exports",
        *_base("malware_exports"),
        sa.Column("name", sa.String(255)),
        sa.Column("ordinal", sa.BigInteger(), nullable=False),
        _address("address"),
    )
    op.create_index("ix_malware_exports_job_id_ordinal", "malware_exports", ["job_id", "ordinal"])

    op.create_table(
        "malware_resources",
        *_base("malware_resources"),
        sa.Column("type", sa.String(64), nullable=False),
        sa.Column("name", sa.String(255)),
        sa.Column("language", sa.String(64)),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("entropy", sa.Double(), nullable=False),
        sa.Column("sha256", sa.String(64)),
    )
    op.create_index("ix_malware_resources_job_id_type", "malware_resources", ["job_id", "type"])

    op.create_table(
        "malware_strings",
        *_base("malware_strings"),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("encoding", sa.String(16), nullable=False),
        sa.Column("offset", sa.BigInteger()),
        sa.CheckConstraint(f"encoding IN {ENCODINGS}", name="ck_malware_strings_encoding"),
    )
    op.create_index("ix_malware_strings_job_id_encoding", "malware_strings", ["job_id", "encoding"])

    op.create_table(
        "malware_signature_matches",
        *_base("malware_signature_matches"),
        sa.Column("engine", sa.String(8), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("namespace", sa.String(128)),
        sa.Column("tags", _jsonb(), nullable=False),
        sa.Column("meta", _jsonb(), nullable=False),
        sa.CheckConstraint(
            "engine IN ('clamav', 'yara')", name="ck_malware_signature_matches_engine"
        ),
    )
    op.create_index(
        "ix_malware_signature_matches_job_id_engine",
        "malware_signature_matches",
        ["job_id", "engine"],
    )

    op.create_table(
        "malware_capabilities",
        *_base("malware_capabilities"),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("namespace", sa.String(255)),
        sa.Column("attack", _jsonb(), nullable=False),
        sa.Column("mbc", _jsonb(), nullable=False),
        sa.Column("matches", sa.BigInteger(), nullable=False),
    )
    op.create_index(
        "ix_malware_capabilities_job_id_namespace",
        "malware_capabilities",
        ["job_id", "namespace"],
    )

    for table in TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            "USING (organization_id = app_org_id()) "
            "WITH CHECK (organization_id = app_org_id())"
        )
        # Written once by ingest, read by the API; never updated or deleted by the app.
        op.execute(f"GRANT SELECT, INSERT ON {table} TO cyberlab_app")


def downgrade() -> None:
    for table in reversed(TABLES):
        op.drop_table(table)
