"""pcap results: flows, records, alerts, findings, iocs, timeline

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-04 21:00:00
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = (
    "network_flows",
    "network_records",
    "network_alerts",
    "analysis_findings",
    "iocs",
    "analysis_timeline",
)
SEVERITIES = "('info', 'low', 'medium', 'high')"


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
            name=f"fk_{table}_job_id_organization_id_analysis_jobs",
        ),
    ]


def _endpoints() -> list[Any]:
    return [
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("src_ip", postgresql.INET()),
        sa.Column("src_port", sa.Integer()),
        sa.Column("dst_ip", postgresql.INET()),
        sa.Column("dst_port", sa.Integer()),
        sa.Column("flow_ref", sa.String(64)),  # not a FK: may name a flow dropped by caps
    ]


def _endpoint_indexes(table: str) -> None:
    for column in ("ts", "src_ip", "dst_ip"):
        op.create_index(f"ix_{table}_job_id_{column}", table, ["job_id", column])


def upgrade() -> None:
    op.create_table(
        "network_flows",
        *_base("network_flows"),
        *_endpoints(),
        sa.Column("proto", sa.String(8), nullable=False),
        sa.Column("service", sa.String(64)),
        sa.Column("duration_s", sa.Double()),
        sa.Column("orig_bytes", sa.BigInteger(), nullable=False),
        sa.Column("resp_bytes", sa.BigInteger(), nullable=False),
        sa.Column("total_bytes", sa.BigInteger(), nullable=False),
        sa.Column("orig_pkts", sa.BigInteger(), nullable=False),
        sa.Column("resp_pkts", sa.BigInteger(), nullable=False),
        sa.Column("conn_state", sa.String(16)),
        sa.Column("community_id", sa.String(64)),
        sa.CheckConstraint(
            "proto IN ('tcp', 'udp', 'icmp', 'other')", name="ck_network_flows_proto"
        ),
    )
    _endpoint_indexes("network_flows")
    op.create_index(
        "ix_network_flows_job_id_total_bytes", "network_flows", ["job_id", "total_bytes"]
    )

    op.create_table(
        "network_records",
        *_base("network_records"),
        *_endpoints(),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint("kind IN ('dns', 'http', 'tls')", name="ck_network_records_kind"),
    )
    _endpoint_indexes("network_records")
    op.create_index(
        "ix_network_records_job_id_kind_ts", "network_records", ["job_id", "kind", "ts"]
    )

    op.create_table(
        "network_alerts",
        *_base("network_alerts"),
        *_endpoints(),
        sa.Column("proto", sa.String(16)),
        sa.Column("signature_id", sa.BigInteger(), nullable=False),
        sa.Column("rev", sa.Integer(), nullable=False),
        sa.Column("signature", sa.String(512), nullable=False),
        sa.Column("category", sa.String(255)),
        sa.Column("severity", sa.SmallInteger(), nullable=False),
        sa.Column("community_id", sa.String(64)),
        sa.CheckConstraint("severity BETWEEN 1 AND 4", name="ck_network_alerts_severity"),
    )
    _endpoint_indexes("network_alerts")
    op.create_index("ix_network_alerts_job_id_severity", "network_alerts", ["job_id", "severity"])

    op.create_table(
        "analysis_findings",
        *_base("analysis_findings"),
        *_endpoints(),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("type", sa.String(64), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(8), nullable=False),
        sa.Column("confidence", sa.Double(), nullable=False),
        sa.Column("detection_method", sa.String(128), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True)),
        sa.Column("protocol", sa.String(16)),
        sa.Column("evidence_refs", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("attributes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.UniqueConstraint("job_id", "finding_id", name="uq_analysis_findings_job_id_finding_id"),
        sa.CheckConstraint(f"severity IN {SEVERITIES}", name="ck_analysis_findings_severity"),
    )
    _endpoint_indexes("analysis_findings")
    for column in ("severity", "type"):
        op.create_index(
            f"ix_analysis_findings_job_id_{column}", "analysis_findings", ["job_id", column]
        )

    op.create_table(
        "iocs",
        *_base("iocs"),
        sa.Column("type", sa.String(16), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.BigInteger(), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
    )
    # md5(value): long values would exceed the btree entry size; ingest refuses exact
    # duplicates before this index is reached.
    op.execute("CREATE UNIQUE INDEX uq_iocs_job_id_type_value ON iocs (job_id, type, md5(value))")

    op.create_table(
        "analysis_timeline",
        *_base("analysis_timeline"),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event", sa.String(16), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("severity", sa.String(8)),
        sa.Column("ref", sa.String(64)),
        sa.Column("src_ip", postgresql.INET()),
        sa.Column("dst_ip", postgresql.INET()),
        sa.CheckConstraint(
            f"severity IS NULL OR severity IN {SEVERITIES}", name="ck_analysis_timeline_severity"
        ),
    )
    op.create_index("ix_analysis_timeline_job_id_ts", "analysis_timeline", ["job_id", "ts"])

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
