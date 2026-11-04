"""pcap results: read-path indexes (flow port filter, IOC ordering)

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-04 23:00:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # `port` matches either side of a flow (src_port = p OR dst_port = p): one index each.
    op.create_index("ix_network_flows_job_id_src_port", "network_flows", ["job_id", "src_port"])
    op.create_index("ix_network_flows_job_id_dst_port", "network_flows", ["job_id", "dst_port"])
    # IOC list order: count DESC, first_seen, id within a job.
    op.execute("CREATE INDEX ix_iocs_job_id_count ON iocs (job_id, count DESC, first_seen, id)")


def downgrade() -> None:
    op.drop_index("ix_iocs_job_id_count", table_name="iocs")
    op.drop_index("ix_network_flows_job_id_dst_port", table_name="network_flows")
    op.drop_index("ix_network_flows_job_id_src_port", table_name="network_flows")
