"""Runtime job metrics (migration 0014, M7 phase 1, FROZEN).

`job_outcomes` is a system table (no org id, no tenant data): one row per terminal transition
of an analysis job, TI run, AI run or report render, written by the `record_job_outcome()`
AFTER UPDATE triggers (SECURITY DEFINER), never by application code. The app role reads it
(`/internal/metrics`); the retention worker deletes rows older than
`RETENTION_JOB_OUTCOMES_DAYS`.
"""

from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models_base import Base, UUIDPk

# M8 (0016): `memory` joins the analyzers (the trigger copies `analyzer::text`).
KINDS = ("pcap", "static", "memory", "ti", "ai", "report")


class JobOutcome(UUIDPk, Base):
    __tablename__ = "job_outcomes"
    __table_args__ = (
        Index(None, "finished_at"),
        Index(None, "kind", "finished_at"),
        CheckConstraint(
            "kind IN ('pcap', 'static', 'memory', 'ti', 'ai', 'report')", name="kind"
        ),
        CheckConstraint("queue_ms IS NULL OR queue_ms >= 0", name="queue_ms_non_negative"),
        CheckConstraint("run_ms IS NULL OR run_ms >= 0", name="run_ms_non_negative"),
    )

    kind: Mapped[str] = mapped_column(String(16))
    # Analysis profile, TI provider (or `multi`), AI provider or report format.
    subkind: Mapped[str | None] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))
    error_code: Mapped[str | None] = mapped_column(String(64))
    queue_ms: Mapped[int | None] = mapped_column(BigInteger)
    run_ms: Mapped[int | None] = mapped_column(BigInteger)
    finished_at: Mapped[datetime] = mapped_column(server_default=func.now())
