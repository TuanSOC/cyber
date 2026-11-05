"""Timeline export models (M6 phase 1, FROZEN; the export route lands in phase 5).

`GET /investigations/{inv}/timeline/export?format=csv|json&kinds&from&to` streams an
attachment of at most TIMELINE_EXPORT_MAX_ROWS entries (a truncation marker row when
capped). CSV: a `# TLP:<label> CASE-xxxxx exported <ts>` header line, then RFC 4180 rows
through `app.core.csv_safe.write_csv`. JSON: `TimelineExportJson`.
"""

from datetime import datetime
from typing import Literal

from cyberlab_jobs.report import TLP
from pydantic import BaseModel

from app.modules.investigations.schemas import TimelineEntryOut

TimelineExportFormat = Literal["csv", "json"]
CSV_COLUMNS = (
    "ts",
    "ts_source",
    "kind",
    "title",
    "severity",
    "evidence_id",
    "job_id",
    "ref_kind",
    "ref_id",
)


class TimelineExportJson(BaseModel):
    tlp: TLP
    case: str  # CASE-xxxxx
    exported_at: datetime
    truncated: bool
    entries: list[TimelineEntryOut]
