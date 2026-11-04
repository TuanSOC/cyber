"""Per-analyzer parameters, in one place for the API, dispatch, ingest and the reaper."""

from app.core.config import Settings
from app.modules.analysis.models import Analyzer


def max_bytes(settings: Settings, analyzer: Analyzer) -> int:
    """Largest evidence the analyzer accepts."""
    return settings.static_max_bytes if analyzer == Analyzer.STATIC else settings.pcap_max_bytes


def timeout_s(settings: Settings, analyzer: Analyzer) -> int:
    """Wall-clock budget of one run (the worker's own limit; the reaper adds a grace)."""
    if analyzer == Analyzer.STATIC:
        return settings.analysis_static_timeout_s
    return settings.analysis_timeout_s


def max_result_bytes(settings: Settings, analyzer: Analyzer) -> int:
    """Upload cap of the result object (presigned POST policy and ingest download)."""
    if analyzer == Analyzer.STATIC:
        return settings.static_max_result_bytes
    return settings.analysis_max_result_bytes
