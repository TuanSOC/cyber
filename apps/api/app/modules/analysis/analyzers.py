"""Per-analyzer parameters, in one place for the API, dispatch, ingest and the reaper.

Every function is a full mapping over `Analyzer` (M8 RT1: no two-way "else" that would hand a
memory job the pcap limits); `test_analyzer_exhaustive.py` checks it.
"""

from app.core.config import Settings
from app.modules.analysis.models import Analyzer


def max_bytes(settings: Settings, analyzer: Analyzer) -> int:
    """Largest evidence the analyzer accepts."""
    return {
        Analyzer.PCAP: settings.pcap_max_bytes,
        Analyzer.STATIC: settings.static_max_bytes,
        Analyzer.MEMORY: settings.memory_max_bytes,
    }[analyzer]


def timeout_s(settings: Settings, analyzer: Analyzer) -> int:
    """Wall-clock budget of one run (the worker's own limit; the reaper adds a grace)."""
    return {
        Analyzer.PCAP: settings.analysis_timeout_s,
        Analyzer.STATIC: settings.analysis_static_timeout_s,
        Analyzer.MEMORY: settings.analysis_memory_timeout_s,
    }[analyzer]


def max_result_bytes(settings: Settings, analyzer: Analyzer) -> int:
    """Upload cap of the result object (presigned POST policy and ingest download)."""
    return {
        Analyzer.PCAP: settings.analysis_max_result_bytes,
        Analyzer.STATIC: settings.static_max_result_bytes,
        Analyzer.MEMORY: settings.memory_max_result_bytes,
    }[analyzer]
