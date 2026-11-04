"""Celery task names and queues. Tasks take one keyword argument: `message` (a dict)."""

from dataclasses import dataclass

PCAP_ANALYZE = "pcap.analyze"
STATIC_ANALYZE = "static.analyze"
INGEST_EVENT = "ingest.event"
REAP = "ingest.reap"


@dataclass(frozen=True)
class Queues:
    """Queue names, optionally prefixed so test jobs never reach dev workers."""

    prefix: str = ""

    @property
    def pcap(self) -> str:
        return f"{self.prefix}pcap"

    @property
    def static(self) -> str:
        return f"{self.prefix}static"

    @property
    def ingest(self) -> str:
        return f"{self.prefix}ingest"
