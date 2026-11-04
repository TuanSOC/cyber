"""Celery task names and queues. Tasks take one keyword argument: `message` (a dict)."""

from dataclasses import dataclass

PCAP_ANALYZE = "pcap.analyze"
STATIC_ANALYZE = "static.analyze"
INGEST_EVENT = "ingest.event"
REAP = "ingest.reap"
# Threat intel (M4): consumed only by the trusted enrich worker. They live here so that the
# analyzer ACL tests can name the queue; analyzers never use them.
TI_ENRICH = "ti.enrich"
TI_RESUME = "ti.resume"
TI_VERIFY = "ti.verify"


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

    @property
    def enrich(self) -> str:
        return f"{self.prefix}enrich"
