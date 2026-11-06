"""Celery task names and queues. Tasks take one keyword argument: `message` (a dict)."""

from dataclasses import dataclass

PCAP_ANALYZE = "pcap.analyze"
STATIC_ANALYZE = "static.analyze"
# Memory forensics (M8): consumed only by the untrusted memory analyzer (queue `memory`).
MEMORY_ANALYZE = "memory.analyze"
INGEST_EVENT = "ingest.event"
REAP = "ingest.reap"
# Threat intel (M4): consumed only by the trusted enrich worker. They live here so that the
# analyzer ACL tests can name the queue; analyzers never use them.
TI_ENRICH = "ti.enrich"
TI_RESUME = "ti.resume"
TI_VERIFY = "ti.verify"
# AI analyst (M5): consumed only by the trusted analyst worker (queue `analyst`).
AI_RUN = "ai.run"
AI_RESUME = "ai.resume"
AI_VERIFY = "ai.verify"
# Reports (M6): `report.render` goes to the untrusted report renderer (queue `report`); its
# answer `report.rendered` goes to the trusted ingest worker (queue `ingest`).
REPORT_RENDER = "report.render"
REPORT_RENDERED = "report.rendered"
# Platform operations (M7): the retention worker (queue `retention`) runs the daily sweep, one
# org's run and the S3 legal-hold sync; the ingest worker indexes correlation keys (beat).
RETENTION_SWEEP = "retention.sweep"
RETENTION_RUN_ORG = "retention.run_org"
RETENTION_SYNC_HOLDS = "retention.sync_holds"
CORRELATION_INDEX_PENDING = "correlation.index_pending"


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
    def memory(self) -> str:
        return f"{self.prefix}memory"

    @property
    def ingest(self) -> str:
        return f"{self.prefix}ingest"

    @property
    def enrich(self) -> str:
        return f"{self.prefix}enrich"

    @property
    def analyst(self) -> str:
        return f"{self.prefix}analyst"

    @property
    def report(self) -> str:
        return f"{self.prefix}report"

    @property
    def retention(self) -> str:
        return f"{self.prefix}retention"
