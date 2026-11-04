import enum
import uuid
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from cyberlab_jobs.base import ErrorCode, Sha256, ShortText, Strict, Token
from cyberlab_jobs.limits import JobLimits

PCAP_SCHEMA = "pcap.v1"
INGEST_SCHEMA = "ingest.v1"

Url = Annotated[str, Field(min_length=1, max_length=4096, pattern=r"^https?://")]


class PresignedPost(Strict):
    """S3 POST policy: the form fields must be sent verbatim with the file."""

    url: Url
    fields: dict[ShortText, Annotated[str, Field(max_length=8192)]]


class PcapJobV1(Strict):
    """API -> pcap analyzer (queue `pcap`)."""

    schema_version: Literal["pcap.v1"] = PCAP_SCHEMA
    job_id: uuid.UUID
    organization_id: uuid.UUID
    evidence_id: uuid.UUID
    expected_sha256: Sha256
    size_bytes: int = Field(ge=0)
    evidence_url: Url
    result_post: PresignedPost
    ingest_token: Token
    limits: JobLimits


class IngestEvent(enum.StrEnum):
    STARTED = "started"
    FINISHED = "finished"


class Outcome(enum.StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class IngestMessageV1(Strict):
    """Analyzer -> trusted ingest (queue `ingest`). Authenticated by the per-job token."""

    schema_version: Literal["ingest.v1"] = INGEST_SCHEMA
    job_id: uuid.UUID
    organization_id: uuid.UUID
    ingest_token: Token
    event: IngestEvent
    outcome: Outcome | None = None
    error_code: ErrorCode | None = None
    result_version_id: ShortText | None = None
    worker_version: ShortText

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.event == IngestEvent.STARTED:
            if self.outcome or self.error_code or self.result_version_id:
                raise ValueError("started events carry no outcome")
            return self
        if self.outcome is None:
            raise ValueError("finished events need an outcome")
        if self.outcome == Outcome.FAILED and not self.error_code:
            raise ValueError("failed outcome needs an error_code")
        if self.outcome == Outcome.SUCCEEDED and (self.error_code or not self.result_version_id):
            raise ValueError("succeeded outcome needs a result_version_id and no error_code")
        return self
