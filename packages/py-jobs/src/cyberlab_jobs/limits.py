from typing import Self

from pydantic import Field, model_validator

from cyberlab_jobs.base import Strict


class JobLimits(Strict):
    """Resource limits the API attaches to every job; workers enforce them."""

    max_bytes: int = Field(gt=0)
    timeout_s: int = Field(gt=0, le=6 * 3600)
    tool_timeout_s: int = Field(gt=0)
    max_flows: int = Field(gt=0, le=1_000_000)
    max_records_per_kind: int = Field(gt=0, le=1_000_000)
    max_findings: int = Field(gt=0, le=100_000)
    max_result_bytes: int = Field(gt=0, le=1024**3)

    @model_validator(mode="after")
    def _tool_within_job(self) -> Self:
        if self.tool_timeout_s >= self.timeout_s:
            raise ValueError("tool_timeout_s must be below timeout_s")
        return self
