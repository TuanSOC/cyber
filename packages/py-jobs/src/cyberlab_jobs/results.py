"""`pcap.v1` result stream: gzip NDJSON, one object per line, `kind` discriminates.

Line 1 is the header, the last line the trailer (line count + sha256 of every byte before
it), so a truncated or spliced stream is detectable before anything is written.
"""

import uuid
from typing import Annotated, Literal

from pydantic import Field

from cyberlab_jobs.base import ErrorCode, Sha256, ShortText, Strict
from cyberlab_jobs.capture import CaptureFormat

ToolVersions = Annotated[dict[ShortText, ShortText], Field(max_length=16)]


class ResultHeader(Strict):
    kind: Literal["header"] = "header"
    schema_version: Literal["pcap.v1"] = "pcap.v1"
    job_id: uuid.UUID
    capture_format: CaptureFormat
    tool_versions: ToolVersions
    engine_errors: Annotated[list[ErrorCode], Field(max_length=16)] = []
    truncated: Annotated[dict[ShortText, bool], Field(max_length=16)] = {}


class ResultTrailer(Strict):
    kind: Literal["trailer"] = "trailer"
    line_count: int = Field(ge=1)
    sha256: Sha256
