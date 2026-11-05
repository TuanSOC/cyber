"""`dynamic.v1`: the dynamic (sandboxed execution) analysis contract. DESIGN ONLY in M7.

Dynamic analysis is **not enabled** (`DYNAMIC_ENABLED` is False). Nothing in the API or the
workers imports this module in M7, it is not exported from `cyberlab_jobs`, and no analyzer
value, queue, broker user, compose service or route exists for it
(`apps/api/tests/unit/test_dynamic_gate.py`). See docs/SANDBOX_SECURITY.md: it may be enabled
only after every item of its gating checklist passes on the target infrastructure.

Engine-neutral on purpose: CAPE specifics live only in the future `sandbox-bridge`, which
converts the engine's report into these lines. Frozen at the end of M7 phase 7, subject to
**one** revision when a bridge is built; change it only together with the trusted ingest.

Framing is exactly `static.v1`'s (gzip NDJSON, header first, hashed `ResultTrailer` last,
checked by the trusted ingest's framing reader), and every value is attacker-controlled: it
is derived from what a hostile sample did inside the guest and from the engine's report about
it. Text is therefore stricter than `static.v1`: length-capped, and free of NUL, C0 controls
(tab excepted), DEL and C1 controls, so it can never carry terminal escapes or line splits.
"""

import uuid
from collections import Counter
from typing import Annotated, Final, Literal, Self

from pydantic import Field, TypeAdapter, ValidationError, model_validator

from cyberlab_jobs.base import Sha256, Strict, Token
from cyberlab_jobs.messages import PresignedPost, Url
from cyberlab_jobs.results import Count, Port, Timestamp

DYNAMIC_SCHEMA: Final = "dynamic.v1"
# The kill switch in code. Enabling dynamic analysis is a parent decision recorded in
# ROADMAP after the SANDBOX_SECURITY.md gating checklist passes; it is never an env var.
DYNAMIC_ENABLED: Final = False

MAX_TIMEOUT_S: Final = 300  # per-job wall clock; the sandbox host hard-kills the VM at it
MAX_DURATION_MS: Final = MAX_TIMEOUT_S * 1000
MAX_RECORD_LINES: Final = 200_000  # record lines per result (header, summary, trailer extra)
MAX_STREAM_LINES: Final = MAX_RECORD_LINES + 3

# Only these two. `internet`, Tor, VPN and SOCKS routing are forbidden: the bridge refuses
# them and this type cannot express them. `none` is the default (and maps to the engine's
# drop-everything mode, never to an engine "no routing" mode that leaves traffic flowing).
RouteMode = Literal["none", "sinkhole"]

# NUL, C0 controls except tab, DEL and C1 controls are refused.
NO_CTRL: Final = r"^[^\x00-\x08\x0a-\x1f\x7f-\x9f]*$"
Text64 = Annotated[str, Field(max_length=64, pattern=NO_CTRL)]
Text255 = Annotated[str, Field(max_length=255, pattern=NO_CTRL)]
Text1024 = Annotated[str, Field(max_length=1024, pattern=NO_CTRL)]
# Command lines, descriptions: the bound of `static.v1`'s longest free text.
BoundedText = Annotated[str, Field(max_length=2048, pattern=NO_CTRL)]
NonEmptyPath = Annotated[str, Field(min_length=1, max_length=1024, pattern=NO_CTRL)]

Pid = Annotated[int, Field(ge=0, le=2**32 - 1)]
Millis = Annotated[int, Field(ge=0, le=MAX_DURATION_MS)]  # since the sample was started
AttackId = Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]
ImageDigest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
# The destination the sample asked for (an IP literal or a name), recorded as a label: it was
# never contacted (route `none` drops it, `sinkhole` answers it from the sandbox host).
DestinationLabel = Annotated[
    str, Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9._:\-]+$")
]

DynamicErrorCode = Literal[
    "integrity",  # sha256 / size mismatch (bridge before submit, or guest agent before run)
    "route_refused",  # the requested route is not `none` / `sinkhole`
    "timeout",  # wall clock hit; the VM was hard-killed
    "revert_failed",  # the clean-state proof failed: nothing from this VM is trusted
    "vm_error",
    "engine_error",
    "result_too_large",
]


class DynamicJobV1(Strict):
    """API -> sandbox-bridge (a future queue; none exists in M7).

    `sample_url` is a presigned GET of the exact evidence version; `upload` the presigned POST
    for the result stream; `token` the per-job ingest token (stored hashed, as for every job).
    """

    schema_version: Literal["dynamic.v1"] = DYNAMIC_SCHEMA
    job_id: uuid.UUID
    org_id: uuid.UUID
    evidence_id: uuid.UUID
    evidence_sha256: Sha256
    evidence_bytes: int = Field(gt=0, le=2**63 - 1)
    sample_url: Url
    route: RouteMode = "none"
    timeout_s: int = Field(gt=0, le=MAX_TIMEOUT_S)
    upload: PresignedPost
    token: Token
    deadline: Timestamp  # the bridge refuses a job received after it (no stale execution)


# --- result lines ------------------------------------------------------------------------


class DynamicResultHeader(Strict):
    kind: Literal["header"] = "header"
    schema_version: Literal["dynamic.v1"] = DYNAMIC_SCHEMA
    job_id: uuid.UUID
    route: RouteMode
    engine: Text64  # e.g. "cape"; shown, never interpreted
    engine_version: Text64
    truncated: Annotated[dict[Text64, bool], Field(max_length=16)] = {}


class ProcessRecord(Strict):
    kind: Literal["process"] = "process"
    pid: Pid
    ppid: Pid
    image: NonEmptyPath
    cmdline: BoundedText
    start_ms: Millis
    end_ms: Millis | None = None

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.end_ms is not None and self.end_ms < self.start_ms:
            raise ValueError("end_ms is before start_ms")
        return self


class FileRecord(Strict):
    kind: Literal["file"] = "file"
    op: Literal["create", "write", "read", "delete", "rename", "execute"]
    path: NonEmptyPath
    sha256: Sha256 | None = None


class RegistryRecord(Strict):
    kind: Literal["registry"] = "registry"
    op: Literal["create", "set", "read", "delete"]
    key: Annotated[str, Field(min_length=1, max_length=1024, pattern=NO_CTRL)]
    value_name: Text255 | None = None


class NetworkRecord(Strict):
    """One attempted connection or lookup. `route` must equal the job's (checked per stream)."""

    kind: Literal["network"] = "network"
    proto: Literal["tcp", "udp", "icmp", "other"]
    dst: DestinationLabel
    port: Port
    dns_query: Text255 | None = None
    bytes: Count
    route: RouteMode


class SignatureRecord(Strict):
    """An engine behaviour signature: an observation shown verbatim, never a verdict."""

    kind: Literal["signature"] = "signature"
    name: Annotated[str, Field(min_length=1, max_length=255, pattern=NO_CTRL)]
    severity: Literal["info", "low", "medium", "high"]
    description: BoundedText
    attack_ids: Annotated[list[AttackId], Field(max_length=20)] = []


class DroppedRecord(Strict):
    """A file the sample wrote. v1 keeps hashes only: the bytes never leave the sandbox."""

    kind: Literal["dropped"] = "dropped"
    sha256: Sha256
    size: Count
    path: NonEmptyPath


RecordKind = Literal["process", "file", "registry", "network", "signature", "dropped"]
RECORD_KINDS: Final[tuple[RecordKind, ...]] = (
    "process",
    "file",
    "registry",
    "network",
    "signature",
    "dropped",
)


class DynamicSummaryV1(Strict):
    """Exactly one, the last line before the trailer. `counts` must match the stream."""

    kind: Literal["summary"] = "summary"
    status: Literal["succeeded", "failed"]
    error_code: DynamicErrorCode | None = None
    route: RouteMode
    duration_ms: Millis
    vm_image_digest: ImageDigest  # the golden image the clone came from
    revert_verified: bool
    counts: Annotated[dict[RecordKind, Count], Field(max_length=len(RECORD_KINDS))] = {}

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.status == "failed" and self.error_code is None:
            raise ValueError("a failed run needs an error_code")
        if self.status == "succeeded":
            if self.error_code is not None:
                raise ValueError("a succeeded run carries no error_code")
            if not self.revert_verified:
                raise ValueError("a run without a verified revert cannot succeed")
        return self


DynamicRecordLine = Annotated[
    ProcessRecord | FileRecord | RegistryRecord | NetworkRecord | SignatureRecord | DroppedRecord,
    Field(discriminator="kind"),
]
# Body lines: records, then the summary.
DynamicBodyLine = Annotated[
    ProcessRecord
    | FileRecord
    | RegistryRecord
    | NetworkRecord
    | SignatureRecord
    | DroppedRecord
    | DynamicSummaryV1,
    Field(discriminator="kind"),
]

DYNAMIC_RECORD_ADAPTER: TypeAdapter[DynamicRecordLine] = TypeAdapter(DynamicRecordLine)
DYNAMIC_BODY_ADAPTER: TypeAdapter[DynamicBodyLine] = TypeAdapter(DynamicBodyLine)


class DynamicStreamError(ValueError):
    """The stream is refused; `reason` is a short code (the ingest maps it to its own)."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class DynamicStreamCheck:
    """Per-stream rules on top of the per-line contract, fed by the ingest's framing reader
    (`header` with line 1, `body` with every line before the trailer, then `finish`).

    Pure and engine-neutral: the header must name this job and route, every network line
    carries the job's route, records stop at the summary, at most `max_records` records,
    and the summary's counts equal what was seen.
    """

    def __init__(
        self, job_id: uuid.UUID, route: RouteMode, *, max_records: int = MAX_RECORD_LINES
    ) -> None:
        if not 0 < max_records <= MAX_RECORD_LINES:
            raise ValueError("max_records must be within 1..MAX_RECORD_LINES")
        self._job_id = job_id
        self._route = route
        self._max_records = max_records
        self._counts: Counter[str] = Counter()
        self._summary: DynamicSummaryV1 | None = None

    def header(self, raw: bytes) -> DynamicResultHeader:
        try:
            header = DynamicResultHeader.model_validate_json(raw)
        except ValidationError as exc:
            raise DynamicStreamError("invalid_header") from exc
        if header.job_id != self._job_id:
            raise DynamicStreamError("wrong_job")
        if header.route != self._route:
            raise DynamicStreamError("route_mismatch")
        return header

    def body(self, raw: bytes) -> DynamicRecordLine | DynamicSummaryV1:
        if self._summary is not None:
            raise DynamicStreamError("line_after_summary")
        try:
            line = DYNAMIC_BODY_ADAPTER.validate_json(raw)
        except ValidationError as exc:
            raise DynamicStreamError("invalid_line") from exc
        if isinstance(line, DynamicSummaryV1):
            if line.route != self._route:
                raise DynamicStreamError("route_mismatch")
            self._summary = line
            return line
        if sum(self._counts.values()) >= self._max_records:
            raise DynamicStreamError("too_many_records")
        if isinstance(line, NetworkRecord) and line.route != self._route:
            raise DynamicStreamError("route_mismatch")
        self._counts[line.kind] += 1
        return line

    def finish(self) -> DynamicSummaryV1:
        if self._summary is None:
            raise DynamicStreamError("missing_summary")
        declared = {kind: n for kind, n in self._summary.counts.items() if n}
        if declared != dict(self._counts):
            raise DynamicStreamError("count_mismatch")
        return self._summary


__all__ = [
    "DYNAMIC_BODY_ADAPTER",
    "DYNAMIC_ENABLED",
    "DYNAMIC_RECORD_ADAPTER",
    "DYNAMIC_SCHEMA",
    "MAX_DURATION_MS",
    "MAX_RECORD_LINES",
    "MAX_STREAM_LINES",
    "MAX_TIMEOUT_S",
    "RECORD_KINDS",
    "BoundedText",
    "DroppedRecord",
    "DynamicBodyLine",
    "DynamicErrorCode",
    "DynamicJobV1",
    "DynamicRecordLine",
    "DynamicResultHeader",
    "DynamicStreamCheck",
    "DynamicStreamError",
    "DynamicSummaryV1",
    "FileRecord",
    "NetworkRecord",
    "ProcessRecord",
    "RecordKind",
    "RegistryRecord",
    "RouteMode",
    "SignatureRecord",
]
