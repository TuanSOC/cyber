"""Error classes of every terminal `error_code` (M7 phase 1, IMPLEMENTED and FROZEN).

Runtime metrics (phase 5) group failures by class: parse success is
`succeeded / (succeeded + failed with class parse)`. The map covers every code the platform
can store on a failed job, run or render:
- analysis jobs: the pcap and static analyzers (`JobFailed` codes and their pipeline's
  `timed_out` / `analyzer_error`), the shared worker kit (`cyberlab_worker.transfer`), the
  trusted ingest (`invalid_result`, `ingest_error`, `analyzer_failed`), the API dispatch
  (`enqueue_failed`) and the reaper (`never_started`, `timed_out`);
- TI runs store no error code (NULL); their item reasons are classified for completeness;
- AI runs: `AiErrorCode`;
- report renders: `RENDER_ERROR_CODES`, the renderer's `snapshot_too_large`, the reaper's
  `timeout`.
`tests/unit/test_error_classes.py` fails on any code found in those sources that is missing.
"""

import enum
from collections.abc import Mapping
from types import MappingProxyType


class ErrorClass(enum.StrEnum):
    PARSE = "parse"  # the input or a result could not be parsed / was invalid
    INFRA = "infra"  # time-outs, storage, broker, worker or renderer failures
    POLICY = "policy"  # refused by a platform or org policy (share policy, budget, guards)
    PROVIDER = "provider"  # an external TI / AI provider failed or refused
    INPUT = "input"  # the input is outside what the platform accepts (size, format)
    OTHER = "other"


# The untrusted analyzers' codes (apps/workers/{pcap,static}, packages/py-worker-kit). They
# are not importable from the api image, so they are listed here and pinned by the test.
ANALYZER_CODES = (
    "unsupported_capture_format",
    "capture_too_large",
    "sample_too_large",
    "result_too_large",
    "timed_out",
    "tool_timeout",
    "zeek_timeout",
    "zeek_failed",
    "unparseable_capture",
    "analyzer_error",
    "url_expired",
    "evidence_unavailable",
    "integrity_mismatch",
    "result_upload_failed",
)

_P, _I, _Y, _V, _N, _O = (
    ErrorClass.PARSE,
    ErrorClass.INFRA,
    ErrorClass.POLICY,
    ErrorClass.PROVIDER,
    ErrorClass.INPUT,
    ErrorClass.OTHER,
)

ERROR_CLASS: Mapping[str, ErrorClass] = MappingProxyType(
    {
        # --- analysis jobs (pcap / static) ---
        "unsupported_capture_format": _N,
        "capture_too_large": _N,
        "sample_too_large": _N,
        "result_too_large": _N,
        "timed_out": _I,
        "tool_timeout": _I,
        "zeek_timeout": _I,
        "zeek_failed": _P,
        "unparseable_capture": _P,
        "analyzer_error": _P,
        "url_expired": _I,
        "evidence_unavailable": _I,
        "integrity_mismatch": _I,
        "result_upload_failed": _I,
        "invalid_result": _P,
        "ingest_error": _I,
        "analyzer_failed": _O,
        "enqueue_failed": _I,
        "never_started": _I,
        # --- threat intel item reasons (runs store no error code) ---
        "rate_limited": _V,
        "quota_exhausted": _V,
        "deadline": _I,
        "auth_failed": _V,
        "policy_blocked": _Y,
        # --- AI runs (AiErrorCode) ---
        "not_implemented": _O,
        "ai_disabled": _Y,
        "provider_disabled": _Y,
        "provider_unavailable": _V,
        "spend_limit": _V,
        "overloaded": _V,
        "max_tokens": _V,
        "invalid_output": _P,
        "context_too_large": _N,
        "budget_exhausted": _Y,
        "provider_error": _V,
        "canary_leak": _Y,
        "no_digest": _N,
        "refused": _V,
        # --- report renders (RENDER_ERROR_CODES + renderer + reaper) ---
        "snapshot_mismatch": _Y,
        "fetch_blocked": _Y,
        "timeout": _I,
        "oom": _I,
        "too_large": _N,
        "too_many_pages": _N,
        "renderer_error": _I,
        "snapshot_too_large": _N,
        # --- shared fallbacks ---
        "internal_error": _I,
        "other": _O,
    }
)


def classify(code: str | None) -> ErrorClass:
    """The class of a stored error code; unknown or missing codes are `other`."""
    if code is None:
        return ErrorClass.OTHER
    return ERROR_CLASS.get(code, ErrorClass.OTHER)
