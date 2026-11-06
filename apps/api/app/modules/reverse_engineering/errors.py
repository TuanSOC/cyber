"""API error codes of reverse engineering (M10 phase 1, FROZEN; raised by phases 7 and 8).

`too_many_active_jobs` (429) with `reason: heavy_analysis_busy` is the platform-wide heavy
analysis cap (RT2, `analysis.service`): it never names another organization's job.
"""

from app.core.errors import AppError, Conflict, NotFound


class StaticAnalysisRequired(Conflict):
    """No succeeded static `full` job identified this evidence as PE / ELF (the source of an
    RE job: its AV scan, format facts and capa links)."""

    code = "static_analysis_required"
    message = "Run a full static analysis of this file first (it must identify a PE or ELF file)"


class ReSampleTooLarge(AppError):
    status_code = 413
    code = "re_sample_too_large"
    message = "The file is larger than the reverse engineering analyzer accepts"


class UnsupportedArchitecture(AppError):
    status_code = 422
    code = "unsupported_architecture"
    message = "Only x86 and x86-64 programs can be reverse engineered"


class UnsupportedManagedCode(AppError):
    status_code = 422
    code = "unsupported_managed_code"
    message = ".NET (managed) programs cannot be reverse engineered here"


class ProfileUnavailable(AppError):
    status_code = 422
    code = "profile_unavailable"
    message = "This reverse engineering profile is not available on this platform"


class FunctionNotFound(NotFound):
    code = "function_not_found"
    message = "No function starts at this address in this analysis"


class HeavyAnalysisBusy(AppError):
    """RT2: one memory / disk / reverse analysis at a time platform-wide (by default)."""

    status_code = 429
    code = "too_many_active_jobs"
    message = "Another heavy analysis is running on this platform; try again later"

    def __init__(self) -> None:
        super().__init__(extra={"reason": "heavy_analysis_busy"}, headers={"Retry-After": "60"})


ERROR_CODES = (
    StaticAnalysisRequired.code,
    ReSampleTooLarge.code,
    UnsupportedArchitecture.code,
    UnsupportedManagedCode.code,
    ProfileUnavailable.code,
    FunctionNotFound.code,
    HeavyAnalysisBusy.code,
)
