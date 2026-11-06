"""API error codes of memory forensics (M8 phase 1, FROZEN; raised by phases 6 and 8).

`memory_requires_tlp_red` is intentionally absent: reports omit restricted memory rows and
count them in the snapshot's `omissions` instead of refusing (RT10).
"""

from app.core.errors import AppError, Conflict


class MemoryImageTooLarge(AppError):
    status_code = 413
    code = "memory_image_too_large"
    message = "The memory image is larger than the memory analyzer accepts"


class MemoryImageEmpty(AppError):
    status_code = 422
    code = "memory_image_empty"
    message = "An empty file cannot be analyzed as a memory image"


class MemorySensitivityRestricted(Conflict):
    """The share-policy flags of restricted memory evidence cannot be cleared before an
    admin releases it."""

    code = "memory_sensitivity_restricted"
    message = "This evidence is a restricted memory image: an admin must release it first"


class MemorySensitivityReleased(Conflict):
    code = "memory_sensitivity_released"
    message = "This memory evidence was already released"


class AcknowledgementRequired(AppError):
    status_code = 422
    code = "acknowledgement_required"
    message = "The release must be acknowledged"


class InsufficientStorage(AppError):
    status_code = 507
    code = "insufficient_storage"
    message = "Not enough free space to accept this upload now"


ERROR_CODES = (
    MemoryImageTooLarge.code,
    MemoryImageEmpty.code,
    MemorySensitivityRestricted.code,
    MemorySensitivityReleased.code,
    AcknowledgementRequired.code,
    InsufficientStorage.code,
)
