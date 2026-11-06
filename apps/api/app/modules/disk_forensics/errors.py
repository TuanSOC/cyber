"""API error codes of disk forensics (M9 phase 1, FROZEN; raised by phases 7, 8 and 10).

`evidence_sensitivity_restricted` / `_released` live in `evidence/sensitivity_errors.py` (the
generic sensitivity, RT2); `insufficient_storage` (507) is M8's.
"""

from app.core.errors import AppError, Conflict


class DiskImageTooLarge(AppError):
    status_code = 413
    code = "disk_image_too_large"
    message = "A disk image segment is larger than the disk analyzer accepts"


class DiskImageSetTooLarge(AppError):
    status_code = 413
    code = "disk_image_set_too_large"
    message = "The disk image segments together are larger than the disk analyzer accepts"


class DiskSegmentsInvalid(AppError):
    status_code = 422
    code = "disk_segments_invalid"
    message = (
        "The segments must be 1 to 64 distinct evidence items of this investigation, "
        "including this evidence"
    )


class DiskImageEmpty(AppError):
    status_code = 422
    code = "disk_image_empty"
    message = "An empty file cannot be analyzed as a disk image"


class DiskExportNotAllowed(Conflict):
    """Deleted, not a regular file, too large, not allocated, or on the never-collected list
    (any name of the inode, RT7)."""

    code = "disk_export_not_allowed"
    message = "This file cannot be exported from the disk image"


class DiskExportNotReady(Conflict):
    code = "disk_export_not_ready"
    message = "The exported file is not ready"


class DiskExportAlreadyPromoted(Conflict):
    code = "disk_export_already_promoted"
    message = "The exported file was already added to the case"


class DiskExportExpired(Conflict):
    code = "disk_export_expired"
    message = "The exported file expired; export it again"


ERROR_CODES = (
    DiskImageTooLarge.code,
    DiskImageSetTooLarge.code,
    DiskSegmentsInvalid.code,
    DiskImageEmpty.code,
    DiskExportNotAllowed.code,
    DiskExportNotReady.code,
    DiskExportAlreadyPromoted.code,
    DiskExportExpired.code,
)
