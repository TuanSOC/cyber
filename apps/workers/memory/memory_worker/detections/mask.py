"""Shim (M9 phase 1, RT8 precedent): the masker now lives in the worker kit as
`cyberlab_worker.mask`, shared with the disk analyzer. Same objects, same behaviour."""

from cyberlab_worker.mask import (
    KEEP,
    MASKED,
    SHORT,
    excerpt,
    mask,
    mask_value,
    secret_spans,
)

__all__ = ["KEEP", "MASKED", "SHORT", "excerpt", "mask", "mask_value", "secret_spans"]
