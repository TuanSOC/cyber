"""Incident reduce context (signature FROZEN in phase 1; phase 4 fills the body).

Pure: adds `J{n}:D{k}` digest-claim items (supported claims and hypotheses of each child,
with the child's flags, RT23) and copies the cited child items (`J{n}:F3` ...) with their
original field values, so the verifier can check quotes. Same caps and hash rules.
"""

from app.modules.ai.contracts import DigestInput, FrozenContext


def build_reduce_context(base: FrozenContext, digests: list[DigestInput]) -> FrozenContext:
    raise NotImplementedError("phase 4")
