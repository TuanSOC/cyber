"""Dedicated worker-thread limiter for evidence I/O and hashing.

Long transfers must not consume anyio's shared default limiter, which also serves argon2
password hashing and health checks.
"""

from functools import cache

import anyio

EVIDENCE_IO_THREADS = 16


@cache
def evidence_io_limiter() -> anyio.CapacityLimiter:
    return anyio.CapacityLimiter(EVIDENCE_IO_THREADS)
