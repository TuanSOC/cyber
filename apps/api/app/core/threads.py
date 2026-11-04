"""Dedicated worker-thread limiter for evidence I/O and hashing.

Long transfers must not consume anyio's shared default limiter, which also serves argon2
password hashing and health checks.
"""

from functools import cache

import anyio

EVIDENCE_IO_THREADS = 16
BROKER_THREADS = 4


@cache
def evidence_io_limiter() -> anyio.CapacityLimiter:
    return anyio.CapacityLimiter(EVIDENCE_IO_THREADS)


@cache
def broker_limiter() -> anyio.CapacityLimiter:
    """Job publishing: a stalled broker can block at most these threads, nothing else."""
    return anyio.CapacityLimiter(BROKER_THREADS)
