"""Engines: the Volatility runner and the test-profile-only replay engine (M8 phase 2).

`engine_for(config)` picks one; both produce the same out-dir files, read by the same root
code (`memory_worker.analyzer`). `magic` is root's compressed / archive refusal (RT19; pure,
so this package imports nothing of the sandbox at import time).
"""

from typing import TYPE_CHECKING

from memory_worker.config import Config

if TYPE_CHECKING:
    from memory_worker.engines.base import Engine


def engine_for(config: Config) -> "Engine":
    if config.engine == "replay":
        from memory_worker.engines.replay import ReplayEngine

        return ReplayEngine()
    from memory_worker.engines.volatility import VolatilityEngine

    return VolatilityEngine(config)


__all__ = ["engine_for"]
