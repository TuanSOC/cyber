"""Root-side normalizers: bounded plugin rows -> `memory.v1` records (M8 phase 2).

`normalize(os, rows, limits) -> Normalized`: `rows` maps each plugin that produced output to
its (already bounded) row dicts. Every row is validated by its plugin's row model
(`models`), a bad row is skipped and counted, never fatal; records are built through the
frozen contract models and capped per kind (`capped`). Pure Python: no Volatility, no
sandbox; the engines hand in rows read through the worker kit.
"""

from collections.abc import Iterable, Mapping
from typing import Any

from cyberlab_jobs.memory import MemoryLimits, MemoryOs, MemoryPlugin

from memory_worker.normalize import linux, windows
from memory_worker.normalize.common import Builder, Normalized, WindowsInfo


def normalize(
    os: MemoryOs, rows: Mapping[MemoryPlugin, Iterable[Mapping[str, Any]]], limits: MemoryLimits
) -> Normalized:
    builder = Builder(limits)
    (windows if os == "windows" else linux).normalize(builder, rows)
    return builder.out


__all__ = ["Normalized", "WindowsInfo", "normalize"]
