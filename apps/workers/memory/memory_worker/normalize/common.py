"""Shared accumulator of the normalizers: parsed rows -> capped contract records."""

from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, TypeVar

from cyberlab_jobs.memory import (
    MemoryArtifactRecord,
    MemoryConnectionRecord,
    MemoryInjectionRecord,
    MemoryLimits,
    MemoryPlugin,
    MemoryProcessRecord,
)
from pydantic import BaseModel, ValidationError

from memory_worker.normalize.models import COLUMNS, MODELS, RESERVED, Row

R = TypeVar("R", bound=Row)
M = TypeVar("M", bound=BaseModel)
INT64_MAX = 2**63 - 1
ATTRIBUTE_TEXT = 1024
RECORD_ERRORS = (ValidationError, ValueError, TypeError, OverflowError)


@dataclass
class WindowsInfo:
    nt_build: str | None = None
    system_time: datetime | None = None


@dataclass
class Normalized:
    processes: list[MemoryProcessRecord] = field(default_factory=list)
    connections: list[MemoryConnectionRecord] = field(default_factory=list)
    injections: list[MemoryInjectionRecord] = field(default_factory=list)
    artifacts: list[MemoryArtifactRecord] = field(default_factory=list)
    info: WindowsInfo = field(default_factory=WindowsInfo)
    # Per plugin (MemoryPlugin value): rows skipped (bad type / record), rows with unknown
    # columns. Record kinds that hit their contract cap.
    skipped: Counter[str] = field(default_factory=Counter)
    unknown_columns: Counter[str] = field(default_factory=Counter)
    capped: set[str] = field(default_factory=set)


class Builder:
    """Parses rows of one run and appends contract records under the caps."""

    def __init__(self, limits: MemoryLimits) -> None:
        self.limits = limits
        self.out = Normalized()
        self._caps = {
            "processes": limits.max_processes,
            "connections": limits.max_connections,
            "injections": limits.max_injections,
            "artifacts": limits.max_artifacts,
        }

    def parse(
        self, plugin: MemoryPlugin, rows: Iterable[Mapping[str, Any]], model: type[R]
    ) -> list[R]:
        known = set(COLUMNS[plugin]) | RESERVED
        assert MODELS[plugin] is model  # noqa: S101 - programming error, not input
        parsed: list[R] = []
        for row in rows:
            if set(row) - known:
                self.out.unknown_columns[plugin.value] += 1
            try:
                parsed.append(model.model_validate(row))
            except RECORD_ERRORS:
                self.out.skipped[plugin.value] += 1
        return parsed

    def record(self, plugin: MemoryPlugin, build: Callable[[], M]) -> M | None:
        """A contract record, or None (skipped and counted) when it does not validate."""
        try:
            item = build()
            item.model_dump_json()  # serializable (no lone surrogates etc.)
        except RECORD_ERRORS:
            self.out.skipped[plugin.value] += 1
            return None
        return item

    def add(self, kind: str, plugin: MemoryPlugin, build: Callable[[], M]) -> None:
        target: list[Any] = getattr(self.out, kind)
        if len(target) >= self._caps[kind]:
            self.out.capped.add(kind)
            return
        item = self.record(plugin, build)
        if item is not None:
            target.append(item)

    def artifact(
        self, plugin: MemoryPlugin, type_: str, pid: int | None, attributes: dict[str, object]
    ) -> None:
        clean = {k: v for k, v in attributes.items() if v is not None}

        def build() -> MemoryArtifactRecord:
            try:
                return MemoryArtifactRecord.model_validate(
                    {"type": type_, "pid": pid, "attributes": clean}
                )
            except ValidationError:
                # Too large for the 4 KiB column: shorten the text values once.
                short = {k: v[:256] if isinstance(v, str) else v for k, v in clean.items()}
                return MemoryArtifactRecord.model_validate(
                    {"type": type_, "pid": pid, "attributes": short}
                )

        self.add("artifacts", plugin, build)


def addr(value: int | None) -> int | str | None:
    """An address attribute: an int while it fits the bigint column, else `0x...` text
    (kernel addresses are above 2**63)."""
    if value is None or value < 0:
        return None
    return value if value <= INT64_MAX else f"0x{value:x}"


__all__ = ["ATTRIBUTE_TEXT", "Builder", "Normalized", "WindowsInfo", "addr"]
