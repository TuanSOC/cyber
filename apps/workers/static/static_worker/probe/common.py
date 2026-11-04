"""Output helpers shared by the probe modes (tool uid side)."""

import json
import math
import sys
from collections import Counter
from typing import Any

NUL = "\x00"


def emit(record: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(record, ensure_ascii=True, allow_nan=False) + "\n")


def error(code: str, detail: str = "") -> None:
    emit({"kind": "error", "code": code, "detail": text(detail, 200)})


def text(value: object, limit: int) -> str:
    """Contract-safe text: decoded, NUL-free, surrogate-free, length-capped."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    elif not isinstance(value, str):
        value = str(value)
    clean = value.replace(NUL, "")[:limit]
    return clean.encode("utf-8", "replace").decode("utf-8")


def entropy(data: bytes | bytearray | memoryview) -> float:
    return entropy_of(Counter(bytes(data)), len(data))


def entropy_of(counts: Counter[int], total: int) -> float:
    if total <= 0:
        return 0.0
    value = -sum(c / total * math.log2(c / total) for c in counts.values() if c)
    return round(min(max(value, 0.0), 8.0), 4)


def u64(value: object) -> int:
    return value if isinstance(value, int) and 0 <= value < 2**64 else 0
