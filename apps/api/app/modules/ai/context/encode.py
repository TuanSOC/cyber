"""Canonical JSON for contexts (M5 phase 4).

The one serialization every hash and size estimate uses: sorted keys, no whitespace, NFC,
non-ASCII kept (`ensure_ascii=False`). It matches `FrozenContext.canonical_json()` byte for
byte, so the running size the builder tracks while filling the budget is exactly the length
of the final canonical context.
"""

import hashlib
import json
import unicodedata
from typing import Any

from app.modules.ai.contracts import CONTEXT_VERSION, AiTask, ContextItem, FieldValue


def canonical(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return unicodedata.normalize("NFC", text)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def fields_sha256(fields: dict[str, FieldValue]) -> str:
    """`ContextRef.fields_sha256`: the sha256 of the rendered fields exactly as sent."""
    return sha256_hex(canonical(fields))


def item_json(item: ContextItem) -> str:
    return canonical(item.model_dump(mode="json"))


def empty_context_json(task: AiTask, version: str = CONTEXT_VERSION) -> str:
    """The canonical context with no items; each item adds `len(item_json)` plus a comma."""
    return canonical({"version": version, "task": task.value, "items": []})
