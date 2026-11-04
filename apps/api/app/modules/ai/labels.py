"""Context labels (M5 phase 1, FROZEN): short per-run ids the model cites instead of UUIDs.

Grammar `^(J\\d{1,3}:)?[A-Z]\\d{1,4}$`: a kind prefix letter plus a 1-based per-kind counter
(`F3`), optionally qualified by a child job of an incident reduce (`J2:F3`).
"""

import re
from dataclasses import dataclass

from app.modules.ai.contracts import RefKind

LABEL_PATTERN = re.compile(r"^(?:J(\d{1,3}):)?([A-Z])(\d{1,4})$")
MAX_INDEX = 9999
MAX_JOB = 999


@dataclass(frozen=True)
class ParsedLabel:
    kind: RefKind
    index: int
    job: int | None = None  # the `J{n}:` qualifier of an incident reduce label


def format_label(kind: RefKind, index: int, job: int | None = None) -> str:
    if not 1 <= index <= MAX_INDEX:
        raise ValueError("label index out of range")
    if job is not None and not 1 <= job <= MAX_JOB:
        raise ValueError("label job out of range")
    base = f"{kind.prefix}{index}"
    return f"J{job}:{base}" if job is not None else base


def qualify(label: str, job: int) -> str:
    """`F3` -> `J2:F3` (a child's label inside the reduce context)."""
    parsed = parse_label(label)
    if parsed is None or parsed.job is not None:
        raise ValueError("only an unqualified valid label can be qualified")
    return format_label(parsed.kind, parsed.index, job)


def parse_label(label: str) -> ParsedLabel | None:
    """None for anything outside the grammar or with an unknown prefix letter."""
    if not isinstance(label, str):
        return None
    match = LABEL_PATTERN.fullmatch(label)
    if match is None:
        return None
    job, prefix, index = match.groups()
    kind = RefKind.from_prefix(prefix)
    if kind is None or int(index) < 1 or (job is not None and int(job) < 1):
        return None
    return ParsedLabel(kind=kind, index=int(index), job=int(job) if job is not None else None)


def is_label(label: str) -> bool:
    return parse_label(label) is not None
